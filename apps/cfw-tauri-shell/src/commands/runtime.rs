//! Runtime configuration commands restored from 0.3.5.
//!
//! 0.3.5 rendered a mihomo YAML file to disk and asked a child process to reload
//! it. In 0.4.0 the runtime configuration is a deterministic projection of the
//! selected profile, and the only way to make a running engine adopt a new one
//! is an Authority-mediated mode transition. "Apply" therefore means: acquire
//! serialized mutation admission, read the then-current desired mode, validate
//! the projection, and hand that mode to the same admitted path as the restored
//! switches. A queued Off can never be undone by a stale pre-admission read.
//!
//! The projected configuration carries the app-owned controller secret, so the
//! preview command redacts it and fails closed if the redacted document still
//! contains the secret anywhere.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use cfw_engine_api::EngineMode;
use cfw_profiles::StoredProfile;
use cfw_singbox_config::{EngineSettings, ProjectionMode};
use serde::Serialize;
use serde_json::Value;
use tauri::State;

use super::ManagedProfiles;
use crate::engine::{ManagedEngine, apply_admitted_engine_mode};
use crate::legacy::LegacyRetirementGate;
use crate::settings_store;

/// Placeholder written over the controller secret in a preview.
const REDACTED_SECRET: &str = "[REDACTED]";
/// GeoIP database file names a 0.3.x installation may have left behind.
const GEOIP_METADB_NAME: &str = "geoip.metadb";
const COUNTRY_MMDB_NAME: &str = "Country.mmdb";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProfileApplyResult {
    id: String,
    name: String,
    bytes: usize,
    digest: String,
    mode: EngineMode,
    /// True when a running engine was restarted onto this projection. When the
    /// engine is Off the profile is validated and staged only.
    applied: bool,
}

/// 0.3.5 reported the mtime of the GeoIP database in mihomo's home directory.
/// The field set is unchanged so the General page keeps rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GeoIpDatabaseStatus {
    present: bool,
    file_name: String,
    path: String,
    mtime_ms: Option<u64>,
    size_bytes: Option<u64>,
}

/// Applies the selected profile.
///
/// With the engine running this is a restart onto a freshly projected
/// configuration; with the engine Off it validates the projection and reports
/// that nothing is running yet, instead of pretending a configuration was
/// pushed.
#[tauri::command]
pub(crate) async fn apply_active_profile(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<ProfileApplyResult, String> {
    let (mode, mode_lease) = engine
        .begin_current_mode_change()
        .await
        .map_err(|error| error.to_string())?;
    let selected = require_selected_profile(&profiles)?;
    let settings = engine.engine_settings()?;
    let projected = project_for_mode(&selected, &settings, mode)?;
    if mode != EngineMode::Off {
        apply_admitted_engine_mode(&engine, &retirement, &profiles, mode, mode_lease).await?;
    } else {
        drop(mode_lease);
    }
    Ok(ProfileApplyResult {
        id: selected.record.id,
        name: selected.record.name,
        bytes: projected,
        digest: selected.record.digest,
        mode,
        applied: mode != EngineMode::Off,
    })
}

/// Returns the engine configuration the selected profile projects, with the
/// app-owned controller secret redacted.
#[tauri::command]
pub(crate) fn read_runtime_config_text(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<String, String> {
    let selected = require_selected_profile(&profiles)?;
    let settings = engine.engine_settings()?;
    let mode = match engine.coordinator.snapshot().desired_mode {
        EngineMode::Tunnel => ProjectionMode::Tunnel,
        // With the engine off there is no live configuration; the System Proxy
        // projection is the one a start would use first.
        EngineMode::Off | EngineMode::SystemProxy => ProjectionMode::SystemProxy,
    };
    let projected = selected
        .profile
        .project(&selected.record.id, mode, &settings)
        .map_err(|error| error.to_string())?;
    let secret = engine
        .controller_access()?
        .client_endpoint()
        .secret
        .ok_or("the app-owned controller has no secret")?;
    redact_projection(projected.as_json(), &secret)
}

/// Replaces the controller secret with a placeholder and proves the result no
/// longer contains it.
fn redact_projection(config_json: &str, secret: &str) -> Result<String, String> {
    let mut document =
        serde_json::from_str::<Value>(config_json).map_err(|error| error.to_string())?;
    if let Some(clash_api) = document
        .get_mut("experimental")
        .and_then(|experimental| experimental.get_mut("clash_api"))
        .and_then(Value::as_object_mut)
        && let Some(stored) = clash_api.get_mut("secret")
    {
        *stored = Value::String(REDACTED_SECRET.to_owned());
    }
    let rendered = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
    if !secret.is_empty() && rendered.contains(secret) {
        return Err("runtime configuration preview could not be redacted".into());
    }
    Ok(rendered)
}

fn require_selected_profile(profiles: &ManagedProfiles) -> Result<StoredProfile, String> {
    profiles
        .repository()
        .load_selected()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no active profile is selected".to_owned())
}

/// Projects the profile for the mode a start would use and returns the projected
/// configuration size. Both modes are projected while the engine is off, so a
/// staged profile is proven startable either way.
fn project_for_mode(
    selected: &StoredProfile,
    settings: &EngineSettings,
    mode: EngineMode,
) -> Result<usize, String> {
    let modes: &[ProjectionMode] = match mode {
        EngineMode::SystemProxy => &[ProjectionMode::SystemProxy],
        EngineMode::Tunnel => &[ProjectionMode::Tunnel],
        EngineMode::Off => &[ProjectionMode::SystemProxy, ProjectionMode::Tunnel],
    };
    let mut bytes = 0;
    for mode in modes {
        let projected = selected
            .profile
            .project(&selected.record.id, *mode, settings)
            .map_err(|error| error.to_string())?;
        bytes = bytes.max(projected.as_json().len());
    }
    Ok(bytes)
}

#[tauri::command]
pub(crate) fn geoip_database_status() -> Result<GeoIpDatabaseStatus, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    Ok(geoip_status(&store.paths().app_home))
}

/// Refuses to fetch a GeoIP database.
///
/// The validated profile subset this release accepts contains no rule set and no
/// GeoIP matcher, so the engine consumes no such database. Downloading one would
/// add an unpinnable third-party data-plane input that nothing reads, so the
/// request fails closed and writes nothing.
#[tauri::command]
pub(crate) fn update_geoip_database(url: Option<String>) -> Result<GeoIpDatabaseStatus, String> {
    let requested = url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    Err(format!(
        "no GeoIP database was downloaded or written{}: the accepted profile subset contains no rule set or GeoIP matcher, so this engine consumes no GeoIP database",
        requested
            .map(|_| " from the requested URL")
            .unwrap_or_default()
    ))
}

fn geoip_status(app_home: &Path) -> GeoIpDatabaseStatus {
    for name in [GEOIP_METADB_NAME, COUNTRY_MMDB_NAME] {
        let path = app_home.join(name);
        if let Some(status) = present_geoip_status(&path, name) {
            return status;
        }
    }
    GeoIpDatabaseStatus {
        present: false,
        file_name: GEOIP_METADB_NAME.to_owned(),
        path: app_home.join(GEOIP_METADB_NAME).display().to_string(),
        mtime_ms: None,
        size_bytes: None,
    }
}

fn present_geoip_status(path: &Path, file_name: &str) -> Option<GeoIpDatabaseStatus> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return None;
    }
    Some(GeoIpDatabaseStatus {
        present: true,
        file_name: file_name.to_owned(),
        path: path.display().to_string(),
        mtime_ms: metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
        size_bytes: Some(metadata.len()),
    })
}

#[cfg(test)]
mod tests {
    use cfw_application::EngineControllerAccess;
    use cfw_profiles::{ProfileRecord, ValidatedSingBoxProfile};

    use super::*;

    const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#;

    fn stored() -> StoredProfile {
        let profile = ValidatedSingBoxProfile::parse(PROFILE_JSON).expect("valid profile");
        StoredProfile {
            record: ProfileRecord {
                id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
                name: "Local".into(),
                bytes: profile.as_json().len(),
                digest: profile.digest().to_owned(),
                created_epoch_secs: 7,
            },
            source_url: None,
            profile,
        }
    }

    #[test]
    fn preview_redacts_the_controller_secret_and_keeps_the_endpoint() {
        let access =
            EngineControllerAccess::resolve(EngineSettings::default()).expect("controller access");
        let secret = access
            .client_endpoint()
            .secret
            .expect("the app-owned controller is authenticated");
        let projected = stored()
            .profile
            .project(
                "34db18b6-9903-4e9f-8854-15648e19e4f3",
                ProjectionMode::SystemProxy,
                access.settings(),
            )
            .expect("projection");
        assert!(
            projected.as_json().contains(&secret),
            "the projection is expected to carry the secret"
        );

        let preview = redact_projection(projected.as_json(), &secret).expect("redacted preview");
        assert!(!preview.contains(&secret));
        assert!(preview.contains(REDACTED_SECRET));
        assert!(preview.contains("external_controller"));
        assert!(preview.contains("127.0.0.1"));
    }

    #[test]
    fn preview_fails_closed_when_the_secret_survives_redaction() {
        // A document whose secret lives somewhere the redactor does not know
        // about must never be returned.
        let smuggled = serde_json::json!({
            "experimental": { "clash_api": { "secret": "s3cret" } },
            "outbounds": [{ "type": "direct", "tag": "s3cret" }],
        })
        .to_string();
        assert!(redact_projection(&smuggled, "s3cret").is_err());
        assert!(redact_projection("not json", "s3cret").is_err());
    }

    #[test]
    fn staged_profiles_are_projected_for_both_modes_while_the_engine_is_off() {
        let settings = EngineSettings::default();
        let selected = stored();
        assert!(project_for_mode(&selected, &settings, EngineMode::Off).expect("off") > 0);
        assert!(
            project_for_mode(&selected, &settings, EngineMode::SystemProxy).expect("proxy") > 0
        );
        assert!(project_for_mode(&selected, &settings, EngineMode::Tunnel).expect("tunnel") > 0);

        // An MTU the tunnel projection rejects must fail the staged validation
        // rather than being discovered at start time.
        let invalid = EngineSettings {
            tunnel_mtu: 1,
            ..EngineSettings::default()
        };
        assert!(project_for_mode(&selected, &invalid, EngineMode::Off).is_err());
    }

    #[test]
    fn apply_reads_current_mode_only_after_serialized_admission() {
        let source = include_str!("runtime.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("module source has a production section");
        assert!(source.contains("begin_current_mode_change"));
        assert!(source.contains("apply_admitted_engine_mode"));
        let apply_start = source
            .find("pub(crate) async fn apply_active_profile")
            .expect("apply command");
        let apply_end = source[apply_start..]
            .find("/// Returns the engine configuration")
            .map(|offset| apply_start + offset)
            .expect("next runtime command");
        assert!(!source[apply_start..apply_end].contains("snapshot().desired_mode"));
        for forbidden in [
            concat!("coordinator", ".set_mode"),
            concat!("prepare_", "cutover"),
            concat!("Command", "::new"),
            concat!("network", "setup"),
            concat!("reload_", "config"),
        ] {
            assert!(
                !source.contains(forbidden),
                "runtime apply bypasses the shared engine transition via {forbidden}"
            );
        }
    }

    #[test]
    fn geoip_status_reports_a_leftover_legacy_database_or_absence() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let missing = geoip_status(temporary.path());
        assert!(!missing.present);
        assert_eq!(missing.file_name, GEOIP_METADB_NAME);
        assert_eq!(missing.size_bytes, None);

        fs::write(temporary.path().join(COUNTRY_MMDB_NAME), vec![7_u8; 32])
            .expect("write legacy database");
        let country = geoip_status(temporary.path());
        assert!(country.present);
        assert_eq!(country.file_name, COUNTRY_MMDB_NAME);
        assert_eq!(country.size_bytes, Some(32));
        assert!(country.mtime_ms.is_some());

        fs::write(temporary.path().join(GEOIP_METADB_NAME), vec![1_u8; 64]).expect("write metadb");
        let metadb = geoip_status(temporary.path());
        assert_eq!(metadb.file_name, GEOIP_METADB_NAME);
        assert_eq!(metadb.size_bytes, Some(64));
    }

    #[test]
    fn geoip_update_writes_nothing_and_says_so() {
        for requested in [None, Some("https://example.com/geoip.metadb".to_owned())] {
            let refusal = update_geoip_database(requested).expect_err("no database may be fetched");
            assert!(refusal.contains("no GeoIP database was downloaded or written"));
        }
    }
}
