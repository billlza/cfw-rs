use std::fs;
use std::path::{Path, PathBuf};

use cfw_core::{LegacyNetworkState, SettingsStore, UiPreferences};
use cfw_platform::{MacOsPlatformService, ServiceModeStatus};
use cfw_profiles::ProfileRepository;
use tauri::{AppHandle, Emitter, Manager};

use super::cutover_plan::RetiredLegacyNetwork;
use super::journal::{CutoverJournalStore, CutoverPhase};
use super::process_cleanup::{require_path_absent, verify_privileged_artifacts_are_gone};
use super::state_gate::{LegacyCleanupAction, LegacyCleanupError, LegacyRetirementStatus};
use crate::commands::sanitize_legacy_preferences;
use crate::settings_store;

pub(super) fn run_launch_preflight(app: &AppHandle) -> Result<(), String> {
    let store = settings_store()?;
    if let Some(journal) = CutoverJournalStore::new(store.paths().app_home.clone()).load()? {
        let status = match journal.phase {
            CutoverPhase::Prepared | CutoverPhase::GuiStopped => {
                let launch = app.state::<crate::LaunchContext>();
                if launch.migration_handoff
                    && super::admission::require_canonical_handoff_candidate().is_ok()
                    && super::recovery::resume_pre_network_cutover_if_intact(&journal, &store)
                        .is_ok()
                {
                    LegacyRetirementStatus::AwaitingConfirmation
                } else {
                    LegacyRetirementStatus::RecoveryStartRequired {
                        target: journal.target,
                        message: format!(
                            "cutover was interrupted in phase {:?}; the old GUI was not resumed because exact live ownership or installed release identity could not be proven",
                            journal.phase
                        ),
                    }
                }
            }
            CutoverPhase::NetworkRetiring | CutoverPhase::LegacyRetired => {
                LegacyRetirementStatus::RecoveryStartRequired {
                    target: journal.target,
                    message: format!(
                        "cutover was interrupted in phase {:?}; use Recover Replacement. The old helper is never restarted automatically",
                        journal.phase
                    ),
                }
            }
            CutoverPhase::ReplacementActive => {
                let engine = app.state::<crate::engine::ManagedEngine>();
                let digest = match journal.target {
                    cfw_engine_api::EngineMode::SystemProxy => &journal.system_proxy_digest,
                    cfw_engine_api::EngineMode::Tunnel => &journal.tunnel_digest,
                    cfw_engine_api::EngineMode::Off => unreachable!("journal rejects Off"),
                };
                if super::require_replacement_active(
                    engine.coordinator.snapshot(),
                    journal.target,
                    digest,
                    &journal.context,
                )
                .is_ok()
                {
                    LegacyRetirementStatus::PostCutoverCleanupRequired {
                        message: "native state proves the journal-bound replacement is Active; finish non-network legacy data cleanup"
                            .into(),
                    }
                } else {
                    LegacyRetirementStatus::RecoveryStartRequired {
                        target: journal.target,
                        message: "journal claimed ReplacementActive but the native owner/context/digest/ready state does not currently prove it; explicit recovery is required"
                            .into(),
                    }
                }
            }
            CutoverPhase::CleanupComplete => launch_preflight_with(
                || {
                    store
                        .legacy_retirement_completed()
                        .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))
                },
                || verify_privileged_artifacts_are_gone(&store.paths().legacy_cores_dir),
                || require_retired_managed_paths_absent(&store),
            ),
        };
        app.state::<super::LegacyRetirementGate>()
            .apply_launch_preflight(status)?;
        return emit_engine_snapshot_refresh(app);
    }
    let status = launch_preflight_with(
        || {
            store
                .legacy_retirement_completed()
                .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))
        },
        || verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path()),
        || require_retired_managed_paths_absent(&store),
    );
    app.state::<super::LegacyRetirementGate>()
        .apply_launch_preflight(status)?;
    emit_engine_snapshot_refresh(app)
}

pub(super) fn launch_preflight_with<Marker, VerifyNetwork, VerifyData>(
    read_completed_marker: Marker,
    verify_network_retired: VerifyNetwork,
    verify_data_removed: VerifyData,
) -> LegacyRetirementStatus
where
    Marker: FnOnce() -> Result<bool, String>,
    VerifyNetwork: FnOnce() -> Result<(), String>,
    VerifyData: FnOnce() -> Result<(), String>,
{
    match read_completed_marker() {
        Ok(false) => LegacyRetirementStatus::AwaitingConfirmation,
        Ok(true) => match verify_network_retired() {
            Err(message) => LegacyRetirementStatus::ManualCleanupRequired {
                action: LegacyCleanupAction::Retry,
                message: format!(
                    "completed legacy retirement could not verify the network boundary: {message}"
                ),
            },
            Ok(()) => match verify_data_removed() {
                Ok(()) => LegacyRetirementStatus::Cleared,
                Err(message) => LegacyRetirementStatus::PostCutoverCleanupRequired {
                    message: format!(
                        "network retirement is verified, but managed data cleanup remains: {message}"
                    ),
                },
            },
        },
        Err(message) => LegacyRetirementStatus::ManualCleanupRequired {
            action: LegacyCleanupAction::Retry,
            message,
        },
    }
}

/// Runs only after the replacement runtime has been verified Active. Failures
/// here never stop or roll back the new network and remain idempotently
/// retryable from the persistent retirement marker.
pub(super) fn finalize_legacy_data(
    app: &AppHandle,
    retired: &RetiredLegacyNetwork,
) -> Result<(), String> {
    let plan = &retired.plan;
    finalize_legacy_data_state(
        app,
        &plan.store,
        plan.retirement_completed,
        plan.legacy_settings.as_ref(),
        &plan.preferences,
    )
}

pub(super) fn finalize_recovered_legacy_data(app: &AppHandle) -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let retirement_completed = store
        .legacy_retirement_completed()
        .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))?;
    let legacy_settings = cfw_core::LegacySettingsMigration::read(store.paths())
        .map_err(|error| format!("legacy settings are unreadable during recovery: {error}"))?;
    let preferences = legacy_settings
        .as_ref()
        .map(|migration| migration.preferences.clone())
        .unwrap_or(store.read_or_default().map_err(|error| error.to_string())?);
    finalize_legacy_data_state(
        app,
        &store,
        retirement_completed,
        legacy_settings.as_ref(),
        &preferences,
    )
}

fn finalize_legacy_data_state(
    app: &AppHandle,
    store: &SettingsStore,
    retirement_completed: bool,
    legacy_settings: Option<&cfw_core::LegacySettingsMigration>,
    preferences: &UiPreferences,
) -> Result<(), String> {
    if !retirement_completed {
        store
            .commit_legacy_retirement()
            .map_err(|error| format!("failed to persist legacy retirement marker: {error}"))?;
    }

    let snapshot = if retirement_completed {
        store.snapshot().map_err(|error| error.to_string())?
    } else {
        ProfileRepository::new(store.paths().legacy_profiles_dir.clone())
            .clear_managed_profiles()
            .map_err(|error| format!("failed to clear managed legacy profiles: {error}"))?;
        reconcile_main_app_login_item(preferences)?;
        let snapshot = sanitize_legacy_preferences(store, preferences.clone())?;
        if let Some(migration) = legacy_settings {
            migration
                .remove_source(store.paths())
                .map_err(|error| format!("failed to remove migrated legacy settings: {error}"))?;
        }
        snapshot
    };

    remove_managed_path(&store.paths().legacy_cores_dir)?;
    remove_managed_path(&store.paths().legacy_helpers_dir)?;
    remove_managed_path(&store.paths().legacy_profiles_dir)?;
    for path in legacy_managed_files(store) {
        remove_managed_path(&path)?;
    }
    verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
    require_retired_managed_paths_absent(store)?;
    app.emit("cfw://settings-changed", snapshot)
        .map_err(|error| format!("failed to publish migrated settings: {error}"))
}

fn require_retired_managed_paths_absent(store: &SettingsStore) -> Result<(), String> {
    require_path_absent(
        &store.paths().legacy_cores_dir,
        "legacy managed core directory",
    )?;
    require_path_absent(
        &store.paths().legacy_helpers_dir,
        "legacy managed helper directory",
    )?;
    require_path_absent(
        &store.paths().legacy_profiles_dir,
        "legacy managed profile directory",
    )?;
    for path in legacy_managed_files(store) {
        require_path_absent(&path, "legacy managed file")?;
    }
    Ok(())
}

fn legacy_managed_files(store: &SettingsStore) -> Vec<PathBuf> {
    let home = &store.paths().app_home;
    vec![
        store.paths().legacy_config_file.clone(),
        home.join("proxy.pac"),
        home.join("mixin.yaml"),
        home.join("mixin.yml"),
        home.join("profile-parser.js"),
        home.join("tray-script.js"),
        home.join("child-process.json"),
        home.join("cache.db"),
        home.join("cache.db-shm"),
        home.join("cache.db-wal"),
    ]
}

pub(super) fn restore_legacy_dns(
    network: &LegacyNetworkState,
    dns_review_confirmed: bool,
) -> Result<(), LegacyCleanupError> {
    let Some(_dns_servers) = network.restore_dns_servers.as_ref() else {
        return Ok(());
    };
    if dns_review_confirmed {
        Ok(())
    } else {
        Err(LegacyCleanupError::ReviewDns(
            "legacy restore-dns-servers has no per-service ownership identity. Before cutover, review DNS for every active service in System Settings; no DNS setting is changed automatically"
                .into(),
        ))
    }
}

fn reconcile_main_app_login_item(preferences: &UiPreferences) -> Result<(), String> {
    let platform = MacOsPlatformService;
    if !preferences.launch_at_login {
        return platform
            .disable_login_item()
            .map_err(|error| format!("failed to keep Start at Login disabled: {error}"));
    }
    let status = match platform.login_item_status() {
        ServiceModeStatus::Enabled => ServiceModeStatus::Enabled,
        ServiceModeStatus::RequiresApproval => ServiceModeStatus::RequiresApproval,
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => {
            platform.enable_login_item().map_err(|error| {
                format!("failed to register the signed main app Login Item: {error}")
            })?
        }
        ServiceModeStatus::Unknown => ServiceModeStatus::Unknown,
    };
    require_enabled_login_item(status)
}

pub(super) fn require_enabled_login_item(status: ServiceModeStatus) -> Result<(), String> {
    match status {
        ServiceModeStatus::Enabled => Ok(()),
        ServiceModeStatus::RequiresApproval => Err(
            "the preserved Start at Login preference requires approval in System Settings; replacement networking remains active and cleanup can be retried after approval"
                .into(),
        ),
        other => Err(format!(
            "the signed main app Login Item is not enabled after migration: {other:?}"
        )),
    }
}

pub(super) fn remove_managed_path(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(|error| {
            format!(
                "failed to remove managed directory {}: {error}",
                path.display()
            )
        })
    } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to remove managed file {}: {error}", path.display()))
    } else {
        Err(format!(
            "refusing to remove unsupported managed path type: {}",
            path.display()
        ))
    }
}

pub(super) fn emit_engine_snapshot_refresh(app: &AppHandle) -> Result<(), String> {
    app.emit("cfw://engine-snapshot", serde_json::Value::Null)
        .map_err(|error| format!("failed to publish engine snapshot refresh: {error}"))
}
