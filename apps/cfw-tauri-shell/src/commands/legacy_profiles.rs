//! Safe, restartable migration of the one legacy profile selected by 0.3.x.
//!
//! The old YAML is read as an inert source document and converted through the
//! existing bounded Clash importer. It is never handed to a running core. A
//! preview stores only a short-lived random authority in memory; commit rereads
//! the exact sidecar/document pair and rejects any source drift before writing
//! the new repository or credential vault.

use std::fmt;
#[cfg(test)]
use std::path::Path;
use std::time::{Duration, Instant};

mod source;
use source::{
    Directory, open_directory_at, open_owned_directory, read_legacy_entry,
    read_optional_legacy_entry,
};

use cfw_engine_api::CredentialVaultProvisioner;
use cfw_profiles::{ExactProfileImportOutcome, ProfileRepository};
use cfw_singbox_config::ValidatedSingBoxProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ManagedProfiles;
use super::imported_credentials::{
    ImportedCredentialProvisionAttemptError, ImportedCredentialProvisionError,
    provision_imported_credentials_with_exact_replay,
};
use super::subscriptions::{
    validate_subscription_url, validated_subscription_import_with_namespace,
};
use crate::engine::ManagedEngine;
use crate::settings_store;
use crate::subscription_import::{ImportedCredential, ImportedSubscription};

const MAX_LEGACY_SIDECAR_BYTES: usize = 16 * 1024;
/// The real legacy subscription is 494,575 bytes. This migration-only raw
/// bound is independent from the 384 KiB validated profile/envelope limit.
const MAX_LEGACY_SUBSCRIPTION_BYTES: usize = 512 * 1024;
const MAX_LEGACY_PROFILE_NAME_BYTES: usize = 256;
const PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);

/// Backend-only authority. None of the source digest, URL, or namespace is
/// serialized to the renderer. The deterministic namespace is derived only
/// from the inert basename, so a process restart can recover by previewing the
/// same source pair again without exposing secret-derived identifiers.
pub(super) struct LegacyProfileMigrationAuthority {
    pub(super) preview_id: String,
    pub(super) created_at: Instant,
    pub(super) active_profile: String,
    pub(super) metadata_digest: [u8; 32],
}

impl fmt::Debug for LegacyProfileMigrationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyProfileMigrationAuthority")
            .field("preview_id", &self.preview_id)
            .field("created_at", &self.created_at)
            .field("active_profile", &self.active_profile)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProfileSidecar {
    id: String,
    name: String,
    source_url: Option<String>,
    #[serde(default, rename = "home_web")]
    _home_web: Option<String>,
    #[serde(default, rename = "subscription_userinfo")]
    _subscription_userinfo: Option<String>,
    #[serde(default, rename = "update_interval")]
    _update_interval: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum LegacyProfileMigrationPreview {
    NoActiveProfile,
    NotSubscription {
        name: String,
        legacy_bytes: usize,
        reason: String,
    },
    Ready {
        preview_id: String,
        name: String,
        source_host: String,
        legacy_bytes: usize,
        active: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct LegacyProfileMigrationOutcome {
    id: String,
    name: String,
    bytes: usize,
    digest: String,
    reused: bool,
    selected: bool,
}

enum LegacyCandidateState {
    NoActiveProfile,
    NotSubscription { name: String, legacy_bytes: usize },
    Ready(LegacyCandidate),
}

struct LegacyCandidate {
    active_profile: String,
    metadata_digest: [u8; 32],
    name: String,
    source_url: reqwest::Url,
    source_host: String,
    legacy_bytes: usize,
    document: Zeroizing<String>,
}

#[tauri::command]
pub(crate) fn preview_legacy_cfw_profile_migration(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<LegacyProfileMigrationPreview, String> {
    crate::platform_maintenance::require_legacy_profile_migration()?;
    // The preview validates the same Off boundary as commit, but does not create
    // directories or write any durable state.
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    match read_selected_legacy_candidate()? {
        LegacyCandidateState::NoActiveProfile => {
            *profiles
                .legacy_profile_migration_preview()
                .lock()
                .map_err(|_| "legacy migration preview lock is poisoned")? = None;
            Ok(LegacyProfileMigrationPreview::NoActiveProfile)
        }
        LegacyCandidateState::NotSubscription { name, legacy_bytes } => {
            *profiles
                .legacy_profile_migration_preview()
                .lock()
                .map_err(|_| "legacy migration preview lock is poisoned")? = None;
            Ok(LegacyProfileMigrationPreview::NotSubscription {
                name,
                legacy_bytes,
                reason: "The selected legacy profile is a local configuration and has no HTTPS subscription URL. Import a supported sing-box JSON profile manually."
                    .into(),
            })
        }
        LegacyCandidateState::Ready(candidate) => {
            let settings = engine.engine_settings()?;
            let namespace = migration_namespace(&candidate.active_profile);
            validated_subscription_import_with_namespace(
                &candidate.document,
                &settings,
                namespace,
            )?;
            let preview_id = Uuid::new_v4().hyphenated().to_string();
            let authority = LegacyProfileMigrationAuthority {
                preview_id: preview_id.clone(),
                created_at: Instant::now(),
                active_profile: candidate.active_profile,
                metadata_digest: candidate.metadata_digest,
            };
            *profiles
                .legacy_profile_migration_preview()
                .lock()
                .map_err(|_| "legacy migration preview lock is poisoned")? = Some(authority);
            Ok(LegacyProfileMigrationPreview::Ready {
                preview_id,
                name: candidate.name,
                source_host: candidate.source_host,
                legacy_bytes: candidate.legacy_bytes,
                active: true,
            })
        }
    }
}

#[tauri::command]
pub(crate) async fn commit_legacy_cfw_profile_migration(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    preview_id: String,
    confirmed: bool,
) -> Result<LegacyProfileMigrationOutcome, String> {
    crate::platform_maintenance::require_legacy_profile_migration()?;
    if !confirmed {
        return Err("legacy profile migration requires explicit confirmation".into());
    }
    let parsed_preview = Uuid::parse_str(&preview_id)
        .map_err(|_| "legacy migration preview id is invalid".to_owned())?;
    if parsed_preview.hyphenated().to_string() != preview_id {
        return Err("legacy migration preview id is not canonical".into());
    }
    // Hold the maintenance lease through source reread, vault preparation,
    // repository commit, and selection. No competing in-process profile
    // mutation can race the created/replayed disposition. Admission occurs
    // before the one-shot preview is consumed, so a busy engine does not erase
    // a preview that never reached the migration transaction.
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let authority = take_preview_authority(&profiles, &preview_id)?;
    let LegacyCandidateState::Ready(candidate) = read_selected_legacy_candidate()? else {
        return Err("the selected legacy profile is no longer a migratable subscription".into());
    };
    if candidate.active_profile != authority.active_profile
        || candidate.metadata_digest != authority.metadata_digest
    {
        return Err(
            "legacy profile metadata changed after preview; review the current candidate before retrying"
                .into(),
        );
    }

    let settings = engine.engine_settings()?;
    let namespace = migration_namespace(&candidate.active_profile);
    let imported =
        validated_subscription_import_with_namespace(&candidate.document, &settings, namespace)?;
    let profile_id = deterministic_profile_uuid(&candidate.active_profile)
        .hyphenated()
        .to_string();

    let ExactProfileImportOutcome {
        profile: record,
        created,
    } = commit_migrated_profile(
        profiles.repository(),
        profiles.credential_vault(),
        &profile_id,
        &candidate.name,
        candidate.source_url.as_str(),
        &imported,
    )
    .await?;

    profiles
        .repository()
        .select(&profile_id)
        .map_err(|error| {
            format!(
                "legacy profile was imported and credentials were verified, but selection failed: {error}"
            )
        })?;

    Ok(LegacyProfileMigrationOutcome {
        id: record.id,
        name: record.name,
        bytes: record.bytes,
        digest: record.digest,
        reused: !created,
        selected: true,
    })
}

fn take_preview_authority(
    profiles: &ManagedProfiles,
    preview_id: &str,
) -> Result<LegacyProfileMigrationAuthority, String> {
    let mut stored = profiles
        .legacy_profile_migration_preview()
        .lock()
        .map_err(|_| "legacy migration preview lock is poisoned")?;
    take_preview_authority_from(&mut stored, preview_id, Instant::now())
}

fn take_preview_authority_from(
    stored: &mut Option<LegacyProfileMigrationAuthority>,
    preview_id: &str,
    now: Instant,
) -> Result<LegacyProfileMigrationAuthority, String> {
    let Some(authority) = stored.as_ref() else {
        return Err("legacy migration preview is missing or expired; preview again".into());
    };
    if authority.preview_id != preview_id {
        return Err("legacy migration preview does not match the current candidate".into());
    }
    if now
        .checked_duration_since(authority.created_at)
        .is_none_or(|elapsed| elapsed > PREVIEW_TTL)
    {
        *stored = None;
        return Err("legacy migration preview has expired; preview again".into());
    }
    stored
        .take()
        .ok_or_else(|| "legacy migration preview disappeared during validation".into())
}

fn read_selected_legacy_candidate() -> Result<LegacyCandidateState, String> {
    let store = settings_store()?;
    let Some(settings) = cfw_core::LegacySettingsMigration::read(store.paths())
        .map_err(|error| format!("legacy settings are unreadable: {error}"))?
    else {
        return Ok(LegacyCandidateState::NoActiveProfile);
    };
    let Some(active_profile) = settings.active_profile.as_deref() else {
        return Ok(LegacyCandidateState::NoActiveProfile);
    };
    let app_home = open_owned_directory(&store.paths().app_home, true)?;
    let profiles_dir = open_directory_at(&app_home, "profiles")?;
    read_candidate_from_directory(&profiles_dir, active_profile)
}

fn read_candidate_from_directory(
    directory: &Directory,
    active_profile: &str,
) -> Result<LegacyCandidateState, String> {
    validate_legacy_basename(active_profile)?;
    let sidecar_name = format!("{active_profile}.json");
    let sidecar = read_legacy_entry(directory, &sidecar_name, MAX_LEGACY_SIDECAR_BYTES)?;
    let yaml_name = format!("{active_profile}.yaml");
    let yml_name = format!("{active_profile}.yml");
    let yaml = read_optional_legacy_entry(directory, &yaml_name, MAX_LEGACY_SUBSCRIPTION_BYTES)?;
    let yml = read_optional_legacy_entry(directory, &yml_name, MAX_LEGACY_SUBSCRIPTION_BYTES)?;
    let (document_name, document) = match (yaml, yml) {
        (Some(document), None) => (yaml_name, document),
        (None, Some(document)) => (yml_name, document),
        (Some(_), Some(_)) => {
            return Err(
                "the selected legacy profile has ambiguous .yaml and .yml documents".into(),
            );
        }
        (None, None) => return Err("the selected legacy profile document is missing".into()),
    };
    let sidecar_text = std::str::from_utf8(&sidecar)
        .map_err(|_| "the selected legacy profile sidecar is not UTF-8")?;
    let sidecar: LegacyProfileSidecar = serde_json::from_str(sidecar_text).map_err(|error| {
        format!(
            "the selected legacy profile sidecar is invalid at line {}, column {}",
            error.line(),
            error.column()
        )
    })?;
    if sidecar.id != active_profile {
        return Err("the selected legacy profile sidecar id does not match its basename".into());
    }
    validate_legacy_name(&sidecar.name)?;
    let metadata_digest = legacy_metadata_digest(
        active_profile,
        &sidecar_name,
        &sidecar,
        &document_name,
        &document,
    );
    let legacy_bytes = document.len();
    let Some(source_text) = sidecar.source_url.map(Zeroizing::new) else {
        return Ok(LegacyCandidateState::NotSubscription {
            name: sidecar.name,
            legacy_bytes,
        });
    };
    let source_url = validate_subscription_url(&source_text)?;
    let source_host = source_url
        .host_str()
        .ok_or("legacy subscription URL has no host")?
        .to_owned();
    let document = String::from_utf8(document)
        .map(Zeroizing::new)
        .map_err(|_| "the selected legacy profile document is not UTF-8")?;
    Ok(LegacyCandidateState::Ready(LegacyCandidate {
        active_profile: active_profile.to_owned(),
        metadata_digest,
        name: sidecar.name,
        source_url,
        source_host,
        legacy_bytes,
        document,
    }))
}

fn validate_legacy_basename(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err("legacy active profile is not a safe bounded basename".into())
    } else {
        Ok(())
    }
}

fn validate_legacy_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_LEGACY_PROFILE_NAME_BYTES
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err("legacy profile name is invalid".into())
    } else {
        Ok(())
    }
}

fn legacy_metadata_digest(
    active_profile: &str,
    sidecar_name: &str,
    sidecar: &LegacyProfileSidecar,
    document_name: &str,
    document: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cfw-legacy-profile-metadata-v2\0");
    hasher.update(active_profile.as_bytes());
    hasher.update([0]);
    hasher.update(sidecar_name.as_bytes());
    hasher.update([0]);
    hasher.update(sidecar.id.as_bytes());
    hasher.update([0]);
    hasher.update(sidecar.name.as_bytes());
    hasher.update([0]);
    hasher.update(sidecar.source_url.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(document_name.as_bytes());
    hasher.update([0]);
    hasher.update(document);
    hasher.finalize().into()
}

fn migration_namespace(active_profile: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"cfw-legacy-profile-namespace-v1\0");
    hasher.update(active_profile.as_bytes());
    let digest = hasher.finalize();
    uuid_from_digest(digest, 5)
}

fn deterministic_profile_uuid(active_profile: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"cfw-legacy-profile-id-v1\0");
    hasher.update(active_profile.as_bytes());
    let digest = hasher.finalize();
    uuid_from_digest(digest, 5)
}

fn uuid_from_digest(digest: impl AsRef<[u8]>, version: u8) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_ref()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | (version << 4);
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

async fn commit_migrated_profile(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    name: &str,
    source_url: &str,
    imported: &ImportedSubscription,
) -> Result<ExactProfileImportOutcome, String> {
    // Hold the repository's cross-process lock across vault preparation and
    // exact-ID commit. Credential GC takes this same lock before its native
    // CAS, so it cannot collect the prepared audience in between these steps.
    let mutation = repository
        .begin_credential_profile_mutation()
        .map_err(|error| {
            format!(
                "legacy profile repository mutation could not begin before credential provisioning: {error}"
            )
        })?;

    // The vault contract is immutable and audience-bound. A transport timeout
    // is resolved by repeating the exact same request once; presence alone is
    // intentionally never treated as proof that secret bytes match.
    provision_migrated_credentials(vault, profile_id, &imported.profile, &imported.credentials)
        .await?;

    mutation
        .commit_exact_import(
            profile_id,
            Some(name),
            &imported.profile,
            Some(source_url),
        )
        .map_err(|error| {
            format!(
                "legacy profile repository commit failed after credential provisioning; the unreferenced vault audience is eligible for credential garbage collection: {error}"
            )
        })
}

async fn provision_migrated_credentials(
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), String> {
    if credentials.is_empty() && profile.credential_references().is_empty() {
        return Ok(());
    }
    match provision_imported_credentials_with_exact_replay(vault, profile_id, profile, credentials)
        .await
    {
        Ok(()) => Ok(()),
        Err(ImportedCredentialProvisionError::OutcomeUnknownReplay { first, replay }) => {
            Err(format!(
                "credential vault did not confirm the exact migration batch after one outcome-unknown replay; no new migration profile was committed ({}; replay: {})",
                migration_provision_attempt_error(&first),
                migration_provision_attempt_error(&replay)
            ))
        }
        Err(ImportedCredentialProvisionError::Rejected(error)) => Err(format!(
            "credential provisioning was not confirmed before repository commit; no new migration profile was committed ({})",
            migration_provision_attempt_error(&error)
        )),
    }
}

fn migration_provision_attempt_error(error: &ImportedCredentialProvisionAttemptError) -> String {
    if matches!(
        error,
        ImportedCredentialProvisionAttemptError::ReceiptAudienceMismatch
    ) {
        "credential vault returned a receipt for a different migration audience".into()
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests;
