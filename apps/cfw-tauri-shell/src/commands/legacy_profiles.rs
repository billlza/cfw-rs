//! Safe, restartable migration of the one legacy profile selected by 0.3.x.
//!
//! The old YAML is read as an inert source document and converted through the
//! existing bounded Clash importer. It is never handed to a running core. A
//! preview stores only a short-lived random authority in memory; commit rereads
//! the exact sidecar/document pair and rejects any source drift before writing
//! the new repository or credential vault.

use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{Duration, Instant};

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
    directory: &File,
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

fn open_owned_directory(path: &Path, require_private: bool) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("legacy profile directory must be absolute".into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("legacy profile directory is unavailable: {error}"))?;
    validate_directory(&directory, require_private)?;
    Ok(directory)
}

fn open_directory_at(parent: &File, name: &str) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| "legacy directory name contains NUL")?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "legacy profile directory could not be opened safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    validate_directory(&directory, false)?;
    Ok(directory)
}

fn validate_directory(directory: &File, require_private: bool) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("legacy profile directory metadata is unavailable: {error}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || (require_private && metadata.mode() & 0o077 != 0)
    {
        return Err(
            "legacy profile directory is not an effective-user-owned real directory".into(),
        );
    }
    Ok(())
}

fn read_legacy_entry(directory: &File, name: &str, maximum: usize) -> Result<Vec<u8>, String> {
    read_optional_legacy_entry(directory, name, maximum)?
        .ok_or_else(|| format!("required legacy profile entry is missing: {name}"))
}

fn read_optional_legacy_entry(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
    let name = CString::new(name).map_err(|_| "legacy profile entry name contains NUL")?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "legacy profile entry could not be opened safely: {error}"
        ));
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .map_err(|error| format!("legacy profile entry metadata is unavailable: {error}"))?;
    if !before.file_type().is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
    {
        return Err(
            "legacy profile entry is not an effective-user-owned regular non-writable file".into(),
        );
    }
    if before.len() > maximum as u64 {
        return Err(format!(
            "legacy profile entry exceeds the {maximum}-byte migration limit"
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("legacy profile entry read failed: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("legacy profile entry metadata is unavailable: {error}"))?;
    if !after.file_type().is_file()
        || after.uid() != unsafe { libc::geteuid() }
        || after.nlink() != 1
        || after.mode() & 0o022 != 0
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() > maximum
    {
        return Err("legacy profile entry changed while it was being read".into());
    }
    Ok(Some(bytes))
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
            "credential vault rejected the migration batch before repository commit; no new migration profile was committed ({})",
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
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::sync::Mutex;

    use cfw_engine_api::{
        CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionCommitRequest,
        CredentialGarbageCollectionPreviewFuture, CredentialGarbageCollectionRequest,
        CredentialPresenceFuture, CredentialPresenceRequest, CredentialProvisionRequest,
        CredentialVaultError, CredentialVaultFuture, CredentialVaultReceipt,
    };

    use super::*;

    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#;
    const PROFILE_SECRET: &str = "migration-test-secret";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ProvisionRequestSnapshot {
        profile_id: String,
        profile_digest: String,
        entries: Vec<(String, [u8; 32])>,
    }

    #[derive(Debug)]
    struct ScriptedCredentialVault {
        responses: Mutex<VecDeque<Result<CredentialVaultReceipt, CredentialVaultError>>>,
        requests: Mutex<Vec<ProvisionRequestSnapshot>>,
    }

    impl ScriptedCredentialVault {
        fn new(responses: Vec<Result<CredentialVaultReceipt, CredentialVaultError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
            self.requests.lock().expect("request lock").clone()
        }
    }

    impl CredentialVaultProvisioner for ScriptedCredentialVault {
        fn provision_profile_credentials<'a>(
            &'a self,
            request: CredentialProvisionRequest<'a>,
        ) -> CredentialVaultFuture<'a> {
            let entries = request
                .entries()
                .iter()
                .map(|entry| {
                    let digest = Sha256::digest(entry.secret().expose_to_vault().as_bytes());
                    (entry.reference().id().to_owned(), digest.into())
                })
                .collect();
            self.requests
                .lock()
                .expect("request lock")
                .push(ProvisionRequestSnapshot {
                    profile_id: request.audience().profile_id().to_owned(),
                    profile_digest: request.audience().profile_digest().to_owned(),
                    entries,
                });
            let response = self
                .responses
                .lock()
                .expect("response lock")
                .pop_front()
                .unwrap_or(Err(CredentialVaultError::Internal));
            Box::pin(async move { response })
        }

        fn query_profile_credentials(
            &self,
            _request: CredentialPresenceRequest,
        ) -> CredentialPresenceFuture<'_> {
            Box::pin(async { Err(CredentialVaultError::Internal) })
        }

        fn preview_credential_garbage_collection(
            &self,
            _request: CredentialGarbageCollectionRequest,
        ) -> CredentialGarbageCollectionPreviewFuture<'_> {
            Box::pin(async { Err(CredentialVaultError::Internal) })
        }

        fn commit_credential_garbage_collection(
            &self,
            _request: CredentialGarbageCollectionCommitRequest,
        ) -> CredentialGarbageCollectionCommitFuture<'_> {
            Box::pin(async { Err(CredentialVaultError::Internal) })
        }
    }

    fn imported_profile(credentials: bool) -> ImportedSubscription {
        let profile = ValidatedSingBoxProfile::parse(PROFILE_JSON).expect("credential profile");
        let imported_credentials = credentials
            .then(|| ImportedCredential {
                reference: profile.credential_references()[0].clone(),
                secret: PROFILE_SECRET.into(),
            })
            .into_iter()
            .collect();
        ImportedSubscription {
            profile,
            credentials: imported_credentials,
        }
    }

    fn legacy_directory() -> tempfile::TempDir {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o775))
            .expect("legacy directory permissions");
        temporary
    }

    fn write_candidate(directory: &Path, source_url: Option<&str>) {
        let sidecar = serde_json::json!({
            "id": "active-profile",
            "name": "Migrated profile",
            "source_url": source_url,
            "home_web": "https://panel.example",
            "subscription_userinfo": "upload=0",
            "update_interval": "0"
        });
        fs::write(
            directory.join("active-profile.json"),
            serde_json::to_vec(&sidecar).expect("sidecar JSON"),
        )
        .expect("write sidecar");
        fs::write(
            directory.join("active-profile.yaml"),
            b"proxies:\n  - name: Direct\n    type: ss\n",
        )
        .expect("write YAML");
    }

    fn ready(directory: &Path) -> LegacyCandidate {
        let file = open_owned_directory(directory, false).expect("open legacy directory");
        match read_candidate_from_directory(&file, "active-profile").expect("read candidate") {
            LegacyCandidateState::Ready(candidate) => candidate,
            _ => panic!("ready candidate"),
        }
    }

    #[test]
    fn preview_payload_contains_only_random_authority_and_safe_metadata() {
        let preview_id = Uuid::new_v4().hyphenated().to_string();
        let preview = LegacyProfileMigrationPreview::Ready {
            preview_id,
            name: "Migrated profile".into(),
            source_host: "subscription.example".into(),
            legacy_bytes: 494_575,
            active: true,
        };
        let serialized = serde_json::to_string(&preview).expect("serialize preview");
        assert!(serialized.contains("subscription.example"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("source_url"));
    }

    #[test]
    fn local_config_is_reported_without_becoming_a_subscription() {
        let directory = legacy_directory();
        write_candidate(directory.path(), None);
        let file = open_owned_directory(directory.path(), false).expect("open directory");
        assert!(matches!(
            read_candidate_from_directory(&file, "active-profile").expect("read candidate"),
            LegacyCandidateState::NotSubscription { .. }
        ));
    }

    #[test]
    fn source_drift_changes_internal_authority() {
        let directory = legacy_directory();
        write_candidate(
            directory.path(),
            Some("https://subscription.example/profile"),
        );
        let first = ready(directory.path());
        fs::write(
            directory.path().join("active-profile.yaml"),
            b"proxies:\n  - name: Changed\n    type: ss\n",
        )
        .expect("change YAML");
        let second = ready(directory.path());
        assert_ne!(first.metadata_digest, second.metadata_digest);
        assert_eq!(first.active_profile, second.active_profile);
    }

    #[test]
    fn symlinks_hard_links_ambiguous_extensions_and_oversize_fail_closed() {
        let directory = legacy_directory();
        write_candidate(
            directory.path(),
            Some("https://subscription.example/profile"),
        );
        fs::write(directory.path().join("active-profile.yml"), b"proxies: []")
            .expect("ambiguous YAML");
        let file = open_owned_directory(directory.path(), false).expect("open directory");
        assert!(read_candidate_from_directory(&file, "active-profile").is_err());
        fs::remove_file(directory.path().join("active-profile.yml")).expect("remove YAML");

        let outside = directory.path().join("outside.json");
        fs::write(&outside, b"{}").expect("outside sidecar");
        fs::remove_file(directory.path().join("active-profile.json")).expect("remove sidecar");
        symlink(&outside, directory.path().join("active-profile.json")).expect("sidecar symlink");
        let file = open_owned_directory(directory.path(), false).expect("open directory");
        assert!(read_candidate_from_directory(&file, "active-profile").is_err());
        fs::remove_file(directory.path().join("active-profile.json")).expect("remove symlink");
        fs::hard_link(&outside, directory.path().join("active-profile.json"))
            .expect("sidecar hard link");
        let file = open_owned_directory(directory.path(), false).expect("open directory");
        assert!(read_candidate_from_directory(&file, "active-profile").is_err());

        fs::remove_file(directory.path().join("active-profile.json")).expect("remove hard link");
        write_candidate(
            directory.path(),
            Some("https://subscription.example/profile"),
        );
        fs::write(
            directory.path().join("active-profile.yaml"),
            vec![b'x'; MAX_LEGACY_SUBSCRIPTION_BYTES + 1],
        )
        .expect("oversized YAML");
        let file = open_owned_directory(directory.path(), false).expect("open directory");
        assert!(read_candidate_from_directory(&file, "active-profile").is_err());
    }

    #[test]
    fn deterministic_profile_namespace_and_identity_are_uuid_v5() {
        let namespace = migration_namespace("active-profile");
        assert_eq!(namespace.get_version_num(), 5);
        assert_eq!(namespace, migration_namespace("active-profile"));
        let profile = deterministic_profile_uuid("active-profile");
        assert_eq!(profile.get_version_num(), 5);
        assert_ne!(profile, deterministic_profile_uuid("other-profile"));
    }

    #[test]
    fn migration_preview_authority_is_expiring_one_shot_and_wrong_ids_do_not_consume_it() {
        let now = Instant::now();
        let preview_id = Uuid::new_v4().hyphenated().to_string();
        let authority = || LegacyProfileMigrationAuthority {
            preview_id: preview_id.clone(),
            created_at: now,
            active_profile: "active-profile".into(),
            metadata_digest: [7; 32],
        };

        let mut stored = Some(authority());
        assert!(take_preview_authority_from(&mut stored, "wrong", now).is_err());
        assert!(
            stored.is_some(),
            "a wrong token must not destroy the current preview"
        );
        assert_eq!(
            take_preview_authority_from(&mut stored, &preview_id, now)
                .expect("consume current preview")
                .preview_id,
            preview_id
        );
        assert!(take_preview_authority_from(&mut stored, &preview_id, now).is_err());

        let mut expired = Some(LegacyProfileMigrationAuthority {
            created_at: now - PREVIEW_TTL - Duration::from_secs(1),
            ..authority()
        });
        assert!(take_preview_authority_from(&mut expired, &preview_id, now).is_err());
        assert!(expired.is_none(), "an expired preview must be erased");
    }

    #[tokio::test]
    async fn migration_credential_provision_replays_the_exact_batch_once() {
        let profile = ValidatedSingBoxProfile::parse(PROFILE_JSON).expect("credential profile");
        let credential = ImportedCredential {
            reference: profile.credential_references()[0].clone(),
            secret: "migration-test-secret".into(),
        };
        let receipt = CredentialVaultReceipt {
            profile_id: PROFILE_ID.into(),
            profile_digest: profile.digest().to_owned(),
        };
        let vault = ScriptedCredentialVault::new(vec![
            Err(CredentialVaultError::OutcomeUnknown),
            Ok(receipt),
        ]);

        provision_migrated_credentials(&vault, PROFILE_ID, &profile, &[credential])
            .await
            .expect("exact replay succeeds");
        let requests = vault.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
    }

    #[tokio::test]
    async fn migration_credential_provision_rejects_a_wrong_receipt_without_replay() {
        let profile = ValidatedSingBoxProfile::parse(PROFILE_JSON).expect("credential profile");
        let credential = ImportedCredential {
            reference: profile.credential_references()[0].clone(),
            secret: "migration-test-secret".into(),
        };
        let wrong_receipt = CredentialVaultReceipt {
            profile_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
            profile_digest: profile.digest().to_owned(),
        };
        let vault = ScriptedCredentialVault::new(vec![Ok(wrong_receipt)]);

        let error = provision_migrated_credentials(&vault, PROFILE_ID, &profile, &[credential])
            .await
            .expect_err("wrong audience must fail");
        assert_eq!(vault.requests().len(), 1);
        assert!(error.contains("different migration audience"));
        assert!(!error.contains("migration-test-secret"));
    }

    #[tokio::test]
    async fn migration_credential_provision_does_not_replay_a_deterministic_error() {
        let profile = ValidatedSingBoxProfile::parse(PROFILE_JSON).expect("credential profile");
        let credential = ImportedCredential {
            reference: profile.credential_references()[0].clone(),
            secret: "migration-test-secret".into(),
        };
        let vault = ScriptedCredentialVault::new(vec![Err(CredentialVaultError::AccessDenied)]);

        let error = provision_migrated_credentials(&vault, PROFILE_ID, &profile, &[credential])
            .await
            .expect_err("access denial must fail without replay");
        assert_eq!(vault.requests().len(), 1);
        assert!(error.contains("access was denied"));
    }

    #[tokio::test]
    async fn migration_vault_failure_commits_no_new_profile() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let imported = imported_profile(true);
        let vault = ScriptedCredentialVault::new(vec![Err(CredentialVaultError::AccessDenied)]);

        let error = commit_migrated_profile(
            &repository,
            &vault,
            PROFILE_ID,
            "Migrated",
            "https://subscription.example/profile",
            &imported,
        )
        .await
        .expect_err("vault rejection before repository commit");

        assert!(error.contains("no new migration profile was committed"));
        assert!(!error.contains(PROFILE_SECRET));
        assert!(
            repository
                .snapshot()
                .expect("empty repository snapshot")
                .profiles
                .is_empty()
        );
    }

    #[tokio::test]
    async fn migration_validates_typed_profile_refs_even_without_secret_entries() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let imported = imported_profile(false);
        let vault = ScriptedCredentialVault::new(vec![Err(CredentialVaultError::AccessDenied)]);

        commit_migrated_profile(
            &repository,
            &vault,
            PROFILE_ID,
            "Migrated",
            "https://subscription.example/profile",
            &imported,
        )
        .await
        .expect_err("missing vault material must fail closed");

        let requests = vault.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].entries.is_empty());
        assert!(
            repository
                .snapshot()
                .expect("empty repository snapshot")
                .profiles
                .is_empty()
        );
    }

    #[tokio::test]
    async fn migration_vault_first_exact_replay_recovers_an_existing_staged_profile() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let imported = imported_profile(true);
        repository
            .import_with_id_and_source(
                PROFILE_ID,
                Some("Migrated"),
                &imported.profile,
                Some("https://subscription.example/profile"),
            )
            .expect("seed pre-fix staged profile");
        let vault = ScriptedCredentialVault::new(vec![Ok(successful_migration_receipt(&imported))]);

        let outcome = commit_migrated_profile(
            &repository,
            &vault,
            PROFILE_ID,
            "Migrated",
            "https://subscription.example/profile",
            &imported,
        )
        .await
        .expect("recover exact staged profile");

        assert!(!outcome.created);
        assert_eq!(vault.requests().len(), 1);
        assert_eq!(
            repository
                .load(PROFILE_ID)
                .expect("load recovered profile")
                .expect("recovered profile")
                .profile,
            imported.profile
        );
    }

    fn successful_migration_receipt(imported: &ImportedSubscription) -> CredentialVaultReceipt {
        CredentialVaultReceipt {
            profile_id: PROFILE_ID.into(),
            profile_digest: imported.profile.digest().to_owned(),
        }
    }
}
