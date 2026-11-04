use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{engine::ManagedEngine, settings_store};
use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionRequest, CredentialPresence, CredentialPresenceRequest,
    CredentialProfileCatalogEntry, CredentialProvision, CredentialProvisionRequest,
    CredentialVaultError, CredentialVaultProvisioner, CredentialVaultReceipt,
};
use cfw_profiles::{
    InvalidProfileRecord, InvalidSelection, ProfileCredentialSnapshot, ProfileRecord,
    ProfileRepository, ProfileRepositorySnapshot, ProfileSourceKind,
};
use cfw_singbox_config::{CredentialRef, CredentialSecret};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use super::legacy_profiles::LegacyProfileMigrationAuthority;

mod credential_gc;
#[cfg(test)]
use credential_gc::CREDENTIAL_GC_PREVIEW_TTL;
use credential_gc::{
    CredentialGcAuthority, cancel_gc_authority, complete_credential_gc, prepare_credential_gc,
    take_gc_authority,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileRecord {
    id: String,
    name: String,
    active: bool,
    bytes: usize,
    updated_epoch_secs: u64,
    source_kind: ProfileSourceKind,
}

impl UiProfileRecord {
    fn from_record(record: ProfileRecord, active: bool) -> Self {
        Self {
            id: record.id,
            name: record.name,
            active,
            bytes: record.bytes,
            updated_epoch_secs: record.created_epoch_secs,
            source_kind: record.source_kind,
        }
    }
}

/// A stored profile that fails current validation. It is shown with its
/// validator message so it can be deleted; `selected` means the selection
/// names it, never that it can start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiInvalidProfileRecord {
    id: String,
    name: String,
    selected: bool,
    updated_epoch_secs: u64,
    source_kind: ProfileSourceKind,
    error: String,
}

impl UiInvalidProfileRecord {
    fn from_record(record: InvalidProfileRecord, selected: bool) -> Self {
        Self {
            id: record.id,
            name: record.name,
            selected,
            updated_epoch_secs: record.created_epoch_secs,
            source_kind: record.source_kind,
            error: listed_error(&record.error),
        }
    }
}

/// A card shows at most this many characters of a validator message.
const MAX_LISTED_ERROR_CHARS: usize = 512;

/// Validator messages are short, but one quoting a document value is bounded
/// on the card and marked as cut.
fn listed_error(error: &cfw_singbox_config::ConfigError) -> String {
    let text = error.to_string();
    match text.char_indices().nth(MAX_LISTED_ERROR_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileSnapshot {
    profiles: Vec<UiProfileRecord>,
    invalid_profiles: Vec<UiInvalidProfileRecord>,
}

pub(crate) struct ManagedProfiles {
    repository: ProfileRepository,
    credential_vault: Arc<dyn CredentialVaultProvisioner>,
    credential_gc_preview: Mutex<Option<CredentialGcAuthority>>,
    legacy_profile_migration_preview: Mutex<Option<LegacyProfileMigrationAuthority>>,
}

impl ManagedProfiles {
    fn new(
        repository: ProfileRepository,
        credential_vault: impl CredentialVaultProvisioner,
    ) -> Self {
        Self {
            repository,
            credential_vault: Arc::new(credential_vault),
            credential_gc_preview: Mutex::new(None),
            legacy_profile_migration_preview: Mutex::new(None),
        }
    }

    pub(crate) fn repository(&self) -> &ProfileRepository {
        &self.repository
    }

    pub(crate) fn credential_vault(&self) -> &Arc<dyn CredentialVaultProvisioner> {
        &self.credential_vault
    }

    pub(super) fn legacy_profile_migration_preview(
        &self,
    ) -> &Mutex<Option<LegacyProfileMigrationAuthority>> {
        &self.legacy_profile_migration_preview
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiCredentialGcPreview {
    preview_id: String,
    orphan_references: Vec<CredentialRef>,
    orphan_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct UiCredentialGcReceipt {
    removed_count: u32,
}

pub(crate) fn build_managed_profiles(
    credential_vault: impl CredentialVaultProvisioner,
) -> Result<ManagedProfiles, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    Ok(ManagedProfiles::new(
        ProfileRepository::new(store.paths().profiles_dir.clone()),
        credential_vault,
    ))
}

#[tauri::command]
pub(crate) async fn profiles_snapshot(
    profiles: State<'_, ManagedProfiles>,
) -> Result<UiProfileSnapshot, String> {
    read_repository(profiles.repository(), |repository| {
        repository
            .snapshot()
            .map(snapshot_view)
            .map_err(|error| error.to_string())
    })
    .await
}

/// Subscription URL of one stored profile, including one that fails
/// validation, so its source can be imported again before the entry is
/// deleted. The profile list never carries URLs; this is one explicit read.
#[tauri::command]
pub(crate) async fn read_profile_source_url(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<Option<String>, String> {
    read_repository(profiles.repository(), move |repository| {
        repository
            .source_url(&id)
            .map_err(|error| error.to_string())
    })
    .await
}

/// Online transactions retain the repository lock through native validation.
/// File-lock waits must run outside the WebView and coordinator executor.
pub(super) async fn read_repository<T, F>(
    repository: &ProfileRepository,
    read: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&ProfileRepository) -> Result<T, String> + Send + 'static,
{
    let repository = repository.clone();
    tauri::async_runtime::spawn_blocking(move || read(&repository))
        .await
        .map_err(|error| format!("profile read task failed: {error}"))?
}

#[cfg(test)]
fn persist_saved_proxy_selection(
    repository: &ProfileRepository,
    profile_id: &str,
    group: &str,
    selected: &str,
) -> Result<(), String> {
    let stored = repository
        .load_selected()
        .map_err(|error| error.to_string())?
        .ok_or("no active profile is selected")?;
    if stored.record.id != profile_id {
        return Err("selected profile changed before the proxy selection was applied".into());
    }
    let profile = stored
        .profile
        .with_selected_outbound(group, selected)
        .map_err(|error| error.to_string())?;
    repository
        .replace_if_unchanged(&stored, None, &profile, stored.source_url.as_deref())
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn profile_credential_requirements(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<Vec<CredentialRef>, String> {
    read_repository(profiles.repository(), move |repository| {
        credential_requirements(repository, &id).map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub(crate) async fn profile_credential_presence(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<Vec<CredentialPresence>, String> {
    let read_id = id.clone();
    let stored = read_repository(profiles.repository(), move |repository| {
        repository
            .load(&read_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("profile does not exist: {read_id}"))
    })
    .await?;
    let request =
        CredentialPresenceRequest::new(&id, &stored.profile).map_err(|error| error.to_string())?;
    let vault = profiles.credential_vault.clone();
    vault
        .query_profile_credentials(request)
        .await
        .map_err(|error| error.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UiCredentialProvision {
    reference: CredentialRef,
    secret: String,
}

impl std::fmt::Debug for UiCredentialProvision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UiCredentialProvision")
            .field("reference", &self.reference)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for UiCredentialProvision {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[tauri::command]
pub(crate) async fn provision_profile_credentials(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    profile_id: String,
    credentials: Vec<UiCredentialProvision>,
) -> Result<CredentialVaultReceipt, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let stored = profiles
        .repository
        .load(&profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("profile does not exist: {profile_id}"))?;
    let entries = credentials
        .iter()
        .map(|credential| {
            CredentialSecret::new(&credential.secret)
                .map(|secret| CredentialProvision::new(&credential.reference, secret))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let request = CredentialProvisionRequest::new(&profile_id, &stored.profile, entries)
        .map_err(|error| error.to_string())?;
    let vault = profiles.credential_vault.clone();
    let receipt = vault
        .provision_profile_credentials(request)
        .await
        .map_err(|error| error.to_string())?;
    if receipt.profile_id != profile_id || receipt.profile_digest != stored.record.digest {
        return Err("credential vault receipt does not match the requested profile".into());
    }
    Ok(receipt)
}

#[tauri::command]
pub(crate) async fn preview_credential_gc(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<UiCredentialGcPreview, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let Some(preview) =
        prepare_credential_gc(profiles.repository(), profiles.credential_vault()).await?
    else {
        *profiles
            .credential_gc_preview
            .lock()
            .map_err(|_| "credential garbage-collection preview state is unavailable")? = None;
        return Ok(UiCredentialGcPreview {
            preview_id: uuid::Uuid::new_v4().to_string(),
            orphan_references: Vec::new(),
            orphan_count: 0,
        });
    };
    let preview_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let response = UiCredentialGcPreview {
        preview_id: preview_id.clone(),
        orphan_references: preview
            .orphan_bindings
            .iter()
            .map(|binding| binding.reference().clone())
            .collect(),
        orphan_count: preview.orphan_count,
    };
    let mut authority = profiles
        .credential_gc_preview
        .lock()
        .map_err(|_| "credential garbage-collection preview state is unavailable".to_owned())?;
    *authority = (preview.orphan_count != 0).then_some(CredentialGcAuthority {
        preview_id,
        created_at: Instant::now(),
        preview,
    });
    Ok(response)
}

#[tauri::command]
pub(crate) fn cancel_credential_gc(
    profiles: State<'_, ManagedProfiles>,
    preview_id: String,
) -> Result<(), String> {
    let mut authority = profiles
        .credential_gc_preview
        .lock()
        .map_err(|_| "credential garbage-collection preview state is unavailable".to_owned())?;
    cancel_gc_authority(&mut authority, &preview_id)
}

#[tauri::command]
pub(crate) async fn commit_credential_gc(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    preview_id: String,
) -> Result<UiCredentialGcReceipt, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let authority = {
        let mut stored = profiles
            .credential_gc_preview
            .lock()
            .map_err(|_| "credential garbage-collection preview state is unavailable".to_owned())?;
        take_gc_authority(&mut stored, &preview_id, Instant::now())?
    };

    let removed_count = complete_credential_gc(
        profiles.repository(),
        profiles.credential_vault(),
        &authority.preview,
    )
    .await?;
    Ok(UiCredentialGcReceipt { removed_count })
}

fn credential_requirements(
    repository: &ProfileRepository,
    id: &str,
) -> Result<Vec<CredentialRef>, cfw_profiles::ProfileError> {
    repository
        .load(id)?
        .ok_or_else(|| cfw_profiles::ProfileError::SelectedProfileMissing(id.to_owned()))
        .map(|stored| stored.profile.credential_references())
}

#[tauri::command]
pub(crate) async fn select_profile(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, crate::platform_maintenance::PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiProfileRecord, String> {
    let repository = profiles.repository().clone();
    crate::engine::apply_profile_change(&engine, &retirement, move |_settings| async move {
        let mutation = repository
            .begin_credential_profile_mutation()
            .map_err(|error| error.to_string())?;
        let stored = mutation.profile(&id).map_err(|error| error.to_string())?;
        let previous = mutation
            .selected_profile()
            .map_err(|error| error.to_string())?
            .into_valid();
        Ok(cfw_application::ProfileChange {
            profile_id: id.clone(),
            profile: stored.profile,
            activate: true,
            previous_profile: previous.map(|prior| (prior.record.id, prior.profile)),
            commit: Box::new(move || {
                mutation
                    .commit_selection(&id)
                    .map(|record| UiProfileRecord::from_record(record, true))
                    .map_err(|error| error.to_string())
            }),
        })
    })
    .await
}

#[tauri::command]
pub(crate) async fn delete_profile(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<bool, String> {
    let maintenance = engine
        .reserve_maintenance()
        .map_err(|error| error.to_string())?;
    // Nothing can run the selected profile only while the engine is Off, and
    // the held reservation keeps it Off for the whole deletion.
    let invalid_selection = if engine.is_off_under(&maintenance) {
        InvalidSelection::Clear
    } else {
        InvalidSelection::Keep
    };
    let repository = profiles.repository.clone();
    let deleted = crate::startup_state::prepare_off_main(move || {
        repository
            .delete(&id, invalid_selection)
            .map_err(deletion_error)
    })
    .await;
    drop(maintenance);
    deleted
}

/// The repository keeps an invalid selection only when the engine was not
/// proven Off, so that refusal says how to go on.
fn deletion_error(error: cfw_profiles::ProfileError) -> String {
    match error {
        cfw_profiles::ProfileError::InvalidSelectionKept(profile) => format!(
            "the selected profile {profile} is invalid; stop the core, or select another profile, before deleting it"
        ),
        error => error.to_string(),
    }
}

fn snapshot_view(snapshot: ProfileRepositorySnapshot) -> UiProfileSnapshot {
    let selected = snapshot.selected_profile_id.as_deref();
    UiProfileSnapshot {
        profiles: snapshot
            .profiles
            .into_iter()
            .map(|record| {
                let active = selected == Some(record.id.as_str());
                UiProfileRecord::from_record(record, active)
            })
            .collect(),
        invalid_profiles: snapshot
            .invalid_profiles
            .into_iter()
            .map(|record| {
                let selected = selected == Some(record.id.as_str());
                UiInvalidProfileRecord::from_record(record, selected)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
