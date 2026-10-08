use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{engine::ManagedEngine, settings_store};
use cfw_apple_network::NativeFrameworkBridge;
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

#[derive(Debug)]
pub(crate) struct ManagedProfiles {
    repository: ProfileRepository,
    credential_vault: NativeFrameworkBridge,
    credential_gc_preview: Mutex<Option<CredentialGcAuthority>>,
    legacy_profile_migration_preview: Mutex<Option<LegacyProfileMigrationAuthority>>,
}

const CREDENTIAL_GC_PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
struct CredentialGcAuthority {
    preview_id: String,
    created_at: Instant,
    preview: CredentialGarbageCollectionPreview,
}

fn cancel_gc_authority(
    stored: &mut Option<CredentialGcAuthority>,
    preview_id: &str,
) -> Result<(), String> {
    match stored.as_ref() {
        Some(preview) if preview.preview_id == preview_id => {
            *stored = None;
            Ok(())
        }
        _ => Err("CredentialGcPreviewExpired: cleanup preview is missing or stale".into()),
    }
}

fn take_gc_authority(
    stored: &mut Option<CredentialGcAuthority>,
    preview_id: &str,
    now: Instant,
) -> Result<CredentialGcAuthority, String> {
    let Some(preview) = stored.as_ref() else {
        return Err("CredentialGcPreviewExpired: cleanup preview is missing".into());
    };
    if preview.preview_id != preview_id {
        return Err("CredentialGcPreviewExpired: cleanup preview token does not match".into());
    }
    if now
        .checked_duration_since(preview.created_at)
        .is_none_or(|elapsed| elapsed > CREDENTIAL_GC_PREVIEW_TTL)
    {
        *stored = None;
        return Err("CredentialGcPreviewExpired: cleanup preview has expired".into());
    }
    stored.take().ok_or_else(|| {
        "CredentialGcPreviewExpired: cleanup preview disappeared during validation".to_owned()
    })
}

impl ManagedProfiles {
    fn new(repository: ProfileRepository, credential_vault: NativeFrameworkBridge) -> Self {
        Self {
            repository,
            credential_vault,
            credential_gc_preview: Mutex::new(None),
            legacy_profile_migration_preview: Mutex::new(None),
        }
    }

    pub(crate) fn repository(&self) -> &ProfileRepository {
        &self.repository
    }

    pub(crate) fn credential_vault(&self) -> &NativeFrameworkBridge {
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
    credential_vault: NativeFrameworkBridge,
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

fn credential_gc_request(
    snapshot: ProfileCredentialSnapshot,
) -> Result<CredentialGarbageCollectionRequest, String> {
    let catalog = snapshot
        .catalog
        .into_iter()
        .map(|entry| CredentialProfileCatalogEntry::new(entry.audience, entry.references))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    CredentialGarbageCollectionRequest::new(snapshot.snapshot_digest, catalog)
        .map_err(|error| error.to_string())
}

/// A missing vault is empty only when the current catalog has no live bindings.
async fn prepare_credential_gc(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
) -> Result<Option<CredentialGarbageCollectionPreview>, String> {
    let snapshot = repository
        .credential_snapshot()
        .map_err(|error| error.to_string())?;
    let request = credential_gc_request(snapshot)?;
    let live = request
        .catalog()
        .iter()
        .flat_map(CredentialProfileCatalogEntry::bindings)
        .collect::<BTreeSet<_>>();
    let preview = match vault
        .preview_credential_garbage_collection(request.clone())
        .await
    {
        Ok(preview) => preview,
        Err(CredentialVaultError::MissingVault) if live.is_empty() => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    CredentialGarbageCollectionCommitRequest::new(request, &preview)
        .map_err(|error| error.to_string())?;
    if preview
        .orphan_bindings
        .iter()
        .any(|binding| live.contains(binding))
    {
        return Err(
            "credential garbage-collection preview marks a live reference as orphaned".into(),
        );
    }
    Ok(Some(preview))
}

/// The caller consumes explicit preview authority first. Keep the cross-process
/// repository lock through native CAS and validate the exact deletion receipt.
async fn complete_credential_gc(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    preview: &CredentialGarbageCollectionPreview,
) -> Result<u32, String> {
    if preview.orphan_count == 0 {
        return Ok(0);
    }
    let locked = repository
        .lock_credential_snapshot()
        .map_err(|error| error.to_string())?;
    let request = credential_gc_request(locked.snapshot().clone())?;
    let commit = CredentialGarbageCollectionCommitRequest::new(request, preview)
        .map_err(|error| error.to_string())?;
    let receipt = vault
        .commit_credential_garbage_collection(commit)
        .await
        .map_err(|error| error.to_string())?;
    receipt.validate().map_err(|error| error.to_string())?;
    if receipt.deleted_count != preview.orphan_count {
        return Err("credential garbage-collection receipt does not match the preview".into());
    }
    Ok(receipt.deleted_count)
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
    retirement: State<'_, crate::legacy::LegacyRetirementGate>,
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
mod tests {
    use super::*;
    use cfw_engine_api::{
        CredentialAudience, CredentialBinding, CredentialGarbageCollectionCommitFuture,
        CredentialGarbageCollectionPreviewFuture, CredentialPresenceFuture,
        CredentialPresenceRequest, CredentialProvisionRequest, CredentialVaultError,
        CredentialVaultFuture,
    };
    use cfw_singbox_config::ValidatedSingBoxProfile;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    #[test]
    fn saved_selection_updates_only_the_selected_profile_and_preserves_credentials() {
        let directory = TempDir::new().expect("profile directory");
        let repository = ProfileRepository::new(directory.path().join("profiles"));
        let profile = ValidatedSingBoxProfile::parse(&serde_json::json!({
            "outbounds": [
                {"type": "socks5", "tag": "Work node", "server": "proxy.example.com", "server_port": 1080, "authentication": {
                    "username_credential_ref": {"id": "11111111-1111-4111-8111-111111111111", "kind": "socks5_username"},
                    "password_credential_ref": {"id": "22222222-2222-4222-8222-222222222222", "kind": "socks5_password"}
                }},
                {"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "REJECT"},
                {"type": "selector", "tag": "PROXY", "outbounds": ["Work node", "DIRECT", "REJECT"]}
            ], "route": {"final": "PROXY"}
        }).to_string()).expect("selector profile");
        let imported = repository.import(Some("Work"), &profile).expect("import");
        repository.select(&imported.id).expect("select profile");
        persist_saved_proxy_selection(&repository, &imported.id, "PROXY", "REJECT")
            .expect("save selection");
        let selected = repository
            .load_selected()
            .expect("reload")
            .expect("selected profile");
        assert_eq!(selected.profile.proxy_selections()["PROXY"], "REJECT");
        assert_eq!(selected.profile.as_json(), profile.as_json());
        assert_eq!(selected.record.name, "Work");
        assert_eq!(
            selected.profile.credential_references(),
            profile.credential_references()
        );
        assert_eq!(selected.profile.digest(), profile.digest());
        for (id, group, node) in [
            ("different-profile", "PROXY", "DIRECT"),
            (imported.id.as_str(), "PROXY", "absent"),
        ] {
            assert!(persist_saved_proxy_selection(&repository, id, group, node).is_err());
            assert_eq!(
                repository
                    .load_selected()
                    .expect("reload after rejection")
                    .expect("selected")
                    .profile,
                selected.profile
            );
        }
    }

    struct OrphanGcVault {
        preview_count: AtomicUsize,
        commit_count: AtomicUsize,
        preview_error: Option<CredentialVaultError>,
        orphan_bindings: Vec<CredentialBinding>,
        orphan_count: u32,
        deleted_count: u32,
        mutate_repository_before_commit: Option<ProfileRepository>,
    }

    impl OrphanGcVault {
        fn orphan_binding() -> CredentialBinding {
            let audience =
                CredentialAudience::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "ab".repeat(32))
                    .expect("synthetic orphan audience");
            let reference = CredentialRef::new(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                cfw_engine_api::CredentialKind::TrojanPassword,
            )
            .expect("synthetic orphan reference");
            CredentialBinding::new(audience, reference)
        }
    }

    impl CredentialVaultProvisioner for OrphanGcVault {
        fn provision_profile_credentials<'a>(
            &'a self,
            _request: CredentialProvisionRequest<'a>,
        ) -> CredentialVaultFuture<'a> {
            Box::pin(async { Err(CredentialVaultError::Internal) })
        }

        fn query_profile_credentials(
            &self,
            _request: CredentialPresenceRequest,
        ) -> CredentialPresenceFuture<'_> {
            Box::pin(async { Err(CredentialVaultError::Internal) })
        }

        fn preview_credential_garbage_collection(
            &self,
            request: CredentialGarbageCollectionRequest,
        ) -> CredentialGarbageCollectionPreviewFuture<'_> {
            self.preview_count.fetch_add(1, Ordering::SeqCst);
            let snapshot_digest = request.snapshot_digest().to_owned();
            let preview_error = self.preview_error;
            let orphan_bindings = self.orphan_bindings.clone();
            let orphan_count = self.orphan_count;
            if let Some(repository) = &self.mutate_repository_before_commit {
                repository
                    .import(Some("Concurrent"), &ValidatedSingBoxProfile::direct())
                    .expect("concurrent repository mutation");
            }
            Box::pin(async move {
                if let Some(error) = preview_error {
                    return Err(error);
                }
                Ok(CredentialGarbageCollectionPreview {
                    snapshot_digest,
                    vault_revision: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                    orphan_bindings,
                    orphan_count,
                })
            })
        }

        fn commit_credential_garbage_collection(
            &self,
            request: CredentialGarbageCollectionCommitRequest,
        ) -> CredentialGarbageCollectionCommitFuture<'_> {
            self.commit_count.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.expected_orphan_bindings(), self.orphan_bindings);
            let deleted_count = self.deleted_count;
            Box::pin(async move {
                Ok(cfw_engine_api::CredentialGarbageCollectionReceipt {
                    vault_revision: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into(),
                    deleted_count,
                })
            })
        }
    }

    #[test]
    fn profile_snapshot_serialization_exposes_no_path_url_or_credentials() {
        let record = ProfileRecord {
            id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
            name: "Profile".into(),
            bytes: 128,
            digest: "01".repeat(32),
            created_epoch_secs: 42,
            source_kind: ProfileSourceKind::Subscription,
        };

        let value = serde_json::to_value(UiProfileRecord::from_record(record, true))
            .expect("serialize record");
        let object = value.as_object().expect("record object");
        assert_eq!(
            object.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "active".to_string(),
                "bytes".to_string(),
                "id".to_string(),
                "name".to_string(),
                "source_kind".to_string(),
                "updated_epoch_secs".to_string(),
            ])
        );
        assert!(!value.to_string().contains("digest"));
        assert!(!value.to_string().contains("path"));
        assert!(!value.to_string().contains("url"));
        assert_eq!(value["active"], true);
        assert_eq!(value["source_kind"], "subscription");
    }

    fn invalid_record(id: &str) -> InvalidProfileRecord {
        InvalidProfileRecord {
            id: id.into(),
            name: "Reality node".into(),
            created_epoch_secs: 3,
            source_kind: ProfileSourceKind::Subscription,
            error: cfw_singbox_config::ConfigError::UnsupportedPolicyShape {
                path: "$.outbounds[0].tls.utls".into(),
                reason: "Reality requires uTLS".into(),
            },
        }
    }

    fn valid_records(selected_id: &str, other_id: &str) -> Vec<ProfileRecord> {
        vec![
            ProfileRecord {
                id: selected_id.into(),
                name: "Selected".into(),
                bytes: 10,
                digest: "01".repeat(32),
                created_epoch_secs: 1,
                source_kind: ProfileSourceKind::Local,
            },
            ProfileRecord {
                id: other_id.into(),
                name: "Other".into(),
                bytes: 11,
                digest: "02".repeat(32),
                created_epoch_secs: 2,
                source_kind: ProfileSourceKind::Subscription,
            },
        ]
    }

    #[test]
    fn snapshot_marks_only_the_digest_bound_selection_active() {
        let selected_id = "34db18b6-9903-4e9f-8854-15648e19e4f3";
        let other_id = "62b37965-02bb-45a8-a1a5-3b617c5cbd17";
        let invalid_id = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
        let view = snapshot_view(ProfileRepositorySnapshot {
            profiles: valid_records(selected_id, other_id),
            invalid_profiles: vec![invalid_record(invalid_id)],
            selected_profile_id: Some(selected_id.into()),
        });

        assert_eq!(view.profiles.len(), 2);
        assert!(view.profiles[0].active);
        assert!(!view.profiles[1].active);
        assert_eq!(view.invalid_profiles.len(), 1);
        assert!(!view.invalid_profiles[0].selected);
    }

    #[test]
    fn a_selected_invalid_profile_is_reported_selected_and_no_valid_profile_is_active() {
        let invalid_id = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
        let view = snapshot_view(ProfileRepositorySnapshot {
            profiles: valid_records(
                "34db18b6-9903-4e9f-8854-15648e19e4f3",
                "62b37965-02bb-45a8-a1a5-3b617c5cbd17",
            ),
            invalid_profiles: vec![invalid_record(invalid_id)],
            selected_profile_id: Some(invalid_id.into()),
        });

        assert!(view.profiles.iter().all(|record| !record.active));
        assert!(view.invalid_profiles[0].selected);
        let value = serde_json::to_value(&view).expect("serialize snapshot");
        assert_eq!(
            value
                .as_object()
                .expect("snapshot object")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["invalid_profiles".to_string(), "profiles".to_string()])
        );
        let invalid = &value["invalid_profiles"][0];
        assert_eq!(
            invalid
                .as_object()
                .expect("invalid record object")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "error".to_string(),
                "id".to_string(),
                "name".to_string(),
                "selected".to_string(),
                "source_kind".to_string(),
                "updated_epoch_secs".to_string(),
            ])
        );
        assert_eq!(
            invalid["error"],
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
        );
        assert_eq!(invalid["source_kind"], "subscription");
        assert_eq!(invalid["updated_epoch_secs"], 3);
        assert!(!value.to_string().contains("digest"));
        assert!(!value.to_string().contains("url"));
    }

    #[test]
    fn a_kept_invalid_selection_tells_the_user_how_to_delete_it() {
        assert_eq!(
            deletion_error(cfw_profiles::ProfileError::InvalidSelectionKept(
                cfw_profiles::ProfileLabel {
                    id: "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d".into(),
                    name: "Reality node".into(),
                }
            )),
            "the selected profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid; stop the core, or select another profile, before deleting it"
        );
        assert_eq!(
            deletion_error(cfw_profiles::ProfileError::NoSelectedProfile),
            "no profile is selected"
        );
    }

    #[test]
    fn a_long_validator_message_is_bounded_on_the_card() {
        let short = invalid_record("3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d");
        assert_eq!(
            UiInvalidProfileRecord::from_record(short, false).error,
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
        );
        let mut long = invalid_record("3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d");
        long.error = cfw_singbox_config::ConfigError::InvalidJson("界".repeat(600));
        let listed = UiInvalidProfileRecord::from_record(long, false).error;
        assert_eq!(listed.chars().count(), MAX_LISTED_ERROR_CHARS + 1);
        assert!(listed.starts_with("sing-box profile JSON is invalid: 界"));
        assert!(listed.ends_with('…'));
    }

    #[test]
    fn credential_requirements_are_loaded_from_the_validated_stored_profile() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path());
        let profile = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
        )
        .expect("typed profile");
        let imported = repository
            .import(Some("Credentials"), &profile)
            .expect("profile import");

        assert_eq!(
            credential_requirements(&repository, &imported.id).expect("requirements"),
            profile.credential_references()
        );
        assert!(
            credential_requirements(&repository, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").is_err()
        );
    }

    #[test]
    fn renderer_credential_input_has_a_closed_shape_and_redacted_debug_output() {
        let credential: UiCredentialProvision = serde_json::from_value(serde_json::json!({
            "reference": {
                "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "kind": "trojan_password",
            },
            "secret": "never-print-this-secret",
        }))
        .expect("credential input");
        let debug = format!("{credential:?}");
        assert!(!debug.contains("never-print-this-secret"));
        assert!(debug.contains("[REDACTED]"));

        assert!(
            serde_json::from_value::<UiCredentialProvision>(serde_json::json!({
                "reference": {
                    "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "kind": "trojan_password",
                },
                "secret": "bounded",
                "unexpected": true,
            }))
            .is_err()
        );
    }

    fn gc_authority(created_at: Instant) -> CredentialGcAuthority {
        CredentialGcAuthority {
            preview_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            created_at,
            preview: CredentialGarbageCollectionPreview {
                snapshot_digest: "01".repeat(32),
                vault_revision: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                orphan_bindings: Vec::new(),
                orphan_count: 0,
            },
        }
    }

    #[test]
    fn credential_gc_authority_is_one_shot_expiring_and_not_destroyed_by_wrong_tokens() {
        let now = Instant::now();
        let mut stored = Some(gc_authority(now));
        assert!(take_gc_authority(&mut stored, "wrong", now).is_err());
        assert!(
            stored.is_some(),
            "wrong token must not invalidate real authority"
        );
        assert!(cancel_gc_authority(&mut stored, "wrong").is_err());
        assert!(stored.is_some());

        let accepted = take_gc_authority(&mut stored, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now)
            .expect("matching authority");
        assert_eq!(accepted.preview.orphan_count, 0);
        assert!(stored.is_none(), "accepted authority is one-shot");

        let expired_at = now
            .checked_sub(CREDENTIAL_GC_PREVIEW_TTL + Duration::from_secs(1))
            .expect("representable prior instant");
        let mut expired = Some(gc_authority(expired_at));
        assert!(
            take_gc_authority(&mut expired, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now).is_err()
        );
        assert!(expired.is_none(), "expired authority is destroyed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn repository_reads_wait_off_executor_while_an_online_transaction_holds_the_lock() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let transaction = repository.begin_credential_profile_mutation().unwrap();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            read_repository(&repository, move |repository| {
                let _ = entered.send(());
                repository.snapshot().map_err(|error| error.to_string())
            })
            .await
        });
        waiting.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!reader.is_finished());
        drop(transaction);
        let result = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(result.profiles.is_empty());
    }

    async fn execute_previewed_credential_gc(
        repository: &ProfileRepository,
        vault: &impl CredentialVaultProvisioner,
    ) -> Result<u32, String> {
        let Some(preview) = prepare_credential_gc(repository, vault).await? else {
            return Ok(0);
        };
        complete_credential_gc(repository, vault, &preview).await
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_revalidates_and_commits_exact_orphans() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![OrphanGcVault::orphan_binding()],
            orphan_count: 1,
            deleted_count: 1,
            mutate_repository_before_commit: None,
        };

        assert_eq!(
            execute_previewed_credential_gc(&repository, &vault)
                .await
                .expect("previewed cleanup"),
            1
        );
        assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_accepts_a_missing_empty_vault() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: Some(CredentialVaultError::MissingVault),
            orphan_bindings: Vec::new(),
            orphan_count: 0,
            deleted_count: 0,
            mutate_repository_before_commit: None,
        };

        assert_eq!(
            execute_previewed_credential_gc(&repository, &vault)
                .await
                .expect("an absent vault with no live bindings is already clean"),
            0
        );
        assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_rejects_a_missing_vault_with_live_bindings() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let profile = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
        )
        .expect("typed profile");
        repository
            .import(Some("Credentials"), &profile)
            .expect("profile import");
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: Some(CredentialVaultError::MissingVault),
            orphan_bindings: Vec::new(),
            orphan_count: 0,
            deleted_count: 0,
            mutate_repository_before_commit: None,
        };

        let error = execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect_err("live references require an existing vault");
        assert_eq!(error, CredentialVaultError::MissingVault.to_string());
        assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_is_refused_while_an_invalid_profile_is_listed() {
        let temporary = TempDir::new().expect("temporary repository");
        let profiles_dir = temporary.path().join("profiles");
        let repository = ProfileRepository::new(&profiles_dir);
        let invalid_id = crate::profile_fixtures::store_selected_reality_without_utls(
            &profiles_dir,
            &repository,
        );
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![OrphanGcVault::orphan_binding()],
            orphan_count: 1,
            deleted_count: 1,
            mutate_repository_before_commit: None,
        };

        let error = execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect_err("cleanup keeps the credentials of a listed profile");
        assert_eq!(
            error,
            format!(
                "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"Reality node\" ({invalid_id})"
            )
        );
        assert_eq!(vault.preview_count.load(Ordering::SeqCst), 0);
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_profile_that_becomes_invalid_after_the_preview_blocks_the_commit() {
        let temporary = TempDir::new().expect("temporary repository");
        let profiles_dir = temporary.path().join("profiles");
        let repository = ProfileRepository::new(&profiles_dir);
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![OrphanGcVault::orphan_binding()],
            orphan_count: 1,
            deleted_count: 1,
            mutate_repository_before_commit: None,
        };
        let preview = prepare_credential_gc(&repository, &vault)
            .await
            .expect("preview of a valid repository")
            .expect("orphan preview");
        let invalid_id = crate::profile_fixtures::store_selected_reality_without_utls(
            &profiles_dir,
            &repository,
        );

        let error = complete_credential_gc(&repository, &vault, &preview)
            .await
            .expect_err("the commit re-reads the repository under its lock");
        assert!(error.contains(&invalid_id), "{error}");
        assert!(
            error.starts_with("credential cleanup needs every stored profile"),
            "{error}"
        );
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_never_commits_a_live_binding_preview() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let profile = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
        )
        .expect("typed profile");
        repository
            .import(Some("Credentials"), &profile)
            .expect("profile import");
        let snapshot = repository
            .credential_snapshot()
            .expect("credential snapshot");
        let entry = snapshot.catalog.first().expect("live catalog entry");
        let live = CredentialBinding::new(entry.audience.clone(), entry.references[0].clone());
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![live],
            orphan_count: 1,
            deleted_count: 1,
            mutate_repository_before_commit: None,
        };

        let error = execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect_err("live binding preview must fail closed");
        assert!(error.contains("marks a live reference as orphaned"));
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_rejects_a_stale_repository_snapshot() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![OrphanGcVault::orphan_binding()],
            orphan_count: 1,
            deleted_count: 1,
            mutate_repository_before_commit: Some(repository.clone()),
        };

        execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect_err("stale repository snapshot must fail closed");
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_rejects_a_mismatched_delete_receipt() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: vec![OrphanGcVault::orphan_binding()],
            orphan_count: 1,
            deleted_count: 0,
            mutate_repository_before_commit: None,
        };

        let error = execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect_err("delete receipt mismatch must fail closed");
        assert!(error.contains("receipt does not match the preview"));
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn explicit_credential_cleanup_skips_commit_for_zero_orphans() {
        let temporary = TempDir::new().expect("temporary repository");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = OrphanGcVault {
            preview_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            preview_error: None,
            orphan_bindings: Vec::new(),
            orphan_count: 0,
            deleted_count: 0,
            mutate_repository_before_commit: None,
        };

        assert_eq!(
            execute_previewed_credential_gc(&repository, &vault)
                .await
                .expect("zero orphan cleanup"),
            0
        );
        assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
        assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
    }
}
