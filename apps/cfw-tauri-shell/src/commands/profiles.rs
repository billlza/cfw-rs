use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{engine::ManagedEngine, settings_store};
use cfw_apple_network::NativeFrameworkBridge;
use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionRequest, CredentialPresence, CredentialPresenceRequest,
    CredentialProfileCatalogEntry, CredentialProvision, CredentialProvisionRequest,
    CredentialVaultProvisioner, CredentialVaultReceipt,
};
use cfw_profiles::{
    ProfileCredentialSnapshot, ProfileImportResult, ProfileRecord, ProfileRepository,
    ProfileRepositorySnapshot,
};
use cfw_singbox_config::{CredentialRef, CredentialSecret, ValidatedSingBoxProfile};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileRecord {
    id: String,
    name: String,
    active: bool,
    bytes: usize,
    updated_epoch_secs: u64,
}

impl UiProfileRecord {
    fn from_record(record: ProfileRecord, active: bool) -> Self {
        Self {
            id: record.id,
            name: record.name,
            active,
            bytes: record.bytes,
            updated_epoch_secs: record.created_epoch_secs,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ManagedProfiles {
    repository: ProfileRepository,
    credential_vault: NativeFrameworkBridge,
    credential_gc_preview: Mutex<Option<CredentialGcAuthority>>,
}

const CREDENTIAL_GC_PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);
const PROJECTION_VALIDATION_PROFILE_ID: &str = "00000000-0000-4000-8000-000000000000";

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
        }
    }

    pub(crate) fn repository(&self) -> &ProfileRepository {
        &self.repository
    }

    pub(crate) fn credential_vault(&self) -> &NativeFrameworkBridge {
        &self.credential_vault
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
pub(crate) fn import_profile_text(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    name: Option<String>,
    body: String,
) -> Result<ProfileImportResult, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let profile = ValidatedSingBoxProfile::parse(&body).map_err(|error| error.to_string())?;
    let settings = engine.engine_settings().clone();
    profile
        .project(
            PROJECTION_VALIDATION_PROFILE_ID,
            cfw_singbox_config::ProjectionMode::SystemProxy,
            &settings,
        )
        .map_err(|error| error.to_string())?;
    profile
        .project(
            PROJECTION_VALIDATION_PROFILE_ID,
            cfw_singbox_config::ProjectionMode::Tunnel,
            &settings,
        )
        .map_err(|error| error.to_string())?;
    profiles
        .repository
        .import(name.as_deref(), &profile)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn profiles_snapshot(
    profiles: State<'_, ManagedProfiles>,
) -> Result<Vec<UiProfileRecord>, String> {
    profiles
        .repository
        .snapshot()
        .map(snapshot_records)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn profile_credential_requirements(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<Vec<CredentialRef>, String> {
    credential_requirements(profiles.repository(), &id).map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn profile_credential_presence(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<Vec<CredentialPresence>, String> {
    let stored = profiles
        .repository
        .load(&id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("profile does not exist: {id}"))?;
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
    let snapshot = profiles
        .repository
        .credential_snapshot()
        .map_err(|error| error.to_string())?;
    let request = credential_gc_request(snapshot)?;
    let live = request
        .catalog()
        .iter()
        .flat_map(CredentialProfileCatalogEntry::bindings)
        .collect::<BTreeSet<_>>();
    let preview = profiles
        .credential_vault
        .preview_credential_garbage_collection(request.clone())
        .await
        .map_err(|error| error.to_string())?;
    // Reuse the commit constructor as the single canonical validation for the
    // native revision, snapshot identity, orphan order, uniqueness and count.
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

    // This guard retains the cross-process repository lock across the native
    // CAS. No import, selection, or deletion can enter after this re-read.
    let locked = profiles
        .repository
        .lock_credential_snapshot()
        .map_err(|error| error.to_string())?;
    let current = locked.snapshot();
    let request = credential_gc_request(current.clone())?;
    let commit = CredentialGarbageCollectionCommitRequest::new(request, &authority.preview)
        .map_err(|error| error.to_string())?;
    let receipt = profiles
        .credential_vault
        .commit_credential_garbage_collection(commit)
        .await
        .map_err(|error| error.to_string())?;
    if receipt.deleted_count != authority.preview.orphan_count {
        return Err("credential garbage-collection receipt does not match the preview".into());
    }
    Ok(UiCredentialGcReceipt {
        removed_count: receipt.deleted_count,
    })
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
pub(crate) fn select_profile(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiProfileRecord, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    profiles
        .repository
        .select(&id)
        .map(|record| UiProfileRecord::from_record(record, true))
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn delete_profile(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<bool, String> {
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    profiles
        .repository
        .delete(&id)
        .map_err(|error| error.to_string())
}

fn snapshot_records(snapshot: ProfileRepositorySnapshot) -> Vec<UiProfileRecord> {
    snapshot
        .profiles
        .into_iter()
        .map(|record| {
            let active = snapshot.selected_profile_id.as_deref() == Some(record.id.as_str());
            UiProfileRecord::from_record(record, active)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    #[test]
    fn profile_snapshot_serialization_exposes_no_path_url_or_credentials() {
        let record = ProfileRecord {
            id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
            name: "Profile".into(),
            bytes: 128,
            digest: "01".repeat(32),
            created_epoch_secs: 42,
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
                "updated_epoch_secs".to_string(),
            ])
        );
        assert!(!value.to_string().contains("digest"));
        assert!(!value.to_string().contains("path"));
        assert!(!value.to_string().contains("url"));
        assert_eq!(value["active"], true);
    }

    #[test]
    fn snapshot_marks_only_the_digest_bound_selection_active() {
        let selected_id = "34db18b6-9903-4e9f-8854-15648e19e4f3".to_owned();
        let other_id = "62b37965-02bb-45a8-a1a5-3b617c5cbd17".to_owned();
        let records = snapshot_records(ProfileRepositorySnapshot {
            profiles: vec![
                ProfileRecord {
                    id: selected_id.clone(),
                    name: "Selected".into(),
                    bytes: 10,
                    digest: "01".repeat(32),
                    created_epoch_secs: 1,
                },
                ProfileRecord {
                    id: other_id,
                    name: "Other".into(),
                    bytes: 11,
                    digest: "02".repeat(32),
                    created_epoch_secs: 2,
                },
            ],
            selected_profile_id: Some(selected_id),
        });

        assert_eq!(records.len(), 2);
        assert!(records[0].active);
        assert!(!records[1].active);
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
}
