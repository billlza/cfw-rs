use std::collections::VecDeque;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
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
    garbage_collection_requests: Mutex<usize>,
}

impl ScriptedCredentialVault {
    fn new(responses: Vec<Result<CredentialVaultReceipt, CredentialVaultError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            garbage_collection_requests: Mutex::new(0),
        }
    }

    fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
        self.requests.lock().expect("request lock").clone()
    }

    fn garbage_collection_requests(&self) -> usize {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock")
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
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn commit_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
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

#[cfg(unix)]
fn legacy_directory() -> tempfile::TempDir {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o775))
        .expect("legacy directory permissions");
    temporary
}

#[cfg(windows)]
struct LegacyTestDirectory {
    _temporary: tempfile::TempDir,
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl LegacyTestDirectory {
    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
fn legacy_directory() -> LegacyTestDirectory {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("legacy");
    cfw_windows_storage::PrivateDirectory::open_or_create(&path).unwrap();
    LegacyTestDirectory {
        _temporary: temporary,
        path,
    }
}

fn write_legacy_file(directory: &Path, name: &str, bytes: &[u8]) {
    #[cfg(unix)]
    fs::write(directory.join(name), bytes).expect("write legacy file");
    #[cfg(windows)]
    {
        // A newly created Win32 file need not inherit its owner's SID.
        // Set the fixture's owner and DACL through the actual private store.
        cfw_windows_storage::PrivateDirectory::open_existing(directory)
            .unwrap()
            .unwrap()
            .write()
            .unwrap()
            .replace(name, bytes, bytes.len().max(1))
            .unwrap();
    }
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
    write_legacy_file(
        directory,
        "active-profile.json",
        &serde_json::to_vec(&sidecar).expect("sidecar JSON"),
    );
    write_legacy_file(
        directory,
        "active-profile.yaml",
        b"proxies:\n  - name: Direct\n    type: ss\n",
    );
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
    write_legacy_file(directory.path(), "active-profile.yml", b"proxies: []");
    let file = open_owned_directory(directory.path(), false).expect("open directory");
    let error = match read_candidate_from_directory(&file, "active-profile") {
        Err(error) => error,
        Ok(_) => panic!("ambiguous YAML must fail"),
    };
    assert!(error.contains("ambiguous .yaml and .yml"), "{error}");
    fs::remove_file(directory.path().join("active-profile.yml")).expect("remove YAML");

    let outside = directory.path().join("outside.json");
    write_legacy_file(directory.path(), "outside.json", b"{}");
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
    let vault =
        ScriptedCredentialVault::new(vec![Err(CredentialVaultError::OutcomeUnknown), Ok(receipt)]);

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
async fn migration_identity_rejection_preserves_profiles_without_replay_or_cleanup() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let original = repository
        .import(Some("Original"), &ValidatedSingBoxProfile::direct())
        .expect("original profile");
    repository.select(&original.id).expect("select original");
    let before = repository.snapshot().expect("original snapshot");
    let imported = imported_profile(true);
    let vault = ScriptedCredentialVault::new(vec![
        Err(CredentialVaultError::IdentityRejected),
        Ok(CredentialVaultReceipt {
            profile_id: PROFILE_ID.into(),
            profile_digest: imported.profile.digest().to_owned(),
        }),
    ]);

    let error = commit_migrated_profile(
        &repository,
        &vault,
        PROFILE_ID,
        "Migrated",
        "https://subscription.example/profile",
        &imported,
    )
    .await
    .expect_err("an unconfirmed native write must not commit the profile");

    assert_eq!(repository.snapshot().expect("unchanged snapshot"), before);
    assert_eq!(vault.requests().len(), 1);
    assert_eq!(vault.garbage_collection_requests(), 0);
    assert!(error.contains("credential provisioning was not confirmed before repository commit"));
    assert!(error.contains("no new migration profile was committed"));
    assert!(error.contains("the operation result is unconfirmed"));
    assert!(!error.contains("vault rejected the migration batch"));
    assert!(!error.contains("data is corrupt"));
    assert!(!error.contains(PROFILE_SECRET));
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
