use std::fs;
use std::process::Command;
use std::sync::{Arc, Barrier};

use cfw_engine_api::{CredentialProfileCatalogEntry, CredentialProvision, EngineSettings};
use cfw_singbox_config::{CredentialSecret, ValidatedSingBoxProfile};
use serde_json::json;
use tempfile::TempDir;

use super::*;

const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const REFERENCE: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SECRET: &str = "test-only-CFW-credential-材料-914";

fn source() -> serde_json::Value {
    json!({"outbounds":[{"type":"trojan","tag":"proxy","server":"node.example.com","server_port":443,"credential_ref":{"id":REFERENCE,"kind":"trojan_password"},"tls":{"enabled":true,"server_name":"node.example.com"}},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}})
}

fn profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&source().to_string()).unwrap()
}

fn fixture() -> (TempDir, WindowsCredentialStore) {
    let root = tempfile::tempdir().unwrap();
    let store = WindowsCredentialStore::new(root.path().join("vault"));
    (root, store)
}

fn provision(
    store: &WindowsCredentialStore,
    id: &str,
    profile: &ValidatedSingBoxProfile,
    secret: &str,
) -> Result<CredentialVaultReceipt, Error> {
    let references = profile.credential_references();
    store.provision(
        CredentialProvisionRequest::new(
            id,
            profile,
            vec![CredentialProvision::new(
                &references[0],
                CredentialSecret::new(secret).unwrap(),
            )],
        )
        .unwrap(),
    )
}

fn audience(id: &str, profile: &ValidatedSingBoxProfile) -> CredentialAudience {
    CredentialAudience::new(id, profile.digest()).unwrap()
}

fn ciphertext(store: &WindowsCredentialStore) -> Vec<u8> {
    fs::read(store.directory.join(VAULT_FILE)).unwrap()
}

fn replace_raw(store: &WindowsCredentialStore, bytes: &[u8]) {
    PrivateDirectory::open_or_create(&store.directory)
        .unwrap()
        .write()
        .unwrap()
        .replace(VAULT_FILE, bytes, MAX_CIPHERTEXT_BYTES + 1)
        .unwrap();
}

fn empty_catalog() -> CredentialGarbageCollectionRequest {
    CredentialGarbageCollectionRequest::new("d".repeat(64), vec![]).unwrap()
}

#[test]
fn absent_vault_is_missing_for_maintenance_but_presence_is_false() {
    let (_root, store) = fixture();
    assert!(
        !store
            .presence(&CredentialPresenceRequest::new(ID, &profile()).unwrap())
            .unwrap()[0]
            .present
    );
    assert_eq!(
        store.preview_garbage_collection(&empty_catalog(), &[]),
        Err(Error::MissingVault)
    );
    assert!(!store.directory.exists());
}

#[test]
fn durable_roundtrip_is_encrypted_and_debug_is_redacted() {
    let (_root, store) = fixture();
    let profile = profile();
    let receipt = provision(&store, ID, &profile, SECRET).unwrap();
    assert_eq!(receipt.profile_digest, profile.digest());
    let bytes = ciphertext(&store);
    assert!(
        !bytes
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());
    let reopened = WindowsCredentialStore::new(&store.directory);
    let material = reopened
        .resolve_for_engine(&audience(ID, &profile), &profile.credential_references())
        .unwrap();
    assert_eq!(material.expose_to_engine().next().unwrap().1, SECRET);
    assert!(!format!("{material:?}").contains(SECRET));
    assert_eq!(
        store.read().unwrap().unwrap().encode().unwrap().as_slice(),
        dpapi::unprotect(&bytes).unwrap().as_slice()
    );
    for entry in fs::read_dir(&store.directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
    }
}

#[test]
fn idempotent_retry_does_not_rewrite_and_conflict_leaves_ciphertext_unchanged() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let before = ciphertext(&store);
    provision(&store, ID, &profile, SECRET).unwrap();
    assert_eq!(before, ciphertext(&store));
    assert_eq!(
        provision(&store, ID, &profile, "different-test-material"),
        Err(Error::ImmutableConflict)
    );
    assert_eq!(before, ciphertext(&store));
}

#[test]
fn another_audience_requires_explicit_material_and_exact_immutable_secret() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let before = ciphertext(&store);
    assert_eq!(
        store.provision(CredentialProvisionRequest::new(OTHER_ID, &profile, vec![]).unwrap()),
        Err(Error::InvalidMaterial)
    );
    assert_eq!(
        provision(&store, OTHER_ID, &profile, "different-test-material"),
        Err(Error::ImmutableConflict)
    );
    assert_eq!(before, ciphertext(&store));
    provision(&store, OTHER_ID, &profile, SECRET).unwrap();
    assert!(
        store
            .presence(&CredentialPresenceRequest::new(OTHER_ID, &profile).unwrap())
            .unwrap()[0]
            .present
    );
}

#[test]
fn an_incomplete_batch_never_partially_publishes_new_bindings() {
    let (_root, store) = fixture();
    let old = profile();
    provision(&store, ID, &old, SECRET).unwrap();
    let before = ciphertext(&store);
    let mut value = source();
    let mut extra = value["outbounds"][0].clone();
    extra["tag"] = json!("second");
    extra["credential_ref"]["id"] = json!("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    value["outbounds"].as_array_mut().unwrap().push(extra);
    let changed = ValidatedSingBoxProfile::parse(&value.to_string()).unwrap();
    assert_eq!(
        provision(&store, ID, &changed, SECRET),
        Err(Error::InvalidMaterial)
    );
    assert_eq!(ciphertext(&store), before);
}

#[test]
fn routing_rebind_preserves_old_audience_and_never_grants_an_unbound_digest() {
    let (_root, store) = fixture();
    let old = profile();
    provision(&store, ID, &old, SECRET).unwrap();
    let mut changed = source();
    changed["route"]["rules"] =
        json!([{"type":"domain","value":"internal.example.com","outbound":"direct"}]);
    let candidate = ValidatedSingBoxProfile::parse(&changed.to_string()).unwrap();
    assert!(
        store
            .resolve_for_engine(
                &audience(ID, &candidate),
                &candidate.credential_references()
            )
            .is_err()
    );
    let request =
        CredentialRebindRequest::new(ID, &old, &candidate, &EngineSettings::default()).unwrap();
    store.rebind(&request).unwrap();
    for profile in [&old, &candidate] {
        assert_eq!(
            store
                .resolve_for_engine(&audience(ID, profile), &profile.credential_references())
                .unwrap()
                .expose_to_engine()
                .next()
                .unwrap()
                .1,
            SECRET
        );
    }
    let bytes = ciphertext(&store);
    store.rebind(&request).unwrap();
    assert_eq!(bytes, ciphertext(&store));
}

#[test]
fn garbage_collection_preserves_runtime_bindings_and_deletes_only_confirmed_orphans() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    provision(&store, OTHER_ID, &profile, SECRET).unwrap();
    let live = vec![CredentialBinding::new(
        audience(ID, &profile),
        profile.credential_references()[0].clone(),
    )];
    let request = empty_catalog();
    let preview = store.preview_garbage_collection(&request, &live).unwrap();
    preview.validate().unwrap();
    assert_eq!(preview.orphan_count, 1);
    assert_eq!(preview.orphan_bindings[0].audience().profile_id(), OTHER_ID);
    let commit = CredentialGarbageCollectionCommitRequest::new(request, &preview).unwrap();
    let receipt = store.commit_garbage_collection(&commit, &live).unwrap();
    assert_eq!(receipt.deleted_count, 1);
    assert_ne!(receipt.vault_revision, preview.vault_revision);
    assert_eq!(
        store
            .preview_garbage_collection(&empty_catalog(), &live)
            .unwrap()
            .vault_revision,
        receipt.vault_revision
    );
    assert!(
        store
            .presence(&CredentialPresenceRequest::new(ID, &profile).unwrap())
            .unwrap()[0]
            .present
    );
    assert!(
        !store
            .presence(&CredentialPresenceRequest::new(OTHER_ID, &profile).unwrap())
            .unwrap()[0]
            .present
    );
}

#[test]
fn a_runtime_change_invalidates_gc_even_without_a_vault_revision_change() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let request = empty_catalog();
    let preview = store.preview_garbage_collection(&request, &[]).unwrap();
    let commit = CredentialGarbageCollectionCommitRequest::new(request, &preview).unwrap();
    let before = ciphertext(&store);
    let live = [CredentialBinding::new(
        audience(ID, &profile),
        profile.credential_references()[0].clone(),
    )];
    assert_eq!(
        store.commit_garbage_collection(&commit, &live),
        Err(Error::ConcurrentModification)
    );
    assert_eq!(before, ciphertext(&store));
}

#[test]
fn a_vault_change_invalidates_gc_and_a_missing_runtime_binding_is_an_error() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let request = empty_catalog();
    let preview = store.preview_garbage_collection(&request, &[]).unwrap();
    let commit = CredentialGarbageCollectionCommitRequest::new(request, &preview).unwrap();
    let other = [CredentialBinding::new(
        audience(OTHER_ID, &profile),
        profile.credential_references()[0].clone(),
    )];
    assert_eq!(
        store.preview_garbage_collection(&empty_catalog(), &other),
        Err(Error::InvalidMaterial)
    );
    provision(&store, OTHER_ID, &profile, SECRET).unwrap();
    let before = ciphertext(&store);
    assert_eq!(
        store.commit_garbage_collection(&commit, &[]),
        Err(Error::ConcurrentModification)
    );
    assert_eq!(before, ciphertext(&store));
}

#[test]
fn empty_gc_commit_preserves_the_existing_revision_and_file() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let catalog = CredentialGarbageCollectionRequest::new(
        "d".repeat(64),
        vec![
            CredentialProfileCatalogEntry::new(
                audience(ID, &profile),
                profile.credential_references(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let preview = store.preview_garbage_collection(&catalog, &[]).unwrap();
    assert_eq!(preview.orphan_count, 0);
    let before = ciphertext(&store);
    let receipt = store
        .commit_garbage_collection(
            &CredentialGarbageCollectionCommitRequest::new(catalog, &preview).unwrap(),
            &[],
        )
        .unwrap();
    assert_eq!(receipt.vault_revision, preview.vault_revision);
    assert_eq!(receipt.deleted_count, 0);
    assert_eq!(before, ciphertext(&store));
}

#[test]
fn corrupt_ciphertext_is_never_treated_as_an_empty_vault_or_overwritten() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let original = ciphertext(&store);
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    for bytes in [
        tampered,
        original[..original.len() / 2].to_vec(),
        b"invalid ciphertext".to_vec(),
        vec![],
    ] {
        replace_raw(&store, &bytes);
        assert!(
            store
                .presence(&CredentialPresenceRequest::new(ID, &profile).unwrap())
                .is_err()
        );
        assert!(provision(&store, ID, &profile, SECRET).is_err());
        assert_eq!(bytes, ciphertext(&store));
    }
}

#[test]
fn decrypted_schema_fields_order_and_secret_syntax_are_checked() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let plaintext = dpapi::unprotect(&ciphertext(&store)).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    for field in [
        "unknown",
        "invalid-secret",
        "duplicate-binding",
        "future-schema",
    ] {
        let mut changed = value.clone();
        match field {
            "unknown" => changed["unknown"] = json!(true),
            "invalid-secret" => changed["entries"][0]["secret"] = json!("bad\nsecret"),
            "duplicate-binding" => {
                let entry = changed["entries"][0].clone();
                changed["entries"].as_array_mut().unwrap().push(entry);
            }
            "future-schema" => changed["schema_version"] = json!(2),
            _ => unreachable!(),
        }
        let encrypted = dpapi::protect(&serde_json::to_vec(&changed).unwrap()).unwrap();
        replace_raw(&store, &encrypted);
        let expected = if field == "future-schema" {
            Error::MigrationRequired
        } else {
            Error::Corrupt
        };
        assert_eq!(
            store.presence(&CredentialPresenceRequest::new(ID, &profile).unwrap()),
            Err(expected)
        );
        assert_eq!(provision(&store, ID, &profile, SECRET), Err(expected));
        assert_eq!(encrypted, ciphertext(&store));
    }
    let mut trailing = plaintext.to_vec();
    trailing.push(b' ');
    replace_raw(&store, &dpapi::protect(&trailing).unwrap());
    assert_eq!(
        store.presence(&CredentialPresenceRequest::new(ID, &profile).unwrap()),
        Err(Error::Corrupt)
    );
}

#[test]
fn oversized_and_hardlinked_vault_files_are_rejected_before_use() {
    let (_root, store) = fixture();
    let profile = profile();
    provision(&store, ID, &profile, SECRET).unwrap();
    let original = ciphertext(&store);
    let oversized = vec![0_u8; MAX_CIPHERTEXT_BYTES + 1];
    replace_raw(&store, &oversized);
    assert_eq!(
        store.presence(&CredentialPresenceRequest::new(ID, &profile).unwrap()),
        Err(Error::Corrupt)
    );
    replace_raw(&store, &original);
    let link = store.directory.join("hardlink");
    fs::hard_link(store.directory.join(VAULT_FILE), &link).unwrap();
    assert_eq!(
        store.presence(&CredentialPresenceRequest::new(ID, &profile).unwrap()),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        provision(&store, ID, &profile, SECRET),
        Err(Error::AccessDenied)
    );
    assert_eq!(original, ciphertext(&store));
}

#[test]
fn simultaneous_writers_keep_both_audience_bindings() {
    let (_root, store) = fixture();
    // Initialize the directory so this tests independent transaction handles.
    PrivateDirectory::open_or_create(&store.directory).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [ID, OTHER_ID]
        .into_iter()
        .map(|id| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                provision(&store, id, &profile(), SECRET).unwrap();
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    for id in [ID, OTHER_ID] {
        assert!(
            store
                .presence(&CredentialPresenceRequest::new(id, &profile()).unwrap())
                .unwrap()[0]
                .present
        );
    }
}

#[test]
fn bounded_lock_contention_fails_without_replacing_the_vault_then_recovers() {
    let (_root, store) = fixture();
    provision(&store, ID, &profile(), SECRET).unwrap();
    let before = ciphertext(&store);
    let directory = PrivateDirectory::open_existing(&store.directory)
        .unwrap()
        .unwrap();
    let held = directory.write().unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        provision(&store, OTHER_ID, &profile(), SECRET),
        Err(Error::ConcurrentModification)
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    assert_eq!(before, ciphertext(&store));
    drop(held);
    provision(&store, OTHER_ID, &profile(), SECRET).unwrap();
}

#[test]
fn persistence_across_a_fresh_process_uses_the_real_dpapi_key() {
    const PATH_ENV: &str = "CFW_CREDENTIAL_TEST_CHILD_DIRECTORY";
    if let Some(path) = std::env::var_os(PATH_ENV) {
        let store = WindowsCredentialStore::new(path);
        assert_eq!(
            store
                .resolve_for_engine(
                    &audience(ID, &profile()),
                    &profile().credential_references()
                )
                .unwrap()
                .expose_to_engine()
                .next()
                .unwrap()
                .1,
            SECRET
        );
        provision(&store, OTHER_ID, &profile(), SECRET).unwrap();
        return;
    }
    let (_root, store) = fixture();
    provision(&store, ID, &profile(), SECRET).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::persistence_across_a_fresh_process_uses_the_real_dpapi_key",
        ])
        .env(PATH_ENV, &store.directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        store
            .presence(&CredentialPresenceRequest::new(OTHER_ID, &profile()).unwrap())
            .unwrap()[0]
            .present
    );
}

#[test]
fn an_impersonating_thread_cannot_create_or_read_a_user_vault() {
    use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    let (_root, store) = fixture();
    // Use a dedicated test thread so impersonation never escapes this operation.
    std::thread::spawn(move || {
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let _revert = Revert;
        assert_eq!(
            provision(&store, ID, &profile(), SECRET),
            Err(Error::AccessDenied)
        );
        assert_eq!(
            store.presence(&CredentialPresenceRequest::new(ID, &profile()).unwrap()),
            Err(Error::AccessDenied)
        );
        assert!(!store.directory.exists());
    })
    .join()
    .unwrap();
}

#[test]
fn invalid_directory_ancestors_never_mean_an_empty_vault() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("file"), b"occupied").unwrap();
    let store = WindowsCredentialStore::new(root.path().join("file/child/vault"));
    assert!(
        store
            .presence(&CredentialPresenceRequest::new(ID, &profile()).unwrap())
            .is_err()
    );
    assert!(provision(&store, ID, &profile(), SECRET).is_err());
}

#[test]
fn aggregate_secret_capacity_is_enforced_before_publication() {
    let (_root, store) = fixture();
    provision(&store, ID, &profile(), SECRET).unwrap();
    let before = ciphertext(&store);
    let mut value = source();
    let template = value["outbounds"][0].clone();
    let mut outbounds = vec![];
    for index in 0..29 {
        let mut node = template.clone();
        node["tag"] = json!(format!("proxy-{index}"));
        node["credential_ref"]["id"] = json!(Uuid::new_v4().to_string());
        outbounds.push(node);
    }
    value["outbounds"] = json!(outbounds);
    value["route"]["final"] = json!("proxy-0");
    let profile = ValidatedSingBoxProfile::parse(&value.to_string()).unwrap();
    let references = profile.credential_references();
    let material = "x".repeat(16 * 1024);
    let entries = references
        .iter()
        .map(|reference| {
            CredentialProvision::new(reference, CredentialSecret::new(&material).unwrap())
        })
        .collect();
    assert_eq!(
        store.provision(CredentialProvisionRequest::new(OTHER_ID, &profile, entries).unwrap()),
        Err(Error::CapacityExceeded)
    );
    assert_eq!(before, ciphertext(&store));
}
