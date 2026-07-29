use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use cfw_profiles::{ProfileError, ProfileRepository, ValidatedSingBoxProfile};
use uuid::Uuid;

const MAX_STORED_BYTES: usize = 384 * 1024;

fn repository(name: &str) -> (PathBuf, ProfileRepository) {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-repository-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let repository = ProfileRepository::new(root.join("profiles"));
    (root, repository)
}

fn profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#,
    )
    .expect("valid profile")
}

fn credential_profile(reference_id: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{reference_id}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .expect("valid credential profile")
}

fn stored_path(root: &std::path::Path, id: &str) -> PathBuf {
    root.join("profiles").join(format!("{id}.profile.json"))
}

fn selection_path(root: &std::path::Path) -> PathBuf {
    root.join("profiles").join("selected-profile-v1.json")
}

#[test]
fn import_list_load_and_delete_round_trip_is_private_and_atomic() {
    let (root, repository) = repository("round-trip");
    let imported = repository
        .import(Some(" Work profile "), &profile())
        .expect("import profile");
    assert_eq!(imported.name, "Work profile");

    let profiles_dir = root.join("profiles");
    assert_eq!(
        fs::metadata(&profiles_dir)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&profiles_dir)
            .expect("directory metadata")
            .uid(),
        unsafe { libc::geteuid() }
    );
    let entries = fs::read_dir(&profiles_dir)
        .expect("read profiles")
        .collect::<Result<Vec<_>, _>>()
        .expect("profile entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]
            .metadata()
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        entries[0].metadata().expect("file metadata").uid(),
        unsafe { libc::geteuid() }
    );
    assert!(!entries[0].file_name().to_string_lossy().contains(".tmp"));

    let records = repository.list().expect("list profiles");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, imported.id);
    assert_eq!(records[0].digest, imported.digest);
    let loaded = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(loaded.profile, profile());

    assert!(repository.delete(&imported.id).expect("delete profile"));
    assert!(!repository.delete(&imported.id).expect("idempotent delete"));
    assert!(repository.list().expect("empty list").is_empty());
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn credential_snapshot_is_stable_and_preserves_cross_profile_reference_ownership() {
    const SHARED: &str = "11111111-1111-4111-8111-111111111111";
    const ROTATED: &str = "22222222-2222-4222-8222-222222222222";
    let (root, repository) = repository("credential-snapshot");
    let empty = repository
        .credential_snapshot()
        .expect("empty credential snapshot");
    assert_eq!(empty.profile_count, 0);
    assert!(empty.catalog.is_empty());
    assert_eq!(empty.snapshot_digest.len(), 64);

    let first = repository
        .import(Some("First"), &credential_profile(SHARED))
        .expect("first shared profile");
    let second = repository
        .import(Some("Second"), &credential_profile(SHARED))
        .expect("second shared profile");
    let shared = repository
        .credential_snapshot()
        .expect("shared credential snapshot");
    assert_eq!(shared.profile_count, 2);
    assert_eq!(shared.catalog.len(), 2);
    assert!(
        shared
            .catalog
            .iter()
            .all(|entry| entry.references.len() == 1 && entry.references[0].id() == SHARED)
    );
    assert_ne!(shared.catalog[0].audience, shared.catalog[1].audience);
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("stable credential snapshot"),
        shared
    );

    repository.select(&first.id).expect("select first profile");
    let selected = repository
        .credential_snapshot()
        .expect("selected credential snapshot");
    assert_eq!(
        selected.selected_profile_id.as_deref(),
        Some(first.id.as_str())
    );
    assert_ne!(selected.snapshot_digest, shared.snapshot_digest);

    repository
        .select(&second.id)
        .expect("select second profile");
    assert!(
        repository
            .delete(&first.id)
            .expect("delete unselected shared profile")
    );
    let retained = repository
        .credential_snapshot()
        .expect("shared reference retained");
    assert_eq!(retained.catalog.len(), 1);
    assert_eq!(retained.catalog[0].references[0].id(), SHARED);

    let rotated = repository
        .import(Some("Rotated"), &credential_profile(ROTATED))
        .expect("rotated profile");
    let pending_rotation = repository
        .credential_snapshot()
        .expect("unselected rotation is live");
    assert_eq!(pending_rotation.profile_count, 2);
    // Catalog order is canonical by audience (randomly generated profile
    // ids), so compare reference sets instead of positions.
    let mut pending_reference_ids = pending_rotation
        .catalog
        .iter()
        .flat_map(|entry| entry.references.iter())
        .map(|reference| reference.id())
        .collect::<Vec<_>>();
    pending_reference_ids.sort_unstable();
    assert_eq!(pending_reference_ids, vec![SHARED, ROTATED]);

    repository
        .select(&rotated.id)
        .expect("select rotated profile");
    assert!(
        repository
            .delete(&second.id)
            .expect("delete obsolete profile")
    );
    let completed_rotation = repository
        .credential_snapshot()
        .expect("completed rotation snapshot");
    assert_eq!(completed_rotation.profile_count, 1);
    assert_eq!(completed_rotation.catalog.len(), 1);
    assert_eq!(completed_rotation.catalog[0].references[0].id(), ROTATED);
    assert_ne!(
        completed_rotation.snapshot_digest,
        pending_rotation.snapshot_digest
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn locked_credential_snapshot_blocks_profile_mutation_until_native_commit_finishes() {
    let (root, repository) = repository("credential-snapshot-lock");
    repository
        .import(Some("Initial"), &profile())
        .expect("initial profile");
    let guard = repository
        .lock_credential_snapshot()
        .expect("credential snapshot lock");
    let expected_digest = guard.snapshot().snapshot_digest.clone();
    let writer_repository = repository.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = writer_repository.import(Some("Blocked"), &profile());
        sender.send(result).expect("send writer result");
    });

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(guard.snapshot().snapshot_digest, expected_digest);
    drop(guard);
    receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("writer unblocked")
        .expect("blocked import succeeds");
    writer.join().expect("writer thread");

    let after = repository
        .credential_snapshot()
        .expect("post-commit snapshot");
    assert_ne!(after.snapshot_digest, expected_digest);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn digest_tampering_is_reported_instead_of_skipped() {
    let (root, repository) = repository("digest-tamper");
    let imported = repository.import(None, &profile()).expect("import profile");
    let path = stored_path(&root, &imported.id);
    let raw = fs::read_to_string(&path).expect("read envelope");
    let tampered = raw.replacen(&imported.digest, &"00".repeat(32), 1);
    assert_ne!(tampered, raw);
    fs::write(&path, tampered).expect("tamper envelope");

    assert!(matches!(
        repository.list(),
        Err(ProfileError::DigestMismatch { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn oversized_stored_file_is_rejected_before_deserialization() {
    let (root, repository) = repository("oversized");
    let profiles_dir = root.join("profiles");
    fs::create_dir_all(&profiles_dir).expect("create directory");
    fs::set_permissions(&profiles_dir, fs::Permissions::from_mode(0o700))
        .expect("set directory permissions");
    let id = Uuid::new_v4().hyphenated().to_string();
    let path = stored_path(&root, &id);
    fs::write(&path, vec![b' '; MAX_STORED_BYTES + 1]).expect("write oversized file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set file permissions");

    assert!(matches!(
        repository.list(),
        Err(ProfileError::StoredProfileTooLarge { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn traversal_and_noncanonical_ids_are_rejected() {
    let (_root, repository) = repository("invalid-id");
    for id in [
        "../profile",
        "00000000000000000000000000000000",
        "NOT-A-UUID",
    ] {
        assert!(matches!(
            repository.load(id),
            Err(ProfileError::InvalidProfileId(_))
        ));
        assert!(matches!(
            repository.delete(id),
            Err(ProfileError::InvalidProfileId(_))
        ));
    }
}

#[test]
fn symlink_profile_is_rejected_without_reading_target() {
    let (root, repository) = repository("symlink");
    fs::create_dir_all(root.join("profiles")).expect("create profiles directory");
    fs::set_permissions(root.join("profiles"), fs::Permissions::from_mode(0o700))
        .expect("set directory mode");
    let outside = root.join("outside.json");
    fs::write(&outside, b"secret").expect("write outside file");
    let id = Uuid::new_v4().hyphenated().to_string();
    symlink(&outside, stored_path(&root, &id)).expect("create symlink");

    assert!(matches!(
        repository.list(),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"secret");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn hard_link_profile_is_rejected() {
    let (root, repository) = repository("hard-link");
    let imported = repository.import(None, &profile()).expect("import profile");
    fs::hard_link(
        stored_path(&root, &imported.id),
        root.join("external-link.json"),
    )
    .expect("create hard link");

    assert!(matches!(
        repository.list(),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn one_way_cleanup_unlinks_symlinks_without_touching_targets() {
    let (root, repository) = repository("cleanup");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("external-profile.json");
    fs::write(&outside, b"external").expect("write external file");
    symlink(&outside, root.join("profiles").join("legacy.yaml")).expect("create legacy symlink");

    assert_eq!(
        repository.clear_managed_profiles().expect("clear profiles"),
        2
    );
    assert!(repository.list().expect("empty profile list").is_empty());
    assert_eq!(fs::read(&outside).expect("external target"), b"external");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn malformed_or_unexpected_entries_are_not_silently_skipped() {
    let (root, repository) = repository("unexpected");
    fs::create_dir_all(root.join("profiles")).expect("create directory");
    fs::write(root.join("profiles").join("legacy.yaml"), b"proxies: []")
        .expect("write legacy entry");
    assert!(matches!(
        repository.list(),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn concurrent_listing_never_observes_an_atomic_write_temporary() {
    let (root, repository) = repository("concurrent-list");
    let repository = Arc::new(repository);
    assert!(repository.list().expect("initial profile list").is_empty());
    let barrier = Arc::new(Barrier::new(2));

    let writer_repository = Arc::clone(&repository);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..12 {
            writer_repository
                .import(Some(&format!("Profile {index}")), &profile())
                .expect("atomic profile import");
        }
    });

    barrier.wait();
    for _ in 0..48 {
        repository
            .list()
            .expect("listing must not observe an in-flight temporary file");
    }
    writer.join().expect("writer thread");
    assert_eq!(repository.list().expect("final profile list").len(), 12);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn abandoned_import_and_selection_temporaries_are_recovered_under_the_lock() {
    let (root, repository) = repository("temporary-recovery");
    let imported = repository.import(None, &profile()).expect("import profile");
    let profiles_dir = root.join("profiles");
    let import_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    let selection_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    for path in [&import_temporary, &selection_temporary] {
        fs::write(path, b"interrupted private transaction").expect("write abandoned temporary");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("private temporary mode");
    }

    assert_eq!(repository.list().expect("recover before listing").len(), 1);
    assert!(!import_temporary.exists());
    assert!(!selection_temporary.exists());
    repository
        .select(&imported.id)
        .expect("selection works after recovery");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn unsafe_matching_temporary_is_rejected_without_following_it() {
    let (root, repository) = repository("unsafe-temporary");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("outside-temporary");
    fs::write(&outside, b"external").expect("outside target");
    let temporary = root
        .join("profiles")
        .join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    symlink(&outside, &temporary).expect("matching temporary symlink");

    assert!(matches!(
        repository.list(),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"external");
    assert!(temporary.is_symlink());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn selection_round_trip_is_private_digest_bound_and_blocks_selected_deletion() {
    let (root, repository) = repository("selection-round-trip");
    let imported = repository.import(None, &profile()).expect("import profile");

    let selected = repository.select(&imported.id).expect("select profile");
    assert_eq!(selected.id, imported.id);
    let selection_metadata = fs::metadata(selection_path(&root)).expect("selection metadata");
    assert_eq!(selection_metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(selection_metadata.uid(), unsafe { libc::geteuid() });

    let snapshot = repository.snapshot().expect("repository snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(imported.id.as_str())
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected")
            .expect("selected profile")
            .record
            .id,
        imported.id
    );
    assert!(matches!(
        repository.delete(&imported.id),
        Err(ProfileError::SelectedProfileDeletion(id)) if id == imported.id
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn missing_selected_profile_is_a_stale_selection_error_without_direct_fallback() {
    let (root, repository) = repository("selection-missing");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    fs::remove_file(stored_path(&root, &imported.id)).expect("remove selected envelope");

    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));
    assert!(matches!(
        repository.import(Some("must not append"), &profile()),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn changed_selection_digest_and_unknown_fields_are_rejected() {
    let (root, repository) = repository("selection-tamper");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let path = selection_path(&root);

    let raw = fs::read_to_string(&path).expect("read selection");
    let tampered = raw.replacen(&imported.digest, &"00".repeat(32), 1);
    assert_ne!(tampered, raw);
    fs::write(&path, tampered).expect("tamper selection digest");
    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == imported.id
    ));

    let with_unknown = format!(
        "{},\"unexpected\":true}}",
        raw.strip_suffix('}').expect("selection object")
    );
    fs::write(&path, with_unknown).expect("add unknown field");
    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::InvalidSelectionJson(_))
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn explicit_selection_can_repair_stale_metadata() {
    let (root, repository) = repository("selection-repair");
    let first = repository
        .import(Some("first"), &profile())
        .expect("first profile");
    let second = repository
        .import(Some("second"), &profile())
        .expect("second profile");
    repository.select(&first.id).expect("select first");

    let path = selection_path(&root);
    fs::write(
        &path,
        br#"{"profile_digest":"invalid","profile_id":"invalid","schema_version":1}"#,
    )
    .expect("corrupt selection");
    repository
        .select(&second.id)
        .expect("explicitly replace stale selection");
    assert_eq!(
        repository
            .load_selected()
            .expect("load repaired selection")
            .expect("selected profile")
            .record
            .id,
        second.id
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn subscription_url_survives_a_round_trip_and_is_bounded() {
    let (root, repository) = repository("subscription-round-trip");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &profile(),
            Some("https://example.com/sub?token=t"),
        )
        .expect("import remote profile");
    let stored = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(
        stored.source_url.as_deref(),
        Some("https://example.com/sub?token=t")
    );

    // A local import has no subscription URL, and the listing never carries one.
    let local = repository
        .import(Some("Local"), &profile())
        .expect("import local profile");
    assert_eq!(
        repository
            .load(&local.id)
            .expect("load local")
            .expect("stored local")
            .source_url,
        None
    );
    let listed = serde_json::to_string(&repository.list().expect("list profiles"))
        .expect("serialize records");
    assert!(!listed.contains("token=t"));
    assert!(!listed.contains("source_url"));

    for rejected in [
        "not-a-url",
        "http://example.com/sub",
        "https://example.com/ sub",
        " https://example.com/sub",
    ] {
        assert!(
            matches!(
                repository.import_with_source(Some("Rejected"), &profile(), Some(rejected)),
                Err(ProfileError::InvalidSourceUrl)
            ),
            "accepted invalid subscription URL: {rejected}"
        );
    }
    let oversized = format!("https://example.com/{}", "a".repeat(2_048));
    assert!(matches!(
        repository.import_with_source(Some("Oversized"), &profile(), Some(&oversized)),
        Err(ProfileError::InvalidSourceUrl)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn envelopes_written_before_subscriptions_existed_are_still_canonical() {
    let (root, repository) = repository("legacy-envelope");
    let imported = repository
        .import(Some("Legacy"), &profile())
        .expect("import profile");
    let path = stored_path(&root, &imported.id);
    let bytes = fs::read(&path).expect("read envelope");
    let rendered = String::from_utf8(bytes).expect("utf-8 envelope");
    assert!(
        !rendered.contains("source_url"),
        "an absent subscription URL must not be written"
    );

    // The unchanged bytes must still decode, so an installation created before
    // this field existed keeps working.
    let stored = repository
        .load(&imported.id)
        .expect("load legacy envelope")
        .expect("stored profile");
    assert_eq!(stored.source_url, None);
    assert_eq!(stored.record.name, "Legacy");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn replace_keeps_identity_credentials_and_rebinds_the_selection_digest() {
    let (root, repository) = repository("replace");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/sub"),
        )
        .expect("import remote profile");
    repository.select(&imported.id).expect("select profile");

    let replacement = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let saved = repository
        .replace(
            &imported.id,
            None,
            &replacement,
            Some("https://example.com/sub2"),
        )
        .expect("replace profile");
    assert_eq!(saved.id, imported.id, "identity must be stable");
    assert_eq!(saved.name, "Remote", "the name is preserved by default");
    assert_eq!(saved.digest, replacement.digest());

    // The selection is rebound under the same lock, so the repository is
    // readable and the selected profile is the replacement.
    let selected = repository
        .load_selected()
        .expect("load selection after replace")
        .expect("selected profile");
    assert_eq!(selected.record.id, imported.id);
    assert_eq!(selected.record.digest, replacement.digest());
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://example.com/sub2")
    );
    assert_eq!(
        selected.profile.credential_references(),
        replacement.credential_references()
    );
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("credential snapshot")
            .catalog
            .into_iter()
            .flat_map(|entry| entry.references)
            .collect::<Vec<_>>(),
        replacement.credential_references(),
        "the replaced document's credential references are no longer live"
    );

    // Only one entry plus the selection exists: replacing never adds a profile.
    let entries = fs::read_dir(root.join("profiles"))
        .expect("read profiles")
        .collect::<Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 2);

    assert!(matches!(
        repository.replace(
            "34db18b6-9903-4e9f-8854-15648e19e4f3",
            None,
            &profile(),
            None
        ),
        Err(ProfileError::Io(_))
    ));
    assert!(matches!(
        repository.replace("not-a-uuid", None, &profile(), None),
        Err(ProfileError::InvalidProfileId(_))
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn rollback_restore_preserves_the_complete_loaded_profile_identity() {
    let (root, repository) = repository("restore");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import original profile");
    repository.select(&imported.id).expect("select profile");
    let original = repository
        .load(&imported.id)
        .expect("load original")
        .expect("original profile");

    repository
        .replace(
            &imported.id,
            Some("Replacement"),
            &profile(),
            Some("https://example.com/replacement"),
        )
        .expect("replace before rollback");
    repository
        .restore(&original)
        .expect("restore exact profile");

    assert_eq!(
        repository
            .load_selected()
            .expect("load restored selection")
            .expect("restored selected profile"),
        original
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn metadata_updates_change_no_document_digest_or_selection() {
    let (root, repository) = repository("metadata");
    let imported = repository
        .import(Some("Original"), &profile())
        .expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let before = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");

    let renamed = repository
        .update_metadata(
            &imported.id,
            Some(" Renamed "),
            Some("https://example.com/sub"),
        )
        .expect("update metadata");
    assert_eq!(renamed.name, "Renamed");
    assert_eq!(renamed.digest, before.record.digest);
    assert_eq!(
        renamed.created_epoch_secs, before.record.created_epoch_secs,
        "renaming is not an update of the profile itself"
    );

    let after = repository
        .load_selected()
        .expect("load selection")
        .expect("selected profile");
    assert_eq!(after.record.id, imported.id);
    assert_eq!(after.record.name, "Renamed");
    assert_eq!(after.source_url.as_deref(), Some("https://example.com/sub"));

    // Clearing the subscription URL is allowed and keeps the profile intact.
    repository
        .update_metadata(&imported.id, None, None)
        .expect("clear subscription");
    let cleared = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(cleared.source_url, None);
    assert_eq!(cleared.record.name, "Renamed");
    assert_eq!(cleared.record.digest, before.record.digest);

    assert!(matches!(
        repository.update_metadata(&imported.id, Some("bad/name"), None),
        Err(ProfileError::InvalidName)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn profile_entry_name_resolves_only_existing_canonical_ids() {
    let (root, repository) = repository("entry-name");
    let imported = repository
        .import(Some("Local"), &profile())
        .expect("import profile");
    assert_eq!(
        repository
            .profile_entry_name(&imported.id)
            .expect("entry name"),
        Some(format!("{}.profile.json", imported.id))
    );
    assert_eq!(
        repository
            .profile_entry_name("34db18b6-9903-4e9f-8854-15648e19e4f3")
            .expect("absent profile"),
        None
    );
    assert!(repository.profile_entry_name("../escape").is_err());

    fs::remove_dir_all(root).expect("remove test directory");
}
