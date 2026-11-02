//! Selecting a profile: prepared selections, the digest binding and stale
//! selection metadata.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};

use crate::support::{assert_private_file, profile, repository, selection_path, stored_path};

#[test]
fn prepared_online_selection_is_invisible_until_commit_and_drop_keeps_the_prior_profile() {
    let (root, repository) = repository("online-selection");
    let first = repository.import(Some("First"), &profile()).unwrap();
    let second = repository.import(Some("Second"), &profile()).unwrap();
    repository.select(&first.id).unwrap();
    let before = fs::read(selection_path(&root)).unwrap();
    {
        let mutation = repository.begin_credential_profile_mutation().unwrap();
        assert_eq!(
            mutation
                .selected_profile()
                .unwrap()
                .into_valid()
                .unwrap()
                .record
                .id,
            first.id
        );
        assert_eq!(mutation.profile(&second.id).unwrap().record.id, second.id);
        assert_eq!(fs::read(selection_path(&root)).unwrap(), before);
    }
    assert_eq!(repository.require_selected().unwrap().record.id, first.id);
    repository
        .begin_credential_profile_mutation()
        .unwrap()
        .commit_selection(&second.id)
        .unwrap();
    assert_eq!(repository.require_selected().unwrap().record.id, second.id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_failed_prepared_selection_preserves_the_prior_selection() {
    let (root, repository) = repository("online-selection-failure");
    let first = repository.import(Some("First"), &profile()).unwrap();
    repository.select(&first.id).unwrap();
    let before = fs::read(selection_path(&root)).unwrap();
    let missing = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let error = repository
        .begin_credential_profile_mutation()
        .unwrap()
        .commit_selection(missing)
        .unwrap_err();
    assert!(matches!(error, ProfileError::SelectedProfileMissing(_)));
    assert_eq!(fs::read(selection_path(&root)).unwrap(), before);
    assert_eq!(repository.require_selected().unwrap().record.id, first.id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn selection_round_trip_is_private_digest_bound_and_blocks_selected_deletion() {
    let (root, repository) = repository("selection-round-trip");
    let imported = repository.import(None, &profile()).expect("import profile");

    let selected = repository.select(&imported.id).expect("select profile");
    assert_eq!(selected.id, imported.id);
    assert_private_file(&selection_path(&root));

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
    // Only an invalid selected profile may be deleted with the engine Off.
    for engine in [InvalidSelection::Keep, InvalidSelection::Clear] {
        assert!(matches!(
            repository.delete(&imported.id, engine),
            Err(ProfileError::SelectedProfileDeletion(id)) if id == imported.id
        ));
    }
    assert!(stored_path(&root, &imported.id).exists());

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
