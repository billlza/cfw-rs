//! Selecting a profile: prepared selections, the digest binding and stale
//! selection metadata.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError, ProfileSelectionState};

use crate::private_file_fixture::write_private;
use crate::support::{
    assert_private_file, profile, repository, selection_path, stored_path, symlink,
};

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

#[test]
fn selection_metadata_must_be_bounded_current_and_canonical() {
    let (root, repository) = repository("selection-form");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let path = selection_path(&root);
    let canonical = fs::read_to_string(&path).expect("read selection");
    type Expect = fn(&ProfileError) -> bool;
    let cases: [(String, Expect); 4] = [
        // Selection metadata is limited to 1,024 bytes: at the limit it is
        // read and refused for its form, one byte over for its size.
        (
            format!("{canonical}{}", " ".repeat(1_024 - canonical.len())),
            |error| matches!(error, ProfileError::NonCanonicalSelection),
        ),
        (
            format!("{canonical}{}", " ".repeat(1_025 - canonical.len())),
            |error| matches!(error, ProfileError::SelectionTooLarge { actual: 1_025 }),
        ),
        (
            canonical.replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1),
            |error| matches!(error, ProfileError::UnsupportedSelectionSchema(2)),
        ),
        (format!("{canonical}\n"), |error| {
            matches!(error, ProfileError::NonCanonicalSelection)
        }),
    ];
    for (selection, expected) in cases {
        write_private(&path, selection.as_bytes());
        let error = repository.snapshot().expect_err("selection refused");
        assert!(expected(&error), "{error}");
    }
    repository
        .select(&imported.id)
        .expect("selecting again repairs the metadata");
    assert_eq!(
        fs::read_to_string(&path).expect("read selection"),
        canonical
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_linked_selection_file_is_refused_without_reading_its_target() {
    let (root, repository) = repository("selection-symlink");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let path = selection_path(&root);
    let outside = root.join("outside-selection.json");
    fs::rename(&path, &outside).expect("move the selection out");
    let selection = fs::read(&outside).expect("read moved selection");
    symlink(&outside, &path).expect("link the selection");

    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::UnsafeSelectionFile)
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), selection);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn an_exact_import_can_be_selected_by_the_same_mutation() {
    const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const UNSELECTED_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let (root, repository) = repository("exact-import-select");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    repository.select(&other.id).expect("select other profile");
    let commit = |id: &str, activate: bool| {
        repository
            .begin_credential_profile_mutation()
            .expect("mutation lock")
            .commit_exact_import_and_select(
                id,
                Some("Migrated"),
                &profile(),
                Some("https://subscription.example/profile"),
                activate,
            )
            .expect("exact import")
    };
    let selected_id = || {
        repository
            .require_selected()
            .expect("selected profile")
            .record
            .id
    };

    assert!(commit(ID, true).created);
    assert_eq!(selected_id(), ID);

    // A replay creates nothing, so it selects nothing either.
    repository.select(&other.id).expect("select other again");
    assert!(!commit(ID, true).created);
    assert_eq!(selected_id(), other.id);

    assert!(commit(UNSELECTED_ID, false).created);
    assert_eq!(selected_id(), other.id);

    // A conflicting exact import is refused and selects nothing.
    let conflict = repository
        .begin_credential_profile_mutation()
        .expect("mutation lock")
        .commit_exact_import_and_select(ID, Some("Renamed"), &profile(), None, true)
        .expect_err("the id is taken by a different profile");
    assert!(matches!(conflict, ProfileError::AlreadyExists(id) if id == ID));
    assert_eq!(selected_id(), other.id);
    assert!(
        repository
            .load(UNSELECTED_ID)
            .expect("load unselected import")
            .is_some()
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_mutation_reports_the_selection_it_holds() {
    let (root, repository) = repository("mutation-selection");
    let imported = repository.import(None, &profile()).expect("import profile");
    let unselected = repository
        .begin_credential_profile_mutation()
        .expect("mutation lock")
        .selected_profile()
        .expect("selection state");
    assert!(matches!(unselected, ProfileSelectionState::Unselected));
    assert_eq!(unselected.into_loaded().expect("no selection"), None);

    repository.select(&imported.id).expect("select profile");
    let selected = repository
        .begin_credential_profile_mutation()
        .expect("mutation lock")
        .selected_profile()
        .expect("selection state")
        .into_loaded()
        .expect("valid selection")
        .expect("selected profile");
    assert_eq!(selected.record.id, imported.id);
    fs::remove_dir_all(root).expect("remove test directory");
}
