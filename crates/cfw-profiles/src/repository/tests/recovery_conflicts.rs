//! Recovery refuses any state the replacement could not have produced and
//! keeps the intent for inspection.

use super::*;

#[test]
fn selected_replace_recovery_never_overwrites_a_different_selection() {
    let (root, repository, original) = selected_fixture("selection-changed");
    let other = repository
        .import(Some("Other"), &profile("direct-other"))
        .expect("import other profile");
    let replacement = profile("direct-replacement");
    let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
    write_private(
        &root
            .join("profiles")
            .join(profile_file_name(&original.record.id)),
        &replacement_bytes,
    );
    let other_selection = ProfileSelection::new(&other.id, &other.digest).expect("other selection");
    let other_selection_bytes = encode_selection(&other_selection).expect("selection bytes");
    write_private(
        &root.join("profiles").join(SELECTION_FILE_NAME),
        &other_selection_bytes,
    );

    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert_eq!(
        fs::read(root.join("profiles").join(SELECTION_FILE_NAME))
            .expect("read preserved selection"),
        other_selection_bytes
    );
    assert!(
        root.join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_preserves_intent_when_required_state_is_missing() {
    let (root, repository, original) = selected_fixture("missing-selection");
    stage_selected_replace(&root, &original, &profile("direct-replacement"));
    fs::remove_file(root.join("profiles").join(SELECTION_FILE_NAME))
        .expect("remove selection for fault fixture");

    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        root.join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_rejects_a_missing_or_third_profile_envelope() {
    let (missing_root, missing_repository, missing_original) = selected_fixture("missing-profile");
    stage_selected_replace(
        &missing_root,
        &missing_original,
        &profile("direct-replacement"),
    );
    fs::remove_file(
        missing_root
            .join("profiles")
            .join(profile_file_name(&missing_original.record.id)),
    )
    .expect("remove profile for fault fixture");
    assert!(matches!(
        missing_repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        missing_root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(missing_root).expect("remove missing-profile repository");

    let (third_root, third_repository, third_original) = selected_fixture("third-profile");
    stage_selected_replace(&third_root, &third_original, &profile("direct-replacement"));
    let third_bytes = encode_with_timestamp(
        &third_original.record.id,
        "Unexpected third state",
        &profile("direct-third"),
        third_original.source_url.as_deref(),
        third_original.record.created_epoch_secs + 2,
    )
    .expect("third envelope");
    write_private(
        &third_root
            .join("profiles")
            .join(profile_file_name(&third_original.record.id)),
        &third_bytes,
    );
    assert!(matches!(
        third_repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        third_root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(third_root).expect("remove third-profile repository");
}

#[test]
fn selected_replace_recovery_rejects_an_unreadable_profile_or_selection() {
    type EntryName = fn(&str) -> String;
    let cases: [(&str, EntryName); 2] = [
        ("replacement profile is unreadable: ", profile_file_name),
        ("selected-profile metadata is unreadable: ", |_| {
            SELECTION_FILE_NAME.to_owned()
        }),
    ];
    for (reason, entry) in cases {
        let (root, repository, original) = selected_fixture("unreadable-state");
        stage_selected_replace(&root, &original, &profile("direct-replacement"));
        write_private(
            &root.join("profiles").join(entry(&original.record.id)),
            b"{}",
        );
        let error = repository.snapshot().expect_err(reason);
        assert!(
            matches!(&error, ProfileError::SelectedReplaceConflict(message) if message.starts_with(reason)),
            "{error}"
        );
        assert!(
            root.join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists(),
            "{reason}"
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }
}
