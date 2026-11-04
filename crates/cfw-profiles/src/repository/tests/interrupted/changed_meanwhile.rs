//! A selected-profile replacement interrupted while another writer, ignoring
//! the repository lock, changes the same entries: recovery reports the state
//! it cannot have produced instead of completing or reverting over it.

use super::*;

/// Reports the replacement failure together with the recovery's finding.
fn recovery_failed(operation: String, recovery: &str) -> String {
    ProfileError::SelectedReplaceRecovery {
        operation,
        recovery: recovery.to_owned(),
    }
    .to_string()
}

#[test]
fn an_intent_removed_before_an_abort_fails_closed() {
    let (root, repository, original) = selected_fixture("meanwhile-abort");
    let profile_entry = profile_file_name(&original.record.id);
    let intent = root.join("profiles").join(SELECTED_REPLACE_FILE_NAME);
    let error = replace_selected(
        &repository,
        &original,
        &profile("direct-replacement"),
        [Step::fail(Operation::Write)
            .on(&profile_entry)
            .meanwhile(move || fs::remove_file(intent).expect("remove the intent"))],
    )
    .expect_err("recovery finds no intent");
    assert_eq!(
        error.to_string(),
        recovery_failed(
            reported(Operation::Write, &profile_entry),
            "replacement intent disappeared before recovery"
        )
    );
    assert_eq!(repository.require_selected().expect("original"), original);
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn an_intent_removed_before_the_selection_rolls_forward_fails_closed() {
    let (root, repository, original) = selected_fixture("meanwhile-roll-forward");
    let replacement = profile("direct-replacement");
    let intent = root.join("profiles").join(SELECTED_REPLACE_FILE_NAME);
    let error = replace_selected(
        &repository,
        &original,
        &replacement,
        [Step::fail(Operation::Write)
            .on(SELECTION_FILE_NAME)
            .meanwhile(move || fs::remove_file(intent).expect("remove the intent"))],
    )
    .expect_err("the selection cannot roll forward");
    assert_eq!(
        error.to_string(),
        recovery_failed(
            reported(Operation::Write, SELECTION_FILE_NAME),
            "profile replacement committed but selection did not roll forward"
        )
    );
    // The selection still names the replaced digest; nothing hides that.
    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == original.record.id
    ));
    repository
        .select(&original.record.id)
        .expect("selecting the profile again repairs the selection");
    assert_eq!(
        repository.require_selected().expect("replacement").profile,
        replacement
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_replacement_reverted_before_its_cleanup_fails_closed() {
    let (root, repository, original) = selected_fixture("meanwhile-cleanup");
    let profiles = root.join("profiles");
    let profile_path = profiles.join(profile_file_name(&original.record.id));
    let selection_path = profiles.join(SELECTION_FILE_NAME);
    let original_envelope = fs::read(&profile_path).expect("read the original envelope");
    let original_selection = fs::read(&selection_path).expect("read the original selection");
    let error = replace_selected(
        &repository,
        &original,
        &profile("direct-replacement"),
        [Step::fail(Operation::Unlink)
            .on(SELECTED_REPLACE_FILE_NAME)
            .meanwhile(move || {
                write_private(&profile_path, &original_envelope);
                write_private(&selection_path, &original_selection);
            })],
    )
    .expect_err("recovery finds the original state");
    assert_eq!(
        error.to_string(),
        recovery_failed(
            reported(Operation::Unlink, SELECTED_REPLACE_FILE_NAME),
            "replacement cleanup reverted after both commits"
        )
    );
    assert_eq!(entry_names(&root), selected_entries(&original.record.id));
    assert_eq!(repository.require_selected().expect("original"), original);
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_replacement_committed_before_the_intent_was_written_fails_closed() {
    let (root, repository, original) = selected_fixture("meanwhile-unstarted");
    let other_writer = profile("direct-other-writer");
    let staged = (root.clone(), original.clone(), other_writer.clone());
    let error = replace_selected(
        &repository,
        &original,
        &profile("direct-replacement"),
        [Step::fail(Operation::Write)
            .on(SELECTED_REPLACE_FILE_NAME)
            .meanwhile(move || {
                let (root, original, other_writer) = staged;
                let (_intent, bytes) = stage_selected_replace(&root, &original, &other_writer);
                let profiles = root.join("profiles");
                write_private(
                    &profiles.join(profile_file_name(&original.record.id)),
                    &bytes,
                );
                let selection = ProfileSelection::new(&original.record.id, other_writer.digest())
                    .expect("selection of the other writer's profile");
                write_private(
                    &profiles.join(SELECTION_FILE_NAME),
                    &encode_selection(&selection).expect("selection bytes"),
                );
            })],
    )
    .expect_err("recovery finds a committed replacement");
    assert_eq!(
        error.to_string(),
        recovery_failed(
            reported(Operation::Write, SELECTED_REPLACE_FILE_NAME),
            "an unstarted replacement was unexpectedly reported committed"
        )
    );
    // The other writer's complete replacement is what remains.
    let selected = repository.require_selected().expect("selected profile");
    assert_eq!(selected.profile, other_writer);
    assert_eq!(selected.record.name, "Replacement");
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_selection_reverted_while_it_rolls_forward_fails_closed() {
    let (root, repository, original) = selected_fixture("meanwhile-selection");
    let replacement = profile("direct-replacement");
    let selection_path = root.join("profiles").join(SELECTION_FILE_NAME);
    let original_selection = fs::read(&selection_path).expect("read the original selection");
    let error = replace_selected(
        &repository,
        &original,
        &replacement,
        [
            Step::fail(Operation::Write).on(SELECTION_FILE_NAME),
            // Recovery's own selection write, reverted once it is in place.
            Step::pass(Operation::Sync)
                .on(SELECTION_FILE_NAME)
                .meanwhile(move || write_private(&selection_path, &original_selection)),
        ],
    )
    .expect_err("the roll-forward does not hold");
    assert_eq!(
        error.to_string(),
        recovery_failed(
            reported(Operation::Write, SELECTION_FILE_NAME),
            &ProfileError::SelectedReplaceConflict(
                "selection roll-forward did not produce the exact replacement state".into()
            )
            .to_string()
        )
    );
    assert!(
        root.join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists(),
        "the intent stays for the next operation"
    );
    assert_eq!(
        repository
            .require_selected()
            .expect("the next operation rolls the selection forward")
            .profile,
        replacement
    );
    assert_eq!(entry_names(&root), selected_entries(&original.record.id));
    fs::remove_dir_all(root).expect("remove test repository");
}
