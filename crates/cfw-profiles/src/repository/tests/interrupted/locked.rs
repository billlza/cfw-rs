//! Commits of a credential profile mutation interrupted under the lock it
//! holds: a selection or replacement that may not be durable is compensated
//! exactly, and a compensation that cannot run is reported with the failure.

use super::*;

/// Commits `id` as the selection of a new mutation while `steps` interrupt
/// its storage operations; every step must be reached.
fn commit_selection(
    repository: &ProfileRepository,
    id: &str,
    steps: impl IntoIterator<Item = Step>,
) -> Result<(), ProfileError> {
    let script = failpoint::script(steps);
    let outcome = repository
        .begin_credential_profile_mutation()
        .expect("mutation lock")
        .commit_selection(id)
        .map(|_| ());
    assert_eq!(script.remaining(), 0, "a scripted step was never reached");
    outcome
}

/// Replaces `expected` with a candidate, under a mutation begun on it, while
/// `steps` interrupt its storage operations; every step must be reached.
fn commit_replacement(
    repository: &ProfileRepository,
    expected: &StoredProfile,
    candidate: &ValidatedSingBoxProfile,
    steps: impl IntoIterator<Item = Step>,
) -> Result<(), ProfileError> {
    let script = failpoint::script(steps);
    let outcome = repository
        .begin_credential_profile_mutation_if_unchanged(expected)
        .expect("mutation lock")
        .commit_replace_if_unchanged(
            expected,
            Some("Candidate"),
            candidate,
            Some("https://subscription.example/candidate"),
        )
        .map(|_| ());
    assert_eq!(script.remaining(), 0, "a scripted step was never reached");
    outcome
}

/// An unselected subscription profile and its stored snapshot.
fn unselected_fixture(name: &str) -> (PathBuf, ProfileRepository, StoredProfile) {
    let (root, repository) = repository(name);
    let imported = repository
        .import_with_source(
            Some("Original"),
            &profile("direct-original"),
            Some("https://subscription.example/original"),
        )
        .expect("import original");
    let stored = repository
        .load(&imported.id)
        .expect("load original")
        .expect("stored original");
    (root, repository, stored)
}

#[test]
fn a_selection_that_may_not_be_durable_restores_the_previous_one() {
    let (root, repository) = repository("locked-selection");
    let first = repository
        .import(Some("First"), &profile("direct-first"))
        .expect("import first");
    let second = repository
        .import(Some("Second"), &profile("direct-second"))
        .expect("import second");
    repository.select(&first.id).expect("select first");
    let error = commit_selection(
        &repository,
        &second.id,
        [Step::fail(Operation::Sync).on(SELECTION_FILE_NAME)],
    )
    .expect_err("the selection may not be durable");
    assert_eq!(
        error.to_string(),
        reported(Operation::Sync, SELECTION_FILE_NAME)
    );
    assert_eq!(
        repository.require_selected().expect("selection").record.id,
        first.id
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_first_selection_that_fails_leaves_nothing_selected() {
    for operation in [Operation::Write, Operation::Sync] {
        let (root, repository) = repository("locked-first-selection");
        let imported = repository
            .import(Some("Only"), &profile("direct-only"))
            .expect("import profile");
        let error = commit_selection(
            &repository,
            &imported.id,
            [Step::fail(operation).on(SELECTION_FILE_NAME)],
        )
        .expect_err("the selection fails");
        assert_eq!(error.to_string(), reported(operation, SELECTION_FILE_NAME));
        assert_eq!(
            entry_names(&root),
            [profile_file_name(&imported.id)],
            "{operation:?}"
        );
        assert_eq!(repository.load_selected().expect("no selection"), None);
        fs::remove_dir_all(root).expect("remove test repository");
    }
}

#[test]
fn a_selection_that_cannot_be_restored_reports_both_failures() {
    let (root, repository) = repository("locked-selection-restore");
    let first = repository
        .import(Some("First"), &profile("direct-first"))
        .expect("import first");
    let second = repository
        .import(Some("Second"), &profile("direct-second"))
        .expect("import second");
    repository.select(&first.id).expect("select first");
    let error = commit_selection(
        &repository,
        &second.id,
        [
            Step::fail(Operation::Sync).on(SELECTION_FILE_NAME),
            Step::fail(Operation::Write).on(SELECTION_FILE_NAME),
        ],
    )
    .expect_err("the restore fails");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Sync, SELECTION_FILE_NAME)
                    && *recovery == reported(Operation::Write, SELECTION_FILE_NAME)
        ),
        "{error}"
    );
    // The renamed selection stays; the error says it may not be durable.
    assert_eq!(
        repository.require_selected().expect("selection").record.id,
        second.id
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_replacement_that_may_not_be_durable_is_restored_exactly() {
    let (root, repository, stored) = unselected_fixture("locked-replacement");
    let profile_entry = profile_file_name(&stored.record.id);
    let error = commit_replacement(
        &repository,
        &stored,
        &profile("direct-candidate"),
        [Step::fail(Operation::Sync).on(&profile_entry)],
    )
    .expect_err("the replacement may not be durable");
    assert_eq!(error.to_string(), reported(Operation::Sync, &profile_entry));
    assert_eq!(entry_names(&root), [profile_entry]);
    // Identity, name, source, document and creation time all come back.
    assert_eq!(
        repository.load(&stored.record.id).expect("load"),
        Some(stored)
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_replacement_that_was_never_written_needs_no_restore() {
    let (root, repository, stored) = unselected_fixture("locked-unwritten");
    let profile_entry = profile_file_name(&stored.record.id);
    let error = commit_replacement(
        &repository,
        &stored,
        &profile("direct-candidate"),
        [Step::fail(Operation::Write).on(&profile_entry)],
    )
    .expect_err("the replacement fails");
    assert_eq!(
        error.to_string(),
        reported(Operation::Write, &profile_entry)
    );
    assert_eq!(entry_names(&root), [profile_entry]);
    assert_eq!(
        repository.load(&stored.record.id).expect("load"),
        Some(stored)
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_selected_replacement_whose_abort_failed_is_compensated_under_the_lock() {
    let (root, repository, original) = selected_fixture("locked-selected-abort");
    let profile_entry = profile_file_name(&original.record.id);
    let error = commit_replacement(
        &repository,
        &original,
        &profile("direct-candidate"),
        [
            Step::fail(Operation::Write).on(&profile_entry),
            Step::fail(Operation::Unlink).on(SELECTED_REPLACE_FILE_NAME),
        ],
    )
    .expect_err("the replacement and its abort fail");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Write, &profile_entry)
                    && *recovery == reported(Operation::Unlink, SELECTED_REPLACE_FILE_NAME)
        ),
        "{error}"
    );
    // The mutation rewrote the selection and finished the abort itself.
    assert_eq!(entry_names(&root), selected_entries(&original.record.id));
    assert_eq!(repository.require_selected().expect("original"), original);
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_replacement_that_cannot_be_restored_reports_both_failures() {
    let (root, repository, stored) = unselected_fixture("locked-restore-fails");
    let profile_entry = profile_file_name(&stored.record.id);
    let candidate = profile("direct-candidate");
    let error = commit_replacement(
        &repository,
        &stored,
        &candidate,
        [
            Step::fail(Operation::Sync).on(&profile_entry),
            Step::fail(Operation::Write).on(&profile_entry),
        ],
    )
    .expect_err("the restore fails");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Sync, &profile_entry)
                    && *recovery == reported(Operation::Write, &profile_entry)
        ),
        "{error}"
    );
    assert_eq!(
        repository
            .load(&stored.record.id)
            .expect("load")
            .expect("stored candidate")
            .profile,
        candidate
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_restore_never_overwrites_a_change_made_meanwhile() {
    let (root, repository, stored) = unselected_fixture("locked-changed-meanwhile");
    let profile_entry = profile_file_name(&stored.record.id);
    let other_writer = encode_with_timestamp(
        &stored.record.id,
        "Other writer",
        &profile("direct-other-writer"),
        None,
        stored.record.created_epoch_secs + 2,
    )
    .expect("other writer's envelope");
    let path = root.join("profiles").join(&profile_entry);
    let error = commit_replacement(
        &repository,
        &stored,
        &profile("direct-candidate"),
        [Step::fail(Operation::Sync)
            .on(&profile_entry)
            .meanwhile(move || write_private(&path, &other_writer))],
    )
    .expect_err("the restore is refused");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Sync, &profile_entry)
                    && *recovery
                        == ProfileError::ProfileChanged { id: stored.record.id.clone() }.to_string()
        ),
        "{error}"
    );
    let current = repository
        .load(&stored.record.id)
        .expect("load")
        .expect("stored profile");
    assert_eq!(current.record.name, "Other writer");
    assert_eq!(current.profile, profile("direct-other-writer"));
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn a_selected_replacement_rolled_forward_then_interrupted_is_undone_under_the_lock() {
    let (root, repository, original) = selected_fixture("locked-selected-rolled-forward");
    let error = commit_replacement(
        &repository,
        &original,
        &profile("direct-candidate"),
        [
            Step::fail(Operation::Write).on(SELECTION_FILE_NAME),
            Step::fail(Operation::Unlink).on(SELECTED_REPLACE_FILE_NAME),
        ],
    )
    .expect_err("the replacement and its cleanup fail");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Write, SELECTION_FILE_NAME)
                    && *recovery == reported(Operation::Unlink, SELECTED_REPLACE_FILE_NAME)
        ),
        "{error}"
    );
    // The profile and the rolled-forward selection both went back.
    assert_eq!(entry_names(&root), selected_entries(&original.record.id));
    assert_eq!(repository.require_selected().expect("original"), original);
    fs::remove_dir_all(root).expect("remove test repository");
}
