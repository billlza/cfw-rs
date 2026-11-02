//! A selected-profile replacement interrupted at each storage step: before the
//! replacement profile is durable it aborts and reports the failure; once it
//! is, the selection rolls forward and the replacement succeeds.

use super::*;

#[test]
fn an_interruption_before_the_profile_commit_keeps_the_original() {
    type EntryName = fn(&str) -> String;
    let cases: [(Operation, EntryName); 3] = [
        (Operation::Write, |_| SELECTED_REPLACE_FILE_NAME.to_owned()),
        (Operation::Sync, |_| SELECTED_REPLACE_FILE_NAME.to_owned()),
        (Operation::Write, profile_file_name),
    ];
    for (operation, entry) in cases {
        let (root, repository, original) = selected_fixture("interrupted-before-commit");
        let entry = entry(&original.record.id);
        let error = replace_selected(
            &repository,
            &original,
            &profile("direct-replacement"),
            [Step::fail(operation).on(&entry)],
        )
        .expect_err("the replacement aborts");
        assert_eq!(error.to_string(), reported(operation, &entry));
        // Checked before any other call, whose recovery would hide leftovers.
        assert_eq!(
            entry_names(&root),
            selected_entries(&original.record.id),
            "{operation:?} {entry}"
        );
        assert_eq!(
            repository.require_selected().expect("selected profile"),
            original,
            "{operation:?} {entry}"
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }
}

#[test]
fn an_interruption_after_the_profile_commit_completes_the_replacement() {
    type Steps = fn(&str) -> Vec<Step>;
    let cases: [(&str, Steps); 5] = [
        ("profile sync", |id| {
            vec![Step::fail(Operation::Sync).on(&profile_file_name(id))]
        }),
        ("selection write", |_| {
            vec![Step::fail(Operation::Write).on(SELECTION_FILE_NAME)]
        }),
        ("selection sync", |_| {
            vec![Step::fail(Operation::Sync).on(SELECTION_FILE_NAME)]
        }),
        ("intent unlink", |_| {
            vec![Step::fail(Operation::Unlink).on(SELECTED_REPLACE_FILE_NAME)]
        }),
        ("intent unlink sync", |_| {
            vec![
                // The intent's own write is synced first.
                Step::pass(Operation::Sync).on(SELECTED_REPLACE_FILE_NAME),
                Step::fail(Operation::Sync).on(SELECTED_REPLACE_FILE_NAME),
            ]
        }),
    ];
    for (case, steps) in cases {
        let (root, repository, original) = selected_fixture("interrupted-after-commit");
        let replacement = profile("direct-replacement");
        let result = replace_selected(
            &repository,
            &original,
            &replacement,
            steps(&original.record.id),
        )
        .unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(result.id, original.record.id, "{case}");
        assert_eq!(result.digest, replacement.digest(), "{case}");
        assert_eq!(
            entry_names(&root),
            selected_entries(&original.record.id),
            "{case}"
        );
        let selected = repository.require_selected().expect("selected profile");
        assert_eq!(selected.profile, replacement, "{case}");
        assert_eq!(selected.record.name, original.record.name, "{case}");
        fs::remove_dir_all(root).expect("remove test repository");
    }
}

#[test]
fn a_failed_abort_leaves_the_intent_for_the_next_operation() {
    let (root, repository, original) = selected_fixture("interrupted-abort");
    let profile_entry = profile_file_name(&original.record.id);
    let error = replace_selected(
        &repository,
        &original,
        &profile("direct-replacement"),
        [
            Step::fail(Operation::Write).on(&profile_entry),
            Step::fail(Operation::Unlink).on(SELECTED_REPLACE_FILE_NAME),
        ],
    )
    .expect_err("the abort fails");
    assert!(
        matches!(
            &error,
            ProfileError::SelectedReplaceRecovery { operation, recovery }
                if *operation == reported(Operation::Write, &profile_entry)
                    && *recovery == reported(Operation::Unlink, SELECTED_REPLACE_FILE_NAME)
        ),
        "{error}"
    );
    let mut with_intent = selected_entries(&original.record.id);
    with_intent.push(SELECTED_REPLACE_FILE_NAME.to_owned());
    with_intent.sort_unstable();
    assert_eq!(entry_names(&root), with_intent);

    assert_eq!(
        repository.require_selected().expect("the abort completes"),
        original
    );
    assert_eq!(entry_names(&root), selected_entries(&original.record.id));
    fs::remove_dir_all(root).expect("remove test repository");
}
