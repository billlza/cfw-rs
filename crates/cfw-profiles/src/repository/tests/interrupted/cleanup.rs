//! The one-way cleanup of the managed profiles directory interrupted by a
//! failed unlink: it stops, and reports how many entries it already removed.

use super::*;

/// Clears two stored profiles while `steps` interrupt the unlinks; every
/// step must be reached. Returns the error and the entries left.
fn interrupted_cleanup(name: &str, steps: impl IntoIterator<Item = Step>) -> (ProfileError, usize) {
    let (root, repository) = repository(name);
    for tag in ["direct-first", "direct-second"] {
        repository
            .import(Some(tag), &profile(tag))
            .expect("import profile");
    }
    let script = failpoint::script(steps);
    let error = repository
        .clear_managed_profiles()
        .expect_err("the cleanup is interrupted");
    assert_eq!(script.remaining(), 0, "a scripted step was never reached");
    drop(script);
    let left = entry_names(&root).len();
    fs::remove_dir_all(root).expect("remove test repository");
    (error, left)
}

#[test]
fn a_cleanup_that_removed_nothing_reports_the_failure_itself() {
    let (error, left) = interrupted_cleanup("cleanup-first", [Step::fail(Operation::Unlink)]);
    assert!(
        matches!(&error, ProfileError::Io(source) if source.to_string().starts_with("injected Unlink failure of ")),
        "{error}"
    );
    assert_eq!(left, 2);
}

#[test]
fn a_cleanup_interrupted_midway_reports_what_it_removed() {
    let (error, left) = interrupted_cleanup(
        "cleanup-midway",
        [Step::pass(Operation::Unlink), Step::fail(Operation::Unlink)],
    );
    assert!(
        matches!(
            &error,
            ProfileError::PartialManagedCleanup { removed: 1, operation }
                if operation.starts_with("profile repository I/O failed: injected Unlink failure of ")
        ),
        "{error}"
    );
    assert_eq!(left, 1);
}

#[test]
fn a_cleanup_whose_removals_may_not_be_durable_says_so() {
    let (root, repository) = repository("cleanup-sync");
    repository
        .import(Some("Only"), &profile("direct-only"))
        .expect("import profile");
    let script = failpoint::script([Step::fail(Operation::Sync).on("managed profile cleanup")]);
    let error = repository
        .clear_managed_profiles()
        .expect_err("the cleanup may not be durable");
    assert_eq!(script.remaining(), 0, "a scripted step was never reached");
    drop(script);
    assert_eq!(
        error.to_string(),
        reported(Operation::Sync, "managed profile cleanup")
    );
    assert!(entry_names(&root).is_empty(), "the entries are unlinked");
    fs::remove_dir_all(root).expect("remove test repository");
}
