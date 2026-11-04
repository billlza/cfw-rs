//! Storage failures injected into real repository operations: every step of
//! a change that spans several entries is interrupted, and so is the recovery
//! that follows, including against changes another writer makes meanwhile.

use crate::ProfileImportResult;
use crate::storage::failpoint::{self, Operation, Step};

use super::*;

mod changed_meanwhile;
mod cleanup;
mod locked;
mod replace;

/// Entry names of the repository directory, sorted.
fn entry_names(root: &Path) -> Vec<String> {
    let mut names = fs::read_dir(root.join("profiles"))
        .expect("read repository directory")
        .map(|entry| {
            entry
                .expect("repository entry")
                .file_name()
                .into_string()
                .expect("UTF-8 entry name")
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

/// The entries of a repository that holds one selected profile and nothing
/// else: no intent and no temporary.
fn selected_entries(id: &str) -> Vec<String> {
    let mut names = vec![profile_file_name(id), SELECTION_FILE_NAME.to_owned()];
    names.sort_unstable();
    names
}

/// How the repository reports the failure a step injects into `operation` on
/// `entry`: a failed directory sync leaves the commit uncertain.
fn reported(operation: Operation, entry: &str) -> String {
    let source = std::io::Error::other(failpoint::injected(operation, entry));
    match operation {
        Operation::Sync => ProfileError::CommitUncertain {
            entry: entry.to_owned(),
            source,
        },
        Operation::Write | Operation::Unlink => ProfileError::Io(source),
    }
    .to_string()
}

/// Replaces the selected `original` with `replacement` while `steps`
/// interrupt its storage operations; every step must be reached.
fn replace_selected(
    repository: &ProfileRepository,
    original: &StoredProfile,
    replacement: &ValidatedSingBoxProfile,
    steps: impl IntoIterator<Item = Step>,
) -> Result<ProfileImportResult, ProfileError> {
    let script = failpoint::script(steps);
    let outcome = repository.replace(&original.record.id, None, replacement, None);
    assert_eq!(script.remaining(), 0, "a scripted step was never reached");
    outcome
}
