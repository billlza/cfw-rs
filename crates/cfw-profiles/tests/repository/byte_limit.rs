//! The 256 MiB limit on everything a repository stores, checked on entry
//! lengths before any entry is read. The oversized entries are sparse files,
//! which APFS keeps without using the space.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cfw_profiles::ProfileError;
use uuid::Uuid;

use crate::support::{create_private_directory, profile, repository, selection_path, stored_path};

/// Mirrors the crate's limit on the bytes of all stored entries.
const MAX_REPOSITORY_BYTES: u64 = 256 * 1024 * 1024;

/// A private file of `length` bytes that holds no data.
fn sparse_private_file(path: &Path, length: u64) {
    let file = fs::File::create(path).expect("create sparse file");
    file.set_len(length).expect("extend sparse file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set private mode");
}

#[test]
fn an_entry_beyond_the_repository_limit_is_refused_before_it_is_read() {
    for length in [MAX_REPOSITORY_BYTES, MAX_REPOSITORY_BYTES + 1] {
        let (root, repository) = repository("byte-limit-entry");
        create_private_directory(&root.join("profiles"));
        let id = Uuid::new_v4().hyphenated().to_string();
        sparse_private_file(&stored_path(&root, &id), length);
        let error = repository.snapshot().expect_err("oversized repository");
        if length > MAX_REPOSITORY_BYTES {
            assert!(
                matches!(error, ProfileError::RepositoryTooLarge { actual } if actual == length),
                "{error}"
            );
        } else {
            // At the limit the repository is read, and the entry refused.
            assert!(
                matches!(error, ProfileError::StoredProfileTooLarge { actual } if actual == length),
                "{error}"
            );
        }
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn selection_metadata_counts_toward_the_repository_limit() {
    for overflow in [0, 1] {
        let (root, repository) = repository("byte-limit-selection");
        let imported = repository.import(None, &profile()).expect("import profile");
        let envelope = fs::metadata(stored_path(&root, &imported.id))
            .expect("envelope metadata")
            .len();
        let length = MAX_REPOSITORY_BYTES - envelope + overflow;
        sparse_private_file(&selection_path(&root), length);
        let error = repository.snapshot().expect_err("oversized selection");
        if overflow > 0 {
            assert!(
                matches!(error, ProfileError::RepositoryTooLarge { actual } if actual == MAX_REPOSITORY_BYTES + 1),
                "{error}"
            );
        } else {
            assert!(
                matches!(error, ProfileError::SelectionTooLarge { actual } if actual == length),
                "{error}"
            );
        }
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
