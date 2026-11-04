//! A repository path that is not an accessible private directory is refused,
//! never read as an empty repository, and whatever is there is kept.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

use cfw_profiles::ProfileError;

use crate::support::{profile, repository};

#[test]
fn a_file_at_the_repository_path_is_refused_and_kept() {
    let (root, repository) = repository("file-repository");
    fs::create_dir_all(&root).expect("create test directory");
    fs::write(root.join("profiles"), b"preserved file").expect("write file");
    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::UnsafeRepositoryDirectory)
    ));
    assert!(matches!(
        repository.import(None, &profile()),
        Err(ProfileError::UnsafeRepositoryDirectory)
    ));
    assert_eq!(
        fs::read(root.join("profiles")).expect("file kept"),
        b"preserved file"
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_repository_below_a_file_cannot_be_created() {
    let (root, repository) = repository("file-ancestor");
    fs::write(&root, b"preserved ancestor").expect("write ancestor");
    assert!(matches!(
        repository.import(None, &profile()),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotADirectory
    ));
    assert_eq!(
        fs::read(&root).expect("ancestor kept"),
        b"preserved ancestor"
    );
    fs::remove_file(root).expect("remove test file");
}

#[test]
fn an_unreadable_repository_directory_is_an_error_not_an_empty_repository() {
    let (root, repository) = repository("unreadable-directory");
    let profiles = root.join("profiles");
    fs::create_dir_all(&profiles).expect("create profiles directory");
    fs::set_permissions(&profiles, fs::Permissions::from_mode(0o000)).expect("remove access");
    let snapshot = repository.snapshot();
    fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700)).expect("restore access");
    assert!(matches!(
        snapshot,
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}
