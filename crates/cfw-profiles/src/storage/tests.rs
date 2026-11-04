#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "macos")]
use uuid::Uuid;

use crate::ProfileError;
use crate::storage::{
    MAX_ABANDONED_TEMPORARIES, ensure_entry_capacity, is_owned_temporary_name,
    remaining_directory_entry_capacity,
};
#[cfg(target_os = "macos")]
use crate::storage::{
    RepositoryDirectory, effective_user_id, relative_c_string, repository_directory_is_safe,
};
use crate::storage_atomic::{committed_sync_result, error_after_cleanup};

#[cfg(target_os = "macos")]
fn test_directory(name: &str) -> (std::path::PathBuf, RepositoryDirectory) {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-storage-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let path = root.join("profiles");
    fs::create_dir_all(&path).expect("create profiles directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("set directory mode");
    let directory = RepositoryDirectory::open(&path).expect("open profiles directory");
    (root, directory)
}

#[test]
#[cfg(target_os = "macos")]
fn repository_directory_requires_effective_user_ownership() {
    let (root, directory) = test_directory("owner");
    let metadata = directory.file.metadata().expect("directory metadata");
    let effective_uid = effective_user_id();
    assert!(repository_directory_is_safe(&metadata, effective_uid));
    assert!(!repository_directory_is_safe(
        &metadata,
        effective_uid.wrapping_add(1)
    ));
    drop(directory);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
#[cfg(target_os = "macos")]
fn fchmod_failure_unlinks_the_new_temporary_entry() {
    let (root, directory) = test_directory("chmod-cleanup");
    let name = ".injected-chmod-failure.tmp";
    let error = directory
        .create_exclusive_with_mode_setter(name, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected fchmod failure",
            ))
        })
        .expect_err("injected fchmod failure must be reported");
    assert!(error.to_string().contains("injected fchmod failure"));
    assert!(!root.join("profiles").join(name).exists());
    drop(directory);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn cleanup_failure_preserves_both_errors() {
    let error = error_after_cleanup(
        ProfileError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "primary fchmod failure",
        )),
        Err(ProfileError::Io(io::Error::new(
            io::ErrorKind::ReadOnlyFilesystem,
            "temporary unlink failure",
        ))),
    );
    let message = error.to_string();
    assert!(message.contains("primary fchmod failure"));
    assert!(message.contains("temporary unlink failure"));
}

#[test]
fn post_rename_sync_failure_is_typed_as_commit_uncertain() {
    let error = committed_sync_result(
        "selected-profile-v1.json",
        Err(io::Error::new(
            io::ErrorKind::ReadOnlyFilesystem,
            "injected directory sync failure",
        )),
    )
    .expect_err("post-rename durability failure");
    assert!(matches!(
        error,
        ProfileError::CommitUncertain { entry, source }
            if entry == "selected-profile-v1.json"
                && source.kind() == io::ErrorKind::ReadOnlyFilesystem
    ));
}

#[test]
fn only_exact_canonical_repository_temporary_names_are_owned() {
    assert!(is_owned_temporary_name(std::ffi::OsStr::new(
        ".34db18b6-9903-4e9f-8854-15648e19e4f3.tmp"
    )));
    for name in [
        ".34DB18B6-9903-4E9F-8854-15648E19E4F3.tmp",
        ".34db18b699034e9f885415648e19e4f3.tmp",
        ".34db18b6-9903-4e9f-8854-15648e19e4f3.tmp.more",
        "34db18b6-9903-4e9f-8854-15648e19e4f3.tmp",
        ".not-a-uuid.tmp",
    ] {
        assert!(!is_owned_temporary_name(std::ffi::OsStr::new(name)));
    }
}

#[test]
fn repository_capacity_allows_reads_at_the_limit_but_rejects_another_write() {
    ensure_entry_capacity(crate::MAX_REPOSITORY_ENTRIES - 1).expect("last admitted entry");
    assert!(matches!(
        ensure_entry_capacity(crate::MAX_REPOSITORY_ENTRIES),
        Err(ProfileError::TooManyEntries)
    ));
}

#[test]
fn directory_enumeration_reserves_bounded_crash_recovery_capacity() {
    remaining_directory_entry_capacity(
        crate::MAX_REPOSITORY_ENTRIES + MAX_ABANDONED_TEMPORARIES + 1,
    )
    .expect("profiles, selection, transaction intent, and final recovery entry fit");
    assert!(matches!(
        remaining_directory_entry_capacity(
            crate::MAX_REPOSITORY_ENTRIES + MAX_ABANDONED_TEMPORARIES + 2
        ),
        Err(ProfileError::TooManyEntries)
    ));
}

#[test]
#[cfg(target_os = "macos")]
fn entry_names_never_leave_the_repository_directory() {
    for name in ["a/b", "/absolute", ".", ".."] {
        assert!(matches!(
            relative_c_string(OsStr::new(name)),
            Err(ProfileError::UnexpectedEntry(entry)) if entry == name
        ));
    }
    assert!(matches!(
        relative_c_string(OsStr::new("nul\0byte")),
        Err(ProfileError::UnexpectedEntry(entry)) if entry == "NUL byte"
    ));
    relative_c_string(OsStr::new("selected-profile-v1.json")).expect("plain entry name");
}

#[test]
#[cfg(target_os = "macos")]
fn a_temporary_name_that_is_not_utf8_is_never_owned() {
    assert!(!is_owned_temporary_name(OsStr::from_bytes(
        b".34db18b6-9903-4e9f-8854-15648e19e4f\xff.tmp"
    )));
}

#[test]
#[cfg(target_os = "macos")]
fn single_entry_operations_report_what_they_could_not_do() {
    let (root, directory) = test_directory("entry-operations");
    let entry = root.join("profiles").join("entry");
    fs::write(&entry, b"kept").expect("write entry");
    assert!(matches!(
        directory.write_new_atomic("entry", b"replacement"),
        Err(ProfileError::AlreadyExists(name)) if name == "entry"
    ));
    assert_eq!(fs::read(&entry).expect("read entry"), b"kept");
    assert!(matches!(
        directory.unlink("missing"),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
    assert!(matches!(
        directory.entry_exists("a/b"),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    assert!(matches!(
        directory.open_selected_replace_file(),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
    drop(directory);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
#[cfg(target_os = "macos")]
fn a_new_entry_already_gone_at_cleanup_is_not_a_second_failure() {
    let (root, directory) = test_directory("vanished-entry");
    let name = ".injected-vanished.tmp";
    let path = root.join("profiles").join(name);
    let error = directory
        .create_exclusive_with_mode_setter(name, |_| {
            fs::remove_file(&path).expect("remove the new entry");
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected fchmod failure",
            ))
        })
        .expect_err("injected fchmod failure must be reported");
    assert!(
        matches!(&error, ProfileError::Io(source) if source.to_string() == "injected fchmod failure"),
        "{error}"
    );
    drop(directory);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
#[cfg(target_os = "macos")]
fn a_panic_before_the_mode_is_set_removes_the_new_entry() {
    let (root, directory) = test_directory("panic-cleanup");
    let name = ".injected-panic.tmp";
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        directory.create_exclusive_with_mode_setter(name, |_| panic!("injected mode setter panic"))
    }));
    assert!(outcome.is_err(), "the panic propagates");
    assert!(!root.join("profiles").join(name).exists());
    drop(directory);
    fs::remove_dir_all(root).expect("remove test directory");
}
