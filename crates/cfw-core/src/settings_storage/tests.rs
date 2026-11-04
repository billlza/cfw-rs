use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::SettingsStoreError;
use crate::test_support::symlink;

const MAXIMUM: usize = 64;

/// A scratch root removed with its contents at the end of the test.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "cfw-core-storage-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("scratch root");
        Self(fs::canonicalize(root).expect("canonical root"))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        restore_modes(&self.0);
        fs::remove_dir_all(&self.0).expect("remove scratch root");
    }
}

fn restore_modes(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("metadata");
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("writable directory");
        for entry in fs::read_dir(path).expect("list") {
            restore_modes(&entry.expect("entry").path());
        }
    } else if metadata.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("readable file");
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

fn private_directory(scratch: &Scratch, name: &str) -> (PathBuf, SecureDirectory) {
    let path = scratch.path(name);
    let directory = SecureDirectory::open_or_create(&path).expect("private directory");
    (path, directory)
}

#[test]
fn only_a_private_directory_of_this_user_is_opened_as_existing() {
    let scratch = Scratch::new("existing");
    assert!(
        SecureDirectory::open_existing(&scratch.path("missing"))
            .expect("missing")
            .is_none()
    );

    let file = scratch.path("file");
    fs::write(&file, b"x").expect("file");
    assert!(matches!(
        SecureDirectory::open_existing(&file),
        Err(SettingsStoreError::UnsafeDirectory)
    ));
    assert!(matches!(
        SecureDirectory::open_existing(&file.join("below")),
        Err(SettingsStoreError::Io(_))
    ));

    let (shared, _) = private_directory(&scratch, "shared");
    set_mode(&shared, 0o755);
    assert!(matches!(
        SecureDirectory::open_existing(&shared),
        Err(SettingsStoreError::UnsafeDirectory)
    ));

    let (private, _) = private_directory(&scratch, "private");
    let linked = scratch.path("linked");
    symlink(&private, &linked).expect("directory link");
    assert!(matches!(
        SecureDirectory::open_existing(&linked),
        Err(SettingsStoreError::UnsafeDirectory)
    ));
    assert!(
        SecureDirectory::open_existing(&private)
            .expect("private")
            .is_some()
    );
}

#[test]
fn creation_makes_a_directory_private_and_refuses_anything_else() {
    let scratch = Scratch::new("create");
    let (created, _) = private_directory(&scratch, "nested/app");
    assert_eq!(
        fs::metadata(&created)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let shared = scratch.path("shared");
    fs::create_dir(&shared).expect("shared directory");
    set_mode(&shared, 0o755);
    SecureDirectory::open_or_create(&shared).expect("narrowed");
    assert_eq!(
        fs::metadata(&shared)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let file = scratch.path("file");
    fs::write(&file, b"x").expect("file");
    assert!(matches!(
        SecureDirectory::open_or_create(&file),
        Err(SettingsStoreError::UnsafeDirectory)
    ));
    assert!(matches!(
        SecureDirectory::open_or_create(&file.join("below")),
        Err(SettingsStoreError::Io(_))
    ));
    let linked = scratch.path("linked");
    symlink(&created, &linked).expect("directory link");
    assert!(matches!(
        SecureDirectory::open_or_create(&linked),
        Err(SettingsStoreError::UnsafeDirectory)
    ));
}

#[test]
fn a_name_is_one_plain_component() {
    let scratch = Scratch::new("names");
    let (_, directory) = private_directory(&scratch, "app");
    for name in ["nested/settings.json", ".", "..", "settings\0.json"] {
        assert!(
            matches!(
                directory.write_atomic(name, b"{}", MAXIMUM),
                Err(SettingsStoreError::InvalidPath)
            ),
            "{name:?}"
        );
    }
}

#[test]
fn oversized_contents_are_refused_before_writing() {
    let scratch = Scratch::new("oversized");
    let (path, directory) = private_directory(&scratch, "app");
    assert!(matches!(
        directory.write_atomic("settings.json", &[b'x'; MAXIMUM + 1], MAXIMUM),
        Err(SettingsStoreError::TooLarge { actual, maximum })
            if actual == MAXIMUM as u64 + 1 && maximum == MAXIMUM
    ));
    assert!(!path.join("settings.json").exists());
}

#[test]
fn a_leftover_temporary_is_replaced_and_the_write_completes() {
    let scratch = Scratch::new("leftover");
    let (path, directory) = private_directory(&scratch, "app");
    let leftover = path.join(".settings.json.tmp");
    fs::write(&leftover, b"interrupted").expect("leftover");
    set_mode(&leftover, 0o600);

    directory
        .write_atomic("settings.json", b"{\"ok\":true}", MAXIMUM)
        .expect("write");
    assert_eq!(
        fs::read(path.join("settings.json")).expect("read"),
        b"{\"ok\":true}"
    );
    assert!(!leftover.exists());
}

#[test]
fn files_are_read_only_under_their_policy() {
    let scratch = Scratch::new("policy");
    let (path, directory) = private_directory(&scratch, "app");
    let file = path.join("settings.json");
    fs::write(&file, b"{}").expect("file");

    set_mode(&file, 0o644);
    assert!(matches!(
        directory.read_optional("settings.json", MAXIMUM, FilePolicy::Private),
        Err(SettingsStoreError::UnsafeFile)
    ));
    directory
        .read_optional("settings.json", MAXIMUM, FilePolicy::LegacyReadOnly)
        .expect("a legacy file may be readable by others")
        .expect("present");
    set_mode(&file, 0o664);
    assert!(matches!(
        directory.read_optional("settings.json", MAXIMUM, FilePolicy::LegacyReadOnly),
        Err(SettingsStoreError::UnsafeFile)
    ));

    set_mode(&file, 0o000);
    assert!(matches!(
        directory.read_optional("settings.json", MAXIMUM, FilePolicy::Private),
        Err(SettingsStoreError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
}

#[test]
fn a_read_only_directory_refuses_writes_and_removals() {
    let scratch = Scratch::new("read-only");
    let (path, directory) = private_directory(&scratch, "app");
    directory
        .write_atomic("settings.json", b"{}", MAXIMUM)
        .expect("write");
    let stored = directory
        .read_optional("settings.json", MAXIMUM, FilePolicy::Private)
        .expect("read")
        .expect("present");

    set_mode(&path, 0o500);
    assert!(matches!(
        directory.write_atomic("other.json", b"{}", MAXIMUM),
        Err(SettingsStoreError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(matches!(
        directory.remove_matching("settings.json", &stored.identity, MAXIMUM, FilePolicy::Private),
        Err(SettingsStoreError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
}

#[test]
fn removal_requires_the_file_it_was_given() {
    let scratch = Scratch::new("remove");
    let (_, directory) = private_directory(&scratch, "app");
    directory
        .write_atomic("settings.json", b"{\"a\":1}", MAXIMUM)
        .expect("write");
    let first = directory
        .read_optional("settings.json", MAXIMUM, FilePolicy::Private)
        .expect("read")
        .expect("present")
        .identity;
    directory
        .write_atomic("settings.json", b"{\"a\":2}", MAXIMUM)
        .expect("rewrite");
    assert!(matches!(
        directory.remove_matching("settings.json", &first, MAXIMUM, FilePolicy::Private),
        Err(SettingsStoreError::LegacySourceChanged)
    ));
    assert!(matches!(
        directory.remove_matching("absent.json", &first, MAXIMUM, FilePolicy::Private),
        Err(SettingsStoreError::LegacySourceChanged)
    ));
}
