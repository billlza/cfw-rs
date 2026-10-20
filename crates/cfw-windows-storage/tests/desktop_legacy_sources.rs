#![cfg(windows)]

#[path = "../../../apps/cfw-tauri-shell/src/commands/legacy_profiles/source.rs"]
mod source;

use cfw_windows_storage::{
    Error, LegacyReadDirectory, LegacyReadError, PrivateDirectory, ReadPolicy,
};
use source::{
    open_directory_at, open_owned_directory, read_legacy_entry, read_optional_legacy_entry,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    PrivateDirectory::open_or_create(&root).unwrap();
    let profiles = root.join("profiles");
    let directory = PrivateDirectory::open_or_create(&profiles).unwrap();
    directory
        .write()
        .unwrap()
        .replace("active.json", b"original", 1024)
        .unwrap();
    (temporary, root, profiles)
}

fn entries(path: &Path) -> std::collections::BTreeSet<std::ffi::OsString> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

#[test]
fn migration_reads_existing_objects_without_creating_or_modifying_entries() {
    let (_temporary, root, profiles) = fixture();
    let root_entries = entries(&root);
    let profile_entries = entries(&profiles);
    let root_reader = open_owned_directory(&root, true).unwrap();
    let reader = open_directory_at(&root_reader, "profiles").unwrap();
    assert_eq!(
        read_legacy_entry(&reader, "active.json", 8).unwrap(),
        b"original"
    );
    assert_eq!(
        read_optional_legacy_entry(&reader, "missing.yaml", 8).unwrap(),
        None
    );
    assert!(read_legacy_entry(&reader, "missing.yaml", 8).is_err());
    assert!(read_legacy_entry(&reader, "active.json", 7).is_err());
    assert!(open_directory_at(&root_reader, "missing").is_err());
    assert_eq!(entries(&root), root_entries);
    assert_eq!(entries(&profiles), profile_entries);
    assert_eq!(fs::read(profiles.join("active.json")).unwrap(), b"original");
}

#[test]
fn missing_source_root_is_an_error_and_is_not_created() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("missing");
    assert!(open_owned_directory(&missing, true).is_err());
    assert!(!missing.exists());
}

#[test]
fn renamed_source_directory_does_not_redirect_reads_to_its_replacement() {
    let (_temporary, root, profiles) = fixture();
    let root_reader = open_owned_directory(&root, true).unwrap();
    let reader = open_directory_at(&root_reader, "profiles").unwrap();
    fs::rename(&profiles, root.join("retained")).unwrap();
    let replacement = PrivateDirectory::open_or_create(&profiles).unwrap();
    replacement
        .write()
        .unwrap()
        .replace("active.json", b"replacement", 1024)
        .unwrap();
    assert_eq!(
        read_legacy_entry(&reader, "active.json", 16).unwrap(),
        b"original"
    );
    let reopened = open_directory_at(&root_reader, "profiles").unwrap();
    assert_eq!(
        read_legacy_entry(&reopened, "active.json", 16).unwrap(),
        b"replacement"
    );
}

#[test]
fn redirected_directories_linked_files_and_escaping_names_are_rejected() {
    let (_temporary, root, profiles) = fixture();
    let root_reader = open_owned_directory(&root, true).unwrap();
    let reader = open_directory_at(&root_reader, "profiles").unwrap();
    std::os::windows::fs::symlink_dir(&profiles, root.join("redirect")).unwrap();
    assert!(open_directory_at(&root_reader, "redirect").is_err());
    assert!(open_owned_directory(&root.join("redirect"), false).is_err());
    std::os::windows::fs::symlink_file(
        profiles.join("active.json"),
        profiles.join("redirect.json"),
    )
    .unwrap();
    assert!(read_legacy_entry(&reader, "redirect.json", 16).is_err());
    fs::hard_link(profiles.join("active.json"), profiles.join("linked.json")).unwrap();
    assert!(read_legacy_entry(&reader, "active.json", 16).is_err());
    assert!(read_legacy_entry(&reader, "linked.json", 16).is_err());
    for name in ["../active.json", r"..\active.json", "active.json:other"] {
        assert!(read_optional_legacy_entry(&reader, name, 16).is_err());
    }
    assert_eq!(fs::read(profiles.join("active.json")).unwrap(), b"original");
}

#[test]
fn an_existing_writer_is_not_misreported_as_an_absent_or_stable_source() {
    let (_temporary, _root, profiles) = fixture();
    let reader = LegacyReadDirectory::open_existing(&profiles, ReadPolicy::LegacyReadOnly).unwrap();
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(profiles.join("active.json"))
        .unwrap();
    assert!(
        matches!(reader.read("active.json", 16), Err(LegacyReadError::Storage(Error::Io(error)))
        if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32))
    );
    drop(writer);
    assert_eq!(
        reader.read("active.json", 16).unwrap().unwrap(),
        b"original"
    );
}

fn grant(path: &Path, rights: &str) {
    let result = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/grant:r", rights])
        .output()
        .unwrap();
    assert!(result.status.success(), "legacy source ACL fixture failed");
}

#[test]
fn legacy_read_grants_are_accepted_and_new_foreign_write_grants_revoke_the_handle() {
    let (_temporary, root, profiles) = fixture();
    grant(&profiles, "*S-1-1-0:(RX)");
    grant(&profiles.join("active.json"), "*S-1-1-0:(R)");
    assert!(open_owned_directory(&profiles, true).is_err());
    let root_reader = open_owned_directory(&root, true).unwrap();
    let reader = open_directory_at(&root_reader, "profiles").unwrap();
    assert_eq!(
        read_legacy_entry(&reader, "active.json", 16).unwrap(),
        b"original"
    );
    grant(&profiles.join("active.json"), "*S-1-1-0:(W)");
    assert!(read_legacy_entry(&reader, "active.json", 16).is_err());
    grant(&profiles, "*S-1-1-0:(W)");
    assert!(open_directory_at(&root_reader, "profiles").is_err());
    assert!(read_optional_legacy_entry(&reader, "missing.yaml", 16).is_err());
    assert_eq!(fs::read(profiles.join("active.json")).unwrap(), b"original");
}
