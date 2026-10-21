#![cfg(windows)]
use cfw_windows_storage::{Error, PrivateDirectory};
use std::{fs, io::Write};

#[test]
fn handoff_pin_excludes_writes_and_replacement_until_its_handle_closes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut output = directory
        .begin_stream("candidate.msi", ".candidate.tmp", 32)
        .unwrap();
    output.write_chunk(b"signed bytes").unwrap();
    output.commit().unwrap();
    let path = root.join("candidate.msi");
    let pin = directory.open_pinned_file("candidate.msi", 32).unwrap();
    assert_eq!(
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    assert!(fs::rename(&path, root.join("replacement.msi")).is_err());
    assert!(fs::remove_file(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"signed bytes");
    drop(pin);
    fs::OpenOptions::new().write(true).open(&path).unwrap();
    fs::rename(&path, root.join("replacement.msi")).unwrap();
}

#[test]
fn installer_log_allows_append_but_retains_its_name_and_rejects_oversized_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let log = directory.open_shared_log("installer.log", 8).unwrap();
    let path = root.join("installer.log");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"failure\n")
        .unwrap();
    assert!(fs::remove_file(&path).is_err());
    drop(log);
    let _reopened = directory.open_shared_log("installer.log", 8).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"failure\n");
    assert!(matches!(
        directory.open_shared_log("installer.log", 7),
        Err(Error::TooLarge { .. })
    ));
    assert!(directory.open_shared_log("installer.log", 0).is_err());
}
