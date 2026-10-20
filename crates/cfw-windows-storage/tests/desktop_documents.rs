#![cfg(windows)]

// Exercise the application's adapter against real Windows files and locks.
#[path = "../../../apps/cfw-tauri-shell/src/private_store.rs"]
mod desktop_documents;

use desktop_documents::{
    AtomicWriteError, LockFileError, PrivateDirectory, PrivateDocument, PrivateReadError,
};
use std::{fs, fs::File, io, time::Duration};

const DOCUMENT: PrivateDocument = PrivateDocument {
    subject: "desktop test journal",
    file: "journal.json",
    temporary: ".journal.tmp",
    maximum_bytes: 1024,
};

#[test]
fn retained_document_transaction_blocks_other_readers_and_commits_on_the_original_handle() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let owner = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    assert_eq!(owner.read().unwrap(), None);
    owner.lock().unwrap();
    owner.lock().unwrap();
    owner
        .write_atomic_with_directory_sync(b"original", File::sync_all)
        .unwrap();
    let other = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    assert!(matches!(other.read(), Err(PrivateReadError::Failed(message)) if !message.is_empty()));
    assert_eq!(owner.read().unwrap().unwrap(), b"original");
    drop(owner);
    other
        .write_atomic_with_directory_sync(b"replacement", File::sync_all)
        .unwrap();
    assert_eq!(other.read().unwrap().unwrap(), b"replacement");
}

#[test]
fn post_rename_flush_failure_remains_uncertain_and_the_committed_document_can_be_inspected() {
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        PrivateDirectory::open_or_create(&temporary.path().join("private"), DOCUMENT).unwrap();
    directory.lock().unwrap();
    directory
        .write_atomic_with_directory_sync(b"old", File::sync_all)
        .unwrap();
    // Real native content write/flush/rename, followed by a deliberately failed
    // directory-flush policy. This checks error semantics, not power-loss proof.
    let failure = directory.write_atomic_with_directory_sync(b"new", |_| {
        Err(io::Error::other("injected directory flush failure"))
    });
    assert!(
        matches!(failure, Err(AtomicWriteError::CommitUncertain(message)) if message.contains("after publication"))
    );
    assert_eq!(directory.read().unwrap().unwrap(), b"new");
    directory.remove().unwrap();
    directory.remove().unwrap();
    assert_eq!(directory.read().unwrap(), None);
}

#[test]
fn unsafe_stale_temporary_is_preserved_without_changing_the_previous_document() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    directory
        .write_atomic_with_directory_sync(b"old", File::sync_all)
        .unwrap();
    let native = cfw_windows_storage::PrivateDirectory::open_or_create(&path).unwrap();
    {
        let mut transaction = native.write().unwrap();
        transaction
            .replace("unrelated.json", b"preserve", 1024)
            .unwrap();
    }
    fs::hard_link(path.join("unrelated.json"), path.join(DOCUMENT.temporary)).unwrap();
    let failure = directory.write_atomic_with_directory_sync(b"new", File::sync_all);
    assert!(matches!(failure, Err(AtomicWriteError::Failed(message)) if !message.is_empty()));
    assert_eq!(directory.read().unwrap().unwrap(), b"old");
    assert_eq!(fs::read(path.join("unrelated.json")).unwrap(), b"preserve");
    assert_eq!(
        fs::read(path.join(DOCUMENT.temporary)).unwrap(),
        b"preserve"
    );
}

#[test]
fn explicit_discard_removes_only_the_unusable_document_entry() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    directory
        .write_atomic_with_directory_sync(b"preserve linked bytes", File::sync_all)
        .unwrap();
    let retained = path.join("retained.json");
    fs::hard_link(path.join(DOCUMENT.file), &retained).unwrap();
    assert!(matches!(
        directory.read(),
        Err(PrivateReadError::Unusable(_))
    ));
    directory.remove().unwrap();
    assert_eq!(directory.read().unwrap(), None);
    assert_eq!(fs::read(retained).unwrap(), b"preserve linked bytes");
}

#[test]
fn process_lease_refuses_contention_and_replacement_until_its_original_handle_closes() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let first = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    let lease = first.acquire_lock_file("installer.lock").unwrap();
    drop(first);
    let second = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        second.acquire_lock_file("installer.lock"),
        Err(LockFileError::Busy)
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "lease admission queued behind its owner"
    );
    assert!(fs::remove_file(path.join("installer.lock")).is_err());
    drop(lease);
    let _next = second.acquire_lock_file("installer.lock").unwrap();
    // The independent lease never replaces the document transaction lock.
    second.lock().unwrap();
    second
        .write_atomic_with_directory_sync(b"journal", File::sync_all)
        .unwrap();
}

#[test]
fn malformed_lease_and_empty_document_remain_explicit_errors() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path, DOCUMENT).unwrap();
    match directory.acquire_lock_file("../outside.lock") {
        Err(LockFileError::Lock(error)) => assert!(!error.to_string().is_empty()),
        other => panic!("invalid lease name was not rejected: {other:?}"),
    }
    let native = cfw_windows_storage::PrivateDirectory::open_or_create(&path).unwrap();
    native
        .write()
        .unwrap()
        .replace("bad.lock", b"x", 1024)
        .unwrap();
    assert!(matches!(
        directory.acquire_lock_file("bad.lock"),
        Err(LockFileError::UnsafeMetadata)
    ));
    directory
        .write_atomic_with_directory_sync(b"", File::sync_all)
        .unwrap();
    assert!(matches!(
        directory.read(),
        Err(PrivateReadError::Unusable(_))
    ));
}
