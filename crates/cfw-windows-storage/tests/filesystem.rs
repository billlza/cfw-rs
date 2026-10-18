#![cfg(windows)]

use std::fs;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use cfw_windows_storage::{Error, PrivateDirectory, ReadPolicy};

#[test]
fn replacement_is_bounded_private_and_changes_the_file_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("state.json", b"first", 1024)
        .unwrap();
    let before = directory
        .read()
        .unwrap()
        .read("state.json", 1024, ReadPolicy::Private)
        .unwrap()
        .unwrap();
    directory
        .write()
        .unwrap()
        .replace("state.json", b"first", 1024)
        .unwrap();
    let after = directory
        .read()
        .unwrap()
        .read("state.json", 1024, ReadPolicy::Private)
        .unwrap()
        .unwrap();
    assert_eq!(before.bytes, after.bytes);
    assert_ne!(before.identity, after.identity);
    assert_ne!(before.identity.revision(), after.identity.revision());
    let revision = after.identity.revision();
    assert_eq!(revision.len(), 64);
    assert!(
        revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(matches!(
        directory
            .write()
            .unwrap()
            .replace("state.json", b"too long", 2),
        Err(Error::TooLarge { .. })
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), b"first");
    assert!(!fs::read_dir(&path).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[test]
fn invalid_names_and_reserved_lock_aliases_do_not_change_existing_data() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(&temporary.path().join("private")).unwrap();
    let mut transaction = directory.write().unwrap();
    transaction
        .replace("state.json", b"preserved", 1024)
        .unwrap();
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "sub\\file",
        "state.json:stream",
        "bad\0name",
        "tail.",
        "tail ",
        ".CFW-STORAGE-LOCK-V1",
    ] {
        assert!(
            matches!(
                transaction.replace(name, b"changed", 1024),
                Err(Error::InvalidName)
            ),
            "accepted {name:?}"
        );
    }
    assert_eq!(
        transaction
            .read("state.json", 1024, ReadPolicy::Private)
            .unwrap()
            .unwrap()
            .bytes,
        b"preserved"
    );
}

#[test]
fn symlinks_hard_links_and_directory_redirection_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("owned.json", b"preserved", 1024)
        .unwrap();
    std::os::windows::fs::symlink_file(path.join("owned.json"), path.join("link.json")).unwrap();
    assert!(matches!(
        directory
            .read()
            .unwrap()
            .read("link.json", 1024, ReadPolicy::Private),
        Err(Error::UnsafeFile)
    ));
    assert!(
        directory
            .write()
            .unwrap()
            .replace("link.json", b"changed", 1024)
            .is_err()
    );
    assert_eq!(fs::read(path.join("owned.json")).unwrap(), b"preserved");
    fs::hard_link(path.join("owned.json"), path.join("hard.json")).unwrap();
    assert!(matches!(
        directory
            .read()
            .unwrap()
            .read("owned.json", 1024, ReadPolicy::Private),
        Err(Error::UnsafeFile)
    ));
    let redirected = temporary.path().join("redirected");
    std::os::windows::fs::symlink_dir(&path, &redirected).unwrap();
    assert!(matches!(
        PrivateDirectory::open_existing(&redirected),
        Err(Error::UnsafeDirectory)
    ));
}

#[test]
fn broad_file_or_directory_acls_are_rejected_before_a_write() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("state.json", b"preserved", 1024)
        .unwrap();
    let file = path.join("state.json");
    let grant = std::process::Command::new("icacls.exe")
        .arg(&file)
        .args(["/grant", "*S-1-1-0:(F)"])
        .output()
        .unwrap();
    assert!(
        grant.status.success(),
        "ACL fixture failed: {}",
        String::from_utf8_lossy(&grant.stderr)
    );
    assert!(matches!(
        directory
            .read()
            .unwrap()
            .read("state.json", 1024, ReadPolicy::Private),
        Err(Error::UnsafeFile)
    ));
    assert!(
        directory
            .write()
            .unwrap()
            .replace("state.json", b"changed", 1024)
            .is_err()
    );
    assert_eq!(fs::read(&file).unwrap(), b"preserved");
    let grant = std::process::Command::new("icacls.exe")
        .arg(&path)
        .args(["/grant", "*S-1-1-0:(F)"])
        .output()
        .unwrap();
    assert!(grant.status.success(), "directory ACL fixture failed");
    assert!(matches!(
        PrivateDirectory::open_existing(&path),
        Err(Error::UnsafeDirectory)
    ));
    assert!(matches!(directory.write(), Err(Error::UnsafeDirectory)));
}

#[test]
fn legacy_read_policy_accepts_read_grants_but_rejects_write_grants() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("legacy.json", b"preserved", 1024)
        .unwrap();
    let file = path.join("legacy.json");
    let read_grant = std::process::Command::new("icacls.exe")
        .arg(&file)
        .args(["/grant:r", "*S-1-1-0:(R)"])
        .output()
        .unwrap();
    assert!(read_grant.status.success(), "read ACL fixture failed");
    assert!(matches!(
        directory
            .read()
            .unwrap()
            .read("legacy.json", 1024, ReadPolicy::Private),
        Err(Error::UnsafeFile)
    ));
    assert_eq!(
        directory
            .read()
            .unwrap()
            .read("legacy.json", 1024, ReadPolicy::LegacyReadOnly)
            .unwrap()
            .unwrap()
            .bytes,
        b"preserved"
    );
    let write_grant = std::process::Command::new("icacls.exe")
        .arg(&file)
        .args(["/grant:r", "*S-1-1-0:(W)"])
        .output()
        .unwrap();
    assert!(write_grant.status.success(), "write ACL fixture failed");
    assert!(matches!(
        directory
            .read()
            .unwrap()
            .read("legacy.json", 1024, ReadPolicy::LegacyReadOnly),
        Err(Error::UnsafeFile)
    ));
    assert_eq!(fs::read(&file).unwrap(), b"preserved");
}

#[test]
fn an_untrusted_temporary_is_preserved_and_cannot_redirect_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("state.json", b"preserved", 1024)
        .unwrap();
    let outside = temporary.path().join("outside.json");
    fs::write(&outside, b"outside").unwrap();
    let linked = path.join(".state.json.tmp");
    std::os::windows::fs::symlink_file(&outside, &linked).unwrap();
    assert!(matches!(
        directory
            .write()
            .unwrap()
            .replace("state.json", b"changed", 1024),
        Err(Error::UnsafeFile)
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), b"preserved");
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert!(fs::symlink_metadata(&linked).unwrap().is_symlink());
}

#[test]
fn contended_lock_has_a_deadline_and_cannot_be_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    let writer = directory.write().unwrap();
    assert!(fs::remove_file(path.join(".cfw-storage-lock-v1")).is_err());
    let started = Instant::now();
    let second = PrivateDirectory::open_existing(&path).unwrap().unwrap();
    assert!(matches!(second.read(), Err(Error::Busy)));
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert!(started.elapsed() < Duration::from_secs(6));
    drop(writer);
    second
        .write()
        .unwrap()
        .replace("state.json", b"recovered", 1024)
        .unwrap();
}

#[test]
fn concurrent_transactions_do_not_lose_updates() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    directory
        .write()
        .unwrap()
        .replace("count", b"0", 128)
        .unwrap();
    let start = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            for _ in 0..16 {
                let directory = PrivateDirectory::open_existing(&path).unwrap().unwrap();
                let mut transaction = directory.write().unwrap();
                let snapshot = transaction
                    .read("count", 128, ReadPolicy::Private)
                    .unwrap()
                    .unwrap();
                let count: usize = std::str::from_utf8(&snapshot.bytes)
                    .unwrap()
                    .parse()
                    .unwrap();
                transaction
                    .replace("count", (count + 1).to_string().as_bytes(), 128)
                    .unwrap();
            }
        }));
    }
    start.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        directory
            .read()
            .unwrap()
            .read("count", 128, ReadPolicy::Private)
            .unwrap()
            .unwrap()
            .bytes,
        b"32"
    );
}

#[test]
fn an_open_directory_cannot_be_redirected_to_a_replacement_path() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let moved = temporary.path().join("moved");
    let directory = PrivateDirectory::open_or_create(&path).unwrap();
    match fs::rename(&path, &moved) {
        Ok(()) => {
            fs::create_dir(&path).unwrap();
            directory
                .write()
                .unwrap()
                .replace("state.json", b"original", 1024)
                .unwrap();
            assert_eq!(fs::read(moved.join("state.json")).unwrap(), b"original");
            assert!(!path.join("state.json").exists());
        }
        Err(error) if matches!(error.raw_os_error(), Some(5 | 32)) => {
            // A filesystem may forbid the rename while the directory is open.
            // It must preserve the original namespace and remain usable.
            assert!(path.is_dir());
            assert!(!moved.exists());
            directory
                .write()
                .unwrap()
                .replace("state.json", b"original", 1024)
                .unwrap();
            assert_eq!(fs::read(path.join("state.json")).unwrap(), b"original");
        }
        Err(error) => panic!("unexpected directory rename error: {error}"),
    }
}
