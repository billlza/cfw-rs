#![cfg(windows)]

use cfw_windows_storage::{Error, PrivateDirectory};
use std::{fs, io, os::windows::fs::symlink_dir, path::Path};

fn absent(path: &Path) {
    assert!(
        matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
    );
}

#[test]
fn fresh_children_are_private_and_existing_entries_are_never_reused() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let mut lease = parent.write().unwrap();
    assert!(lease.open_private_child("absent").unwrap().is_none());
    absent(&path.join("absent"));
    let child = lease.create_private_child("暂存").unwrap();
    assert!(
        PrivateDirectory::open_existing(&path.join("暂存"))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        lease.create_private_child("暂存"),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
    ));
    child
        .write()
        .unwrap()
        .replace("package.msi", b"contents", 8)
        .unwrap();
    assert_eq!(
        fs::read(path.join("暂存/package.msi")).unwrap(),
        b"contents"
    );
    lease.remove_flat_child("暂存", child, 1).unwrap();
    absent(&path.join("暂存"));
    lease.create_private_child("暂存").unwrap();
}

#[test]
fn flat_cleanup_unlinks_links_without_reading_or_touching_their_targets() {
    let temporary = tempfile::tempdir().unwrap();
    let external = temporary.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("keep"), b"outside").unwrap();
    let path = temporary.path().join("private");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let mut lease = parent.write().unwrap();
    let child = lease.create_private_child("transaction").unwrap();
    let child_path = path.join("transaction");
    symlink_dir(&external, child_path.join("redirect")).unwrap();
    fs::hard_link(external.join("keep"), child_path.join("alias")).unwrap();
    lease.remove_flat_child("transaction", child, 2).unwrap();
    absent(&child_path);
    assert_eq!(fs::read(external.join("keep")).unwrap(), b"outside");
}

#[test]
fn bounds_and_real_subdirectories_are_refused_before_any_removal() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let mut lease = parent.write().unwrap();
    let child = lease.create_private_child("transaction").unwrap();
    child
        .write()
        .unwrap()
        .replace("package", b"keep", 4)
        .unwrap();
    child.write().unwrap().replace("extra", b"keep", 4).unwrap();
    assert!(matches!(
        lease.remove_flat_child("transaction", child, 1),
        Err(Error::TooManyEntries { maximum: 1 })
    ));
    let child = lease.open_private_child("transaction").unwrap().unwrap();
    let nested = child.open_or_create_child("nested").unwrap();
    nested
        .write()
        .unwrap()
        .replace("keep", b"nested", 6)
        .unwrap();
    drop(nested);
    assert!(matches!(
        lease.remove_flat_child("transaction", child, 3),
        Err(Error::UnexpectedDirectory)
    ));
    for name in ["package", "extra"] {
        assert_eq!(
            fs::read(path.join("transaction").join(name)).unwrap(),
            b"keep"
        );
    }
    assert_eq!(
        fs::read(path.join("transaction/nested/keep")).unwrap(),
        b"nested"
    );
}

#[test]
fn retained_parent_cleanup_is_not_redirected_by_a_replaced_parent_path() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let moved = temporary.path().join("moved");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let held = parent.write().unwrap();
    assert!(
        matches!(fs::rename(&path, &moved), Err(error) if matches!(error.raw_os_error(), Some(5 | 32)))
    );
    absent(&moved);
    drop(held);
    // Replace the pathname before acquiring the lifecycle lease. An active
    // non-delete-shared lock file prevents renaming its parent on NTFS, so
    // renaming after lease acquisition never reaches the redirection scenario.
    fs::rename(&path, &moved).unwrap();
    fs::create_dir_all(path.join("transaction")).unwrap();
    fs::write(path.join("transaction/keep"), b"replacement").unwrap();
    let mut lease = parent.write().unwrap();
    let child = lease.create_private_child("transaction").unwrap();
    child
        .write()
        .unwrap()
        .replace("package", b"owned", 5)
        .unwrap();
    assert_eq!(
        fs::read(moved.join("transaction/package")).unwrap(),
        b"owned"
    );
    lease.remove_flat_child("transaction", child, 1).unwrap();
    absent(&moved.join("transaction"));
    assert_eq!(
        fs::read(path.join("transaction/keep")).unwrap(),
        b"replacement"
    );
}

#[test]
fn a_replaced_child_name_is_rejected_before_deleting_either_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let mut lease = parent.write().unwrap();
    let child = lease.create_private_child("transaction").unwrap();
    child
        .write()
        .unwrap()
        .replace("package", b"owned", 5)
        .unwrap();
    fs::rename(path.join("transaction"), path.join("moved")).unwrap();
    let other = lease.create_private_child("transaction").unwrap();
    other.write().unwrap().replace("keep", b"other", 5).unwrap();
    drop(other);
    assert!(matches!(
        lease.remove_flat_child("transaction", child, 1),
        Err(Error::UnsafeDirectory)
    ));
    assert_eq!(fs::read(path.join("moved/package")).unwrap(), b"owned");
    assert_eq!(fs::read(path.join("transaction/keep")).unwrap(), b"other");
}

#[test]
fn active_child_writers_prevent_cleanup_until_their_transaction_retires() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let parent = PrivateDirectory::open_or_create(&path).unwrap();
    let mut lease = parent.write().unwrap();
    let child = lease.create_private_child("transaction").unwrap();
    let mut stream = child.begin_stream("package", ".package.tmp", 7).unwrap();
    stream.write_chunk(b"partial").unwrap();
    assert!(matches!(
        lease.remove_flat_child("transaction", child, 1),
        Err(Error::Busy)
    ));
    assert!(path.join("transaction/.package.tmp").try_exists().unwrap());
    stream.commit().unwrap();
    let child = lease.open_private_child("transaction").unwrap().unwrap();
    lease.remove_flat_child("transaction", child, 1).unwrap();
    absent(&path.join("transaction"));
}
