#![cfg(windows)]

use cfw_windows_storage::{Error, PrivateDirectory};
use std::{fs, io, path::Path};

fn absent(path: &Path) {
    assert!(
        matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
    );
}

#[test]
fn streamed_bytes_stay_private_until_atomic_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("暂存");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut stream = directory
        .begin_stream("package.msi", ".package.partial.tmp", 256 * 1024)
        .unwrap();
    let chunk = vec![42; 32 * 1024];
    for _ in 0..8 {
        stream.write_chunk(&chunk).unwrap();
        absent(&root.join("package.msi"));
        assert_eq!(
            fs::read(root.join(".package.partial.tmp"))
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        assert_eq!(
            fs::OpenOptions::new()
                .write(true)
                .open(root.join(".package.partial.tmp"))
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
    }
    // The owner may cross executor threads without losing its native handles.
    std::thread::spawn(move || stream.commit())
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read(root.join("package.msi")).unwrap(),
        vec![42; 256 * 1024]
    );
    absent(&root.join(".package.partial.tmp"));
    cfw_windows_storage::validate_private_file(&fs::File::open(root.join("package.msi")).unwrap())
        .unwrap();
}

#[test]
fn exceeding_the_limit_poisoned_the_stream_instead_of_publishing_a_prefix() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut stream = directory
        .begin_stream("package", ".package.tmp", 4)
        .unwrap();
    stream.write_chunk(b"tes").unwrap();
    assert!(matches!(
        stream.write_chunk(b"too long"),
        Err(Error::TooLarge { .. })
    ));
    assert!(matches!(
        stream.write_chunk(b"t"),
        Err(Error::IncompleteStream)
    ));
    assert!(matches!(stream.commit(), Err(Error::IncompleteStream)));
    absent(&root.join("package"));
    absent(&root.join(".package.tmp"));
}

#[test]
fn existing_destinations_and_temporary_files_are_never_overwritten() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut stream = directory
        .begin_stream("package", ".package.tmp", 64)
        .unwrap();
    stream.write_chunk(b"candidate").unwrap();
    fs::write(root.join("package"), b"original").unwrap();
    assert!(stream.commit().is_err());
    assert_eq!(fs::read(root.join("package")).unwrap(), b"original");
    absent(&root.join(".package.tmp"));
    assert!(directory.begin_stream("package", ".other.tmp", 64).is_err());
    fs::write(root.join(".reserved.tmp"), b"reserved").unwrap();
    assert!(
        directory
            .begin_stream("other", ".reserved.tmp", 64)
            .is_err()
    );
    assert_eq!(fs::read(root.join(".reserved.tmp")).unwrap(), b"reserved");
}

#[test]
fn cancellation_deletes_the_owned_file_not_a_replacement_at_the_old_name() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut stream = directory
        .begin_stream("package", ".package.tmp", 64)
        .unwrap();
    stream.write_chunk(b"partial").unwrap();
    fs::rename(root.join(".package.tmp"), root.join("moved")).unwrap();
    fs::write(root.join(".package.tmp"), b"replacement").unwrap();
    stream.discard().unwrap();
    absent(&root.join("package"));
    absent(&root.join("moved"));
    assert_eq!(fs::read(root.join(".package.tmp")).unwrap(), b"replacement");
}

#[test]
fn a_failed_directory_flush_reports_uncertainty_and_keeps_the_published_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    let mut stream = directory
        .begin_stream("package", ".package.tmp", 64)
        .unwrap();
    stream.write_chunk(b"complete").unwrap();
    let result = stream.commit_with_sync(|_| Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    assert!(matches!(result, Err(Error::CommitUncertain(_))));
    assert_eq!(fs::read(root.join("package")).unwrap(), b"complete");
    absent(&root.join(".package.tmp"));
}

#[test]
fn abandoning_a_stream_removes_partial_bytes_and_releases_the_transaction() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let directory = PrivateDirectory::open_or_create(&root).unwrap();
    {
        let mut stream = directory
            .begin_stream("package", ".package.tmp", 64)
            .unwrap();
        stream.write_chunk(b"partial").unwrap();
    }
    absent(&root.join("package"));
    absent(&root.join(".package.tmp"));
    let mut next = directory
        .begin_stream("package", ".package.tmp", 64)
        .unwrap();
    next.write_chunk(b"next").unwrap();
    next.commit().unwrap();
    assert_eq!(fs::read(root.join("package")).unwrap(), b"next");
}
