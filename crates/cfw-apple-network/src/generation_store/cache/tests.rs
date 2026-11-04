use std::os::unix::fs::symlink;
use std::path::PathBuf;

use super::*;
use crate::generation_store::failpoint;

/// A fresh directory under the temporary directory for one test.
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "cfw-lineage-cache-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    fs::create_dir(&path).expect("create scratch directory");
    path
}

fn is_io(error: &GenerationStoreError, expected: &str) -> bool {
    matches!(error, GenerationStoreError::Io { operation, .. } if *operation == expected)
}

#[test]
fn the_cache_root_must_be_a_private_directory_of_this_user() {
    let scratch = scratch("root");
    let file = scratch.join("file");
    fs::write(&file, b"not a directory").expect("write file");
    let error = prepare_root(&file).expect_err("a file is no root");
    assert!(is_io(&error, "create-lineage-cache-root"), "{error}");

    let real = scratch.join("real");
    fs::create_dir(&real).expect("real root");
    let link = scratch.join("link");
    symlink(&real, &link).expect("linked root");
    assert!(matches!(
        prepare_root(&link),
        Err(GenerationStoreError::UnsafeRoot(path)) if path == link
    ));

    let shared = scratch.join("shared");
    fs::create_dir(&shared).expect("shared root");
    fs::set_permissions(&shared, Permissions::from_mode(0o755)).expect("widen root");
    prepare_root(&shared).expect("a widened root is narrowed");
    assert_eq!(
        fs::metadata(&shared).expect("root").permissions().mode() & 0o777,
        0o700
    );
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn a_cache_file_must_be_a_private_regular_file_of_this_user() {
    let scratch = scratch("file");
    let cache = scratch.join(LINEAGE_FILE);

    let outside = scratch.join("outside");
    fs::write(&outside, b"{}").expect("outside file");
    symlink(&outside, &cache).expect("linked cache");
    let error = read(&scratch).expect_err("a link is never followed");
    assert!(is_io(&error, "open-lineage-cache-file"), "{error}");
    fs::remove_file(&cache).expect("remove link");

    fs::write(&cache, b"{}").expect("cache");
    fs::hard_link(&cache, scratch.join("second-name")).expect("hard link");
    assert!(matches!(
        read(&scratch),
        Err(GenerationStoreError::UnsafeFile(path)) if path == cache
    ));
    fs::remove_file(scratch.join("second-name")).expect("remove second name");

    fs::set_permissions(&cache, Permissions::from_mode(0o644)).expect("widen cache");
    assert_eq!(read(&scratch).expect("read cache"), Some(b"{}".to_vec()));
    assert_eq!(
        fs::metadata(&cache).expect("cache").permissions().mode() & 0o777,
        0o600
    );

    for length in [0, MAX_LINEAGE_BYTES as usize + 1] {
        fs::write(&cache, vec![b' '; length]).expect("cache of this length");
        assert!(matches!(
            read(&scratch),
            Err(GenerationStoreError::DocumentTooLarge(actual)) if actual == length as u64
        ));
    }
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn reading_needs_a_directory_root() {
    let scratch = scratch("read-root");
    let file = scratch.join("file");
    fs::write(&file, b"not a directory").expect("write file");
    let error = read(&file).expect_err("no cache below a file");
    assert!(is_io(&error, "inspect-lineage-cache"), "{error}");
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn writes_are_bounded_and_leave_no_temporary_behind() {
    let scratch = scratch("write");
    for length in [0, MAX_LINEAGE_BYTES as usize + 1] {
        assert!(matches!(
            write(&scratch, &vec![b' '; length]),
            Err(GenerationStoreError::DocumentTooLarge(actual)) if actual == length as u64
        ));
    }

    let missing = scratch.join("missing");
    let error = write(&missing, b"{}").expect_err("no root to write into");
    assert!(is_io(&error, "create-lineage-cache-temporary"), "{error}");

    fs::create_dir(scratch.join(LINEAGE_FILE)).expect("directory in the cache's place");
    let error = write(&scratch, b"{}").expect_err("a directory is not replaced");
    assert!(is_io(&error, "replace-lineage-cache"), "{error}");
    let left = fs::read_dir(&scratch)
        .expect("scratch entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(left, [LINEAGE_FILE], "the temporary was removed");
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn the_lock_file_must_not_be_a_link() {
    let scratch = scratch("lock");
    let outside = scratch.join("outside");
    fs::write(&outside, b"").expect("outside file");
    symlink(&outside, scratch.join(LOCK_FILE)).expect("linked lock");
    let error = exclusive_lock(&scratch)
        .map(|_| ())
        .expect_err("a linked lock is refused");
    assert!(is_io(&error, "open-lineage-cache-file"), "{error}");
    fs::remove_dir_all(scratch).expect("remove scratch");
}

/// Entries of `root` that are left-over write temporaries.
fn temporaries(root: &Path) -> Vec<std::ffi::OsString> {
    fs::read_dir(root)
        .expect("root entries")
        .map(|entry| entry.expect("entry").file_name())
        .filter(|name| name.to_string_lossy().ends_with(".tmp"))
        .collect()
}

#[test]
fn every_named_filesystem_step_reports_its_own_failure() {
    let scratch = scratch("steps");
    for step in [
        "create-lineage-cache-root",
        "inspect-lineage-cache-root",
        "protect-lineage-cache-root",
    ] {
        let root = scratch.join(step);
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, Permissions::from_mode(0o755)).expect("widen root");
        let failures = failpoint::fail(&[step]);
        let error = prepare_root(&root).expect_err(step);
        assert_eq!(failures.remaining(), 0, "{step}");
        assert!(is_io(&error, step), "{step}: {error}");
    }

    let root = scratch.join("write");
    fs::create_dir(&root).expect("write root");
    for step in [
        "create-lineage-cache-temporary",
        "write-lineage-cache-temporary",
        "sync-lineage-cache-temporary",
        "replace-lineage-cache",
        "sync-lineage-cache-directory",
    ] {
        let failures = failpoint::fail(&[step]);
        let error = write(&root, b"{}").expect_err(step);
        assert_eq!(failures.remaining(), 0, "{step}");
        assert!(is_io(&error, step), "{step}: {error}");
        assert!(temporaries(&root).is_empty(), "{step} left a temporary");
    }

    let cache = root.join(LINEAGE_FILE);
    for step in [
        "inspect-lineage-cache",
        "open-lineage-cache-file",
        "inspect-open-lineage-cache-file",
        "protect-lineage-cache-file",
        "stat-lineage-cache",
        "read-lineage-cache",
    ] {
        fs::set_permissions(&cache, Permissions::from_mode(0o644)).expect("widen cache");
        let failures = failpoint::fail(&[step]);
        let error = read(&root).expect_err(step);
        assert_eq!(failures.remaining(), 0, "{step}");
        assert!(is_io(&error, step), "{step}: {error}");
    }
    fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn a_failed_write_whose_temporary_cannot_be_removed_reports_both() {
    let scratch = scratch("cleanup");
    let failures = failpoint::fail(&[
        "write-lineage-cache-temporary",
        "remove-lineage-cache-temporary",
    ]);
    let error = write(&scratch, b"{}").expect_err("write and cleanup fail");
    assert_eq!(failures.remaining(), 0);
    assert!(
        matches!(
            &error,
            GenerationStoreError::WriteAndCleanupFailed { write_error, cleanup_error }
                if write_error.contains("write-lineage-cache-temporary")
                    && cleanup_error.to_string()
                        == "injected failure of remove-lineage-cache-temporary"
        ),
        "{error}"
    );
    assert_eq!(temporaries(&scratch).len(), 1, "the temporary is kept");
    fs::remove_dir_all(scratch).expect("remove scratch");
}
