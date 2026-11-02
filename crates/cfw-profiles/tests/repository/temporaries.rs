//! Atomic writes: a listing never sees a temporary, and an interrupted
//! write is recovered without following a link.

use std::fs;
use std::sync::{Arc, Barrier};

use cfw_profiles::ProfileError;
use uuid::Uuid;

use crate::private_file_fixture::write_private;
use crate::support::{listed, profile, repository, symlink};

#[test]
fn concurrent_listing_never_observes_an_atomic_write_temporary() {
    let (root, repository) = repository("concurrent-list");
    let repository = Arc::new(repository);
    assert!(
        listed(&repository)
            .expect("initial profile list")
            .is_empty()
    );
    let barrier = Arc::new(Barrier::new(2));

    let writer_repository = Arc::clone(&repository);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..12 {
            writer_repository
                .import(Some(&format!("Profile {index}")), &profile())
                .expect("atomic profile import");
        }
    });

    barrier.wait();
    for _ in 0..48 {
        listed(&repository).expect("listing must not observe an in-flight temporary file");
    }
    writer.join().expect("writer thread");
    assert_eq!(listed(&repository).expect("final profile list").len(), 12);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn abandoned_import_and_selection_temporaries_are_recovered_under_the_lock() {
    let (root, repository) = repository("temporary-recovery");
    let imported = repository.import(None, &profile()).expect("import profile");
    let profiles_dir = root.join("profiles");
    let import_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    let selection_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    for path in [&import_temporary, &selection_temporary] {
        write_private(path, b"interrupted private transaction");
    }

    assert_eq!(
        listed(&repository).expect("recover before listing").len(),
        1
    );
    assert!(!import_temporary.exists());
    assert!(!selection_temporary.exists());
    repository
        .select(&imported.id)
        .expect("selection works after recovery");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn unsafe_matching_temporary_is_rejected_without_following_it() {
    let (root, repository) = repository("unsafe-temporary");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("outside-temporary");
    fs::write(&outside, b"external").expect("outside target");
    let temporary = root
        .join("profiles")
        .join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    symlink(&outside, &temporary).expect("matching temporary symlink");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"external");
    assert!(temporary.is_symlink());

    fs::remove_dir_all(root).expect("remove test directory");
}
