//! The repository lock: a held selected profile keeps every other operation
//! out, and a waiting operation reports the repository busy at its limit.

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use cfw_profiles::ProfileError;

use crate::support::{profile, repository};

/// Mirrors how long an operation waits for the repository lock.
const LOCK_WAIT: Duration = Duration::from_secs(3);

#[test]
fn a_locked_selected_profile_keeps_other_operations_out() {
    let (root, repository) = repository("locked-selected");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let locked = repository
        .lock_selected()
        .expect("lock the selected profile");
    assert_eq!(locked.stored().record.id, imported.id);

    let waiting = repository.clone();
    let started = Instant::now();
    let waited = thread::spawn(move || waiting.snapshot())
        .join()
        .expect("snapshot thread");
    assert!(matches!(waited, Err(ProfileError::RepositoryBusy)));
    assert!(started.elapsed() >= LOCK_WAIT);

    drop(locked);
    assert_eq!(
        repository
            .snapshot()
            .expect("snapshot once the lock is released")
            .selected_profile_id,
        Some(imported.id)
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
