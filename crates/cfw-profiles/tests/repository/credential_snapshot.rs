//! Credential snapshots, and the lock that orders them against profile
//! mutations.

use std::fs;
use std::time::Duration;

use cfw_profiles::InvalidSelection;

use crate::support::{credential_profile, profile, repository};

#[test]
fn credential_snapshot_is_stable_and_preserves_cross_profile_reference_ownership() {
    const SHARED: &str = "11111111-1111-4111-8111-111111111111";
    const ROTATED: &str = "22222222-2222-4222-8222-222222222222";
    let (root, repository) = repository("credential-snapshot");
    let empty = repository
        .credential_snapshot()
        .expect("empty credential snapshot");
    assert_eq!(empty.profile_count, 0);
    assert!(empty.catalog.is_empty());
    assert_eq!(empty.snapshot_digest.len(), 64);

    let first = repository
        .import(Some("First"), &credential_profile(SHARED))
        .expect("first shared profile");
    let second = repository
        .import(Some("Second"), &credential_profile(SHARED))
        .expect("second shared profile");
    let shared = repository
        .credential_snapshot()
        .expect("shared credential snapshot");
    assert_eq!(shared.profile_count, 2);
    assert_eq!(shared.catalog.len(), 2);
    assert!(
        shared
            .catalog
            .iter()
            .all(|entry| entry.references.len() == 1 && entry.references[0].id() == SHARED)
    );
    assert_ne!(shared.catalog[0].audience, shared.catalog[1].audience);
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("stable credential snapshot"),
        shared
    );

    repository.select(&first.id).expect("select first profile");
    let selected = repository
        .credential_snapshot()
        .expect("selected credential snapshot");
    assert_eq!(
        selected.selected_profile_id.as_deref(),
        Some(first.id.as_str())
    );
    assert_ne!(selected.snapshot_digest, shared.snapshot_digest);

    repository
        .select(&second.id)
        .expect("select second profile");
    assert!(
        repository
            .delete(&first.id, InvalidSelection::Keep)
            .expect("delete unselected shared profile")
    );
    let retained = repository
        .credential_snapshot()
        .expect("shared reference retained");
    assert_eq!(retained.catalog.len(), 1);
    assert_eq!(retained.catalog[0].references[0].id(), SHARED);

    let rotated = repository
        .import(Some("Rotated"), &credential_profile(ROTATED))
        .expect("rotated profile");
    let pending_rotation = repository
        .credential_snapshot()
        .expect("unselected rotation is live");
    assert_eq!(pending_rotation.profile_count, 2);
    // Catalog order is canonical by audience (randomly generated profile
    // ids), so compare reference sets instead of positions.
    let mut pending_reference_ids = pending_rotation
        .catalog
        .iter()
        .flat_map(|entry| entry.references.iter())
        .map(|reference| reference.id())
        .collect::<Vec<_>>();
    pending_reference_ids.sort_unstable();
    assert_eq!(pending_reference_ids, vec![SHARED, ROTATED]);

    repository
        .select(&rotated.id)
        .expect("select rotated profile");
    assert!(
        repository
            .delete(&second.id, InvalidSelection::Keep)
            .expect("delete obsolete profile")
    );
    let completed_rotation = repository
        .credential_snapshot()
        .expect("completed rotation snapshot");
    assert_eq!(completed_rotation.profile_count, 1);
    assert_eq!(completed_rotation.catalog.len(), 1);
    assert_eq!(completed_rotation.catalog[0].references[0].id(), ROTATED);
    assert_ne!(
        completed_rotation.snapshot_digest,
        pending_rotation.snapshot_digest
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn locked_credential_snapshot_blocks_profile_mutation_until_native_commit_finishes() {
    let (root, repository) = repository("credential-snapshot-lock");
    repository
        .import(Some("Initial"), &profile())
        .expect("initial profile");
    let guard = repository
        .lock_credential_snapshot()
        .expect("credential snapshot lock");
    let expected_digest = guard.snapshot().snapshot_digest.clone();
    let writer_repository = repository.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = writer_repository.import(Some("Blocked"), &profile());
        sender.send(result).expect("send writer result");
    });

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(guard.snapshot().snapshot_digest, expected_digest);
    drop(guard);
    receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("writer unblocked")
        .expect("blocked import succeeds");
    writer.join().expect("writer thread");

    let after = repository
        .credential_snapshot()
        .expect("post-commit snapshot");
    assert_ne!(after.snapshot_digest, expected_digest);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn locked_credential_profile_mutation_blocks_gc_reread_until_audience_commit() {
    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const REFERENCE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let (root, repository) = repository("credential-mutation-lock");
    let stale_preview_snapshot = repository
        .credential_snapshot()
        .expect("pre-provision credential snapshot");
    let mutation = repository
        .begin_credential_profile_mutation()
        .expect("credential profile mutation lock");

    let gc_repository = repository.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let gc_reread = std::thread::spawn(move || {
        let locked = gc_repository
            .lock_credential_snapshot()
            .expect("competing GC snapshot lock");
        sender
            .send(locked.snapshot().clone())
            .expect("send GC snapshot");
    });

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    let imported = mutation
        .commit_exact_import(
            PROFILE_ID,
            Some("Vault prepared"),
            &credential_profile(REFERENCE_ID),
            Some("https://subscription.example/profile"),
        )
        .expect("commit prepared audience");
    assert!(imported.created);

    let current = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("GC reread unblocked after profile commit");
    gc_reread.join().expect("GC reread thread");
    assert_ne!(
        current.snapshot_digest, stale_preview_snapshot.snapshot_digest,
        "a GC commit bound to the pre-provision snapshot must fail closed"
    );
    let live = current
        .catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == PROFILE_ID)
        .expect("new audience is live when GC acquires the lock");
    assert_eq!(live.audience.profile_digest(), imported.profile.digest);
    assert_eq!(live.references.len(), 1);
    assert_eq!(live.references[0].id(), REFERENCE_ID);

    fs::remove_dir_all(root).expect("remove test directory");
}
