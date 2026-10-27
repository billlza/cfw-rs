#![cfg(windows)]

#[path = "../../../apps/cfw-tauri-shell/src/legacy/handoff_ticket/storage_contract.rs"]
mod contract;
use contract::{
    HANDOFF_DIRECTORY, LockedDocument, MAX_DOCUMENT_BYTES, MAX_HANDOFF_DOCUMENTS, WriteNewFailure,
};
#[path = "../../../apps/cfw-tauri-shell/src/legacy/handoff_ticket/storage_windows.rs"]
mod desktop;
use cfw_windows_storage::{Error, PrivateDirectory as NativeDirectory};
use desktop::PrivateDirectory;
use std::{fs, io, path::PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    NativeDirectory::open_or_create(&root).unwrap();
    let desktop = PrivateDirectory::open_or_create(&root).unwrap();
    (temporary, root, desktop)
}

#[test]
fn consumed_ticket_name_disappears_while_its_retained_lease_allows_a_separate_ready_document() {
    let (_temporary, root, owner) = fixture();
    assert!(owner.entry_names().unwrap().is_empty());
    owner.write_new("ticket.json", b"ticket").unwrap();
    let (lease, bytes) = owner.read_locked_optional("ticket.json").unwrap().unwrap();
    assert_eq!(bytes, b"ticket");
    let other = PrivateDirectory::open_or_create(&root).unwrap();
    assert!(other.read_locked_optional("ticket.json").is_err());
    assert!(
        other
            .read_ready_locked_optional("ticket.json")
            .unwrap()
            .is_none()
    );
    assert!(other.write_new("ticket.json", b"replacement").is_err());
    owner
        .unlink_locked("ticket.json", lease.try_clone().unwrap())
        .unwrap();
    assert!(other.read_locked_optional("ticket.json").unwrap().is_none());
    assert!(owner.entry_names().unwrap().is_empty());
    owner.write_new("ready.json", b"ready").unwrap();
    let (ready, bytes) = other
        .read_ready_locked_optional("ready.json")
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"ready");
    other.unlink_locked("ready.json", ready).unwrap();
    other.unlink_optional("ready.json").unwrap();
    drop(lease);
}

#[test]
fn retaining_a_lease_preserves_native_exclusion_until_the_last_reference_closes() {
    let (_temporary, root, owner) = fixture();
    owner.write_new("ready.json", b"ready").unwrap();
    let (lease, _) = owner.read_locked_optional("ready.json").unwrap().unwrap();
    let retained = lease.try_clone().unwrap();
    drop(lease);
    let other = PrivateDirectory::open_or_create(&root).unwrap();
    assert!(
        other
            .read_ready_locked_optional("ready.json")
            .unwrap()
            .is_none()
    );
    drop(retained);
    let (lease, bytes) = other
        .read_ready_locked_optional("ready.json")
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"ready");
    other.unlink_locked("ready.json", lease).unwrap();
}

#[test]
fn consumption_refuses_a_replaced_name_without_removing_either_file() {
    let (_temporary, root, owner) = fixture();
    owner.write_new("ticket.json", b"original").unwrap();
    let (lease, _) = owner.read_locked_optional("ticket.json").unwrap().unwrap();
    let directory = root.join(HANDOFF_DIRECTORY);
    fs::rename(
        directory.join("ticket.json"),
        directory.join("retained.json"),
    )
    .unwrap();
    owner.write_new("ticket.json", b"replacement").unwrap();
    assert!(
        owner
            .unlink_locked("ticket.json", lease.try_clone().unwrap())
            .is_err()
    );
    drop(lease);
    assert_eq!(
        fs::read(directory.join("ticket.json")).unwrap(),
        b"replacement"
    );
    assert_eq!(
        fs::read(directory.join("retained.json")).unwrap(),
        b"original"
    );
}

#[test]
fn failed_publication_and_cleanup_keep_ready_bytes_quarantined_until_explicit_retirement() {
    let (_temporary, root, owner) = fixture();
    let native = NativeDirectory::open_existing(&root)
        .unwrap()
        .unwrap()
        .open_or_create_child(HANDOFF_DIRECTORY)
        .unwrap();
    let ready = root.join(HANDOFF_DIRECTORY).join("ready.json");
    let mut original_permissions = None;
    let failure = native.write_new_exclusive_document(
        "ready.json",
        b"must not become readiness",
        MAX_DOCUMENT_BYTES as usize,
        |_| {
            assert!(
                owner
                    .read_ready_locked_optional("ready.json")
                    .unwrap()
                    .is_none()
            );
            let mut permissions = fs::metadata(&ready).unwrap().permissions();
            original_permissions = Some(permissions.clone());
            permissions.set_readonly(true);
            fs::set_permissions(&ready, permissions).unwrap();
            Err(io::Error::other("injected publication flush failure"))
        },
    );
    let mut failure = match failure {
        Err(failure) => failure,
        Ok(()) => panic!("publication failure became success"),
    };
    assert!(matches!(failure.error, Error::CleanupFailed { .. }));
    assert!(failure.quarantine.is_some());
    assert!(
        owner
            .read_ready_locked_optional("ready.json")
            .unwrap()
            .is_none()
    );
    assert!(fs::read(&ready).is_err());
    fs::set_permissions(&ready, original_permissions.unwrap()).unwrap();
    native
        .unlink_exclusive_document("ready.json", failure.quarantine.take().unwrap())
        .unwrap();
    assert!(
        owner
            .read_ready_locked_optional("ready.json")
            .unwrap()
            .is_none()
    );
    assert!(!ready.exists());
}

#[test]
fn failed_publication_with_successful_cleanup_remains_an_error_and_leaves_no_ready_entry() {
    let (_temporary, root, owner) = fixture();
    let native = NativeDirectory::open_existing(&root)
        .unwrap()
        .unwrap()
        .open_or_create_child(HANDOFF_DIRECTORY)
        .unwrap();
    let failure = native.write_new_exclusive_document(
        "ready.json",
        b"ready",
        MAX_DOCUMENT_BYTES as usize,
        |_| Err(io::Error::other("injected publication flush failure")),
    );
    let failure = match failure {
        Err(failure) => failure,
        Ok(()) => panic!("publication failure became success"),
    };
    assert!(matches!(failure.error, Error::CommitUncertain(_)));
    assert!(failure.quarantine.is_none());
    assert!(
        owner
            .read_ready_locked_optional("ready.json")
            .unwrap()
            .is_none()
    );
    assert!(owner.entry_names().unwrap().is_empty());
}

#[test]
fn handoff_size_enumeration_and_link_bounds_fail_without_truncation_or_replacement() {
    let (_temporary, root, owner) = fixture();
    let failure = owner
        .write_new_retaining_ambiguous_failure(
            "oversize.json",
            &vec![b'x'; MAX_DOCUMENT_BYTES as usize + 1],
        )
        .expect_err("oversize document rejected");
    assert!(failure.quarantine.is_none());
    assert!(!failure.message.is_empty());
    assert!(
        owner
            .read_locked_optional("oversize.json")
            .unwrap()
            .is_none()
    );
    for number in 0..MAX_HANDOFF_DOCUMENTS {
        owner
            .write_new(&format!("ticket-{number}.json"), b"{}")
            .unwrap();
    }
    assert_eq!(owner.entry_names().unwrap().len(), MAX_HANDOFF_DOCUMENTS);
    owner.write_new("extra.json", b"{}").unwrap();
    assert!(owner.entry_names().is_err());
    let directory = root.join(HANDOFF_DIRECTORY);
    fs::hard_link(directory.join("extra.json"), directory.join("linked.json")).unwrap();
    assert!(owner.read_locked_optional("extra.json").is_err());
    assert_eq!(fs::read(directory.join("extra.json")).unwrap(), b"{}");
}
