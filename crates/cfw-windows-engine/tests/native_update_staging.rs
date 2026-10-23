#![cfg(windows)]

use cfw_windows_engine::update_package::{StagingError, UpdateStaging};
use cfw_windows_storage::{Error as StorageError, PrivateDirectory};
use std::{fs, io, path::Path, process::Command};
use uuid::Uuid;

#[test]
fn handoff_custody_precedes_namespace_transfer_and_does_not_trust_payload_bytes() {
    use cfw_windows_engine::update_package::UpdateHandoff;
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let id = Uuid::new_v4();
    let staging = UpdateStaging::create(&home, id).unwrap();
    staging
        .directory()
        .write()
        .unwrap()
        .replace("package.msi", b"not yet authenticated", 64)
        .unwrap();
    let handoff = UpdateHandoff::open(&home, id).unwrap();
    assert_eq!(handoff.package(), staging.package());
    assert_eq!(
        fs::read(handoff.package()).unwrap(),
        b"not yet authenticated"
    );
    assert_eq!(
        fs::write(handoff.package(), b"changed")
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    drop(staging);
    let successor = UpdateStaging::open_existing(&home, id).unwrap().unwrap();
    assert_eq!(successor.root(), handoff.root());
    assert!(fs::rename(handoff.package(), handoff.root().join("changed.msi")).is_err());
    drop(handoff);
    successor.remove().unwrap();
}

fn absent(path: &Path) {
    assert!(
        matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
    );
}

#[test]
fn staging_retains_private_downloads_until_explicit_removal() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let id = Uuid::new_v4();
    let staging = UpdateStaging::create(&home, id).unwrap();
    assert_eq!(staging.package(), staging.root().join("package.msi"));
    let mut download = staging
        .directory()
        .begin_stream("package.msi", ".package.download.tmp", 32)
        .unwrap();
    download.write_chunk(b"downloaded package").unwrap();
    download.commit().unwrap();
    let root = staging.root().to_path_buf();
    drop(staging);
    assert_eq!(
        fs::read(root.join("package.msi")).unwrap(),
        b"downloaded package"
    );
    assert!(matches!(
        UpdateStaging::create(&home, id),
        Err(StagingError::Storage { source: StorageError::Io(error), .. })
            if error.kind() == io::ErrorKind::AlreadyExists
    ));
    UpdateStaging::open_existing(&home, id)
        .unwrap()
        .unwrap()
        .remove()
        .unwrap();
    absent(&root);
    assert!(UpdateStaging::open_existing(&home, id).unwrap().is_none());
}

#[test]
fn a_live_transaction_excludes_recovery_and_releases_its_lease_on_drop() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let staging = UpdateStaging::create(&home, Uuid::new_v4()).unwrap();
    staging
        .directory()
        .write()
        .unwrap()
        .replace("package.msi", b"keep", 4)
        .unwrap();
    assert!(matches!(
        UpdateStaging::recover(&home),
        Err(StagingError::Storage {
            operation: "acquire lifecycle lease",
            source: StorageError::Busy,
        })
    ));
    assert_eq!(fs::read(staging.package()).unwrap(), b"keep");
    let root = staging.root().to_path_buf();
    drop(staging);
    assert_eq!(UpdateStaging::recover(&home).unwrap(), 1);
    absent(&root);
    assert_eq!(UpdateStaging::recover(&home).unwrap(), 0);
}

#[test]
fn missing_staging_is_distinguished_from_an_invalid_home_or_namespace() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("absent");
    assert_eq!(UpdateStaging::recover(&home).unwrap(), 0);
    assert!(
        UpdateStaging::open_existing(&home, Uuid::new_v4())
            .unwrap()
            .is_none()
    );
    absent(&home);
    assert!(matches!(
        UpdateStaging::create(&home, Uuid::nil()),
        Err(StagingError::InvalidTransaction)
    ));
    absent(&home);
    fs::write(&home, b"not a directory").unwrap();
    assert!(UpdateStaging::recover(&home).is_err());
    assert!(UpdateStaging::open_existing(&home, Uuid::new_v4()).is_err());
    fs::remove_file(&home).unwrap();
    let directory = PrivateDirectory::open_or_create(&home).unwrap();
    directory
        .write()
        .unwrap()
        .replace("updates-msi-v1", b"not a directory", 20)
        .unwrap();
    assert!(UpdateStaging::recover(&home).is_err());
    assert_eq!(
        fs::read(home.join("updates-msi-v1")).unwrap(),
        b"not a directory"
    );
}

#[test]
fn unknown_namespace_entries_prevent_any_transaction_cleanup() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let staging = UpdateStaging::create(&home, Uuid::new_v4()).unwrap();
    staging
        .directory()
        .write()
        .unwrap()
        .replace("package.msi", b"keep", 4)
        .unwrap();
    let package = staging.package();
    drop(staging);
    let namespace = PrivateDirectory::open_existing(&home.join("updates-msi-v1"))
        .unwrap()
        .unwrap();
    namespace
        .write()
        .unwrap()
        .replace("unknown", b"keep", 4)
        .unwrap();
    assert!(matches!(
        UpdateStaging::recover(&home),
        Err(StagingError::UnknownEntry)
    ));
    assert_eq!(fs::read(package).unwrap(), b"keep");
    assert_eq!(
        fs::read(home.join("updates-msi-v1/unknown")).unwrap(),
        b"keep"
    );
}

#[test]
fn an_oversized_transaction_is_not_partially_cleaned() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let staging = UpdateStaging::create(&home, Uuid::new_v4()).unwrap();
    for index in 0..9 {
        staging
            .directory()
            .write()
            .unwrap()
            .replace(&format!("part-{index}"), b"keep", 4)
            .unwrap();
    }
    let root = staging.root().to_path_buf();
    drop(staging);
    assert!(matches!(
        UpdateStaging::recover(&home),
        Err(StagingError::Recovery {
            completed: 0,
            source: StorageError::TooManyEntries { maximum: 8 },
        })
    ));
    for index in 0..9 {
        assert_eq!(
            fs::read(root.join(format!("part-{index}"))).unwrap(),
            b"keep"
        );
    }
}

#[test]
fn process_exit_without_rust_cleanup_leaves_a_recoverable_partial_download() {
    const ROOT: &str = "CFW_UPDATE_STAGING_EXIT_TEST_ROOT";
    if let Some(home) = std::env::var_os(ROOT) {
        let staging = UpdateStaging::create(Path::new(&home), Uuid::from_u128(17)).unwrap();
        let mut download = staging
            .directory()
            .begin_stream("package.msi", ".package.partial.tmp", 64)
            .unwrap();
        download.write_chunk(b"partial unverified bytes").unwrap();
        // Intentionally bypass every Rust destructor. The kernel closes the
        // process's handles, as it would for an interrupted download owner.
        std::process::exit(41);
    }
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_exit_without_rust_cleanup_leaves_a_recoverable_partial_download",
        ])
        .env(ROOT, &home)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(41),
        "child stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let root = home
        .join("updates-msi-v1")
        .join(Uuid::from_u128(17).to_string());
    absent(&root.join("package.msi"));
    assert_eq!(
        fs::read(root.join(".package.partial.tmp")).unwrap(),
        b"partial unverified bytes"
    );
    assert_eq!(UpdateStaging::recover(&home).unwrap(), 1);
    absent(&root);
}
