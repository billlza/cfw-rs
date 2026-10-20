#![cfg(windows)]

use cfw_windows_engine::{
    Error,
    runtime_host::{InstalledRuntime, MSI_UPGRADE_CODE},
    update_package::{
        AuthenticodePublisher, InspectedMsi, PackageError, UpdateStaging, WorkerFailureCategory,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

fn fixture(name: &str) -> PathBuf {
    assert_eq!(
        std::env::var("CFW_NATIVE_PACKAGE_TESTS").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("CFW_NATIVE_PACKAGE_FIXTURES").unwrap());
    assert!(root.is_absolute());
    root.join(name)
}

fn inspect(path: &Path, directory: &Path) -> Result<InspectedMsi, PackageError> {
    InstalledRuntime::open()
        .unwrap()
        .package_inspector()
        .unwrap()
        .inspect(path, "0.5.0", directory, Duration::from_secs(30), || false)
}

#[test]
fn protected_installed_release_has_a_build_floor_and_distinct_msi_identities() {
    let installed = InstalledRuntime::open().unwrap();
    let release = installed.release();
    assert_eq!(release.version, "0.5.0");
    assert_eq!(release.build, 1);
    assert_eq!(
        release.product_code,
        "{6D762E56-384D-4203-8520-A9B83D0F0652}"
    );
    assert_eq!(
        release.package_code,
        "{C1BB0951-CB20-43FC-8ECA-AC8AC63F0A12}"
    );
    assert_ne!(release.product_code, MSI_UPGRADE_CODE);
    assert_ne!(release.package_code, MSI_UPGRADE_CODE);
    installed.runtime().unwrap();
    installed.desktop().unwrap();
    installed.engine().unwrap();
    assert!(installed.require_desktop_process().is_err());
    assert!(installed.require_runtime_process().is_err());
}

#[test]
fn the_installed_worker_verifies_a_real_signed_unicode_msi() {
    let temporary = tempfile::tempdir().unwrap();
    let staged =
        UpdateStaging::create(&temporary.path().join("校验 进程"), uuid::Uuid::new_v4()).unwrap();
    let fixture_bytes = fs::read(fixture("有效 安装包.msi")).unwrap();
    let mut download = staged
        .directory()
        .begin_stream("package.msi", ".package.copy.tmp", 192 * 1024 * 1024)
        .unwrap();
    for chunk in fixture_bytes.chunks(32 * 1024) {
        download.write_chunk(chunk).unwrap();
    }
    // This is a local fixture copy, not the network/Minisign download boundary.
    download.commit().unwrap();
    let path = staged.package();
    let package = inspect(&path, staged.root()).unwrap();
    assert_eq!(package.path(), path);
    assert_eq!(package.identity().version, "0.5.0");
    assert_eq!(package.identity().build, 2);
    assert_eq!(package.identity().architecture, "x64");
    assert_eq!(package.identity().minimum_windows_version, "10.0.19041");
    assert_eq!(
        package.publisher(),
        &AuthenticodePublisher::observe(&fixture("publisher.exe")).unwrap()
    );
    let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
    assert_eq!(package.sha256(), digest);
    let fixture_digest: [u8; 32] = Sha256::digest(&fixture_bytes).into();
    assert_eq!(digest, fixture_digest);
    drop(package);
    staged.remove().unwrap();
    assert!(!path.try_exists().unwrap());
}

#[test]
fn worker_rejections_preserve_signature_and_release_failure_categories() {
    for (name, expected) in [
        ("unsigned.msi", WorkerFailureCategory::Authenticity),
        ("tampered.msi", WorkerFailureCategory::Authenticity),
        ("untrusted.msi", WorkerFailureCategory::Authenticity),
        ("other-publisher.msi", WorkerFailureCategory::Authenticity),
        ("wrong-release.msi", WorkerFailureCategory::Package),
        ("wrong-product.msi", WorkerFailureCategory::Package),
        ("replayed-build.msi", WorkerFailureCategory::Package),
        ("future-windows.msi", WorkerFailureCategory::Package),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        match inspect(&fixture(name), &temporary.path().join("worker")) {
            Err(PackageError::WorkerRejected { category, detail }) => {
                assert_eq!(category, expected, "{name}: {detail}");
                assert!(!detail.is_empty());
                assert!(detail.len() <= 512);
            }
            Err(error) => panic!("wrong rejection for {name}: {error}"),
            Ok(_) => panic!("invalid candidate accepted: {name}"),
        }
    }
}

#[test]
fn the_parent_keeps_the_inspected_file_and_ancestors_pinned_after_worker_exit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("candidate.msi");
    fs::copy(fixture("有效 安装包.msi"), &path).unwrap();
    let package = inspect(&path, &temporary.path().join("worker")).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    assert!(fs::rename(&path, temporary.path().join("changed.msi")).is_err());
    assert!(fs::rename(temporary.path(), temporary.path().with_extension("moved")).is_err());
    drop(package);
    fs::rename(&path, temporary.path().join("changed.msi")).unwrap();
}

#[test]
fn hardlinked_input_and_precreation_cancellation_do_not_launch_a_worker() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("worker");
    let inspector = InstalledRuntime::open()
        .unwrap()
        .package_inspector()
        .unwrap();
    let result = inspector.inspect(
        &fixture("有效 安装包.msi"),
        "0.5.0",
        &directory,
        Duration::from_secs(30),
        || true,
    );
    assert!(matches!(result, Err(PackageError::File(Error::Cancelled))));
    assert!(!directory.exists());
    let path = temporary.path().join("candidate.msi");
    fs::copy(fixture("有效 安装包.msi"), &path).unwrap();
    fs::hard_link(&path, temporary.path().join("alias.msi")).unwrap();
    assert!(matches!(
        inspect(&path, &directory),
        Err(PackageError::File(Error::ExecutableIdentity))
    ));
    assert!(!directory.exists());
}
