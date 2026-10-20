#![cfg(windows)]

use cfw_windows_engine::update_package::{
    AuthenticodePublisher, InspectedMsi, PackageError, PackageExpectation,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn fixture(name: &str) -> PathBuf {
    assert_eq!(
        std::env::var("CFW_NATIVE_PACKAGE_TESTS").as_deref(),
        Ok("1"),
        "native package tests require explicitly provisioned disposable fixtures"
    );
    let root = PathBuf::from(std::env::var_os("CFW_NATIVE_PACKAGE_FIXTURES").unwrap());
    assert!(root.is_absolute());
    root.join(name)
}

fn publisher() -> AuthenticodePublisher {
    AuthenticodePublisher::observe(&fixture("publisher.exe")).unwrap()
}

fn expectation() -> PackageExpectation {
    PackageExpectation::new("0.5.0", 1, "10.0.26100").unwrap()
}

fn rejection(name: &str) -> PackageError {
    match InspectedMsi::inspect(&fixture(name), &publisher(), &expectation()) {
        Ok(_) => panic!("invalid package was admitted: {name}"),
        Err(error) => error,
    }
}

#[test]
fn native_authenticode_and_msi_identity_match_the_requested_release() {
    let publisher = publisher();
    let path = fixture("有效 安装包.msi");
    let package = InspectedMsi::inspect(&path, &publisher, &expectation()).unwrap();
    assert_eq!(package.path(), path);
    assert_eq!(package.identity().version, "0.5.0");
    assert_eq!(package.identity().build, 2);
    assert_eq!(package.identity().architecture, "x64");
    assert_eq!(package.identity().minimum_windows_version, "10.0.19041");
    assert_eq!(package.publisher(), &publisher);
    let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
    assert_eq!(package.sha256(), digest);
    assert_ne!(publisher.spki_sha256(), [0u8; 32]);
}

#[test]
fn a_trusted_certificate_with_the_same_subject_but_another_key_is_not_the_publisher() {
    let other = AuthenticodePublisher::observe(&fixture("other-publisher.exe")).unwrap();
    assert_ne!(other, publisher());
    assert!(matches!(
        rejection("other-publisher.msi"),
        PackageError::PublisherMismatch
    ));
}

#[test]
fn unsigned_tampered_and_untrusted_signatures_fail_before_metadata_is_admitted() {
    for name in ["unsigned.msi", "tampered.msi", "untrusted.msi"] {
        assert!(
            matches!(rejection(name), PackageError::Signature(_)),
            "{name}"
        );
    }
    assert!(AuthenticodePublisher::observe(&fixture("unsigned.exe")).is_err());
}

#[test]
fn signed_wrong_product_scope_restart_policy_and_package_identities_are_rejected() {
    for name in [
        "wrong-product.msi",
        "wrong-name.msi",
        "wrong-upgrade.msi",
        "per-user.msi",
        "automatic-shutdown.msi",
        "wrong-msi-version.msi",
        "wrong-product-code.msi",
        "wrong-package-code.msi",
        "reused-code.msi",
        "wrong-architecture.msi",
        "multiple-architectures.msi",
        "bad-language.msi",
        "noncanonical-build.msi",
        "zero-build.msi",
        "overflow-build.msi",
        "invalid-minimum-os.msi",
        "oversized-product.msi",
    ] {
        assert!(
            matches!(rejection(name), PackageError::Invalid(_)),
            "{name}"
        );
    }
    assert!(matches!(
        rejection("missing-product.msi"),
        PackageError::Native { .. }
    ));
}

#[test]
fn signed_release_build_and_os_requirements_are_enforced() {
    for (name, expected) in [
        ("wrong-release.msi", "requested release version"),
        ("replayed-build.msi", "newer build number"),
        ("future-windows.msi", "minimum Windows version"),
    ] {
        assert!(
            matches!(rejection(name), PackageError::Requirement(reason) if reason == expected),
            "{name}"
        );
    }
}

#[test]
fn inspected_package_cannot_be_written_deleted_or_replaced_until_released() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("candidate.msi");
    fs::copy(fixture("有效 安装包.msi"), &path).unwrap();
    let held = InspectedMsi::inspect(&path, &publisher(), &expectation()).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    let renamed = temporary.path().join("renamed.msi");
    assert!(fs::rename(&path, &renamed).is_err());
    assert!(fs::rename(temporary.path(), temporary.path().with_extension("moved")).is_err());
    drop(held);
    fs::rename(&path, &renamed).unwrap();
    fs::remove_file(&renamed).unwrap();
}

#[test]
fn hardlinked_and_ambiguous_candidate_paths_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("candidate.msi");
    fs::copy(fixture("有效 安装包.msi"), &path).unwrap();
    fs::hard_link(&path, temporary.path().join("alias.msi")).unwrap();
    assert!(InspectedMsi::inspect(&path, &publisher(), &expectation()).is_err());
    assert!(
        InspectedMsi::inspect(
            &fixture("unused/../有效 安装包.msi"),
            &publisher(),
            &expectation()
        )
        .is_err()
    );
    assert!(
        InspectedMsi::inspect(
            &PathBuf::from("candidate.msi"),
            &publisher(),
            &expectation()
        )
        .is_err()
    );
}

#[test]
fn caller_policy_rejects_noncanonical_or_unrepresentable_versions() {
    for version in ["0.5", "v0.5.0", "0.05.0", "256.0.0", "0.256.0", "0.5.65536"] {
        assert!(
            PackageExpectation::new(version, 0, "10.0.19041").is_err(),
            "{version}"
        );
    }
    for system in [
        "10",
        "10.0",
        "10.0.019041",
        "10.0.19041.1",
        "0.0.1",
        "-1.0.1",
    ] {
        assert!(
            PackageExpectation::new("0.5.0", 0, system).is_err(),
            "{system}"
        );
    }
    assert!(PackageExpectation::new("0.5.0-rc.1", 0, "10.0.19041").is_ok());
}
