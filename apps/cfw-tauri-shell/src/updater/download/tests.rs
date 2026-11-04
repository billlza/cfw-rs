use std::fs;
#[cfg(windows)]
use std::io::Write as _;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt as _;

use futures_util::stream;

use super::*;

// The published minisign pre-hashed test vector, also used by
// scripts/tests/test_release_verifier_reproducibility.py. It signs the
// four bytes "test" and names the archive "test".
const TEST_PUBLIC_KEY: &str = concat!(
    "untrusted comment: minisign public key E7620F1842B4E81F\n",
    "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
);
const TEST_SIGNATURE: &str = concat!(
    "untrusted comment: signature from minisign secret key\n",
    "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/",
    "z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n",
    "trusted comment: timestamp:1556193335\tfile:test\n",
    "y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1",
    "FkZZSNCisQbuQY+bHwhEBg==",
);
const V035_SIGNATURE: &str = concat!(
    "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkK",
    "UlVUZElOVklSNGhuUVgrL3NFZk9VN0NkckJxbmxiVmFUcXl2QnQyUU9NYTVidm5MZjBD",
    "K2tIeTM5Yzd6YzZ2U3JuVU1zcFRxZ3dBZ2gwV256bUM1UnVhc0Jnek90eGl2Q0FrPQp0",
    "cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg0NjM5ODc0CWZpbGU6Q2xhc2guZm9y",
    "Lk1hY18wLjMuNV9hYXJjaDY0LmFwcC50YXIuZ3oKckhKallPaXFqTjJIUDVxTDdYZzRI",
    "dldMNWl0akhqMGwxZkU4Yi8rZDMxNXBlUVBxVjgwejdxbDBIMm5kb0JaSW9vWDBRZW5v",
    "Y1U5UFVGMHJNMXRZQnc9PQo="
);

fn test_key() -> PublicKey {
    PublicKey::decode(TEST_PUBLIC_KEY).expect("test public key")
}

fn authorization(archive_name: &str) -> UpdateAuthorization {
    UpdateAuthorization {
        version: "9.9.9".into(),
        archive_name: archive_name.into(),
        download_url: "https://github.com/billlza/cfw-rs/releases/download/v9.9.9/test".into(),
        signature: STANDARD.encode(TEST_SIGNATURE),
    }
}

#[test]
fn offline_handoff_rechecks_bytes_signature_archive_name_and_size() {
    let key = test_key();
    let auth = authorization("test");
    assert_eq!(
        verify_archive_reader(&key, &auth, &b"test"[..], 4).unwrap(),
        <[u8; 32]>::from(Sha256::digest(b"test"))
    );
    for bytes in [&b"tesT"[..], &b"tes"[..], &b"test!"[..]] {
        assert!(matches!(
            verify_archive_reader(&key, &auth, bytes, 16),
            Err(UpdateError::SignatureVerification)
        ));
    }
    assert!(matches!(
        verify_archive_reader(&key, &authorization("another"), &b"test"[..], 4),
        Err(UpdateError::SignatureArchiveMismatch)
    ));
    assert!(matches!(
        verify_archive_reader(&key, &auth, &b"test"[..], 3),
        Err(UpdateError::ArchiveTooLarge { maximum: 3 })
    ));
}

fn bounds(declared_length: Option<u64>) -> ArchiveBounds {
    ArchiveBounds {
        declared_length,
        maximum: 1024,
        stall_timeout: Duration::from_secs(30),
    }
}

fn chunks(parts: &[&[u8]]) -> impl Stream<Item = Result<Vec<u8>>> {
    stream::iter(
        parts
            .iter()
            .map(|part| Ok(part.to_vec()))
            .collect::<Vec<_>>(),
    )
}

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let guard = tempfile::tempdir().expect("scratch");
    #[cfg(target_os = "macos")]
    let root = guard.path().to_owned();
    #[cfg(windows)]
    let root = {
        let root = guard.path().join("private");
        cfw_windows_storage::PrivateDirectory::open_or_create(&root).expect("private staging");
        root
    };
    (guard, root)
}

async fn receive(
    key: &PublicKey,
    authorization: &UpdateAuthorization,
    bounds: ArchiveBounds,
    parts: &[&[u8]],
    destination: &Path,
) -> Result<[u8; 32]> {
    receive_verified_archive(
        key,
        authorization,
        bounds,
        chunks(parts),
        destination,
        &DownloadCancellation::new(),
        |_, _| Ok(()),
    )
    .await
}

#[tokio::test]
async fn an_archive_matching_its_signature_is_kept_privately() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive.tar.gz");
    let mut progress = Vec::new();
    let received = receive_verified_archive(
        &test_key(),
        &authorization("test"),
        bounds(Some(4)),
        chunks(&[b"te", b"st"]),
        &destination,
        &DownloadCancellation::new(),
        |downloaded, total| {
            progress.push((downloaded, total));
            Ok(())
        },
    )
    .await
    .expect("verified archive");
    // SHA-256("test"), independent of the destination and stream chunks.
    assert_eq!(
        received,
        [
            0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a,
            0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15,
            0xb0, 0xf0, 0x0a, 0x08,
        ]
    );
    assert_eq!(progress, [(2, Some(4)), (4, Some(4))]);
    assert_eq!(fs::read(&destination).expect("archive"), b"test");
    #[cfg(target_os = "macos")]
    assert_eq!(
        fs::metadata(&destination)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    #[cfg(windows)]
    cfw_windows_storage::validate_private_file(&fs::File::open(&destination).expect("file"))
        .expect("private archive security");
}

#[tokio::test]
async fn altered_truncated_or_extended_bytes_fail_verification_and_leave_no_file() {
    let (_guard, scratch) = scratch();
    let key = test_key();
    let cases: [&[&[u8]]; 4] = [&[b"tesT"], &[b"tes"], &[b"test", b"!"], &[b"TEST"]];
    for (index, parts) in cases.into_iter().enumerate() {
        let destination = scratch.join(format!("archive-{index}"));
        let outcome = receive(
            &key,
            &authorization("test"),
            bounds(None),
            parts,
            &destination,
        )
        .await;
        assert!(
            matches!(outcome, Err(UpdateError::SignatureVerification)),
            "{parts:?}: {outcome:?}"
        );
        assert!(
            !destination.exists(),
            "{parts:?} left an unauthenticated file"
        );
    }
}

#[tokio::test]
async fn a_signature_for_another_archive_name_is_refused_before_any_byte_is_stored() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive");
    let outcome = receive(
        &test_key(),
        &authorization("Clash.for.Mac_9.9.9_aarch64.app.tar.gz"),
        bounds(None),
        &[b"test"],
        &destination,
    )
    .await;
    assert!(matches!(
        outcome,
        Err(UpdateError::SignatureArchiveMismatch)
    ));
    assert!(!destination.exists());
}

#[tokio::test]
async fn a_signature_from_another_key_is_refused() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive");
    let release_key = embedded_public_key().expect("release key");
    let outcome = receive(
        &release_key,
        &authorization("test"),
        bounds(None),
        &[b"test"],
        &destination,
    )
    .await;
    assert!(matches!(outcome, Err(UpdateError::SignatureVerification)));
    assert!(!destination.exists());
}

#[tokio::test]
async fn size_bounds_are_enforced_before_and_during_the_transfer() {
    let (_guard, scratch) = scratch();
    let key = test_key();
    let destination = scratch.join("archive");
    let tight = ArchiveBounds {
        maximum: 3,
        ..bounds(None)
    };
    assert!(matches!(
        receive(
            &key,
            &authorization("test"),
            tight,
            &[b"test"],
            &destination
        )
        .await,
        Err(UpdateError::ArchiveTooLarge { maximum: 3 })
    ));
    assert!(!destination.exists());

    let declared = bounds(Some(2048));
    assert!(matches!(
        receive(
            &key,
            &authorization("test"),
            declared,
            &[b"test"],
            &destination
        )
        .await,
        Err(UpdateError::DeclaredArchiveTooLarge {
            declared: 2048,
            maximum: 1024,
        })
    ));
    assert!(!destination.exists());

    assert!(matches!(
        receive(
            &key,
            &authorization("test"),
            bounds(Some(5)),
            &[b"test"],
            &destination
        )
        .await,
        Err(UpdateError::ArchiveLengthMismatch {
            declared: 5,
            actual: 4,
        })
    ));
    assert!(!destination.exists());

    assert!(matches!(
        receive(
            &key,
            &authorization("test"),
            bounds(None),
            &[],
            &destination
        )
        .await,
        Err(UpdateError::EmptyArchive)
    ));
    assert!(!destination.exists());
}

#[tokio::test]
async fn cancellation_and_transfer_errors_remove_the_partial_file() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive");
    let cancellation = DownloadCancellation::new();
    cancellation.cancel();
    let cancelled = receive_verified_archive(
        &test_key(),
        &authorization("test"),
        bounds(None),
        chunks(&[b"test"]),
        &destination,
        &cancellation,
        |_, _| Ok(()),
    )
    .await;
    assert!(matches!(cancelled, Err(UpdateError::DownloadCancelled)));
    assert!(!destination.exists());

    let failing = stream::iter(vec![
        Ok(b"te".to_vec()),
        Err(UpdateError::HttpStatus(reqwest::StatusCode::BAD_GATEWAY)),
    ]);
    let failed = receive_verified_archive(
        &test_key(),
        &authorization("test"),
        bounds(None),
        failing,
        &destination,
        &DownloadCancellation::new(),
        |_, _| Ok(()),
    )
    .await;
    assert!(matches!(failed, Err(UpdateError::HttpStatus(_))));
    assert!(!destination.exists());

    let progress_failure = receive_verified_archive(
        &test_key(),
        &authorization("test"),
        bounds(None),
        chunks(&[b"test"]),
        &destination,
        &DownloadCancellation::new(),
        |_, _| Err(UpdateError::ProgressEvent),
    )
    .await;
    assert!(matches!(progress_failure, Err(UpdateError::ProgressEvent)));
    assert!(!destination.exists());
}

#[tokio::test]
async fn a_transfer_that_stops_delivering_bytes_is_a_timeout_and_leaves_nothing() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive");
    let stalled = stream::iter(vec![Ok(b"te".to_vec())]).chain(stream::pending());
    let started = std::time::Instant::now();
    let outcome = receive_verified_archive(
        &test_key(),
        &authorization("test"),
        ArchiveBounds {
            stall_timeout: Duration::from_millis(80),
            ..bounds(None)
        },
        stalled,
        &destination,
        &DownloadCancellation::new(),
        |_, _| Ok(()),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(UpdateError::Network {
                stage: DownloadFailureStage::ArchiveBody,
                category: NetworkFailureCategory::Timeout,
                status_code: None,
            })
        ),
        "{outcome:?}"
    );
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert!(!destination.exists());
}

#[tokio::test]
async fn an_existing_destination_is_never_overwritten() {
    let (_guard, scratch) = scratch();
    let destination = scratch.join("archive");
    #[cfg(target_os = "macos")]
    fs::write(&destination, b"earlier").expect("existing file");
    #[cfg(windows)]
    cfw_windows_storage::PrivateDirectory::open_existing(&scratch)
        .expect("directory")
        .expect("present")
        .write()
        .expect("transaction")
        .create_private_output("archive")
        .expect("existing file")
        .write_all(b"earlier")
        .expect("existing bytes");
    let outcome = receive(
        &test_key(),
        &authorization("test"),
        bounds(None),
        &[b"test"],
        &destination,
    )
    .await;
    #[cfg(target_os = "macos")]
    assert!(matches!(
        outcome,
        Err(UpdateError::Staging {
            stage: "create-archive",
            kind: std::io::ErrorKind::AlreadyExists,
        })
    ));
    #[cfg(windows)]
    assert!(matches!(
        outcome,
        Err(UpdateError::WindowsStorage {
            stage: "create-archive",
            source: cfw_windows_storage::Error::Io(error),
        }) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(&destination).expect("untouched"), b"earlier");
}

#[test]
fn redirect_policy_accepts_one_github_asset_redirect_only() {
    let expected = "https://github.com/billlza/cfw-rs/releases/download/v1.2.3/asset.tar.gz";
    let previous = [Url::parse(expected).expect("initial URL")];
    let allowed = Url::parse(
        "https://release-assets.githubusercontent.com/github-production-release-asset/12345/abcdef?sp=r&sig=test",
    )
    .expect("asset URL");
    assert_eq!(validate_redirect(expected, &previous, &allowed), Ok(()));

    let two_hops = [previous[0].clone(), allowed.clone()];
    assert!(validate_redirect(expected, &two_hops, &allowed).is_err());
    let wrong_origin =
        Url::parse("https://example.com/github-production-release-asset/12345/abcdef?sig=test")
            .expect("wrong origin URL");
    assert!(validate_redirect(expected, &previous, &wrong_origin).is_err());
    let other_start = [Url::parse("https://github.com/other/asset.tar.gz").expect("URL")];
    assert!(validate_redirect(expected, &other_start, &allowed).is_err());
}

#[test]
fn embedded_release_public_key_decodes() {
    embedded_public_key().expect("the release public key must decode");
}

#[test]
fn signed_archive_name_must_match_the_authorized_release() {
    let signature = decode_signature(V035_SIGNATURE).expect("historical signature");
    validate_signature_archive(&signature, "Clash.for.Mac_0.3.5_aarch64.app.tar.gz")
        .expect("matching signed archive name");
    assert!(matches!(
        validate_signature_archive(&signature, "Clash.for.Mac_0.4.0_aarch64.app.tar.gz"),
        Err(UpdateError::SignatureArchiveMismatch)
    ));
    assert!(matches!(
        decode_signature("%%%"),
        Err(UpdateError::InvalidSignature)
    ));
    assert!(matches!(
        decode_signature(&STANDARD.encode("not a signature envelope")),
        Err(UpdateError::InvalidSignature)
    ));
}

#[test]
fn trusted_comment_parser_requires_one_canonical_timestamp_and_file() {
    assert_eq!(
        parse_trusted_comment("timestamp:1784639874\tfile:archive.tar.gz")
            .expect("canonical comment"),
        "archive.tar.gz"
    );
    for comment in [
        "file:archive.tar.gz\ttimestamp:1784639874",
        "timestamp:now\tfile:archive.tar.gz",
        "timestamp:01784639874\tfile:archive.tar.gz",
        "timestamp:18446744073709551616\tfile:archive.tar.gz",
        "timestamp:1784639874\tfile:..",
        "timestamp:1784639874\tfile:../archive.tar.gz",
        "timestamp:1784639874\tfile:archive.tar.gz\tfile:second.tar.gz",
        "timestamp:1784639874\tfile:archive.tar.gz\nfile:second.tar.gz",
        "timestamp:1784639874",
        "",
    ] {
        assert!(
            matches!(
                parse_trusted_comment(comment),
                Err(UpdateError::InvalidSignatureComment)
            ),
            "malformed trusted comment was accepted: {comment:?}"
        );
    }
}

#[test]
fn signature_failures_do_not_echo_untrusted_content() {
    let secret = "must-not-reach-diagnostics";
    let oversized = format!("timestamp:1784639874\tfile:{secret}{}", "a".repeat(1024));
    for comment in [
        oversized,
        format!("timestamp:1784639874\tfile:{secret}\u{0007}.tar.gz"),
        format!("timestamp:1784639874\tfile:{secret}/archive.tar.gz"),
    ] {
        let diagnostic = parse_trusted_comment(&comment)
            .expect_err("untrusted comment must be rejected")
            .to_string();
        assert!(!diagnostic.contains(secret));
    }
    assert!(
        !UpdateError::SignatureArchiveMismatch
            .to_string()
            .contains(secret)
    );
}
