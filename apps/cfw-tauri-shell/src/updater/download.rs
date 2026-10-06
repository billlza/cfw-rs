use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::{Stream, StreamExt as _};
use minisign_verify::{PublicKey, Signature};
use reqwest::Url;
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;

use super::contract::UpdateAuthorization;
use super::error::{DownloadFailureStage, NetworkFailureCategory, Result, UpdateError};
use super::metadata::{
    CONNECT_TIMEOUT, USER_AGENT, sanitized_network_error, validate_release_asset_url,
};
use super::state::DownloadCancellation;
use crate::transport_security::external_https_client_builder;

// Keep this release/runtime contract aligned with scripts/make_updater_manifest.sh.
pub(super) const MAX_UPDATE_ARCHIVE_BYTES: u64 = 192 * 1024 * 1024;
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// A transfer that delivers nothing for this long has stalled; the whole
/// request is bounded separately.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
const EMBEDDED_TAURI_CONFIG: &str = include_str!("../../tauri.conf.json");
const MAX_TRUSTED_COMMENT_BYTES: usize = 1024;
const MAX_ARCHIVE_NAME_BYTES: usize = 255;

/// Downloads the authorized archive into `destination` and returns its size.
///
/// The file exists afterwards only if every byte was received within bounds
/// and the complete stream matches the release signature for exactly this
/// archive name. Nothing parses the archive before that.
pub(super) async fn download_verified_archive<F>(
    authorization: &UpdateAuthorization,
    destination: &Path,
    cancellation: &DownloadCancellation,
    on_progress: F,
) -> Result<u64>
where
    F: FnMut(u64, Option<u64>) -> Result<()>,
{
    let public_key = embedded_public_key()?;
    let expected_url = authorization.download_url.clone();
    let client = external_https_client_builder()
        .map_err(|_| UpdateError::TlsProviderUnavailable)?
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .redirect(Policy::custom(move |attempt| {
            match validate_redirect(&expected_url, attempt.previous(), attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        }))
        .build()
        .map_err(|error| sanitized_network_error(DownloadFailureStage::ClientBuild, &error))?;

    let request = client
        .get(&authorization.download_url)
        .header(ACCEPT, "application/octet-stream")
        .send();
    tokio::pin!(request);
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
        response = &mut request => response.map_err(|error| {
            sanitized_network_error(DownloadFailureStage::ArchiveRequest, &error)
        })?,
    };
    if response.url().as_str() != authorization.download_url {
        validate_release_asset_url(response.url()).map_err(UpdateError::Redirect)?;
    }
    if !response.status().is_success() {
        return Err(UpdateError::HttpStatus(response.status()));
    }
    let declared_length = response.content_length();
    let chunks = response.bytes_stream().map(|chunk| {
        chunk.map_err(|error| sanitized_network_error(DownloadFailureStage::ArchiveBody, &error))
    });
    receive_verified_archive(
        &public_key,
        authorization,
        ArchiveBounds {
            declared_length,
            maximum: MAX_UPDATE_ARCHIVE_BYTES,
            stall_timeout: STALL_TIMEOUT,
        },
        chunks,
        destination,
        cancellation,
        on_progress,
    )
    .await
}

#[derive(Debug, Clone, Copy)]
struct ArchiveBounds {
    declared_length: Option<u64>,
    maximum: u64,
    stall_timeout: Duration,
}

async fn receive_verified_archive<S, B, F>(
    public_key: &PublicKey,
    authorization: &UpdateAuthorization,
    bounds: ArchiveBounds,
    chunks: S,
    destination: &Path,
    cancellation: &DownloadCancellation,
    mut on_progress: F,
) -> Result<u64>
where
    S: Stream<Item = Result<B>>,
    B: AsRef<[u8]>,
    F: FnMut(u64, Option<u64>) -> Result<()>,
{
    let signature = decode_signature(&authorization.signature)?;
    // Reject an obviously replayed signature before any transfer. The same
    // check is repeated after finalize(), when the comment is authenticated.
    validate_signature_archive(&signature, &authorization.archive_name)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| UpdateError::SignatureVerification)?;
    if let Some(declared) = bounds.declared_length
        && declared > bounds.maximum
    {
        return Err(UpdateError::DeclaredArchiveTooLarge {
            declared,
            maximum: bounds.maximum,
        });
    }

    let mut partial = PartialArchive::create(destination)?;
    let mut received = 0_u64;
    tokio::pin!(chunks);
    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
            next = tokio::time::timeout(bounds.stall_timeout, chunks.next()) => {
                next.map_err(|_| UpdateError::Network {
                    stage: DownloadFailureStage::ArchiveBody,
                    category: NetworkFailureCategory::Timeout,
                    status_code: None,
                })?
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk?;
        let chunk = chunk.as_ref();
        received = received
            .checked_add(chunk.len() as u64)
            .filter(|total| *total <= bounds.maximum)
            .ok_or(UpdateError::ArchiveTooLarge {
                maximum: bounds.maximum,
            })?;
        partial.write(chunk)?;
        verifier.update(chunk);
        on_progress(received, bounds.declared_length)?;
    }
    if received == 0 {
        return Err(UpdateError::EmptyArchive);
    }
    if let Some(declared) = bounds.declared_length
        && declared != received
    {
        return Err(UpdateError::ArchiveLengthMismatch {
            declared,
            actual: received,
        });
    }
    verifier
        .finalize()
        .map_err(|_| UpdateError::SignatureVerification)?;
    validate_signature_archive(&signature, &authorization.archive_name)?;
    partial.commit()?;
    Ok(received)
}

/// The archive file while it is still unauthenticated. Dropping it without
/// `commit` removes the file, so no failed transfer leaves bytes behind.
struct PartialArchive {
    path: PathBuf,
    file: Option<File>,
}

impl PartialArchive {
    fn create(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(staging_error("create-archive"))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.file
            .as_mut()
            .expect("an uncommitted archive keeps its file")
            .write_all(chunk)
            .map_err(staging_error("write-archive"))
    }

    fn commit(mut self) -> Result<()> {
        let file = self
            .file
            .take()
            .expect("an uncommitted archive keeps its file");
        if let Err(error) = file.sync_all() {
            self.file = Some(file);
            return Err(staging_error("sync-archive")(error));
        }
        Ok(())
    }
}

impl Drop for PartialArchive {
    fn drop(&mut self) {
        if self.file.take().is_some()
            && let Err(error) = fs::remove_file(&self.path)
        {
            eprintln!("failed to remove an unauthenticated update archive: {error}");
        }
    }
}

fn staging_error(stage: &'static str) -> impl Fn(std::io::Error) -> UpdateError {
    move |error| UpdateError::Staging {
        stage,
        kind: error.kind(),
    }
}

fn validate_redirect(
    expected_url: &str,
    previous: &[Url],
    target: &Url,
) -> std::result::Result<(), String> {
    if previous.len() != 1 || previous[0].as_str() != expected_url {
        return Err("only one redirect from the canonical GitHub URL is allowed".into());
    }
    validate_release_asset_url(target)
}

fn embedded_public_key() -> Result<PublicKey> {
    let config: serde_json::Value =
        serde_json::from_str(EMBEDDED_TAURI_CONFIG).map_err(|_| UpdateError::InvalidPublicKey)?;
    let encoded = config
        .pointer("/plugins/updater/pubkey")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(UpdateError::InvalidPublicKey)?;
    let envelope = decode_base64_utf8(encoded).ok_or(UpdateError::InvalidPublicKey)?;
    PublicKey::decode(&envelope).map_err(|_| UpdateError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature> {
    let envelope = decode_base64_utf8(encoded).ok_or(UpdateError::InvalidSignature)?;
    Signature::decode(envelope.trim()).map_err(|_| UpdateError::InvalidSignature)
}

fn validate_signature_archive(signature: &Signature, expected_archive: &str) -> Result<()> {
    if parse_trusted_comment(signature.trusted_comment())? != expected_archive {
        return Err(UpdateError::SignatureArchiveMismatch);
    }
    Ok(())
}

// Keep this grammar identical to the release verifier in
// crates/cfw-release-verifier/src/main.rs, which is built in isolation and
// cannot share code with the application. Minisign authenticates this trusted
// comment only when stream finalization succeeds.
fn parse_trusted_comment(comment: &str) -> Result<&str> {
    if comment.len() > MAX_TRUSTED_COMMENT_BYTES
        || comment
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let mut fields = comment.split('\t');
    let timestamp = fields
        .next()
        .and_then(|field| field.strip_prefix("timestamp:"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(UpdateError::InvalidSignatureComment)?;
    if timestamp.len() > 20
        || timestamp
            .parse::<u64>()
            .map_or(true, |parsed| parsed.to_string() != timestamp)
    {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let archive = fields
        .next()
        .and_then(|field| field.strip_prefix("file:"))
        .filter(|value| {
            !value.is_empty()
                && !matches!(*value, "." | "..")
                && value.len() <= MAX_ARCHIVE_NAME_BYTES
                && !value.contains(['/', '\\', ':'])
                && value.bytes().all(|byte| !byte.is_ascii_control())
        })
        .ok_or(UpdateError::InvalidSignatureComment)?;
    if fields.next().is_some() {
        return Err(UpdateError::InvalidSignatureComment);
    }
    Ok(archive)
}

fn decode_base64_utf8(encoded: &str) -> Option<String> {
    String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
}

#[cfg(test)]
mod tests {
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

    async fn receive(
        key: &PublicKey,
        authorization: &UpdateAuthorization,
        bounds: ArchiveBounds,
        parts: &[&[u8]],
        destination: &Path,
    ) -> Result<u64> {
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive.tar.gz");
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
        assert_eq!(received, 4);
        assert_eq!(progress, [(2, Some(4)), (4, Some(4))]);
        assert_eq!(fs::read(&destination).expect("archive"), b"test");
        let mode = fs::metadata(&destination)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn altered_truncated_or_extended_bytes_fail_verification_and_leave_no_file() {
        let scratch = tempfile::tempdir().expect("scratch");
        let key = test_key();
        let cases: [&[&[u8]]; 4] = [&[b"tesT"], &[b"tes"], &[b"test", b"!"], &[b"TEST"]];
        for (index, parts) in cases.into_iter().enumerate() {
            let destination = scratch.path().join(format!("archive-{index}"));
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive");
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive");
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
        let scratch = tempfile::tempdir().expect("scratch");
        let key = test_key();
        let destination = scratch.path().join("archive");
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive");
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive");
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
        let scratch = tempfile::tempdir().expect("scratch");
        let destination = scratch.path().join("archive");
        fs::write(&destination, b"earlier").expect("existing file");
        let outcome = receive(
            &test_key(),
            &authorization("test"),
            bounds(None),
            &[b"test"],
            &destination,
        )
        .await;
        assert!(matches!(
            outcome,
            Err(UpdateError::Staging {
                stage: "create-archive",
                kind: std::io::ErrorKind::AlreadyExists,
            })
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
}
