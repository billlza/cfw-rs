use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::StreamExt as _;
use minisign_verify::{PublicKey, Signature};
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use reqwest::{Client, Url};

use super::contract::UpdateAuthorization;
use super::error::{DownloadFailureStage, NetworkFailureCategory, Result, UpdateError};
use super::state::DownloadCancellation;

// Keep this release/runtime contract aligned with scripts/make_updater_manifest.sh.
pub(super) const MAX_UPDATE_ARCHIVE_BYTES: u64 = 192 * 1024 * 1024;
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const UPDATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UPDATE_USER_AGENT: &str = concat!("cfw-rs/", env!("CARGO_PKG_VERSION"));
const EMBEDDED_TAURI_CONFIG: &str = include_str!("../../tauri.conf.json");
const RELEASE_ASSET_HOST: &str = "release-assets.githubusercontent.com";
const RELEASE_ASSET_PATH_PREFIX: &str = "/github-production-release-asset/";
const MAX_TRUSTED_COMMENT_BYTES: usize = 1024;
const MAX_ARCHIVE_NAME_BYTES: usize = 255;

pub(super) async fn download_verified_update<F>(
    authorization: &UpdateAuthorization,
    cancellation: &DownloadCancellation,
    mut on_progress: F,
) -> Result<Vec<u8>>
where
    F: FnMut(u64, Option<u64>, Option<u64>) -> Result<()>,
{
    // Admit every response chunk against the project-owned bound before it
    // enters memory. The archive parser and installer run only after this
    // streaming signature verifier has authenticated the complete byte stream.
    let public_key = embedded_public_key()?;
    let signature = decode_signature(&authorization.signature)?;
    // Reject an obviously replayed archive before network I/O. The same check
    // is repeated after finalize(), when the trusted comment is authenticated.
    validate_signature_archive(&signature, &authorization.archive_name)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| UpdateError::InvalidSignature)?;
    let client = build_client(&authorization.download_url)?;
    let url = Url::parse(&authorization.download_url).map_err(|_| UpdateError::Network {
        stage: DownloadFailureStage::Request,
        category: NetworkFailureCategory::Request,
        status_code: None,
    })?;

    let request = client
        .get(url)
        .header(ACCEPT, "application/octet-stream")
        .send();
    tokio::pin!(request);
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
        response = &mut request => response.map_err(|error| {
            sanitized_network_error(DownloadFailureStage::Request, &error)
        })?,
    };
    validate_response_url(&authorization.download_url, response.url())?;
    if !response.status().is_success() {
        return Err(UpdateError::HttpStatus(response.status()));
    }

    let declared_length = response.content_length();
    let mut archive = BoundedArchive::new(declared_length, MAX_UPDATE_ARCHIVE_BYTES)?;
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
            next = stream.next() => next,
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk
            .map_err(|error| sanitized_network_error(DownloadFailureStage::ResponseBody, &error))?;
        archive.push(&chunk)?;
        verifier.update(&chunk);
        let downloaded = archive.len();
        let percent = declared_length
            .filter(|total| *total > 0)
            .map(|total| downloaded.saturating_mul(100) / total);
        on_progress(downloaded, declared_length, percent)?;
    }

    let bytes = archive.finish()?;
    verifier
        .finalize()
        .map_err(|_| UpdateError::SignatureVerification)?;
    validate_signature_archive(&signature, &authorization.archive_name)?;
    Ok(bytes)
}

fn build_client(expected_url: &str) -> Result<Client> {
    ensure_tls_crypto_provider()?;
    let expected_url = expected_url.to_owned();
    Client::builder()
        .user_agent(UPDATE_USER_AGENT)
        .connect_timeout(UPDATE_CONNECT_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .redirect(Policy::custom(move |attempt| {
            match validate_redirect(&expected_url, attempt.previous(), attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        }))
        .build()
        .map_err(|error| sanitized_network_error(DownloadFailureStage::ClientBuild, &error))
}

pub(super) fn ensure_tls_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A concurrent initializer may win this one-time process-global race.
        // Re-read below instead of interpreting that benign race as failure.
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(UpdateError::TlsProviderUnavailable);
    }
    Ok(())
}

pub(super) fn sanitized_network_error(
    stage: DownloadFailureStage,
    error: &reqwest::Error,
) -> UpdateError {
    let category = if error.is_timeout() {
        NetworkFailureCategory::Timeout
    } else if error.is_connect() {
        NetworkFailureCategory::Connect
    } else if error.is_status() {
        NetworkFailureCategory::Status
    } else if error.is_body() {
        NetworkFailureCategory::Body
    } else if error.is_decode() {
        NetworkFailureCategory::Decode
    } else if error.is_request() {
        NetworkFailureCategory::Request
    } else {
        NetworkFailureCategory::Other
    };
    UpdateError::Network {
        stage,
        category,
        status_code: error.status().map(|status| status.as_u16()),
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

fn validate_response_url(expected_url: &str, response_url: &Url) -> Result<()> {
    if response_url.as_str() == expected_url {
        return Ok(());
    }
    validate_release_asset_url(response_url).map_err(UpdateError::Redirect)
}

pub(super) fn validate_release_asset_url(url: &Url) -> std::result::Result<(), String> {
    if url.scheme() != "https"
        || url.host_str() != Some(RELEASE_ASSET_HOST)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err("redirect origin or authority is not allowed".into());
    }
    let path_tail = url
        .path()
        .strip_prefix(RELEASE_ASSET_PATH_PREFIX)
        .ok_or_else(|| "redirect path is not a GitHub release-asset path".to_string())?;
    let segments = path_tail.split('/').collect::<Vec<_>>();
    if segments.len() != 2
        || segments
            .iter()
            .any(|segment| segment.is_empty() || segment.contains('%'))
        || !segments[0].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("redirect path has an unexpected release-asset identifier".into());
    }
    if url.query().is_none_or(str::is_empty) {
        return Err("redirect is missing GitHub's signed asset query".into());
    }
    Ok(())
}

fn embedded_public_key() -> Result<PublicKey> {
    let config: serde_json::Value = serde_json::from_str(EMBEDDED_TAURI_CONFIG)
        .map_err(|_| UpdateError::InvalidPublicKey)?;
    let encoded = config
        .pointer("/plugins/updater/pubkey")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(UpdateError::InvalidPublicKey)?;
    let envelope = decode_base64_utf8(encoded).map_err(|()| UpdateError::InvalidPublicKey)?;
    PublicKey::decode(&envelope).map_err(|_| UpdateError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature> {
    let envelope = decode_base64_utf8(encoded).map_err(|()| UpdateError::InvalidSignature)?;
    Signature::decode(envelope.trim()).map_err(|_| UpdateError::InvalidSignature)
}

fn validate_signature_archive(signature: &Signature, expected_archive: &str) -> Result<()> {
    let actual_archive = parse_trusted_comment(signature.trusted_comment())?;
    if actual_archive != expected_archive {
        return Err(UpdateError::SignatureArchiveMismatch);
    }
    Ok(())
}

fn parse_trusted_comment(comment: &str) -> Result<&str> {
    if comment.len() > MAX_TRUSTED_COMMENT_BYTES
        || comment.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let mut fields = comment.split('\t');
    let timestamp = fields
        .next()
        .and_then(|field| field.strip_prefix("timestamp:"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(UpdateError::InvalidSignatureComment)?;
    if timestamp.len() > 20 {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let parsed_timestamp = timestamp
        .parse::<u64>()
        .map_err(|_| UpdateError::InvalidSignatureComment)?;
    if parsed_timestamp.to_string() != timestamp {
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

fn decode_base64_utf8(encoded: &str) -> std::result::Result<String, ()> {
    let bytes = STANDARD.decode(encoded).map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
}

struct BoundedArchive {
    bytes: Vec<u8>,
    declared_length: Option<u64>,
    maximum: u64,
    maximum_capacity: usize,
}

impl BoundedArchive {
    fn new(declared_length: Option<u64>, maximum: u64) -> Result<Self> {
        if let Some(declared) = declared_length
            && declared > maximum
        {
            return Err(UpdateError::DeclaredArchiveTooLarge { declared, maximum });
        }
        let maximum_capacity =
            usize::try_from(maximum).map_err(|_| UpdateError::ArchiveTooLarge { maximum })?;
        Ok(Self {
            bytes: Vec::new(),
            declared_length,
            maximum,
            maximum_capacity,
        })
    }

    fn push(&mut self, chunk: &[u8]) -> Result<()> {
        let chunk_length =
            u64::try_from(chunk.len()).map_err(|_| UpdateError::ArchiveTooLarge {
                maximum: self.maximum,
            })?;
        let next_length =
            self.len()
                .checked_add(chunk_length)
                .ok_or(UpdateError::ArchiveTooLarge {
                    maximum: self.maximum,
                })?;
        if next_length > self.maximum {
            return Err(UpdateError::ArchiveTooLarge {
                maximum: self.maximum,
            });
        }
        let required_capacity =
            usize::try_from(next_length).map_err(|_| UpdateError::ArchiveTooLarge {
                maximum: self.maximum,
            })?;
        self.reserve_bounded(required_capacity)?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn reserve_bounded(&mut self, required_capacity: usize) -> Result<()> {
        if required_capacity <= self.bytes.capacity() {
            return Ok(());
        }
        let growth_target = if self.bytes.capacity() == 0 {
            64 * 1024
        } else {
            self.bytes.capacity().saturating_mul(2)
        };
        let target_capacity = growth_target
            .max(required_capacity)
            .min(self.maximum_capacity);
        let additional = target_capacity.saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| UpdateError::ArchiveAllocation)
    }

    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn finish(self) -> Result<Vec<u8>> {
        let actual = self.len();
        if actual == 0 {
            return Err(UpdateError::EmptyArchive);
        }
        if let Some(declared) = self.declared_length
            && declared != actual
        {
            return Err(UpdateError::ContentLengthMismatch { declared, actual });
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V035_SIGNATURE: &str = concat!(
        "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkK",
        "UlVUZElOVklSNGhuUVgrL3NFZk9VN0NkckJxbmxiVmFUcXl2QnQyUU9NYTVidm5MZjBD",
        "K2tIeTM5Yzd6YzZ2U3JuVU1zcFRxZ3dBZ2gwV256bUM1UnVhc0Jnek90eGl2Q0FrPQp0",
        "cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg0NjM5ODc0CWZpbGU6Q2xhc2guZm9y",
        "Lk1hY18wLjMuNV9hYXJjaDY0LmFwcC50YXIuZ3oKckhKallPaXFqTjJIUDVxTDdYZzRI",
        "dldMNWl0akhqMGwxZkU4Yi8rZDMxNXBlUVBxVjgwejdxbDBIMm5kb0JaSW9vWDBRZW5v",
        "Y1U5UFVGMHJNMXRZQnc9PQo="
    );

    #[test]
    fn bounded_archive_accepts_the_exact_limit() {
        let mut archive = BoundedArchive::new(Some(4), 4).expect("bounded archive");
        archive.push(&[1, 2]).expect("first chunk");
        archive.push(&[3, 4]).expect("second chunk");
        assert_eq!(archive.finish().expect("complete archive"), [1, 2, 3, 4]);
    }

    #[test]
    fn bounded_archive_rejects_declared_and_streamed_overflow_before_copying() {
        assert!(matches!(
            BoundedArchive::new(Some(5), 4),
            Err(UpdateError::DeclaredArchiveTooLarge {
                declared: 5,
                maximum: 4
            })
        ));

        let mut archive = BoundedArchive::new(None, 4).expect("bounded archive");
        archive.push(&[1, 2, 3, 4]).expect("limit-sized chunk");
        assert!(matches!(
            archive.push(&[5]),
            Err(UpdateError::ArchiveTooLarge { maximum: 4 })
        ));
        assert_eq!(archive.len(), 4, "rejected bytes must not enter the buffer");
    }

    #[test]
    fn bounded_archive_rejects_empty_and_truncated_responses() {
        assert!(matches!(
            BoundedArchive::new(None, 4).expect("archive").finish(),
            Err(UpdateError::EmptyArchive)
        ));
        let mut archive = BoundedArchive::new(Some(4), 4).expect("archive");
        archive.push(&[1, 2, 3]).expect("partial body");
        assert!(matches!(
            archive.finish(),
            Err(UpdateError::ContentLengthMismatch {
                declared: 4,
                actual: 3
            })
        ));
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
    }

    #[test]
    fn redirect_policy_rejects_authority_path_and_query_variants() {
        let cases = [
            "http://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x",
            "https://user@release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x",
            "https://release-assets.githubusercontent.com:8443/github-production-release-asset/123/abc?sig=x",
            "https://release-assets.githubusercontent.com/not-release-assets/123/abc?sig=x",
            "https://release-assets.githubusercontent.com/github-production-release-asset/not-a-number/abc?sig=x",
            "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc",
            "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x#fragment",
        ];
        for value in cases {
            let url = Url::parse(value).expect("edge-case URL must parse");
            assert!(
                validate_release_asset_url(&url).is_err(),
                "redirect URL was accepted: {value}"
            );
        }
    }

    #[test]
    fn embedded_updater_public_key_is_valid() {
        embedded_public_key().expect("Tauri updater public key must decode");
    }

    #[test]
    fn signed_archive_filename_must_match_the_authorized_version() {
        let signature = decode_signature(V035_SIGNATURE).expect("historical signature");
        validate_signature_archive(&signature, "Clash.for.Mac_0.3.5_aarch64.app.tar.gz")
            .expect("matching signed filename");
        assert!(matches!(
            validate_signature_archive(
                &signature,
                "Clash.for.Mac_0.4.0_aarch64.app.tar.gz"
            ),
            Err(UpdateError::SignatureArchiveMismatch)
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
        ] {
            assert!(
                parse_trusted_comment(comment).is_err(),
                "malformed trusted comment was accepted: {comment:?}"
            );
        }
    }

    #[test]
    fn trusted_comment_failures_do_not_echo_untrusted_content() {
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
            assert_eq!(diagnostic, "update signature trusted comment is invalid");
        }

        let mismatch = UpdateError::SignatureArchiveMismatch.to_string();
        assert!(!mismatch.contains(secret));
        assert_eq!(mismatch, "update signature is bound to a different archive");
    }

    #[tokio::test]
    async fn reqwest_errors_never_expose_the_request_url_or_query() {
        let secret = "must-not-reach-diagnostics";
        ensure_tls_crypto_provider().expect("test TLS provider");
        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("test client");
        let error = client
            .get(format!(
                "http://127.0.0.1:0/archive?X-Amz-Signature={secret}&sig={secret}"
            ))
            .send()
            .await
            .expect_err("port zero must reject the request");
        let diagnostic = sanitized_network_error(DownloadFailureStage::Request, &error).to_string();
        assert!(!diagnostic.contains(secret));
        assert!(!diagnostic.contains("127.0.0.1"));
        assert!(!diagnostic.contains("X-Amz"));
        assert!(diagnostic.contains("during request"));
        assert!(diagnostic.contains("category:"));
    }
}
