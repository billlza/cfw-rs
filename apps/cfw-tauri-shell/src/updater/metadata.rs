use std::time::Duration;

use futures_util::StreamExt as _;
use reqwest::Url;
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use semver::Version;
use serde_json::Value;

use super::contract::{UpdateAuthorization, target, validate_update};
use super::error::{DownloadFailureStage, NetworkFailureCategory, Result, UpdateError};
use crate::transport_security::external_https_client_builder;
use cfw_core::update::ReleaseTarget;
pub(super) use cfw_core::update::validate_release_asset_url;

const MAX_METADATA_BYTES: u64 = 64 * 1024;
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const USER_AGENT: &str = concat!("cfw-rs/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckedUpdate {
    pub(super) authorization: UpdateAuthorization,
    pub(super) notes: String,
    pub(super) publication_date: String,
}

pub(super) async fn check_bounded_update() -> Result<Option<CheckedUpdate>> {
    let release_target = target()?;
    let client = external_https_client_builder()
        .map_err(|_| UpdateError::TlsProviderUnavailable)?
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::custom(move |attempt| {
            validate_metadata_redirect(release_target, attempt)
        }))
        .build()
        .map_err(|error| sanitized_network_error(DownloadFailureStage::ClientBuild, &error))?;
    let response = client
        .get(release_target.metadata_url())
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| sanitized_network_error(DownloadFailureStage::MetadataRequest, &error))?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(UpdateError::HttpStatus(response.status()));
    }

    let declared_length = response.content_length();
    if let Some(declared) = declared_length
        && declared > MAX_METADATA_BYTES
    {
        return Err(UpdateError::MetadataDeclaredTooLarge {
            declared,
            maximum: MAX_METADATA_BYTES,
        });
    }
    let mut bytes =
        Vec::with_capacity(declared_length.unwrap_or(0).min(MAX_METADATA_BYTES) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| sanitized_network_error(DownloadFailureStage::MetadataBody, &error))?;
        let next = (bytes.len() as u64).checked_add(chunk.len() as u64).ok_or(
            UpdateError::MetadataTooLarge {
                maximum: MAX_METADATA_BYTES,
            },
        )?;
        if next > MAX_METADATA_BYTES {
            return Err(UpdateError::MetadataTooLarge {
                maximum: MAX_METADATA_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(UpdateError::EmptyMetadata);
    }
    if let Some(declared) = declared_length
        && declared != bytes.len() as u64
    {
        return Err(UpdateError::MetadataLengthMismatch {
            declared,
            actual: bytes.len() as u64,
        });
    }

    parse_checked_update(&bytes)
}

fn parse_checked_update(bytes: &[u8]) -> Result<Option<CheckedUpdate>> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(UpdateError::InvalidMetadata(
            "document size is outside the accepted range".into(),
        ));
    }
    let raw_manifest: Value = serde_json::from_slice(bytes)
        .map_err(|error| UpdateError::InvalidMetadata(format!("{:?}", error.classify())))?;
    let version = raw_manifest
        .get("version")
        .and_then(Value::as_str)
        .ok_or(UpdateError::InvalidMetadata("version field".into()))?;
    let release_target = target()?;
    let platform = raw_manifest
        .get("platforms")
        .and_then(|platforms| platforms.get(release_target.platform_key()))
        .and_then(Value::as_object)
        .ok_or(UpdateError::InvalidMetadata("platform field".into()))?;
    let url = platform
        .get("url")
        .and_then(Value::as_str)
        .ok_or(UpdateError::InvalidMetadata("URL field".into()))?;
    let signature = platform
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(UpdateError::InvalidMetadata("signature field".into()))?;
    let parsed_url =
        Url::parse(url).map_err(|_| UpdateError::InvalidMetadata("URL syntax".into()))?;
    let authorization = validate_update(version, &parsed_url, signature, &raw_manifest)?;
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| UpdateError::InvalidMetadata("current version".into()))?;
    let available = Version::parse(&authorization.version)
        .map_err(|_| UpdateError::InvalidMetadata("release version".into()))?;
    if available <= current {
        return Ok(None);
    }
    Ok(Some(CheckedUpdate {
        authorization,
        notes: raw_manifest
            .get("notes")
            .and_then(Value::as_str)
            .expect("validated notes")
            .to_owned(),
        publication_date: raw_manifest
            .get("pub_date")
            .and_then(Value::as_str)
            .expect("validated publication date")
            .to_owned(),
    }))
}

fn validate_metadata_redirect(
    target: ReleaseTarget,
    attempt: reqwest::redirect::Attempt<'_>,
) -> reqwest::redirect::Action {
    match target.validate_metadata_redirect(attempt.previous(), attempt.url()) {
        Ok(()) => attempt.follow(),
        Err(error) => attempt.error(error),
    }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn manifest(version: &str) -> Vec<u8> {
        let target = target().expect("qualified test target");
        let url = target.download_url(version, &target.archive_name(version));
        let platforms = target
            .platform_keys()
            .iter()
            .map(|key| {
                (
                    (*key).to_owned(),
                    json!({ "url": url, "signature": "signature" }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::to_vec(&json!({
            "version": version,
            "notes": "Release notes",
            "pub_date": "2026-07-22T00:00:00Z",
            "platforms": platforms
        }))
        .expect("manifest")
    }

    #[test]
    fn metadata_parser_rejects_empty_oversized_and_extra_fields() {
        assert!(parse_checked_update(&[]).is_err());
        assert!(parse_checked_update(&vec![b' '; MAX_METADATA_BYTES as usize + 1]).is_err());
        let mut value: Value = serde_json::from_slice(&manifest("9.0.0")).expect("JSON");
        value["unexpected"] = Value::Bool(true);
        assert!(parse_checked_update(&serde_json::to_vec(&value).expect("JSON")).is_err());
    }

    #[test]
    fn metadata_parser_returns_only_newer_strictly_valid_releases() {
        assert!(
            parse_checked_update(&manifest("0.4.0"))
                .expect("current")
                .is_none()
        );
        let checked = parse_checked_update(&manifest("9.0.0"))
            .expect("valid")
            .expect("newer");
        assert_eq!(checked.authorization.version, "9.0.0");
    }

    #[test]
    fn versioned_metadata_redirect_is_exact() {
        let validate_versioned_metadata_url = |url: &Url| {
            ReleaseTarget::MacArm64.validate_metadata_redirect(
                &[Url::parse(ReleaseTarget::MacArm64.metadata_url()).unwrap()],
                url,
            )
        };
        assert!(
            validate_versioned_metadata_url(
                &Url::parse(
                    "https://github.com/billlza/cfw-rs/releases/download/v0.4.0/latest.json"
                )
                .expect("URL")
            )
            .is_ok()
        );
        for value in [
            "https://example.com/billlza/cfw-rs/releases/download/v0.4.0/latest.json",
            "https://github.com/billlza/cfw-rs/releases/download/v01.4.0/latest.json",
            "https://github.com/billlza/cfw-rs/releases/download/v0.4.0/other.json",
        ] {
            assert!(validate_versioned_metadata_url(&Url::parse(value).expect("URL")).is_err());
        }
    }

    #[test]
    fn release_asset_redirect_is_exact_and_bounded() {
        assert!(
            validate_release_asset_url(
                &Url::parse(
                    "https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset?sp=read"
                )
                .expect("URL")
            )
            .is_ok()
        );
        for value in [
            "https://github.com/github-production-release-asset/12345/asset?sp=read",
            "https://release-assets.githubusercontent.com/github-production-release-asset/not-a-number/asset?sp=read",
            "https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset",
            "https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset/extra?sp=read",
        ] {
            assert!(
                validate_release_asset_url(&Url::parse(value).expect("URL")).is_err(),
                "accepted unsafe redirect {value:?}"
            );
        }
    }
}
