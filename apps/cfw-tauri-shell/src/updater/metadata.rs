use std::time::Duration;

use futures_util::StreamExt as _;
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use semver::Version;
use serde_json::Value;

use super::contract::{UpdateAuthorization, validate_update};
use super::download::{
    ensure_tls_crypto_provider, sanitized_network_error, validate_release_asset_url,
};
use super::error::{DownloadFailureStage, Result, UpdateError};

const METADATA_URL: &str = "https://github.com/billlza/cfw-rs/releases/latest/download/latest.json";
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const USER_AGENT: &str = concat!("cfw-rs/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckedUpdate {
    pub(super) authorization: UpdateAuthorization,
    pub(super) notes: String,
    pub(super) publication_date: String,
}

pub(super) async fn check_bounded_update() -> Result<Option<CheckedUpdate>> {
    ensure_tls_crypto_provider()?;
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::custom(validate_metadata_redirect))
        .build()
        .map_err(|error| sanitized_network_error(DownloadFailureStage::ClientBuild, &error))?;
    let response = client
        .get(METADATA_URL)
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
    let platform = raw_manifest
        .pointer("/platforms/darwin-aarch64")
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
    attempt: reqwest::redirect::Attempt<'_>,
) -> reqwest::redirect::Action {
    let result = match attempt.previous() {
        [initial] if initial.as_str() == METADATA_URL => {
            validate_versioned_metadata_url(attempt.url())
        }
        [initial, versioned]
            if initial.as_str() == METADATA_URL
                && validate_versioned_metadata_url(versioned).is_ok() =>
        {
            validate_release_asset_url(attempt.url())
        }
        _ => Err("update metadata exceeded the fixed redirect chain".into()),
    };
    match result {
        Ok(()) => attempt.follow(),
        Err(error) => attempt.error(error),
    }
}

fn validate_versioned_metadata_url(url: &Url) -> std::result::Result<(), String> {
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("versioned metadata URL has a forbidden authority".into());
    }
    let version = url
        .path()
        .strip_prefix("/billlza/cfw-rs/releases/download/v")
        .and_then(|tail| tail.strip_suffix("/latest.json"))
        .ok_or_else(|| "versioned metadata URL has a forbidden path".to_owned())?;
    let parsed = Version::parse(version)
        .map_err(|_| "versioned metadata URL is not strict SemVer".to_owned())?;
    if parsed.to_string() != version {
        return Err("versioned metadata URL is not canonical SemVer".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn manifest(version: &str) -> Vec<u8> {
        let archive = format!("Clash.for.Mac_{version}_aarch64.app.tar.gz");
        let url =
            format!("https://github.com/billlza/cfw-rs/releases/download/v{version}/{archive}");
        serde_json::to_vec(&json!({
            "version": version,
            "notes": "Release notes",
            "pub_date": "2026-07-22T00:00:00Z",
            "platforms": {
                "darwin-aarch64": { "url": url, "signature": "signature" },
                "darwin-arm64": { "url": url, "signature": "signature" }
            }
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
}
