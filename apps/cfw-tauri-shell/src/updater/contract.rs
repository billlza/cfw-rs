use std::collections::BTreeSet;

use reqwest::Url;
use semver::Version;
use serde_json::Value;
use thiserror::Error;

const RELEASE_ORIGIN: &str = "https://github.com";
const RELEASE_REPOSITORY_PATH: &str = "/billlza/cfw-rs/releases/download";
const RELEASE_PLATFORM_KEYS: [&str; 2] = ["darwin-aarch64", "darwin-arm64"];
const MAX_DOWNLOAD_URL_BYTES: usize = 2 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_NOTES_BYTES: usize = 16 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct UpdateAuthorization {
    pub(super) version: String,
    pub(super) archive_name: String,
    pub(super) download_url: String,
    pub(super) signature: String,
}

impl std::fmt::Debug for UpdateAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpdateAuthorization")
            .field("version", &self.version)
            .field("archive_name", &self.archive_name)
            .field("download_url", &self.download_url)
            .field("signature", &"<minisign signature>")
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(super) enum UpdateContractError {
    #[error("update version is not strict SemVer")]
    InvalidVersion,
    #[error("update version is not in canonical SemVer form")]
    NonCanonicalVersion,
    #[error("update download URL exceeds {MAX_DOWNLOAD_URL_BYTES} bytes")]
    DownloadUrlTooLong,
    #[error("update download URL has forbidden origin, authority, or components")]
    InvalidDownloadUrl,
    #[error("update download URL is not the canonical versioned release asset")]
    UnexpectedDownloadUrl,
    #[error("update signature is empty or exceeds {MAX_SIGNATURE_BYTES} bytes")]
    InvalidSignatureLength,
    #[error("update manifest must contain exactly the two Apple Silicon platform aliases")]
    UnexpectedPlatforms,
    #[error("update manifest field is missing or invalid: {0}")]
    InvalidManifestField(&'static str),
    #[error("update manifest version differs from the parsed update")]
    ManifestVersionMismatch,
    #[error("update manifest URL is not the canonical release URL")]
    ManifestUrlMismatch,
    #[error("update manifest signature differs from the parsed update")]
    ManifestSignatureMismatch,
    #[error("update manifest contains unexpected fields")]
    UnexpectedManifestFields,
    #[error("update manifest notes or publication date is invalid")]
    InvalidPresentationMetadata,
}

pub(super) fn validate_update(
    version: &str,
    download_url: &Url,
    signature: &str,
    raw_manifest: &Value,
) -> Result<UpdateAuthorization, UpdateContractError> {
    let parsed_version =
        Version::parse(version).map_err(|_| UpdateContractError::InvalidVersion)?;
    if parsed_version.to_string() != version {
        return Err(UpdateContractError::NonCanonicalVersion);
    }
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(UpdateContractError::InvalidSignatureLength);
    }

    let archive_name = expected_archive_name(version);
    let expected_url = expected_download_url(version, &archive_name);
    validate_download_url(download_url, &expected_url)?;
    validate_raw_manifest(raw_manifest, version, &expected_url, signature)?;

    Ok(UpdateAuthorization {
        version: version.to_owned(),
        archive_name,
        download_url: expected_url,
        signature: signature.to_owned(),
    })
}

fn expected_archive_name(version: &str) -> String {
    format!("Clash.for.Mac_{version}_aarch64.app.tar.gz")
}

fn expected_download_url(version: &str, archive_name: &str) -> String {
    format!("{RELEASE_ORIGIN}{RELEASE_REPOSITORY_PATH}/v{version}/{archive_name}")
}

fn validate_download_url(
    download_url: &Url,
    expected_url: &str,
) -> Result<(), UpdateContractError> {
    let actual = download_url.as_str();
    if actual.len() > MAX_DOWNLOAD_URL_BYTES {
        return Err(UpdateContractError::DownloadUrlTooLong);
    }
    if download_url.scheme() != "https"
        || download_url.host_str() != Some("github.com")
        || !download_url.username().is_empty()
        || download_url.password().is_some()
        || download_url.port().is_some()
        || download_url.query().is_some()
        || download_url.fragment().is_some()
    {
        return Err(UpdateContractError::InvalidDownloadUrl);
    }
    if actual != expected_url {
        return Err(UpdateContractError::UnexpectedDownloadUrl);
    }
    Ok(())
}

fn validate_raw_manifest(
    raw_manifest: &Value,
    version: &str,
    expected_url: &str,
    signature: &str,
) -> Result<(), UpdateContractError> {
    let object = raw_manifest
        .as_object()
        .ok_or(UpdateContractError::InvalidManifestField("root"))?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["notes", "platforms", "pub_date", "version"])
    {
        return Err(UpdateContractError::UnexpectedManifestFields);
    }
    if raw_manifest.get("version").and_then(Value::as_str) != Some(version) {
        return Err(UpdateContractError::ManifestVersionMismatch);
    }
    let notes = raw_manifest
        .get("notes")
        .and_then(Value::as_str)
        .ok_or(UpdateContractError::InvalidPresentationMetadata)?;
    let publication_date = raw_manifest
        .get("pub_date")
        .and_then(Value::as_str)
        .ok_or(UpdateContractError::InvalidPresentationMetadata)?;
    if notes.len() > MAX_NOTES_BYTES || !valid_publication_date(publication_date) {
        return Err(UpdateContractError::InvalidPresentationMetadata);
    }
    let platforms = raw_manifest
        .get("platforms")
        .and_then(Value::as_object)
        .ok_or(UpdateContractError::InvalidManifestField("platforms"))?;
    let platform_keys = platforms
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if platform_keys != BTreeSet::from(RELEASE_PLATFORM_KEYS) {
        return Err(UpdateContractError::UnexpectedPlatforms);
    }

    for key in RELEASE_PLATFORM_KEYS {
        let platform = platforms
            .get(key)
            .and_then(Value::as_object)
            .ok_or(UpdateContractError::InvalidManifestField("platform entry"))?;
        if platform.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["signature", "url"])
        {
            return Err(UpdateContractError::UnexpectedManifestFields);
        }
        if platform.get("url").and_then(Value::as_str) != Some(expected_url) {
            return Err(UpdateContractError::ManifestUrlMismatch);
        }
        if platform.get("signature").and_then(Value::as_str) != Some(signature) {
            return Err(UpdateContractError::ManifestSignatureMismatch);
        }
    }
    Ok(())
}

fn valid_publication_date(value: &str) -> bool {
    value.len() == 20
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const VERSION: &str = "1.2.3-beta.4+build.5";
    const SIGNATURE: &str = "encoded-minisign-envelope";

    fn manifest(url: &str) -> Value {
        json!({
            "version": VERSION,
            "notes": "Release notes",
            "pub_date": "2026-07-22T00:00:00Z",
            "platforms": {
                "darwin-aarch64": { "url": url, "signature": SIGNATURE },
                "darwin-arm64": { "url": url, "signature": SIGNATURE }
            }
        })
    }

    fn validate_url(url: &str) -> Result<UpdateAuthorization, UpdateContractError> {
        let parsed = Url::parse(url).expect("test URL must parse");
        validate_update(VERSION, &parsed, SIGNATURE, &manifest(url))
    }

    #[test]
    fn accepts_only_the_canonical_github_release_asset() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let authorization = validate_url(&expected).expect("canonical update must validate");
        assert_eq!(authorization.version, VERSION);
        assert_eq!(authorization.archive_name, expected_archive_name(VERSION));
        assert_eq!(authorization.download_url, expected);
        assert_eq!(authorization.signature, SIGNATURE);
    }

    #[test]
    fn rejects_alternate_origins_and_url_components() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let cases = [
            expected.replacen("https://", "http://", 1),
            expected.replacen("github.com", "example.com", 1),
            expected.replacen("github.com", "user@github.com", 1),
            expected.replacen("github.com", "github.com:8443", 1),
            format!("{expected}?download=1"),
            format!("{expected}#archive"),
        ];
        for candidate in cases {
            assert!(
                validate_url(&candidate).is_err(),
                "alternate URL was accepted: {candidate}"
            );
        }
    }

    #[test]
    fn rejects_encodings_and_lexical_traversal_even_after_url_normalization() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let encoded = expected.replace("Clash.for.Mac", "Clash%2Efor%2EMac");
        assert!(validate_url(&encoded).is_err());

        let asset = expected.rsplit('/').next().expect("asset name");
        let traversal = expected.replace(asset, &format!("ignored/../{asset}"));
        let normalized = Url::parse(&traversal).expect("traversal URL must parse");
        assert_eq!(normalized.as_str(), expected);
        assert_eq!(
            validate_update(VERSION, &normalized, SIGNATURE, &manifest(&traversal)),
            Err(UpdateContractError::ManifestUrlMismatch)
        );
    }

    #[test]
    fn rejects_noncanonical_versions_and_wrong_asset_names() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        assert!(matches!(
            validate_update("01.2.3", &parsed, SIGNATURE, &manifest(&expected)),
            Err(UpdateContractError::InvalidVersion)
        ));

        let wrong_arch = expected.replace("_aarch64", "_arm64");
        assert!(validate_url(&wrong_arch).is_err());
    }

    #[test]
    fn rejects_manifest_alias_or_signature_drift() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        let mut wrong_alias = manifest(&expected);
        wrong_alias["platforms"]["darwin-arm64"]["url"] =
            Value::String("https://example.com/update".into());
        assert_eq!(
            validate_update(VERSION, &parsed, SIGNATURE, &wrong_alias),
            Err(UpdateContractError::ManifestUrlMismatch)
        );

        let mut wrong_signature = manifest(&expected);
        wrong_signature["platforms"]["darwin-aarch64"]["signature"] =
            Value::String("different".into());
        assert_eq!(
            validate_update(VERSION, &parsed, SIGNATURE, &wrong_signature),
            Err(UpdateContractError::ManifestSignatureMismatch)
        );
    }

    #[test]
    fn rejects_dynamic_or_multi_platform_manifests() {
        let expected = expected_download_url(VERSION, &expected_archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        let dynamic = json!({ "version": VERSION, "url": expected, "signature": SIGNATURE });
        assert_eq!(
            validate_update(VERSION, &parsed, SIGNATURE, &dynamic),
            Err(UpdateContractError::UnexpectedManifestFields)
        );

        let mut extra = manifest(parsed.as_str());
        extra["platforms"]["linux-aarch64"] = json!({
            "url": parsed.as_str(),
            "signature": SIGNATURE
        });
        assert_eq!(
            validate_update(VERSION, &parsed, SIGNATURE, &extra),
            Err(UpdateContractError::UnexpectedPlatforms)
        );
    }
}
