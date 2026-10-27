//! Release metadata contracts shared by desktop platforms. Validated metadata
//! selects exact release bytes; it does not grant permission to install them.

use std::collections::BTreeSet;

use semver::Version;
use serde_json::Value;
use thiserror::Error;
use url::Url;

#[cfg(test)]
mod platform_tests;

const RELEASE_ORIGIN: &str = "https://github.com";
const RELEASE_REPOSITORY_PATH: &str = "/billlza/cfw-rs/releases/download";
const MAX_DOWNLOAD_URL_BYTES: usize = 2 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_NOTES_BYTES: usize = 16 * 1024;
const RELEASE_ASSET_HOST: &str = "release-assets.githubusercontent.com";
const RELEASE_ASSET_PATH_PREFIX: &str = "/github-production-release-asset/";

/// The qualified release families. Runtime callers select from their actual
/// build target; metadata cannot choose an OS, architecture or update channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseTarget {
    MacArm64,
    WindowsX64,
}

impl ReleaseTarget {
    pub fn for_platform(os: &str, architecture: &str) -> Result<Self, UpdateContractError> {
        match (os, architecture) {
            ("macos", "aarch64") => Ok(Self::MacArm64),
            ("windows", "x86_64") => Ok(Self::WindowsX64),
            _ => Err(UpdateContractError::UnsupportedTarget),
        }
    }

    pub const fn metadata_url(self) -> &'static str {
        match self {
            Self::MacArm64 => {
                "https://github.com/billlza/cfw-rs/releases/latest/download/latest.json"
            }
            // A separately published channel pointer. Windows releases must
            // not change the repository's Mac `latest` selection.
            Self::WindowsX64 => {
                "https://github.com/billlza/cfw-rs/releases/download/cfw-stable/latest-windows.json"
            }
        }
    }

    pub const fn platform_key(self) -> &'static str {
        match self {
            Self::MacArm64 => "darwin-aarch64",
            Self::WindowsX64 => "windows-x86_64",
        }
    }

    pub const fn platform_keys(self) -> &'static [&'static str] {
        match self {
            Self::MacArm64 => &["darwin-aarch64", "darwin-arm64"],
            Self::WindowsX64 => &["windows-x86_64"],
        }
    }

    pub fn archive_name(self, version: &str) -> String {
        match self {
            Self::MacArm64 => format!("Clash.for.Mac_{version}_aarch64.app.tar.gz"),
            Self::WindowsX64 => format!("Clash.for.Windows_{version}_x64.msi"),
        }
    }

    pub fn download_url(self, version: &str, archive: &str) -> String {
        format!(
            "{RELEASE_ORIGIN}{RELEASE_REPOSITORY_PATH}/{}{version}/{archive}",
            self.tag_prefix(),
        )
    }

    pub fn release_page_url(self, version: &str) -> Result<String, UpdateContractError> {
        let parsed = Version::parse(version).map_err(|_| UpdateContractError::InvalidVersion)?;
        if parsed.to_string() != version {
            return Err(UpdateContractError::NonCanonicalVersion);
        }
        self.require_version(&parsed, version)?;
        Ok(format!(
            "{RELEASE_ORIGIN}/billlza/cfw-rs/releases/tag/{}{version}",
            self.tag_prefix(),
        ))
    }

    /// Mac's existing latest pointer resolves through a versioned metadata
    /// asset. The independent Windows channel already names its fixed asset
    /// and may redirect once to GitHub's signed asset host, never through Mac.
    pub fn validate_metadata_redirect(self, previous: &[Url], next: &Url) -> Result<(), String> {
        match (self, previous) {
            (Self::MacArm64, [initial]) if initial.as_str() == self.metadata_url() => {
                validate_versioned_mac_metadata_url(next)
            }
            (Self::MacArm64, [initial, versioned])
                if initial.as_str() == self.metadata_url()
                    && validate_versioned_mac_metadata_url(versioned).is_ok() =>
            {
                validate_release_asset_url(next)
            }
            (Self::WindowsX64, [initial]) if initial.as_str() == self.metadata_url() => {
                validate_release_asset_url(next)
            }
            _ => Err("update metadata exceeded its target's fixed redirect chain".into()),
        }
    }

    const fn tag_prefix(self) -> &'static str {
        match self {
            Self::MacArm64 => "v",
            Self::WindowsX64 => "cfw-v",
        }
    }

    fn require_version(self, parsed: &Version, version: &str) -> Result<(), UpdateContractError> {
        if self == Self::WindowsX64
            && (version.len() > 128
                || parsed.major > 255
                || parsed.minor > 255
                || parsed.patch > 65_535)
        {
            return Err(UpdateContractError::InvalidMsiVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAuthorization {
    pub version: String,
    pub archive_name: String,
    pub download_url: String,
    pub signature: String,
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

impl UpdateAuthorization {
    /// Recheck persisted release-byte expectations without inventing presentation
    /// metadata. This validates fields only; the signature still needs verification.
    pub fn validate_for(&self, target: ReleaseTarget) -> Result<(), UpdateContractError> {
        let url =
            Url::parse(&self.download_url).map_err(|_| UpdateContractError::InvalidDownloadUrl)?;
        let checked = validate_authorization_fields(target, &self.version, &url, &self.signature)?;
        if &checked != self {
            return Err(UpdateContractError::UnexpectedDownloadUrl);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UpdateContractError {
    #[error("this operating system and architecture have no qualified update target")]
    UnsupportedTarget,
    #[error("update version is outside the Windows MSI identity limits")]
    InvalidMsiVersion,
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
    #[error("update manifest platform set differs from the selected release target")]
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

pub fn validate_update(
    target: ReleaseTarget,
    version: &str,
    download_url: &Url,
    signature: &str,
    raw_manifest: &Value,
) -> Result<UpdateAuthorization, UpdateContractError> {
    let authorization = validate_authorization_fields(target, version, download_url, signature)?;
    validate_raw_manifest(
        target,
        raw_manifest,
        version,
        &authorization.download_url,
        signature,
    )?;
    Ok(authorization)
}

fn validate_authorization_fields(
    target: ReleaseTarget,
    version: &str,
    download_url: &Url,
    signature: &str,
) -> Result<UpdateAuthorization, UpdateContractError> {
    let parsed_version =
        Version::parse(version).map_err(|_| UpdateContractError::InvalidVersion)?;
    if parsed_version.to_string() != version {
        return Err(UpdateContractError::NonCanonicalVersion);
    }
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(UpdateContractError::InvalidSignatureLength);
    }

    target.require_version(&parsed_version, version)?;
    let archive_name = target.archive_name(version);
    let expected_url = target.download_url(version, &archive_name);
    validate_download_url(download_url, &expected_url)?;

    Ok(UpdateAuthorization {
        version: version.to_owned(),
        archive_name,
        download_url: expected_url,
        signature: signature.to_owned(),
    })
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
    target: ReleaseTarget,
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
    if platform_keys
        != target
            .platform_keys()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    {
        return Err(UpdateContractError::UnexpectedPlatforms);
    }

    for &key in target.platform_keys() {
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

pub fn validate_release_asset_url(url: &Url) -> std::result::Result<(), String> {
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

fn validate_versioned_mac_metadata_url(url: &Url) -> std::result::Result<(), String> {
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
        validate_update(
            ReleaseTarget::MacArm64,
            VERSION,
            &parsed,
            SIGNATURE,
            &manifest(url),
        )
    }

    #[test]
    fn accepts_only_the_canonical_github_release_asset() {
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
        let authorization = validate_url(&expected).expect("canonical update must validate");
        assert_eq!(authorization.version, VERSION);
        assert_eq!(
            authorization.archive_name,
            ReleaseTarget::MacArm64.archive_name(VERSION)
        );
        assert_eq!(authorization.download_url, expected);
        assert_eq!(authorization.signature, SIGNATURE);
    }

    #[test]
    fn rejects_alternate_origins_and_url_components() {
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
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
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
        let encoded = expected.replace("Clash.for.Mac", "Clash%2Efor%2EMac");
        assert!(validate_url(&encoded).is_err());

        let asset = expected.rsplit('/').next().expect("asset name");
        let traversal = expected.replace(asset, &format!("ignored/../{asset}"));
        let normalized = Url::parse(&traversal).expect("traversal URL must parse");
        assert_eq!(normalized.as_str(), expected);
        assert_eq!(
            validate_update(
                ReleaseTarget::MacArm64,
                VERSION,
                &normalized,
                SIGNATURE,
                &manifest(&traversal)
            ),
            Err(UpdateContractError::ManifestUrlMismatch)
        );
    }

    #[test]
    fn rejects_noncanonical_versions_and_wrong_asset_names() {
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        assert!(matches!(
            validate_update(
                ReleaseTarget::MacArm64,
                "01.2.3",
                &parsed,
                SIGNATURE,
                &manifest(&expected)
            ),
            Err(UpdateContractError::InvalidVersion)
        ));

        let wrong_arch = expected.replace("_aarch64", "_arm64");
        assert!(validate_url(&wrong_arch).is_err());
    }

    #[test]
    fn rejects_manifest_alias_or_signature_drift() {
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        let mut wrong_alias = manifest(&expected);
        wrong_alias["platforms"]["darwin-arm64"]["url"] =
            Value::String("https://example.com/update".into());
        assert_eq!(
            validate_update(
                ReleaseTarget::MacArm64,
                VERSION,
                &parsed,
                SIGNATURE,
                &wrong_alias
            ),
            Err(UpdateContractError::ManifestUrlMismatch)
        );

        let mut wrong_signature = manifest(&expected);
        wrong_signature["platforms"]["darwin-aarch64"]["signature"] =
            Value::String("different".into());
        assert_eq!(
            validate_update(
                ReleaseTarget::MacArm64,
                VERSION,
                &parsed,
                SIGNATURE,
                &wrong_signature
            ),
            Err(UpdateContractError::ManifestSignatureMismatch)
        );
    }

    #[test]
    fn rejects_dynamic_or_multi_platform_manifests() {
        let expected = ReleaseTarget::MacArm64
            .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
        let parsed = Url::parse(&expected).expect("expected URL");
        let dynamic = json!({ "version": VERSION, "url": expected, "signature": SIGNATURE });
        assert_eq!(
            validate_update(
                ReleaseTarget::MacArm64,
                VERSION,
                &parsed,
                SIGNATURE,
                &dynamic
            ),
            Err(UpdateContractError::UnexpectedManifestFields)
        );

        let mut extra = manifest(parsed.as_str());
        extra["platforms"]["linux-aarch64"] = json!({
            "url": parsed.as_str(),
            "signature": SIGNATURE
        });
        assert_eq!(
            validate_update(ReleaseTarget::MacArm64, VERSION, &parsed, SIGNATURE, &extra),
            Err(UpdateContractError::UnexpectedPlatforms)
        );
    }
}
