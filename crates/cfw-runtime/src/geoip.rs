//! GeoIP database status + update for mihomo's home directory.
//!
//! CFW shows `Country.mmdb` mtime on General. Mihomo Meta prefers
//! `geoip.metadb` in the same home; we surface whichever is present
//! (preferring metadb) and download MetaCubeX's metadb by default.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cfw_core::MacOsAppPaths;
use serde::{Deserialize, Serialize};

use crate::CoreRuntimeError;

pub const GEOIP_METADB_NAME: &str = "geoip.metadb";
pub const COUNTRY_MMDB_NAME: &str = "Country.mmdb";

/// Default / pinned GeoIP database for mihomo Meta (checksum-verified on update).
///
/// MetaCubeX publishes under the rolling `latest` tag; we pin the URL *and* SHA-256
/// so updates stay reproducible until this pin is intentionally bumped.
pub const DEFAULT_GEOIP_METADB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb";
pub const PINNED_GEOIP_METADB_SHA256: &str =
    "0f904f0eafb9a43bebd309c0d193166454d1f28844f7426d8b9083dfe36528ae";

/// Classic MaxMind Country DB URL (CFW default). Written as `Country.mmdb`.
/// Custom / non-pinned URLs skip SHA-256 verification (size floor still applies).
pub const DEFAULT_COUNTRY_MMDB_URL: &str =
    "https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb";

const MIN_GEOIP_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpDatabaseStatus {
    pub present: bool,
    pub file_name: String,
    pub path: String,
    /// Modified time as Unix epoch milliseconds (local display is UI-side).
    pub mtime_ms: Option<u64>,
    pub size_bytes: Option<u64>,
}

impl GeoIpDatabaseStatus {
    pub fn missing(app_home: &Path) -> Self {
        Self {
            present: false,
            file_name: GEOIP_METADB_NAME.into(),
            path: app_home.join(GEOIP_METADB_NAME).display().to_string(),
            mtime_ms: None,
            size_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpUpdateResult {
    pub status: GeoIpDatabaseStatus,
    pub source_url: String,
    pub bytes: usize,
}

pub fn geoip_database_status(paths: &MacOsAppPaths) -> GeoIpDatabaseStatus {
    let home = &paths.app_home;
    for name in [GEOIP_METADB_NAME, COUNTRY_MMDB_NAME] {
        let path = home.join(name);
        if let Some(status) = status_for_file(&path, name) {
            return status;
        }
    }
    GeoIpDatabaseStatus::missing(home)
}

fn status_for_file(path: &Path, file_name: &str) -> Option<GeoIpDatabaseStatus> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 {
        return None;
    }
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64);
    Some(GeoIpDatabaseStatus {
        present: true,
        file_name: file_name.into(),
        path: path.display().to_string(),
        mtime_ms,
        size_bytes: Some(meta.len()),
    })
}

fn target_file_name_for_url(url: &str) -> &'static str {
    let lower = url.to_ascii_lowercase();
    if lower.contains("country.mmdb") {
        COUNTRY_MMDB_NAME
    } else {
        GEOIP_METADB_NAME
    }
}

pub async fn update_geoip_database(
    paths: &MacOsAppPaths,
    url: Option<&str>,
) -> Result<GeoIpUpdateResult, CoreRuntimeError> {
    let source_url = url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_GEOIP_METADB_URL)
        .to_string();

    let parsed = reqwest::Url::parse(&source_url)
        .map_err(|_| CoreRuntimeError::UnsupportedUrl(source_url.clone()))?;
    if parsed.scheme() != "https" {
        return Err(CoreRuntimeError::UnsupportedUrl(parsed.scheme().into()));
    }

    let http = reqwest::Client::builder()
        .user_agent(format!(
            "Clash-for-Mac/{} (cfw-rs geoip)",
            env!("CARGO_PKG_VERSION")
        ))
        .connect_timeout(std::time::Duration::from_secs(20))
        .timeout(std::time::Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let bytes = http
        .get(parsed.clone())
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    if bytes.len() < MIN_GEOIP_BYTES {
        return Err(CoreRuntimeError::InvalidBinary(format!(
            "GeoIP download too small ({} bytes); expected at least {MIN_GEOIP_BYTES}",
            bytes.len()
        )));
    }

    // Verify the pinned metadb checksum when using the default URL (or an
    // identical pinned path). Custom Country.mmdb / override URLs skip this.
    let using_pinned_metadb = source_url == DEFAULT_GEOIP_METADB_URL
        || source_url.ends_with("/meta-rules-dat/releases/download/latest/geoip.metadb");
    if using_pinned_metadb {
        let actual = crate::sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(PINNED_GEOIP_METADB_SHA256) {
            return Err(CoreRuntimeError::ChecksumMismatch {
                expected: PINNED_GEOIP_METADB_SHA256.into(),
                actual,
            });
        }
    }

    fs::create_dir_all(&paths.app_home)?;
    let file_name = target_file_name_for_url(&source_url);
    let target_path = paths.app_home.join(file_name);
    let tmp_path = target_path.with_extension("download.tmp");
    fs::write(&tmp_path, &bytes)?;
    fs::rename(&tmp_path, &target_path)?;

    // Touch mtime to "now" so the UI reflects this update even if the CDN
    // asset carries an older Last-Modified.
    let _ = filetime_now(&target_path);

    let status = status_for_file(&target_path, file_name)
        .unwrap_or_else(|| GeoIpDatabaseStatus::missing(&paths.app_home));

    Ok(GeoIpUpdateResult {
        status,
        source_url: parsed.to_string(),
        bytes: bytes.len(),
    })
}

fn filetime_now(path: &Path) -> std::io::Result<()> {
    let now = SystemTime::now();
    let file = fs::File::options().write(true).open(path)?;
    file.set_modified(now)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn temp_paths(name: &str) -> MacOsAppPaths {
        let root = std::env::temp_dir().join(format!(
            "cfw-geoip-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        MacOsAppPaths::from_app_home(root)
    }

    #[test]
    fn status_missing_when_no_database() {
        let paths = temp_paths("missing");
        let status = geoip_database_status(&paths);
        assert!(!status.present);
        assert_eq!(status.file_name, GEOIP_METADB_NAME);
        let _ = fs::remove_dir_all(&paths.app_home);
    }

    #[test]
    fn status_prefers_metadb_over_country_mmdb() {
        let paths = temp_paths("prefer");
        fs::write(paths.app_home.join(COUNTRY_MMDB_NAME), vec![0u8; 128]).unwrap();
        fs::write(paths.app_home.join(GEOIP_METADB_NAME), vec![1u8; 256]).unwrap();
        let status = geoip_database_status(&paths);
        assert!(status.present);
        assert_eq!(status.file_name, GEOIP_METADB_NAME);
        assert_eq!(status.size_bytes, Some(256));
        assert!(status.mtime_ms.is_some());
        let _ = fs::remove_dir_all(&paths.app_home);
    }

    #[test]
    fn status_falls_back_to_country_mmdb() {
        let paths = temp_paths("fallback");
        let path = paths.app_home.join(COUNTRY_MMDB_NAME);
        fs::write(&path, vec![0u8; 128]).unwrap();
        let past = SystemTime::now() - Duration::from_secs(3600);
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(past).unwrap();
        let status = geoip_database_status(&paths);
        assert!(status.present);
        assert_eq!(status.file_name, COUNTRY_MMDB_NAME);
        let _ = fs::remove_dir_all(&paths.app_home);
    }

    #[test]
    fn url_picks_target_file_name() {
        assert_eq!(
            target_file_name_for_url(DEFAULT_GEOIP_METADB_URL),
            GEOIP_METADB_NAME
        );
        assert_eq!(
            target_file_name_for_url(DEFAULT_COUNTRY_MMDB_URL),
            COUNTRY_MMDB_NAME
        );
    }
}
