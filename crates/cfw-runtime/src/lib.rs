use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use cfw_core::{CoreKind, MacOsAppPaths, PersistedSettings};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod config;
mod geoip;
pub use config::{default_config_mapping, write_default_config};
pub use geoip::{
    COUNTRY_MMDB_NAME, DEFAULT_COUNTRY_MMDB_URL, DEFAULT_GEOIP_METADB_URL, GEOIP_METADB_NAME,
    GeoIpDatabaseStatus, GeoIpUpdateResult, geoip_database_status, update_geoip_database,
};

/// Default / mihomo managed binary name (historical CFW path).
pub const DEFAULT_CORE_BINARY_NAME: &str = "clash-darwin";
pub const MIHOMO_CORE_BINARY_NAME: &str = DEFAULT_CORE_BINARY_NAME;
/// Optional Rust core (Watfaq clash-rs); **default** engine on Apple Silicon.
pub const CLASH_RS_CORE_BINARY_NAME: &str = "clash-rs";
pub const CORE_LOG_FILE_NAME: &str = "clash-core.log";
const MIHOMO_LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest";
const CFW_CORE_KIND_ENV: &str = "CFW_CORE_KIND";
/// When set to `1`/`true`, clash-rs is started with `--compatibility`
/// (may trigger GeoIP download on first boot).
const CFW_CLASH_RS_COMPAT_ENV: &str = "CFW_CLASH_RS_COMPAT";

/// Pinned, known-good mihomo build used as the download fallback when no core
/// binary is bundled into the app. The checksum is of the *decompressed* Mach-O
/// binary, which is what [`CoreInstaller::install_from_url`] verifies after it
/// gunzips the downloaded `.gz` asset.
pub const PINNED_MIHOMO_VERSION: &str = "v1.19.28";
pub const PINNED_MIHOMO_ARM64_URL: &str =
    "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/mihomo-darwin-arm64-v1.19.28.gz";
pub const PINNED_MIHOMO_ARM64_SHA256: &str =
    "55b7286331cb30a54b2564013b02b84a0c280e8b690bd1e5da4b9d4f4ca007ac";

/// Pinned clash-rs aarch64 build (uncompressed Mach-O asset from GitHub Releases).
pub const PINNED_CLASH_RS_VERSION: &str = "v0.10.7";
pub const PINNED_CLASH_RS_ARM64_URL: &str =
    "https://github.com/Watfaq/clash-rs/releases/download/v0.10.7/clash-rs-aarch64-apple-darwin";
pub const PINNED_CLASH_RS_ARM64_SHA256: &str =
    "d1be0a2c2bf8ecbb4841a4992b24b6bcb5b5de46214215934ac2eb18cdc9f0c9";

pub fn core_binary_name(kind: CoreKind) -> &'static str {
    match kind {
        CoreKind::Mihomo => MIHOMO_CORE_BINARY_NAME,
        CoreKind::ClashRs => CLASH_RS_CORE_BINARY_NAME,
    }
}

/// Resolve preferred core: `CFW_CORE_KIND` env overrides settings.
pub fn resolve_core_kind(settings: &PersistedSettings) -> CoreKind {
    if let Ok(value) = env::var(CFW_CORE_KIND_ENV) {
        if let Some(kind) = CoreKind::parse_loose(&value) {
            return kind;
        }
    }
    settings.core_kind
}

fn clash_rs_compat_enabled() -> bool {
    env::var(CFW_CLASH_RS_COMPAT_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum CoreRuntimeError {
    #[error("Clash core binary is missing: {0}")]
    MissingBinary(String),
    #[error("Clash config is missing: {0}")]
    MissingConfig(String),
    #[error("core process I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("core download failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("core URL must use https: {0}")]
    UnsupportedUrl(String),
    #[error("downloaded core checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("core install requires a pinned SHA-256 checksum")]
    MissingPinnedChecksum,
    #[error("downloaded core is not an Apple Silicon Mach-O binary: {0}")]
    InvalidBinary(String),
    #[error("could not find a darwin-arm64 mihomo asset in the latest release")]
    MissingLatestAsset,
    #[error("{purpose} port {port} is already in use")]
    PortInUse { purpose: String, port: u16 },
    #[error("config generation failed: {0}")]
    Config(String),
    #[error("Intel / Universal Binary cores are not supported (Apple Silicon only)")]
    UnsupportedArchitecture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreProcessSpec {
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub home_dir: PathBuf,
    pub log_file: PathBuf,
    pub controller_host: String,
    pub controller_port: u16,
    pub mixed_port: u16,
    #[serde(default)]
    pub core_kind: CoreKind,
}

impl CoreProcessSpec {
    pub fn from_settings(paths: &MacOsAppPaths, settings: &PersistedSettings) -> Self {
        let kind = resolve_core_kind(settings);
        Self::from_settings_with_kind(paths, settings, kind)
    }

    pub fn from_settings_with_kind(
        paths: &MacOsAppPaths,
        settings: &PersistedSettings,
        kind: CoreKind,
    ) -> Self {
        Self {
            binary_path: paths.cores_dir.join(core_binary_name(kind)),
            config_path: paths.config_file.clone(),
            home_dir: paths.app_home.clone(),
            log_file: paths.logs_dir.join(CORE_LOG_FILE_NAME),
            controller_host: settings.external_controller_host.clone(),
            controller_port: settings.external_controller_port,
            mixed_port: settings.mixed_port,
            core_kind: kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreProcessState {
    Running,
    Stopped,
    MissingBinary,
    MissingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreStatus {
    pub state: CoreProcessState,
    pub pid: Option<u32>,
    pub spec: CoreProcessSpec,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreInstallRequest {
    pub url: String,
    pub sha256: Option<String>,
    /// Target file name under `cores_dir`. Defaults to mihomo's `clash-darwin`.
    #[serde(default)]
    pub binary_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreInstallResult {
    pub target_path: PathBuf,
    pub source_url: String,
    pub bytes: usize,
    pub sha256: String,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestCoreAsset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone)]
pub struct CoreInstaller {
    paths: MacOsAppPaths,
    http: reqwest::Client,
}

impl CoreInstaller {
    pub fn new(paths: MacOsAppPaths) -> Result<Self, CoreRuntimeError> {
        let http = reqwest::Client::builder()
            .user_agent("Clash-for-Mac/0.3 core-installer")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(90))
            .build()?;
        Ok(Self { paths, http })
    }

    pub async fn latest_mihomo_arm64_asset(&self) -> Result<LatestCoreAsset, CoreRuntimeError> {
        let release = self
            .http
            .get(MIHOMO_LATEST_RELEASE_API)
            .send()
            .await?
            .error_for_status()?
            .json::<GithubRelease>()
            .await?;
        release
            .assets
            .into_iter()
            .filter(|asset| is_darwin_arm64_core_asset(&asset.name))
            .max_by_key(|asset| core_asset_score(&asset.name))
            .map(|asset| LatestCoreAsset {
                name: asset.name,
                url: asset.browser_download_url,
            })
            .ok_or(CoreRuntimeError::MissingLatestAsset)
    }

    /// Install the pinned, known-good mihomo arm64 build (the download fallback).
    pub async fn install_pinned_mihomo_arm64(&self) -> Result<CoreInstallResult, CoreRuntimeError> {
        self.install_from_url(CoreInstallRequest {
            url: PINNED_MIHOMO_ARM64_URL.to_string(),
            sha256: Some(PINNED_MIHOMO_ARM64_SHA256.to_string()),
            binary_name: Some(MIHOMO_CORE_BINARY_NAME.to_string()),
        })
        .await
    }

    /// Deprecated name kept for callers; identical to [`Self::install_pinned_mihomo_arm64`].
    pub async fn install_latest_mihomo_arm64(&self) -> Result<CoreInstallResult, CoreRuntimeError> {
        self.install_pinned_mihomo_arm64().await
    }

    /// Install pinned clash-rs aarch64 beside mihomo (does not change the default core).
    pub async fn install_pinned_clash_rs_arm64(&self) -> Result<CoreInstallResult, CoreRuntimeError> {
        self.install_from_url(CoreInstallRequest {
            url: PINNED_CLASH_RS_ARM64_URL.to_string(),
            sha256: Some(PINNED_CLASH_RS_ARM64_SHA256.to_string()),
            binary_name: Some(CLASH_RS_CORE_BINARY_NAME.to_string()),
        })
        .await
    }

    pub async fn install_pinned_for_kind(
        &self,
        kind: CoreKind,
    ) -> Result<CoreInstallResult, CoreRuntimeError> {
        match kind {
            CoreKind::Mihomo => self.install_pinned_mihomo_arm64().await,
            CoreKind::ClashRs => self.install_pinned_clash_rs_arm64().await,
        }
    }

    pub async fn install_from_url(
        &self,
        request: CoreInstallRequest,
    ) -> Result<CoreInstallResult, CoreRuntimeError> {
        let parsed = reqwest::Url::parse(&request.url)
            .map_err(|_| CoreRuntimeError::UnsupportedUrl(request.url.clone()))?;
        if parsed.scheme() != "https" {
            return Err(CoreRuntimeError::UnsupportedUrl(parsed.scheme().into()));
        }
        reject_non_arm64_url(&request.url)?;

        let bytes = self
            .http
            .get(parsed.clone())
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let binary = maybe_decompress_gzip(&bytes)?;
        validate_arm64_macho(&binary)?;

        let sha256 = sha256_hex(&binary);
        let expected = request
            .sha256
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CoreRuntimeError::MissingPinnedChecksum)?;
        if !sha256.eq_ignore_ascii_case(expected) {
            return Err(CoreRuntimeError::ChecksumMismatch {
                expected: expected.into(),
                actual: sha256,
            });
        }

        let binary_name = request
            .binary_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(DEFAULT_CORE_BINARY_NAME);

        fs::create_dir_all(&self.paths.cores_dir)?;
        let target_path = self.paths.cores_dir.join(binary_name);
        let tmp_path = target_path.with_extension("download.tmp");
        fs::write(&tmp_path, &binary)?;
        let mut permissions = fs::metadata(&tmp_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tmp_path, permissions)?;
        fs::rename(&tmp_path, &target_path)?;

        Ok(CoreInstallResult {
            target_path,
            source_url: parsed.to_string(),
            bytes: binary.len(),
            sha256,
            executable: true,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CoreManager {
    spec: CoreProcessSpec,
}

fn reject_non_arm64_url(url: &str) -> Result<(), CoreRuntimeError> {
    let lower = url.to_ascii_lowercase();
    if lower.contains("amd64")
        || lower.contains("x86_64")
        || lower.contains("x86-64")
        || lower.contains("i686")
        || lower.contains("universal")
    {
        return Err(CoreRuntimeError::UnsupportedArchitecture);
    }
    Ok(())
}

fn is_darwin_arm64_core_asset(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("darwin")
        && (name.contains("arm64") || name.contains("aarch64"))
        && !name.contains("amd64")
        && !name.contains("x86_64")
        && !name.contains(".sha")
        && !name.ends_with(".txt")
        && (name.ends_with(".gz") || !name.contains('.'))
}

fn core_asset_score(name: &str) -> u8 {
    let name = name.to_ascii_lowercase();
    let mut score = 0;
    if name.ends_with(".gz") {
        score += 3;
    }
    if name.contains("-arm64-v") {
        score += 3;
    }
    if !name.contains("go120") && !name.contains("go122") && !name.contains("go124") {
        score += 2;
    }
    if name.contains("compatible") {
        score += 1;
    } else {
        score += 2;
    }
    score
}

fn maybe_decompress_gzip(bytes: &[u8]) -> Result<Vec<u8>, CoreRuntimeError> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(Cursor::new(bytes));
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        return Ok(out);
    }
    Ok(bytes.to_vec())
}

fn validate_arm64_macho(bytes: &[u8]) -> Result<(), CoreRuntimeError> {
    if bytes.len() < 8 {
        return Err(CoreRuntimeError::InvalidBinary("file is too small".into()));
    }
    if bytes[0..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        return Err(CoreRuntimeError::InvalidBinary(
            "expected 64-bit little-endian Mach-O magic".into(),
        ));
    }
    if bytes[4..8] != [0x0c, 0x00, 0x00, 0x01] {
        return Err(CoreRuntimeError::InvalidBinary(
            "expected CPU_TYPE_ARM64".into(),
        ));
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl CoreManager {
    pub fn new(spec: CoreProcessSpec) -> Self {
        Self { spec }
    }

    pub fn spec(&self) -> &CoreProcessSpec {
        &self.spec
    }

    pub fn status(&self, pid: Option<u32>) -> CoreStatus {
        if let Some(pid) = pid {
            return CoreStatus {
                state: CoreProcessState::Running,
                pid: Some(pid),
                spec: self.spec.clone(),
                message: format!(
                    "{} core is running with pid {pid}",
                    self.spec.core_kind.as_str()
                ),
            };
        }

        if !self.spec.binary_path.exists() {
            return CoreStatus {
                state: CoreProcessState::MissingBinary,
                pid: None,
                spec: self.spec.clone(),
                message: format!("Missing {}", self.spec.binary_path.display()),
            };
        }

        if !self.spec.config_path.exists() {
            return CoreStatus {
                state: CoreProcessState::MissingConfig,
                pid: None,
                spec: self.spec.clone(),
                message: format!("Missing {}", self.spec.config_path.display()),
            };
        }

        CoreStatus {
            state: CoreProcessState::Stopped,
            pid: None,
            spec: self.spec.clone(),
            message: format!("{} core is ready to start", self.spec.core_kind.as_str()),
        }
    }

    pub fn spawn(&self) -> Result<Child, CoreRuntimeError> {
        self.verify_startable()?;
        fs::create_dir_all(&self.spec.home_dir)?;
        if let Some(parent) = self.spec.log_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spec.log_file)?;
        let stderr = stdout.try_clone()?;

        let mut command = Command::new(&self.spec.binary_path);
        command
            .arg("-d")
            .arg(&self.spec.home_dir)
            .arg("-f")
            .arg(&self.spec.config_path);
        if self.spec.core_kind == CoreKind::ClashRs && clash_rs_compat_enabled() {
            // Opt-in: can pull GeoIP on first boot and delay controller ready.
            command.arg("--compatibility");
        }
        Ok(command
            .current_dir(&self.spec.home_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?)
    }

    fn verify_startable(&self) -> Result<(), CoreRuntimeError> {
        if !self.spec.binary_path.exists() {
            return Err(CoreRuntimeError::MissingBinary(
                self.spec.binary_path.display().to_string(),
            ));
        }
        if !self.spec.config_path.exists() {
            return Err(CoreRuntimeError::MissingConfig(
                self.spec.config_path.display().to_string(),
            ));
        }
        ensure_port_available(self.spec.mixed_port, "mixed-port")?;
        ensure_port_available(self.spec.controller_port, "external-controller")?;
        Ok(())
    }
}

fn ensure_port_available(port: u16, purpose: &str) -> Result<(), CoreRuntimeError> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            Err(CoreRuntimeError::PortInUse {
                purpose: purpose.to_string(),
                port,
            })
        }
        Err(error) => Err(CoreRuntimeError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_status_is_explicit() {
        let paths = MacOsAppPaths::from_app_home(std::env::temp_dir().join("cfm-runtime-test"));
        let spec = CoreProcessSpec::from_settings(&paths, &PersistedSettings::default());
        let manager = CoreManager::new(spec);
        let status = manager.status(None);
        assert_eq!(status.state, CoreProcessState::MissingBinary);
        assert!(status.message.contains("clash-rs"));
        assert_eq!(status.spec.core_kind, CoreKind::ClashRs);
    }

    #[test]
    fn clash_rs_spec_uses_dedicated_binary_name() {
        let paths = MacOsAppPaths::from_app_home(std::env::temp_dir().join("cfm-runtime-clashrs"));
        let mut settings = PersistedSettings::default();
        settings.core_kind = CoreKind::ClashRs;
        let spec = CoreProcessSpec::from_settings(&paths, &settings);
        assert_eq!(spec.core_kind, CoreKind::ClashRs);
        assert!(spec.binary_path.ends_with(CLASH_RS_CORE_BINARY_NAME));
    }

    #[test]
    fn validates_arm64_macho_header() {
        let mut bytes = vec![0_u8; 32];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&[0x0c, 0x00, 0x00, 0x01]);
        assert!(validate_arm64_macho(&bytes).is_ok());
        bytes[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]);
        assert!(validate_arm64_macho(&bytes).is_err());
    }

    #[test]
    fn prefers_darwin_arm64_gzip_assets() {
        assert!(is_darwin_arm64_core_asset("mihomo-darwin-arm64-v1.0.gz"));
        assert!(!is_darwin_arm64_core_asset("mihomo-darwin-amd64-v1.0.gz"));
        assert!(
            core_asset_score("mihomo-darwin-arm64-v1.0.gz")
                > core_asset_score("mihomo-darwin-arm64-go124-v1.0.gz")
        );
    }

    #[test]
    fn rejects_intel_download_urls() {
        assert!(
            reject_non_arm64_url("https://example.com/clash-rs-x86_64-apple-darwin").is_err()
        );
        assert!(reject_non_arm64_url(PINNED_CLASH_RS_ARM64_URL).is_ok());
    }

    #[test]
    fn detects_used_ports_before_spawn() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let error = ensure_port_available(port, "mixed-port").unwrap_err();
        assert!(matches!(error, CoreRuntimeError::PortInUse { .. }));
    }
}
