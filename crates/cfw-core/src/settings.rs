use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{self, AtomicU64};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{DEFAULT_DELAY_TEST_URL, PRODUCT_NAME, RuntimeMode, SettingsSkeleton};

/// Process-wide counter making each settings temp file name unique.
static WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Current on-disk settings schema version. Bump this and add an arm to
/// [`migrate_settings`] whenever the persisted shape changes.
pub const CURRENT_SETTINGS_SCHEMA_VERSION: u16 = 1;

pub const APP_HOME_DIR_NAME: &str = PRODUCT_NAME;
pub const SETTINGS_FILE_NAME: &str = "cfw-settings.yaml";
pub const APP_CONFIG_FILE_NAME: &str = "config.yaml";
pub const PROFILES_DIR_NAME: &str = "profiles";
pub const LOGS_DIR_NAME: &str = "logs";
pub const CORES_DIR_NAME: &str = "cores";
pub const HELPERS_DIR_NAME: &str = "helpers";

#[derive(Debug, Error)]
pub enum SettingsStoreError {
    #[error("HOME is not available; cannot resolve Clash for Mac data directory")]
    MissingHome,
    #[error("settings I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings YAML is invalid: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAppPaths {
    pub app_home: PathBuf,
    pub settings_file: PathBuf,
    pub config_file: PathBuf,
    pub profiles_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub cores_dir: PathBuf,
    pub helpers_dir: PathBuf,
}

impl MacOsAppPaths {
    pub fn default_for_current_user() -> Result<Self, SettingsStoreError> {
        let home = env::var_os("HOME").ok_or(SettingsStoreError::MissingHome)?;
        Ok(Self::for_user_home(home))
    }

    pub fn for_user_home(home: impl Into<PathBuf>) -> Self {
        let app_home = home
            .into()
            .join("Library")
            .join("Application Support")
            .join(APP_HOME_DIR_NAME);
        Self::from_app_home(app_home)
    }

    pub fn from_app_home(app_home: impl Into<PathBuf>) -> Self {
        let app_home = app_home.into();
        Self {
            settings_file: app_home.join(SETTINGS_FILE_NAME),
            config_file: app_home.join(APP_CONFIG_FILE_NAME),
            profiles_dir: app_home.join(PROFILES_DIR_NAME),
            logs_dir: app_home.join(LOGS_DIR_NAME),
            cores_dir: app_home.join(CORES_DIR_NAME),
            helpers_dir: app_home.join(HELPERS_DIR_NAME),
            app_home,
        }
    }

    pub fn managed_dirs(&self) -> [&Path; 5] {
        [
            &self.app_home,
            &self.profiles_dir,
            &self.logs_dir,
            &self.cores_dir,
            &self.helpers_dir,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedSettings {
    pub schema_version: u16,
    pub runtime_mode: RuntimeMode,
    pub active_profile: Option<String>,
    pub system_proxy: bool,
    pub tun_mode: bool,
    pub mixin: bool,
    pub mixin_yaml: String,
    pub allow_lan: bool,
    pub enable_ipv6: bool,
    pub launch_at_login: bool,
    pub silent_start: bool,
    pub break_connections_on_proxy_change: bool,
    pub mixed_port: u16,
    pub external_controller_host: String,
    pub external_controller_port: u16,
    pub secret: Option<String>,
    pub retain_window_bounds: bool,
    pub show_tray_proxy_delay_indicator: bool,
    pub proxy_bypass: Vec<String>,
    /// When true with system_proxy, apply PAC via macOS Auto Proxy URL instead of manual HTTP/SOCKS.
    #[serde(default, rename = "usePacScript", alias = "use_pac_script")]
    pub use_pac_script: bool,
    /// PAC body used when `use_pac_script` is enabled. Empty → generate PROXY/SOCKS for mixed-port.
    #[serde(default, rename = "pacScript", alias = "pac_script")]
    pub pac_script: String,
    /// When true, pick a free loopback mixed-port on core start (CFW `randomMixedPort`).
    #[serde(default, rename = "randomMixedPort", alias = "random_mixed_port")]
    pub random_mixed_port: bool,
    /// URL used by Proxies delay tests (CFW delay/liveness URL).
    #[serde(default = "default_delay_test_url", rename = "delayTestUrl", alias = "delay_test_url")]
    pub delay_test_url: String,
    pub only_arm64_macos_supported: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

fn default_delay_test_url() -> String {
    DEFAULT_DELAY_TEST_URL.into()
}

impl Default for PersistedSettings {
    fn default() -> Self {
        let skeleton = SettingsSkeleton::default();
        Self {
            schema_version: 1,
            runtime_mode: RuntimeMode::Rule,
            active_profile: None,
            system_proxy: false,
            tun_mode: false,
            mixin: false,
            mixin_yaml: String::new(),
            allow_lan: false,
            enable_ipv6: false,
            launch_at_login: skeleton.launch_at_login,
            silent_start: false,
            break_connections_on_proxy_change: true,
            mixed_port: 7890,
            external_controller_host: "127.0.0.1".into(),
            external_controller_port: 9090,
            secret: None,
            retain_window_bounds: skeleton.retain_window_bounds,
            show_tray_proxy_delay_indicator: skeleton.show_tray_proxy_delay_indicator,
            proxy_bypass: Vec::new(),
            use_pac_script: false,
            pac_script: String::new(),
            random_mixed_port: false,
            delay_test_url: default_delay_test_url(),
            only_arm64_macos_supported: skeleton.only_arm64_macos_supported,
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsSnapshot {
    pub paths: MacOsAppPaths,
    pub settings: PersistedSettings,
    pub persisted: bool,
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    paths: MacOsAppPaths,
}

impl SettingsStore {
    pub fn default_for_current_user() -> Result<Self, SettingsStoreError> {
        Ok(Self::new(MacOsAppPaths::default_for_current_user()?))
    }

    pub fn new(paths: MacOsAppPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &MacOsAppPaths {
        &self.paths
    }

    pub fn ensure_layout(&self) -> Result<(), SettingsStoreError> {
        for dir in self.paths.managed_dirs() {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<SettingsSnapshot, SettingsStoreError> {
        let persisted = self.paths.settings_file.exists();
        Ok(SettingsSnapshot {
            paths: self.paths.clone(),
            settings: self.read_or_default()?,
            persisted,
        })
    }

    pub fn read_or_default(&self) -> Result<PersistedSettings, SettingsStoreError> {
        if !self.paths.settings_file.exists() {
            return Ok(PersistedSettings::default());
        }

        let raw = fs::read_to_string(&self.paths.settings_file)?;
        let mut settings: PersistedSettings = serde_yaml::from_str(&raw)?;
        migrate_settings(&mut settings);
        Ok(settings)
    }

    pub fn write(&self, settings: &PersistedSettings) -> Result<(), SettingsStoreError> {
        self.ensure_layout()?;
        let yaml = serde_yaml::to_string(settings)?;
        // Unique temp name per writer (pid + process-wide counter) so concurrent
        // writers never clobber each other's staging file; the rename is atomic,
        // so the final settings file is always a complete, consistent document.
        let unique = format!(
            "{}.{}.tmp",
            std::process::id(),
            WRITE_COUNTER.fetch_add(1, atomic::Ordering::Relaxed)
        );
        let tmp_path = self.paths.settings_file.with_extension(unique);
        fs::write(&tmp_path, yaml)?;
        fs::rename(&tmp_path, &self.paths.settings_file)?;
        Ok(())
    }
}

/// Normalize settings loaded from disk to the current schema. Forward-compatible
/// by design: unknown future keys are preserved via `extra` (serde flatten), and
/// older documents are upgraded here. Add a match arm per version when a real
/// field-level migration becomes necessary.
fn migrate_settings(settings: &mut PersistedSettings) {
    if settings.schema_version < CURRENT_SETTINGS_SCHEMA_VERSION {
        settings.schema_version = CURRENT_SETTINGS_SCHEMA_VERSION;
    }
    // Promote legacy CFW keys that previously lived only in `extra`.
    if let Some(value) = settings.extra.remove("randomMixedPort") {
        if let Some(flag) = value.as_bool() {
            settings.random_mixed_port = flag;
        }
    }
    if let Some(value) = settings.extra.remove("delayTestUrl") {
        if let Some(url) = value.as_str() {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                settings.delay_test_url = trimmed.to_string();
            }
        }
    }
    if settings.delay_test_url.trim().is_empty() {
        settings.delay_test_url = default_delay_test_url();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_paths_match_macos_convention() {
        let paths = MacOsAppPaths::for_user_home("/Users/example");
        assert_eq!(
            paths.settings_file,
            PathBuf::from("/Users/example")
                .join("Library")
                .join("Application Support")
                .join("Clash for Mac")
                .join("cfw-settings.yaml")
        );
        assert_eq!(paths.profiles_dir.file_name().unwrap(), PROFILES_DIR_NAME);
    }

    #[test]
    fn missing_settings_returns_defaults_without_writing() {
        let unique = format!(
            "clash-for-mac-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let app_home = env::temp_dir().join(unique);
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(&app_home));
        let snapshot = store.snapshot().unwrap();
        assert!(!snapshot.persisted);
        assert_eq!(snapshot.settings.runtime_mode, RuntimeMode::Rule);
        assert!(!snapshot.paths.settings_file.exists());
    }

    #[test]
    fn unknown_original_cfw_settings_survive_round_trip() {
        let settings = serde_yaml::from_str::<PersistedSettings>(
            r#"
schema_version: 1
theme: dark
bypassText: |
  localhost
  127.0.0.1
randomMixedPort: true
"#,
        )
        .unwrap();

        assert_eq!(
            settings.extra.get("theme"),
            Some(&serde_yaml::Value::String("dark".into()))
        );
        let yaml = serde_yaml::to_string(&settings).unwrap();
        assert!(yaml.contains("theme: dark"));
        assert!(yaml.contains("randomMixedPort: true"));
        assert!(yaml.contains("bypassText:"));
    }
}
