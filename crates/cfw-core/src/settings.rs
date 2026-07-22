use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PRODUCT_NAME;
use crate::settings_storage::{FilePolicy, SecureDirectory};

pub const APP_HOME_DIR_NAME: &str = PRODUCT_NAME;
pub const PREFERENCES_FILE_NAME: &str = "cfw-preferences.json";
pub const LEGACY_SETTINGS_FILE_NAME: &str = "cfw-settings.yaml";
pub const LEGACY_CONFIG_FILE_NAME: &str = "config.yaml";
/// 0.4 native profiles live outside the historical Clash-managed directory so
/// they can be staged and validated before the one-way network cutover.
pub const PROFILES_DIR_NAME: &str = "sing-box-profiles-v1";
pub const LEGACY_PROFILES_DIR_NAME: &str = "profiles";
pub const LOGS_DIR_NAME: &str = "logs";
pub const LEGACY_CORES_DIR_NAME: &str = "cores";
pub const LEGACY_HELPERS_DIR_NAME: &str = "helpers";

const PREFERENCES_SCHEMA_VERSION: u16 = 1;
const MAX_PREFERENCES_BYTES: usize = 16 * 1024;
const RETIREMENT_MARKER_FILE_NAME: &str = ".legacy-network-retired-v1.json";
const RETIREMENT_MARKER_BYTES: &[u8] = b"{\"schema_version\":1,\"completed\":true}";

#[derive(Debug, Error)]
pub enum SettingsStoreError {
    #[error("HOME is not available; cannot resolve Clash for Mac data directory")]
    MissingHome,
    #[error("settings I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("settings schema version is unsupported: {0}")]
    UnsupportedSchema(u16),
    #[error("settings file is not canonical JSON")]
    NonCanonicalJson,
    #[error("settings path contains an invalid component")]
    InvalidPath,
    #[error("settings directory is not a private, user-owned real directory")]
    UnsafeDirectory,
    #[error("settings file is not a private, user-owned regular single-link file")]
    UnsafeFile,
    #[error("settings file is too large: {actual} bytes exceeds {maximum}")]
    TooLarge { actual: u64, maximum: usize },
    #[error(
        "settings transaction failed ({operation}); temporary-file cleanup also failed ({cleanup})"
    )]
    CleanupFailed { operation: String, cleanup: String },
    #[error("legacy settings source changed after it was parsed")]
    LegacySourceChanged,
    #[error("legacy settings are invalid at line {line}: {message}")]
    InvalidLegacySettings { line: usize, message: String },
    #[error("legacy settings contain duplicate or aliased values for {key}")]
    AmbiguousLegacySetting { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppearanceTheme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FontFamily {
    #[default]
    #[serde(rename = "")]
    System,
    #[serde(rename = "Avenir Next")]
    AvenirNext,
    #[serde(rename = "SF Mono")]
    SfMono,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiPreferences {
    pub theme: AppearanceTheme,
    pub font_family: FontFamily,
    pub retain_window_bounds: bool,
    pub launch_at_login: bool,
    pub silent_start: bool,
    pub check_for_updates: bool,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            theme: AppearanceTheme::System,
            font_family: FontFamily::System,
            retain_window_bounds: true,
            launch_at_login: false,
            silent_start: false,
            check_for_updates: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPreferences {
    pub schema_version: u16,
    pub preferences: UiPreferences,
}

impl AppPreferences {
    pub fn new(preferences: UiPreferences) -> Self {
        Self {
            schema_version: PREFERENCES_SCHEMA_VERSION,
            preferences,
        }
    }

    fn validate(self) -> Result<Self, SettingsStoreError> {
        if self.schema_version != PREFERENCES_SCHEMA_VERSION {
            return Err(SettingsStoreError::UnsupportedSchema(self.schema_version));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsAppPaths {
    pub app_home: PathBuf,
    pub preferences_file: PathBuf,
    pub legacy_settings_file: PathBuf,
    pub legacy_config_file: PathBuf,
    pub legacy_profiles_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub legacy_cores_dir: PathBuf,
    pub legacy_helpers_dir: PathBuf,
}

impl MacOsAppPaths {
    pub fn default_for_current_user() -> Result<Self, SettingsStoreError> {
        let home = env::var_os("HOME").ok_or(SettingsStoreError::MissingHome)?;
        Ok(Self::for_user_home(home))
    }

    pub fn for_user_home(home: impl Into<PathBuf>) -> Self {
        Self::from_app_home(
            home.into()
                .join("Library")
                .join("Application Support")
                .join(APP_HOME_DIR_NAME),
        )
    }

    pub fn from_app_home(app_home: impl Into<PathBuf>) -> Self {
        let app_home = app_home.into();
        Self {
            preferences_file: app_home.join(PREFERENCES_FILE_NAME),
            legacy_settings_file: app_home.join(LEGACY_SETTINGS_FILE_NAME),
            legacy_config_file: app_home.join(LEGACY_CONFIG_FILE_NAME),
            legacy_profiles_dir: app_home.join(LEGACY_PROFILES_DIR_NAME),
            profiles_dir: app_home.join(PROFILES_DIR_NAME),
            logs_dir: app_home.join(LOGS_DIR_NAME),
            legacy_cores_dir: app_home.join(LEGACY_CORES_DIR_NAME),
            legacy_helpers_dir: app_home.join(LEGACY_HELPERS_DIR_NAME),
            app_home,
        }
    }

    pub fn managed_dirs(&self) -> [&Path; 3] {
        [&self.app_home, &self.profiles_dir, &self.logs_dir]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsSnapshot {
    pub settings: UiPreferences,
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
        for path in self.paths.managed_dirs() {
            SecureDirectory::open_or_create(path)?;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<SettingsSnapshot, SettingsStoreError> {
        let (settings, persisted) = self.read_optional()?;
        Ok(SettingsSnapshot {
            settings: settings.unwrap_or_default(),
            persisted,
        })
    }

    pub fn read_or_default(&self) -> Result<UiPreferences, SettingsStoreError> {
        Ok(self.read_optional()?.0.unwrap_or_default())
    }

    pub fn write(&self, preferences: &UiPreferences) -> Result<(), SettingsStoreError> {
        self.ensure_layout()?;
        let application = AppPreferences::new(preferences.clone());
        let bytes = serde_json::to_vec(&application)?;
        SecureDirectory::open_or_create(&self.paths.app_home)?.write_atomic(
            PREFERENCES_FILE_NAME,
            &bytes,
            MAX_PREFERENCES_BYTES,
        )
    }

    pub fn legacy_retirement_completed(&self) -> Result<bool, SettingsStoreError> {
        let directory = SecureDirectory::open_or_create(&self.paths.app_home)?;
        let Some(stored) = directory.read_optional(
            RETIREMENT_MARKER_FILE_NAME,
            RETIREMENT_MARKER_BYTES.len(),
            FilePolicy::Private,
        )?
        else {
            return Ok(false);
        };
        if stored.bytes != RETIREMENT_MARKER_BYTES {
            return Err(SettingsStoreError::NonCanonicalJson);
        }
        Ok(true)
    }

    pub fn commit_legacy_retirement(&self) -> Result<(), SettingsStoreError> {
        SecureDirectory::open_or_create(&self.paths.app_home)?.write_atomic(
            RETIREMENT_MARKER_FILE_NAME,
            RETIREMENT_MARKER_BYTES,
            RETIREMENT_MARKER_BYTES.len(),
        )
    }

    fn read_optional(&self) -> Result<(Option<UiPreferences>, bool), SettingsStoreError> {
        let directory = SecureDirectory::open_or_create(&self.paths.app_home)?;
        let Some(stored) = directory.read_optional(
            PREFERENCES_FILE_NAME,
            MAX_PREFERENCES_BYTES,
            FilePolicy::Private,
        )?
        else {
            return Ok((None, false));
        };
        let application = serde_json::from_slice::<AppPreferences>(&stored.bytes)?.validate()?;
        if serde_json::to_vec(&application)? != stored.bytes {
            return Err(SettingsStoreError::NonCanonicalJson);
        }
        Ok((Some(application.preferences), true))
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
