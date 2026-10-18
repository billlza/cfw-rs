//! Small, data-plane-independent application primitives.

#[cfg(target_os = "macos")]
mod control_session;
mod diagnostics;
mod legacy_settings;
#[cfg(windows)]
mod paths_windows;
mod runtime_settings;
mod settings;
mod settings_storage;
#[cfg(test)]
mod test_support;
pub use diagnostics::{
    DiagnosticEntry, DiagnosticJournal, DiagnosticTopic, redact_diagnostic_text,
};
pub use runtime_settings::RuntimeSettingsSnapshot;

#[cfg(target_os = "macos")]
pub use control_session::{
    LegacyControlSession, LegacyControlSessionError, LegacyControlSessionObservation,
};
pub use legacy_settings::{LegacyNetworkState, LegacySettingsMigration};
pub use settings::{
    APP_HOME_DIR_NAME, AppPaths, AppPreferences, AppearanceTheme, FontFamily,
    LEGACY_CONFIG_FILE_NAME, LEGACY_CORES_DIR_NAME, LEGACY_HELPERS_DIR_NAME,
    LEGACY_PROFILES_DIR_NAME, LEGACY_SETTINGS_FILE_NAME, LOGS_DIR_NAME, PREFERENCES_FILE_NAME,
    PROFILES_DIR_NAME, SettingsSnapshot, SettingsStore, SettingsStoreError, UiLanguage,
    UiPreferences, WINDOW_STATE_FILE_NAME, WindowBounds,
};

#[cfg(not(windows))]
pub const PRODUCT_NAME: &str = "Clash for Mac";
#[cfg(windows)]
pub const PRODUCT_NAME: &str = "Clash for Windows";
pub const PRODUCT_VERSION: &str = "0.5.0";
