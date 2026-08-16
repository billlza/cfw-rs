use cfw_core::{SettingsSnapshot, SettingsStore, UiPreferences};
use cfw_platform::{MacOsPlatformService, ServiceModeStatus};
use serde::Serialize;
use tauri::{AppHandle, State};

use crate::settings_store;
use crate::window_state::WindowBoundsManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiLoginItemLiveStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

impl From<ServiceModeStatus> for UiLoginItemLiveStatus {
    fn from(status: ServiceModeStatus) -> Self {
        match status {
            ServiceModeStatus::NotRegistered => Self::NotRegistered,
            ServiceModeStatus::Enabled => Self::Enabled,
            ServiceModeStatus::RequiresApproval => Self::RequiresApproval,
            ServiceModeStatus::NotFound => Self::NotFound,
            ServiceModeStatus::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiLaunchAtLoginState {
    persisted_intent: bool,
    live_status: UiLoginItemLiveStatus,
    matches_persisted_intent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiSettingsSnapshot {
    settings: UiPreferences,
    persisted: bool,
    launch_at_login: UiLaunchAtLoginState,
}

fn launch_at_login_state(
    persisted_intent: bool,
    status: ServiceModeStatus,
) -> UiLaunchAtLoginState {
    let matches_persisted_intent = match status {
        ServiceModeStatus::Enabled => persisted_intent,
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => !persisted_intent,
        ServiceModeStatus::RequiresApproval | ServiceModeStatus::Unknown => false,
    };
    UiLaunchAtLoginState {
        persisted_intent,
        live_status: status.into(),
        matches_persisted_intent,
    }
}

fn with_login_item_status(
    snapshot: SettingsSnapshot,
    status: ServiceModeStatus,
) -> UiSettingsSnapshot {
    let launch_at_login = launch_at_login_state(snapshot.settings.launch_at_login, status);
    UiSettingsSnapshot {
        settings: snapshot.settings,
        persisted: snapshot.persisted,
        launch_at_login,
    }
}

pub(crate) fn settings_snapshot_with_live_status(
    store: &SettingsStore,
) -> Result<UiSettingsSnapshot, String> {
    let snapshot = store.snapshot().map_err(|error| error.to_string())?;
    Ok(with_login_item_status(
        snapshot,
        MacOsPlatformService.login_item_status(),
    ))
}

fn write_preferences(
    store: &SettingsStore,
    preferences: UiPreferences,
) -> Result<SettingsSnapshot, String> {
    store
        .write(&preferences)
        .map_err(|error| error.to_string())?;
    store.snapshot().map_err(|error| error.to_string())
}

fn write_renderer_preferences(
    store: &SettingsStore,
    preferences: UiPreferences,
) -> Result<SettingsSnapshot, String> {
    let current = store.read_or_default().map_err(|error| error.to_string())?;
    if preferences.launch_at_login != current.launch_at_login {
        return Err(
            "launch_at_login can only be changed through the transactional Login Item command"
                .into(),
        );
    }
    write_preferences(store, preferences)
}

fn require_completed_migration(store: &SettingsStore) -> Result<(), String> {
    if store
        .legacy_retirement_completed()
        .map_err(|error| error.to_string())?
    {
        Ok(())
    } else {
        Err("legacy settings migration is still pending; preferences remain read-only".into())
    }
}

pub(crate) fn sanitize_legacy_preferences(
    store: &SettingsStore,
    preferences: UiPreferences,
) -> Result<UiSettingsSnapshot, String> {
    let snapshot = write_preferences(store, preferences)?;
    Ok(with_login_item_status(
        snapshot,
        MacOsPlatformService.login_item_status(),
    ))
}

pub(crate) fn silent_start_enabled() -> Result<bool, String> {
    settings_store()?
        .read_or_default()
        .map(|preferences| preferences.silent_start)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn read_settings_snapshot() -> Result<UiSettingsSnapshot, String> {
    settings_snapshot_with_live_status(&settings_store()?)
}

#[tauri::command]
pub(crate) fn write_settings_snapshot(
    app: AppHandle,
    window_bounds: State<'_, WindowBoundsManager>,
    settings: UiPreferences,
) -> Result<UiSettingsSnapshot, String> {
    let store = settings_store()?;
    require_completed_migration(&store)?;
    let retain_window_bounds = settings.retain_window_bounds;
    window_bounds.commit_retention(&app, retain_window_bounds, || {
        let snapshot = write_renderer_preferences(&store, settings)?;
        Ok(with_login_item_status(
            snapshot,
            MacOsPlatformService.login_item_status(),
        ))
    })
}

#[tauri::command]
pub(crate) fn set_launch_at_login_enabled(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    let store = settings_store()?;
    require_completed_migration(&store)?;
    let mut preferences = store.read_or_default().map_err(|error| error.to_string())?;
    let platform = MacOsPlatformService;
    let original_status = platform.login_item_status();
    if original_status == ServiceModeStatus::Unknown {
        return Err(
            "macOS returned an unknown Login Item state; preferences were not changed".into(),
        );
    }

    if enabled {
        let status = match original_status {
            ServiceModeStatus::Enabled => ServiceModeStatus::Enabled,
            ServiceModeStatus::RequiresApproval => ServiceModeStatus::RequiresApproval,
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => platform
                .enable_login_item()
                .map_err(|error| error.to_string())?,
            ServiceModeStatus::Unknown => unreachable!("rejected above"),
        };
        match status {
            ServiceModeStatus::Enabled => {}
            ServiceModeStatus::RequiresApproval => {
                platform.open_login_items_settings();
                return Err(
                    "Start at Login needs approval in System Settings › General › Login Items"
                        .into(),
                );
            }
            other => {
                return Err(format!(
                    "could not enable Login Item (status: {other:?}); a signed app in /Applications is required"
                ));
            }
        }
    } else {
        if !matches!(
            original_status,
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
        ) {
            platform
                .disable_login_item()
                .map_err(|error| error.to_string())?;
        }
    }
    preferences.launch_at_login = enabled;
    match write_preferences(&store, preferences) {
        Ok(snapshot) => Ok(with_login_item_status(
            snapshot,
            platform.login_item_status(),
        )),
        Err(persist_error) => match restore_login_item_status(&platform, original_status) {
            Ok(()) => Err(format!(
                "failed to persist the Login Item preference; restored the previous macOS state: {persist_error}"
            )),
            Err(rollback_error) => Err(format!(
                "failed to persist the Login Item preference: {persist_error}; failed to restore the previous macOS state: {rollback_error}"
            )),
        },
    }
}

fn restore_login_item_status(
    platform: &MacOsPlatformService,
    original_status: ServiceModeStatus,
) -> Result<(), String> {
    let current_status = platform.login_item_status();
    if login_item_status_matches(current_status, original_status) {
        return Ok(());
    }
    match original_status {
        ServiceModeStatus::Enabled => match platform
            .enable_login_item()
            .map_err(|error| error.to_string())?
        {
            ServiceModeStatus::Enabled => Ok(()),
            status => Err(format!(
                "restored Login Item has unexpected status {status:?}"
            )),
        },
        ServiceModeStatus::RequiresApproval => match platform
            .enable_login_item()
            .map_err(|error| error.to_string())?
        {
            ServiceModeStatus::Enabled | ServiceModeStatus::RequiresApproval => Ok(()),
            status => Err(format!(
                "restored Login Item has unexpected status {status:?}"
            )),
        },
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => {
            platform
                .disable_login_item()
                .map_err(|error| error.to_string())?;
            match platform.login_item_status() {
                ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => Ok(()),
                status => Err(format!(
                    "restored Login Item has unexpected status {status:?}"
                )),
            }
        }
        ServiceModeStatus::Unknown => Err("cannot restore an unknown Login Item state".into()),
    }
}

fn login_item_status_matches(
    current_status: ServiceModeStatus,
    expected_status: ServiceModeStatus,
) -> bool {
    match expected_status {
        ServiceModeStatus::Enabled => current_status == ServiceModeStatus::Enabled,
        ServiceModeStatus::RequiresApproval => matches!(
            current_status,
            ServiceModeStatus::Enabled | ServiceModeStatus::RequiresApproval
        ),
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => matches!(
            current_status,
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
        ),
        ServiceModeStatus::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cfw_core::{AppearanceTheme, FontFamily};

    use super::*;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_settings_store(name: &str) -> (std::path::PathBuf, SettingsStore) {
        let root = std::env::temp_dir().join(format!(
            "cfw-command-settings-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = SettingsStore::new(cfw_core::MacOsAppPaths::from_app_home(root.join("app")));
        (root, store)
    }

    #[test]
    fn ipc_preferences_deserialize_only_the_whitelisted_shape() {
        let preferences = serde_json::from_value::<UiPreferences>(serde_json::json!({
            "theme": "dark",
            "font_family": "SF Mono",
            "retain_window_bounds": false,
            "launch_at_login": true,
            "silent_start": true,
            "check_for_updates": true
        }))
        .expect("deserialize safe preferences");
        assert_eq!(preferences.theme, AppearanceTheme::Dark);
        assert_eq!(preferences.font_family, FontFamily::SfMono);

        let mut unsafe_value = serde_json::to_value(preferences).expect("serialize preferences");
        unsafe_value["pac_script"] = serde_json::Value::String("sensitive".into());
        assert!(serde_json::from_value::<UiPreferences>(unsafe_value).is_err());
    }

    #[test]
    fn login_item_rollback_is_idempotent_for_equivalent_states() {
        assert!(login_item_status_matches(
            ServiceModeStatus::Enabled,
            ServiceModeStatus::Enabled
        ));
        assert!(login_item_status_matches(
            ServiceModeStatus::Enabled,
            ServiceModeStatus::RequiresApproval
        ));
        assert!(login_item_status_matches(
            ServiceModeStatus::NotFound,
            ServiceModeStatus::NotRegistered
        ));
        assert!(!login_item_status_matches(
            ServiceModeStatus::RequiresApproval,
            ServiceModeStatus::Enabled
        ));
        assert!(!login_item_status_matches(
            ServiceModeStatus::Unknown,
            ServiceModeStatus::Unknown
        ));
    }

    #[test]
    fn login_item_snapshot_keeps_persisted_intent_and_live_status_distinct() {
        let cases = [
            (
                false,
                ServiceModeStatus::NotRegistered,
                UiLoginItemLiveStatus::NotRegistered,
                true,
            ),
            (
                true,
                ServiceModeStatus::NotFound,
                UiLoginItemLiveStatus::NotFound,
                false,
            ),
            (
                false,
                ServiceModeStatus::Enabled,
                UiLoginItemLiveStatus::Enabled,
                false,
            ),
            (
                true,
                ServiceModeStatus::Enabled,
                UiLoginItemLiveStatus::Enabled,
                true,
            ),
            (
                true,
                ServiceModeStatus::RequiresApproval,
                UiLoginItemLiveStatus::RequiresApproval,
                false,
            ),
            (
                false,
                ServiceModeStatus::Unknown,
                UiLoginItemLiveStatus::Unknown,
                false,
            ),
        ];
        for (intent, status, live_status, matches_persisted_intent) in cases {
            assert_eq!(
                launch_at_login_state(intent, status),
                UiLaunchAtLoginState {
                    persisted_intent: intent,
                    live_status,
                    matches_persisted_intent,
                }
            );
        }
    }

    #[test]
    fn login_item_snapshot_has_a_stable_typed_wire_shape() {
        let snapshot = with_login_item_status(
            SettingsSnapshot {
                settings: UiPreferences {
                    launch_at_login: true,
                    ..UiPreferences::default()
                },
                persisted: true,
            },
            ServiceModeStatus::RequiresApproval,
        );
        assert_eq!(
            serde_json::to_value(snapshot).expect("serialize settings snapshot"),
            serde_json::json!({
                "settings": {
                    "theme": "system",
                    "font_family": "",
                    "retain_window_bounds": true,
                    "launch_at_login": true,
                    "silent_start": false,
                    "check_for_updates": false
                },
                "persisted": true,
                "launch_at_login": {
                    "persisted_intent": true,
                    "live_status": "requires_approval",
                    "matches_persisted_intent": false
                }
            })
        );
    }

    #[test]
    fn renderer_settings_cannot_bypass_login_item_transaction() {
        let (root, store) = test_settings_store("login-item-boundary");
        store
            .write(&UiPreferences::default())
            .expect("write initial preferences");

        let bypass = UiPreferences {
            launch_at_login: true,
            ..UiPreferences::default()
        };
        let error = write_renderer_preferences(&store, bypass)
            .expect_err("renderer must not change Login Item preference directly");
        assert!(error.contains("transactional Login Item command"));
        assert!(
            !store
                .snapshot()
                .expect("unchanged snapshot")
                .settings
                .launch_at_login
        );

        let allowed = UiPreferences {
            theme: AppearanceTheme::Dark,
            ..UiPreferences::default()
        };
        let snapshot = write_renderer_preferences(&store, allowed)
            .expect("unrelated renderer preference should persist");
        assert_eq!(snapshot.settings.theme, AppearanceTheme::Dark);
        assert!(!snapshot.settings.launch_at_login);

        fs::remove_dir_all(root).expect("remove settings test root");
    }
}
