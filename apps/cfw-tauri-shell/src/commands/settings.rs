use cfw_core::{SettingsSnapshot, SettingsStore, UiPreferences};
#[cfg(target_os = "macos")]
use cfw_platform::{MacOsPlatformService, ServiceModeStatus};
use serde::Serialize;
use tauri::{AppHandle, State};

use crate::settings_store;
use crate::window_state::WindowBoundsManager;

#[derive(Default)]
pub(crate) struct UiSettingsMutations(tokio::sync::Mutex<()>);

impl UiSettingsMutations {
    pub(crate) fn reserve(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, String> {
        self.0
            .try_lock()
            .map_err(|_| "another settings change is still in progress".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiLoginItemLiveStatus {
    Checking,
    NotRegistered,
    #[cfg(target_os = "macos")]
    Enabled,
    #[cfg(windows)]
    Registered,
    #[cfg(target_os = "macos")]
    RequiresApproval,
    #[cfg(target_os = "macos")]
    NotFound,
    #[cfg(target_os = "macos")]
    Unknown,
}

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
impl From<cfw_windows_engine::WindowsStartupStatus> for UiLoginItemLiveStatus {
    fn from(status: cfw_windows_engine::WindowsStartupStatus) -> Self {
        match status {
            cfw_windows_engine::WindowsStartupStatus::NotRegistered => Self::NotRegistered,
            cfw_windows_engine::WindowsStartupStatus::Registered => Self::Registered,
        }
    }
}

pub(super) fn live_login_item_status() -> Result<UiLoginItemLiveStatus, String> {
    #[cfg(target_os = "macos")]
    {
        Ok(MacOsPlatformService.login_item_status().into())
    }
    #[cfg(windows)]
    {
        cfw_windows_engine::observe_windows_startup()
            .map(Into::into)
            .map_err(|error| error.to_string())
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
    resolved_locale: cfw_core::UiLanguage,
}

fn launch_at_login_state(
    persisted_intent: bool,
    status: UiLoginItemLiveStatus,
) -> UiLaunchAtLoginState {
    let matches_persisted_intent = match status {
        #[cfg(target_os = "macos")]
        UiLoginItemLiveStatus::Enabled => persisted_intent,
        #[cfg(windows)]
        UiLoginItemLiveStatus::Registered => persisted_intent,
        UiLoginItemLiveStatus::NotRegistered => !persisted_intent,
        #[cfg(target_os = "macos")]
        UiLoginItemLiveStatus::NotFound => !persisted_intent,
        UiLoginItemLiveStatus::Checking => false,
        #[cfg(target_os = "macos")]
        UiLoginItemLiveStatus::RequiresApproval | UiLoginItemLiveStatus::Unknown => false,
    };
    UiLaunchAtLoginState {
        persisted_intent,
        live_status: status,
        matches_persisted_intent,
    }
}

pub(super) fn with_login_item_status(
    snapshot: SettingsSnapshot,
    status: UiLoginItemLiveStatus,
) -> Result<UiSettingsSnapshot, String> {
    let launch_at_login = launch_at_login_state(snapshot.settings.launch_at_login, status);
    Ok(UiSettingsSnapshot {
        resolved_locale: crate::i18n::resolve(snapshot.settings.language)?,
        settings: snapshot.settings,
        persisted: snapshot.persisted,
        launch_at_login,
    })
}

pub(crate) fn settings_snapshot_with_live_status(
    store: &SettingsStore,
) -> Result<UiSettingsSnapshot, String> {
    let snapshot = store.snapshot().map_err(|error| error.to_string())?;
    with_login_item_status(snapshot, live_login_item_status()?)
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

#[cfg(target_os = "macos")]
pub(crate) fn sanitize_legacy_preferences(
    store: &SettingsStore,
    preferences: UiPreferences,
) -> Result<UiSettingsSnapshot, String> {
    let snapshot = write_preferences(store, preferences)?;
    live_login_item_status()
        .and_then(|status| with_login_item_status(snapshot, status))
        .map_err(|error| {
            format!("preferences were saved, but their display status is unavailable: {error}")
        })
}

#[tauri::command]
pub(crate) async fn read_settings_snapshot(
    app: AppHandle,
    include_login_item_status: Option<bool>,
) -> Result<UiSettingsSnapshot, String> {
    let result = crate::startup_state::prepare_off_main(move || {
        let store = settings_store()?;
        if include_login_item_status == Some(false) {
            let snapshot = store.snapshot().map_err(|error| error.to_string())?;
            Ok(UiSettingsSnapshot {
                resolved_locale: crate::i18n::resolve(snapshot.settings.language)?,
                launch_at_login: UiLaunchAtLoginState {
                    persisted_intent: snapshot.settings.launch_at_login,
                    live_status: UiLoginItemLiveStatus::Checking,
                    matches_persisted_intent: false,
                },
                settings: snapshot.settings,
                persisted: snapshot.persisted,
            })
        } else {
            settings_snapshot_with_live_status(&store)
        }
    })
    .await;
    if let Err(error) = &result {
        crate::diagnostics::record(
            &app,
            cfw_core::DiagnosticTopic::Startup,
            "settings_read_failed",
            error,
        );
    }
    result
}

#[tauri::command]
pub(crate) async fn write_settings_snapshot(
    app: AppHandle,
    window_bounds: State<'_, WindowBoundsManager>,
    mutations: State<'_, UiSettingsMutations>,
    settings: UiPreferences,
) -> Result<UiSettingsSnapshot, String> {
    let _mutation = mutations.reserve()?;
    let store = settings_store()?;
    let retain_window_bounds = settings.retain_window_bounds;
    let snapshot = window_bounds
        .commit_retention(&app, retain_window_bounds, move || {
            write_renderer_preferences(&store, settings)
        })
        .await?;
    crate::i18n::apply(&app, snapshot.settings.language)
        .await
        .map_err(|error| {
            format!("preferences were saved, but language application failed: {error}")
        })?;
    crate::startup_state::prepare_off_main(move || {
        live_login_item_status()
            .and_then(|status| with_login_item_status(snapshot, status))
            .map_err(|error| {
                format!("preferences were saved, but their display status is unavailable: {error}")
            })
    })
    .await
}

#[tauri::command]
pub(crate) async fn set_launch_at_login_enabled(
    mutations: State<'_, UiSettingsMutations>,
    enabled: bool,
) -> Result<UiSettingsSnapshot, String> {
    let _mutation = mutations.reserve()?;
    crate::startup_state::prepare_off_main(move || update_launch_at_login(enabled)).await
}

#[cfg(windows)]
fn update_launch_at_login(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    let store = settings_store()?;
    let (snapshot, status) = cfw_windows_engine::set_windows_startup(enabled, || {
        let mut preferences = store.read_or_default().map_err(|error| error.to_string())?;
        preferences.launch_at_login = enabled;
        write_preferences(&store, preferences)
    })
    .map_err(|error| error.to_string())?;
    with_login_item_status(snapshot, status.into()).map_err(|error| {
        format!("startup registration and preferences were saved, but their display status is unavailable: {error}")
    })
}

#[cfg(target_os = "macos")]
fn update_launch_at_login(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    let store = settings_store()?;
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
        Ok(snapshot) => with_login_item_status(
            snapshot,
            platform.login_item_status().into(),
        ).map_err(|error| format!("Login Item and preferences were saved, but their display status is unavailable: {error}")),
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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
mod tests;
