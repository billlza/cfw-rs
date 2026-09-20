//! User-configured background controls. Hotkeys and network edges dispatch
//! through the existing engine coordinator and never own networking themselves.
mod hotkeys;
mod network;
mod policy;
use cfw_core::{RuntimeSettingsSnapshot, SettingsStore, SettingsStoreError};
pub(crate) use policy::AutomationPreferences;
use policy::ShortcutAction;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{Shortcut, ShortcutState};

pub(crate) struct ManagedAutomation {
    operation: tokio::sync::Mutex<()>,
    registered: RwLock<Vec<(Shortcut, ShortcutAction)>>,
    pressed: Mutex<BTreeSet<u32>>,
    blocked: AtomicBool,
    last_error: RwLock<Option<String>>,
    preferences: tokio::sync::watch::Sender<AutomationPreferences>,
}
impl Default for ManagedAutomation {
    fn default() -> Self {
        Self {
            operation: tokio::sync::Mutex::new(()),
            registered: RwLock::new(Vec::new()),
            pressed: Mutex::new(BTreeSet::new()),
            blocked: AtomicBool::new(true),
            last_error: RwLock::new(None),
            preferences: tokio::sync::watch::channel(AutomationPreferences::default()).0,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AutomationView {
    settings: AutomationPreferences,
    revision: Option<String>,
    registered_shortcuts: Vec<String>,
    network_active: bool,
    error: Option<String>,
    network: Option<cfw_platform::NetworkContext>,
    network_error: Option<String>,
}

fn report(app: &AppHandle, message: String) {
    if let Ok(mut stored) = app.state::<ManagedAutomation>().last_error.write() {
        if stored.as_ref() == Some(&message) {
            return;
        }
        *stored = Some(message.clone())
    }
    if let Err(error) = app.emit(
        "cfw://shell-error",
        serde_json::json!({"code":"automation_failed","message":message}),
    ) {
        eprintln!("automation error notification failed: {error}")
    }
}

pub(crate) async fn initialize(app: AppHandle) -> Result<(), String> {
    let saved = crate::startup_state::prepare_off_main(|| {
        crate::settings_store()?
            .automation_settings::<AutomationPreferences>()
            .map_err(|error| error.to_string())
    })
    .await?;
    app.state::<crate::startup_state::NativeStartup>()
        .wait()
        .await?;
    let result = crate::startup::on_main(&app, move |app| {
        if !app
            .state::<crate::lifecycle::AppLifecycle>()
            .startup_work_allowed()
        {
            return Err("application exited before automation initialization".into());
        }
        initialize_controls(&app, saved)
    })
    .await;
    if let Err(error) = &result {
        report(&app, error.clone());
    }
    result
}

fn initialize_controls(
    app: &AppHandle,
    saved: RuntimeSettingsSnapshot<AutomationPreferences>,
) -> Result<(), String> {
    app.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_handler(|app, key, event| {
                let state = app.state::<ManagedAutomation>();
                let Ok(mut pressed) = state.pressed.lock() else {
                    report(app, "shortcut key state is unavailable".into());
                    return;
                };
                if event.state() == ShortcutState::Released {
                    pressed.remove(&key.id());
                    return;
                }
                if state.blocked.load(Ordering::Acquire) || !pressed.insert(key.id()) {
                    return;
                }
                drop(pressed);
                let action = state.registered.read().ok().and_then(|keys| {
                    keys.iter()
                        .find(|(registered, _)| registered.id() == key.id())
                        .map(|(_, action)| *action)
                });
                if let Some(action) = action {
                    dispatch_shortcut(app, action)
                }
            })
            .build(),
    )
    .map_err(|error| error.to_string())?;
    network::start(app.clone());
    let keys = saved.settings.validate()?;
    hotkeys::replace_keys(app, &[], &keys, || Ok(())).map_err(|error| error.message)?;
    let state = app.state::<ManagedAutomation>();
    *state
        .registered
        .write()
        .map_err(|_| "shortcut state is unavailable")? = keys;
    state.preferences.send_replace(saved.settings);
    state.blocked.store(false, Ordering::Release);
    Ok(())
}

fn dispatch_shortcut(app: &AppHandle, action: ShortcutAction) {
    use crate::shell::TrayEngineAction;
    let snapshot = app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .snapshot();
    let action = match action {
        ShortcutAction::ShowDashboard => {
            crate::shell::show_dashboard(app);
            return;
        }
        ShortcutAction::ToggleCore => {
            if snapshot.desired_mode == cfw_engine_api::EngineMode::Off {
                TrayEngineAction::StartCore
            } else {
                TrayEngineAction::StopCore
            }
        }
        ShortcutAction::ToggleSystemProxy => {
            TrayEngineAction::SystemProxy(!snapshot.desired_mode.system_proxy_enabled())
        }
        ShortcutAction::ToggleTunnel => {
            TrayEngineAction::Tunnel(!snapshot.desired_mode.tunnel_enabled())
        }
    };
    crate::shell::handle_tray_engine_event(app, action);
}

#[tauri::command]
pub(crate) async fn read_automation_settings(app: AppHandle) -> Result<AutomationView, String> {
    let store = crate::settings_store()?;
    let saved: RuntimeSettingsSnapshot<AutomationPreferences> =
        tauri::async_runtime::spawn_blocking(move || store.automation_settings())
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
    saved.settings.validate()?;
    let observation = tauri::async_runtime::spawn_blocking(cfw_platform::current_network_context)
        .await
        .map_err(|error| error.to_string())?;
    let (network, network_error) = match observation {
        Ok(network) => (network, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let state = app.state::<ManagedAutomation>();
    let keys = state
        .registered
        .read()
        .map_err(|_| "shortcut state is unavailable")?;
    let blocked = state.blocked.load(Ordering::Acquire);
    Ok(AutomationView {
        settings: saved.settings,
        revision: saved.revision,
        registered_shortcuts: if blocked {
            Vec::new()
        } else {
            keys.iter().map(|(key, _)| key.to_string()).collect()
        },
        network_active: !blocked && state.preferences.borrow().network_enabled,
        error: state
            .last_error
            .read()
            .map_err(|_| "automation status is unavailable")?
            .clone(),
        network,
        network_error,
    })
}

#[tauri::command]
pub(crate) async fn request_wifi_name_access(app: AppHandle) -> Result<(), String> {
    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        return Err("Wi-Fi permission cannot be requested during migration handoff".into());
    }
    let (send, receive) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let result = cfw_platform::request_wifi_name_access().map_err(|error| error.to_string());
        let _ = send.send(result);
    })
    .map_err(|error| error.to_string())?;
    receive
        .await
        .map_err(|_| "Wi-Fi permission request did not reach the main thread".to_string())?
}

#[tauri::command]
pub(crate) async fn write_automation_settings(
    app: AppHandle,
    settings: AutomationPreferences,
    revision: Option<String>,
) -> Result<AutomationView, String> {
    tauri::async_runtime::spawn(apply_settings(app, settings, revision))
        .await
        .map_err(|error| format!("automation transaction ended without a response: {error}"))?
}

async fn apply_settings(
    app: AppHandle,
    settings: AutomationPreferences,
    revision: Option<String>,
) -> Result<AutomationView, String> {
    let state = app.state::<ManagedAutomation>();
    if app
        .try_state::<tauri_plugin_global_shortcut::GlobalShortcut<tauri::Wry>>()
        .is_none()
    {
        return Err("macOS global shortcut registration is unavailable".into());
    }

    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        return Err("automation cannot change during migration handoff".into());
    }
    let keys = settings.validate()?;
    let _operation = state.operation.lock().await;
    let before = state
        .registered
        .read()
        .map_err(|_| "shortcut state is unavailable")?
        .clone();
    let store = crate::settings_store()?;
    let (store, previous): (
        SettingsStore,
        RuntimeSettingsSnapshot<AutomationPreferences>,
    ) = tauri::async_runtime::spawn_blocking(move || {
        let previous = store.automation_settings()?;
        Ok::<_, SettingsStoreError>((store, previous))
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    if previous.revision != revision {
        return Err(SettingsStoreError::RuntimeSettingsChanged.to_string());
    }
    state.blocked.store(true, Ordering::Release);
    let task_app = app.clone();
    let next = settings.clone();
    let next_keys = keys.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        hotkeys::replace_keys(&task_app, &before, &next_keys, || {
            commit_settings(&store, &previous, &next)
        })
    })
    .await;
    match result {
        Ok(Ok(())) => {
            *state
                .registered
                .write()
                .map_err(|_| "shortcut state is unavailable")? = keys;
            state
                .pressed
                .lock()
                .map_err(|_| "shortcut state is unavailable")?
                .clear();
            *state
                .last_error
                .write()
                .map_err(|_| "automation status is unavailable")? = None;
            state.preferences.send_replace(settings);
            state.blocked.store(false, Ordering::Release);
        }
        Ok(Err(error)) => {
            state.blocked.store(!error.restored, Ordering::Release);
            report(&app, error.message.clone());
            return Err(error.message);
        }
        Err(error) => {
            let message = format!("automation transaction did not complete: {error}");
            report(&app, message.clone());
            return Err(message);
        }
    }
    read_automation_settings(app.clone()).await
}

fn commit_settings(
    store: &SettingsStore,
    previous: &RuntimeSettingsSnapshot<AutomationPreferences>,
    next: &AutomationPreferences,
) -> Result<(), hotkeys::KeyChangeError> {
    match store.compare_and_swap_automation_settings(previous.revision.as_deref(), next) {
        Ok(()) => Ok(()),
        Err(SettingsStoreError::RuntimeSettingsChanged) => Err(hotkeys::KeyChangeError::preserved(
            SettingsStoreError::RuntimeSettingsChanged.to_string(),
        )),
        Err(error) => {
            let observed: RuntimeSettingsSnapshot<AutomationPreferences> =
                store.automation_settings().map_err(|read| {
                    hotkeys::KeyChangeError::uncertain(format!(
                        "{error}; preference storage is uncertain: {read}"
                    ))
                })?;
            if observed.settings == *next && observed.revision != previous.revision {
                store
                    .compare_and_swap_automation_settings(
                        observed.revision.as_deref(),
                        &previous.settings,
                    )
                    .map_err(|restore| {
                        hotkeys::KeyChangeError::uncertain(format!(
                            "{error}; preference restoration failed: {restore}"
                        ))
                    })?;
            } else if observed.settings != previous.settings {
                return Err(hotkeys::KeyChangeError::uncertain(format!(
                    "{error}; stored preferences changed during recovery"
                )));
            }
            Err(hotkeys::KeyChangeError::preserved(error.to_string()))
        }
    }
}
