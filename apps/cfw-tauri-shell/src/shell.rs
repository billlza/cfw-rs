use std::collections::BTreeMap;
use std::sync::Mutex;

use cfw_controller::ProxiesSnapshot;
use cfw_core::PRODUCT_NAME;
use cfw_engine_api::{EngineEvent, EngineMode, EngineSnapshot, EngineState};
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::commands::controller_client_for_app;
use crate::lifecycle::request_shutdown;
use crate::updater::check_for_updates;

mod app_menu;
mod tray;
mod tray_updates;
pub(crate) use app_menu::{build_app_menu, handle_app_menu_event};
pub(crate) use tray::{TRAY_ID, TrayEngineAction, TrayMenuState, build_tray};
use tray::{TRAY_PROXY_ID_PREFIX, build_tray_menu, tray_proxy_groups};
pub(crate) use tray_updates::{handle_tray_engine_event, refresh_tray_from_controller};
use tray_updates::{handle_tray_proxy_event, ready_mode, start_tray_state_updates};

/// Renderer pages that can be opened by native shell affordances.
///
/// Keeping this as a closed type prevents menu and tray handlers from emitting
/// ad-hoc page ids that the renderer cannot resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainPage {
    General,
    Feedback,
}

impl MainPage {
    #[cfg(test)]
    const ALL: [Self; 2] = [Self::General, Self::Feedback];

    const fn id(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Feedback => "feedback",
        }
    }
}

fn request_shell_shutdown(app: &AppHandle, exit_code: i32) {
    if let Err(error) = request_shutdown(app.clone(), exit_code) {
        emit_shell_error(app, "shutdown_rejected", error);
    }
}

fn open_diagnostic_logs(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let worker = app.clone();
        if let Err(error) = crate::startup_state::prepare_off_main(move || {
            worker.state::<crate::diagnostics::Diagnostics>().flush()
        })
        .await
        {
            eprintln!("diagnostic export flush failed: {error}");
        }
        if let Err(error) = crate::commands::reveal_logs_directory().await {
            emit_shell_error(&app, "diagnostic_folder_unavailable", error);
        }
    });
}

fn request_dashboard_reload(app: &AppHandle) {
    if let Err(error) = reload_dashboard(app) {
        emit_shell_error(app, "dashboard_reload_failed", error);
    }
}

pub(crate) fn reload_dashboard(app: &AppHandle) -> Result<(), String> {
    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        return Err("Reload is unavailable during migration handoff".into());
    }
    app.get_webview_window("main")
        .ok_or_else(|| "main dashboard window is unavailable".to_owned())
        .and_then(|window| window.reload().map_err(|error| error.to_string()))
}

pub(crate) fn apply_silent_start(app: &AppHandle) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        app.set_activation_policy(tauri::ActivationPolicy::Accessory)
            .map_err(|error| error.to_string())?;
        app.set_dock_visibility(false)
            .map_err(|error| error.to_string())?;
    }
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable during silent start".to_string())?;
    #[cfg(windows)]
    window
        .set_skip_taskbar(true)
        .map_err(|error| error.to_string())?;
    window.hide().map_err(|error| error.to_string())
}

pub(crate) fn focus_main_window(app: &AppHandle) {
    show_main_page(app, MainPage::General);
}

pub(crate) fn prepare_migration_handoff_window(app: &AppHandle) -> Result<(), String> {
    show_main_page_result(app, MainPage::General)
}

fn show_main_page(app: &AppHandle, page: MainPage) {
    let result = show_main_page_result(app, page);
    if let Err(error) = result {
        emit_shell_error(app, "window_activation_failed", error);
    }
}

pub(crate) fn show_dashboard(app: &AppHandle) {
    show_main_page(app, MainPage::General);
}

fn show_main_page_result(app: &AppHandle, page: MainPage) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        app.set_activation_policy(tauri::ActivationPolicy::Regular)
            .map_err(|error| error.to_string())?;
        app.set_dock_visibility(true)
            .map_err(|error| error.to_string())?;
    }
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable".to_string())?;
    #[cfg(windows)]
    window
        .set_skip_taskbar(false)
        .map_err(|error| error.to_string())?;
    window.show().map_err(|error| error.to_string())?;
    #[cfg(windows)]
    window.unminimize().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())?;
    app.state::<crate::LaunchContext>().note_window_presented();
    app.emit("cfw://page", page.id())
        .map_err(|error| error.to_string())
}

fn emit_shell_error(app: &AppHandle, kind: &str, message: String) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(kind, message),
    ) {
        eprintln!("failed to publish shell error: {error}");
    }
}

#[cfg(test)]
mod tests;
