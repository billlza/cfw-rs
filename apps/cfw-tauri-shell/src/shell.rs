use cfw_engine_api::EngineEvent;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::commands::silent_start_enabled;
use crate::lifecycle::request_shutdown;
use crate::updater::check_for_updates;

const PRODUCT_NAME: &str = "Clash for Mac";
const TRAY_ID: &str = "cfw-tray";

pub(crate) fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let about = MenuItem::with_id(app, "about", "About Clash for Mac", true, None::<&str>)?;
    let check_update =
        MenuItem::with_id(app, "check-update", "Check for Update…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Clash for Mac", true, Some("CmdOrCtrl+Q"))?;
    let app_menu = Submenu::with_items(
        app,
        PRODUCT_NAME,
        true,
        &[
            &about,
            &check_update,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let edit = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;
    let window = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
        ],
    )?;
    Menu::with_items(app, &[&app_menu, &edit, &window])
}

pub(crate) fn handle_app_menu_event(app: &AppHandle, id: &str) {
    match id {
        "about" => show_main_page(app, "about"),
        "check-update" => {
            show_main_page(app, "about");
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = check_for_updates(app.clone()).await {
                    emit_shell_error(&app, "update_check_failed", error);
                }
            });
        }
        "quit" => request_shutdown(app.clone(), 0),
        _ => {}
    }
}

pub(crate) fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let dashboard = MenuItem::with_id(app, "dashboard", "Dashboard", true, None::<&str>)?;
    let about = MenuItem::with_id(app, "tray-about", "About", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "tray-quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &dashboard,
            &about,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip(PRODUCT_NAME)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "dashboard" => show_main_page(app, "general"),
            "tray-about" => show_main_page(app, "about"),
            "tray-quit" => request_shutdown(app.clone(), 0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_page(tray.app_handle(), "general");
            }
        })
        .build(app)?;
    Ok(())
}

pub(crate) fn apply_silent_start(app: &AppHandle) -> Result<(), String> {
    if !silent_start_enabled()? {
        return Ok(());
    }
    app.set_activation_policy(tauri::ActivationPolicy::Accessory)
        .map_err(|error| error.to_string())?;
    app.set_dock_visibility(false)
        .map_err(|error| error.to_string())?;
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable during silent start".to_string())?;
    window.hide().map_err(|error| error.to_string())
}

pub(crate) fn focus_main_window(app: &AppHandle) {
    show_main_page(app, "general");
}

fn show_main_page(app: &AppHandle, page: &str) {
    let result = (|| -> Result<(), String> {
        app.set_activation_policy(tauri::ActivationPolicy::Regular)
            .map_err(|error| error.to_string())?;
        app.set_dock_visibility(true)
            .map_err(|error| error.to_string())?;
        let window = app
            .get_webview_window("main")
            .ok_or_else(|| "main window is unavailable".to_string())?;
        window.show().map_err(|error| error.to_string())?;
        window.set_focus().map_err(|error| error.to_string())?;
        app.emit("cfw://page", page)
            .map_err(|error| error.to_string())
    })();
    if let Err(error) = result {
        emit_shell_error(app, "window_activation_failed", error);
    }
}

fn emit_shell_error(app: &AppHandle, kind: &str, message: String) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(kind, message),
    ) {
        eprintln!("failed to publish shell error: {error}");
    }
}
