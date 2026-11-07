//! The application menu: its items, the actions they map to, and their
//! handling.

use super::*;

pub(super) const APP_MENU_ABOUT_ID: &str = "about";
pub(super) const APP_MENU_CHECK_UPDATE_ID: &str = "check-update";
pub(super) const APP_MENU_QUIT_ID: &str = "quit";
pub(super) const APP_MENU_DIAGNOSTICS_ID: &str = "diagnostic-logs";
pub(super) const APP_MENU_RELOAD_ID: &str = "reload-dashboard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AppMenuAction {
    OpenPage(MainPage),
    CheckForUpdates(MainPage),
    Quit,
    OpenDiagnostics,
    ReloadDashboard,
}

pub(super) fn app_menu_action(id: &str) -> Option<AppMenuAction> {
    match id {
        APP_MENU_ABOUT_ID => Some(AppMenuAction::OpenPage(MainPage::Feedback)),
        APP_MENU_CHECK_UPDATE_ID => Some(AppMenuAction::CheckForUpdates(MainPage::Feedback)),
        APP_MENU_QUIT_ID => Some(AppMenuAction::Quit),
        APP_MENU_DIAGNOSTICS_ID => Some(AppMenuAction::OpenDiagnostics),
        APP_MENU_RELOAD_ID => Some(AppMenuAction::ReloadDashboard),
        _ => None,
    }
}

pub(crate) fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let about = MenuItem::with_id(
        app,
        APP_MENU_ABOUT_ID,
        crate::i18n::text(app, "About Clash for Mac"),
        true,
        None::<&str>,
    )?;
    let check_update = MenuItem::with_id(
        app,
        APP_MENU_CHECK_UPDATE_ID,
        crate::i18n::text(app, "Check for Update…"),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        APP_MENU_QUIT_ID,
        crate::i18n::text(app, "Quit Clash for Mac"),
        true,
        Some("CmdOrCtrl+Q"),
    )?;
    let app_menu = Submenu::with_items(
        app,
        PRODUCT_NAME,
        true,
        &[
            &about,
            &check_update,
            &MenuItem::with_id(
                app,
                APP_MENU_RELOAD_ID,
                crate::i18n::text(app, "Reload dashboard"),
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                APP_MENU_DIAGNOSTICS_ID,
                crate::i18n::text(app, "Open diagnostic logs…"),
                true,
                None::<&str>,
            )?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, Some(&crate::i18n::text(app, "Services")))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, Some(&crate::i18n::text(app, "Hide Clash for Mac")))?,
            &PredefinedMenuItem::hide_others(app, Some(&crate::i18n::text(app, "Hide Others")))?,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let edit = Submenu::with_items(
        app,
        crate::i18n::text(app, "Edit"),
        true,
        &[
            &PredefinedMenuItem::undo(app, Some(&crate::i18n::text(app, "Undo")))?,
            &PredefinedMenuItem::redo(app, Some(&crate::i18n::text(app, "Redo")))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, Some(&crate::i18n::text(app, "Cut")))?,
            &PredefinedMenuItem::copy(app, Some(&crate::i18n::text(app, "Copy")))?,
            &PredefinedMenuItem::paste(app, Some(&crate::i18n::text(app, "Paste")))?,
            &PredefinedMenuItem::select_all(app, Some(&crate::i18n::text(app, "Select All")))?,
        ],
    )?;
    let window = Submenu::with_items(
        app,
        crate::i18n::text(app, "Window"),
        true,
        &[
            &PredefinedMenuItem::minimize(app, Some(&crate::i18n::text(app, "Minimize")))?,
            &PredefinedMenuItem::maximize(app, Some(&crate::i18n::text(app, "Zoom")))?,
        ],
    )?;
    #[cfg(feature = "native-dashboard")]
    window.append(&MenuItem::with_id(
        app,
        "native-overview",
        crate::i18n::text(app, "Native Overview"),
        true,
        Some("CmdOrCtrl+Shift+O"),
    )?)?;
    Menu::with_items(app, &[&app_menu, &edit, &window])
}

pub(crate) fn handle_app_menu_event(app: &AppHandle, id: &str) {
    #[cfg(feature = "native-dashboard")]
    if id == "native-overview" {
        crate::native_dashboard::open(app.clone());
        return;
    }
    match app_menu_action(id) {
        Some(AppMenuAction::OpenPage(page)) => show_main_page(app, page),
        Some(AppMenuAction::CheckForUpdates(page)) => {
            if app.state::<crate::LaunchContext>().is_migration_handoff() {
                emit_shell_error(
                    app,
                    "handoff_command_rejected",
                    "update checks are unavailable during migration handoff".into(),
                );
                return;
            }
            show_main_page(app, page);
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = check_for_updates(app.clone()).await {
                    emit_shell_error(&app, "update_check_failed", error);
                }
            });
        }
        Some(AppMenuAction::Quit) => request_shell_shutdown(app, 0),
        Some(AppMenuAction::OpenDiagnostics) => open_diagnostic_logs(app),
        Some(AppMenuAction::ReloadDashboard) => request_dashboard_reload(app),
        None => {}
    }
}
