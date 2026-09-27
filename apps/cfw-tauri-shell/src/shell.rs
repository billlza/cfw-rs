use std::collections::BTreeMap;
use std::sync::Mutex;

use cfw_controller::ProxiesSnapshot;
use cfw_engine_api::{EngineEvent, EngineMode, EngineSnapshot, EngineState};
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::commands::controller_client_for_app;
use crate::lifecycle::request_shutdown;
use crate::updater::check_for_updates;

const PRODUCT_NAME: &str = "Clash for Mac";
pub(crate) const TRAY_ID: &str = "cfw-tray";
const APP_MENU_ABOUT_ID: &str = "about";
const APP_MENU_CHECK_UPDATE_ID: &str = "check-update";
const APP_MENU_QUIT_ID: &str = "quit";
const APP_MENU_DIAGNOSTICS_ID: &str = "diagnostic-logs";
const APP_MENU_RELOAD_ID: &str = "reload-dashboard";
const TRAY_DASHBOARD_ID: &str = "dashboard";
const TRAY_ABOUT_ID: &str = "tray-about";
const TRAY_QUIT_ID: &str = "tray-quit";
const TRAY_DIAGNOSTICS_ID: &str = "tray-diagnostic-logs";
const TRAY_RELOAD_ID: &str = "tray-reload-dashboard";
/// Bounds on what a controller response may add to the menu bar. A hostile or
/// broken controller cannot grow the tray without limit.
const MAX_TRAY_GROUPS: usize = 24;
const MAX_TRAY_GROUP_OPTIONS: usize = 64;
const MAX_TRAY_LABEL_CHARS: usize = 64;
/// Prefix of generated proxy menu ids. Group and node names never appear in an
/// id, so a name cannot be parsed back out of one or smuggle a separator.
const TRAY_PROXY_ID_PREFIX: &str = "cfw-proxy-";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppMenuAction {
    OpenPage(MainPage),
    CheckForUpdates(MainPage),
    Quit,
    OpenDiagnostics,
    ReloadDashboard,
}

fn app_menu_action(id: &str) -> Option<AppMenuAction> {
    match id {
        APP_MENU_ABOUT_ID => Some(AppMenuAction::OpenPage(MainPage::Feedback)),
        APP_MENU_CHECK_UPDATE_ID => Some(AppMenuAction::CheckForUpdates(MainPage::Feedback)),
        APP_MENU_QUIT_ID => Some(AppMenuAction::Quit),
        APP_MENU_DIAGNOSTICS_ID => Some(AppMenuAction::OpenDiagnostics),
        APP_MENU_RELOAD_ID => Some(AppMenuAction::ReloadDashboard),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayAction {
    OpenPage(MainPage),
    Quit,
    ProxySelection,
    Engine(TrayEngineAction),
    OpenDiagnostics,
    ReloadDashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrayEngineAction {
    StartCore,
    StopCore,
    SystemProxy(bool),
    Tunnel(bool),
    RouteMode(&'static str),
}

fn tray_action(id: &str) -> TrayAction {
    match id {
        TRAY_DASHBOARD_ID => TrayAction::OpenPage(MainPage::General),
        TRAY_ABOUT_ID => TrayAction::OpenPage(MainPage::Feedback),
        TRAY_QUIT_ID => TrayAction::Quit,
        TRAY_DIAGNOSTICS_ID => TrayAction::OpenDiagnostics,
        TRAY_RELOAD_ID => TrayAction::ReloadDashboard,
        "core-start" => TrayAction::Engine(TrayEngineAction::StartCore),
        "core-stop" => TrayAction::Engine(TrayEngineAction::StopCore),
        "proxy-enable" => TrayAction::Engine(TrayEngineAction::SystemProxy(true)),
        "proxy-disable" => TrayAction::Engine(TrayEngineAction::SystemProxy(false)),
        "tun-enable" => TrayAction::Engine(TrayEngineAction::Tunnel(true)),
        "tun-disable" => TrayAction::Engine(TrayEngineAction::Tunnel(false)),
        "route-rule" => TrayAction::Engine(TrayEngineAction::RouteMode("rule")),
        "route-global" => TrayAction::Engine(TrayEngineAction::RouteMode("global")),
        "route-direct" => TrayAction::Engine(TrayEngineAction::RouteMode("direct")),
        _ => TrayAction::ProxySelection,
    }
}

/// Group and node behind each generated proxy menu id.
#[derive(Default)]
pub(crate) struct TrayMenuState {
    selections: Mutex<BTreeMap<String, TrayProxySelection>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayProxySelection {
    group: String,
    proxy: String,
}

impl TrayMenuState {
    fn replace(&self, selections: BTreeMap<String, TrayProxySelection>) -> Result<(), String> {
        let mut stored = self
            .selections
            .lock()
            .map_err(|_| "tray menu state is unavailable".to_owned())?;
        *stored = selections;
        Ok(())
    }

    fn resolve(&self, id: &str) -> Option<TrayProxySelection> {
        self.selections.lock().ok()?.get(id).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayProxyGroup {
    name: String,
    now: Option<String>,
    options: Vec<String>,
    selectable: bool,
}

/// Bounded, sanitised tray view of a controller proxies snapshot.
fn tray_proxy_groups(snapshot: ProxiesSnapshot) -> Vec<TrayProxyGroup> {
    snapshot
        .groups
        .into_iter()
        .filter(|group| is_tray_label(&group.name))
        .take(MAX_TRAY_GROUPS)
        .map(|group| TrayProxyGroup {
            selectable: group.kind.eq_ignore_ascii_case("selector"),
            now: group.now.filter(|now| {
                is_tray_label(now) && group.options.iter().any(|option| option == now)
            }),
            options: group
                .options
                .into_iter()
                .filter(|option| is_tray_label(option))
                .take(MAX_TRAY_GROUP_OPTIONS)
                .collect(),
            name: group.name,
        })
        .filter(|group| !group.options.is_empty())
        .collect()
}

/// Menu labels come from a controller response, so they are bounded and free of
/// control characters before they can reach AppKit.
fn is_tray_label(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_TRAY_LABEL_CHARS
        && !value.chars().any(char::is_control)
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

pub(crate) fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let snapshot = app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .snapshot();
    let menu = build_tray_menu(app, &snapshot, &[], None)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip(PRODUCT_NAME)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match tray_action(event.id.as_ref()) {
            TrayAction::OpenPage(page) => show_main_page(app, page),
            TrayAction::Quit => request_shell_shutdown(app, 0),
            TrayAction::ProxySelection => handle_tray_proxy_event(app, event.id.as_ref()),
            TrayAction::Engine(action) => handle_tray_engine_event(app, action),
            TrayAction::OpenDiagnostics => open_diagnostic_logs(app),
            TrayAction::ReloadDashboard => request_dashboard_reload(app),
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_page(tray.app_handle(), MainPage::General);
            }
        })
        .build(app)?;
    start_tray_state_updates(app.clone());
    Ok(())
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

fn build_tray_menu(
    app: &AppHandle,
    snapshot: &EngineSnapshot,
    groups: &[TrayProxyGroup],
    route_mode: Option<&str>,
) -> tauri::Result<Menu<Wry>> {
    let dashboard = MenuItem::with_id(
        app,
        TRAY_DASHBOARD_ID,
        crate::i18n::text(app, "Dashboard"),
        true,
        None::<&str>,
    )?;
    let about = MenuItem::with_id(
        app,
        TRAY_ABOUT_ID,
        crate::i18n::text(app, "About"),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        TRAY_QUIT_ID,
        crate::i18n::text(app, "Quit"),
        true,
        None::<&str>,
    )?;
    let separator = PredefinedMenuItem::separator(app)?;

    let mut items: Vec<Box<dyn IsMenuItem<Wry>>> = vec![
        Box::new(dashboard),
        Box::new(MenuItem::with_id(
            app,
            TRAY_RELOAD_ID,
            crate::i18n::text(app, "Reload dashboard"),
            true,
            None::<&str>,
        )?),
        Box::new(MenuItem::with_id(
            app,
            TRAY_DIAGNOSTICS_ID,
            crate::i18n::text(app, "Open diagnostic logs…"),
            true,
            None::<&str>,
        )?),
    ];
    let ready = ready_mode(snapshot);
    items.push(Box::new(MenuItem::with_id(
        app,
        "core-start",
        crate::i18n::text(app, "Start local core"),
        snapshot.desired_mode == EngineMode::Off,
        None::<&str>,
    )?));
    items.push(Box::new(MenuItem::with_id(
        app,
        "core-stop",
        crate::i18n::text(app, "Stop core"),
        snapshot.desired_mode != EngineMode::Off || snapshot.state != EngineState::Off,
        None::<&str>,
    )?));
    for (enabled_id, disabled_id, label, active) in [
        (
            "proxy-enable",
            "proxy-disable",
            "System Proxy",
            ready.is_some_and(EngineMode::system_proxy_enabled),
        ),
        (
            "tun-enable",
            "tun-disable",
            "TUN Mode",
            ready.is_some_and(EngineMode::tunnel_enabled),
        ),
    ] {
        items.push(Box::new(CheckMenuItem::with_id(
            app,
            if active { disabled_id } else { enabled_id },
            crate::i18n::text(app, label),
            true,
            active,
            None::<&str>,
        )?));
    }
    let mut route_items: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::new();
    for (id, label) in [
        ("route-rule", "Rule"),
        ("route-global", "Global"),
        ("route-direct", "Direct"),
    ] {
        route_items.push(Box::new(CheckMenuItem::with_id(
            app,
            id,
            crate::i18n::text(app, label),
            ready.is_some(),
            route_mode.is_some_and(|mode| mode.eq_ignore_ascii_case(label)),
            None::<&str>,
        )?));
    }
    let route_references = route_items
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&dyn IsMenuItem<Wry>>>();
    items.push(Box::new(Submenu::with_items(
        app,
        crate::i18n::text(app, "Routing mode"),
        ready.is_some(),
        &route_references,
    )?));
    items.push(Box::new(PredefinedMenuItem::separator(app)?));
    let mut selections = BTreeMap::new();
    let mut next_id = 0_usize;
    let menu_id = uuid::Uuid::new_v4();
    for group in groups {
        let mut options: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::with_capacity(group.options.len());
        for option in &group.options {
            let id = format!("{TRAY_PROXY_ID_PREFIX}{menu_id}-{next_id}");
            next_id += 1;
            options.push(Box::new(CheckMenuItem::with_id(
                app,
                &id,
                option,
                group.selectable,
                group.now.as_deref() == Some(option.as_str()),
                None::<&str>,
            )?));
            if group.selectable {
                selections.insert(
                    id,
                    TrayProxySelection {
                        group: group.name.clone(),
                        proxy: option.clone(),
                    },
                );
            }
        }
        let references = options
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&dyn IsMenuItem<Wry>>>();
        items.push(Box::new(Submenu::with_items(
            app,
            &group.name,
            true,
            &references,
        )?));
    }
    items.push(Box::new(about));
    items.push(Box::new(separator));
    items.push(Box::new(quit));

    let references = items
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&dyn IsMenuItem<Wry>>>();
    let menu = Menu::with_items(app, &references)?;
    if let Err(error) = app.state::<TrayMenuState>().replace(selections) {
        emit_shell_error(app, "tray_menu_state_unavailable", error);
    }
    Ok(menu)
}

/// Rebuilds the tray menu from the running engine's controller.
///
/// Refreshing is read-only. Network menu actions use the same serialized
/// commands as the dashboard; the menu never owns network state itself.
pub(crate) async fn refresh_tray_from_controller(app: &AppHandle) -> Result<(), String> {
    let snapshot = app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .snapshot();
    let mut groups = Vec::new();
    let mut route_mode = None;
    let mut observation_error = None;
    if ready_mode(&snapshot).is_some() {
        match controller_client_for_app(app) {
            Ok(client) => {
                let (proxies, configs) = tokio::join!(client.proxies(), client.configs());
                match (proxies, configs) {
                    (Ok(proxies), Ok(configs)) => {
                        groups = tray_proxy_groups(proxies);
                        route_mode = configs.mode;
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        observation_error = Some(error.to_string());
                    }
                }
            }
            Err(error) => {
                observation_error = Some(error);
            }
        }
    }
    if app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .snapshot()
        != snapshot
    {
        return Err("engine changed while the tray was being refreshed".into());
    }
    let menu = build_tray_menu(app, &snapshot, &groups, route_mode.as_deref())
        .map_err(|error| error.to_string())?;
    app.tray_by_id(TRAY_ID)
        .ok_or_else(|| "tray icon is unavailable".to_owned())?
        .set_menu(Some(menu))
        .map_err(|error| error.to_string())?;
    match observation_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn ready_mode(snapshot: &EngineSnapshot) -> Option<EngineMode> {
    match &snapshot.state {
        EngineState::LocalProxyActive { runtime }
        | EngineState::ProxyActive { runtime }
        | EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime }
            if runtime.ready
                && snapshot.desired_mode == snapshot.state.active_mode()
                && runtime.context.generation == snapshot.generation
                && snapshot.config_digest.as_deref() == Some(runtime.config_digest.as_str())
                && runtime.owner
                    == if snapshot.desired_mode.tunnel_enabled() {
                        cfw_engine_api::EngineOwner::PacketTunnelSystemExtension
                    } else {
                        cfw_engine_api::EngineOwner::ProxyAgent
                    } =>
        {
            Some(snapshot.desired_mode)
        }
        _ => None,
    }
}

fn start_tray_state_updates(app: AppHandle) {
    let mut snapshots = app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .subscribe();
    tauri::async_runtime::spawn(async move {
        while snapshots.changed().await.is_ok() {
            if refresh_tray_from_controller(&app).await.is_err() {
                // A ready snapshot can precede the controller identity commit.
                // One bounded retry also absorbs superseded state notifications.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Err(error) = refresh_tray_from_controller(&app).await {
                    emit_shell_error(&app, "tray_menu_refresh_failed", error);
                }
            }
        }
    });
}

pub(crate) fn handle_tray_engine_event(app: &AppHandle, action: TrayEngineAction) {
    if let Err(error) = app
        .state::<crate::startup_state::NativeStartup>()
        .require_ready()
    {
        emit_shell_error(app, "native_initialization_pending", error);
        return;
    }
    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        emit_shell_error(
            app,
            "handoff_command_rejected",
            "network controls are unavailable during migration handoff".into(),
        );
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = match action {
            TrayEngineAction::StartCore | TrayEngineAction::StopCore => {
                crate::commands::set_core_enabled(
                    app.state(),
                    app.state(),
                    app.state(),
                    action == TrayEngineAction::StartCore,
                )
                .await
                .map(|_| ())
            }
            TrayEngineAction::SystemProxy(enabled) => crate::commands::set_system_proxy_enabled(
                app.state(),
                app.state(),
                app.state(),
                enabled,
            )
            .await
            .map(|_| ()),
            TrayEngineAction::Tunnel(enabled) => {
                crate::commands::set_tun_enabled(app.state(), app.state(), app.state(), enabled)
                    .await
                    .map(|_| ())
            }
            TrayEngineAction::RouteMode(mode) => {
                crate::commands::set_proxy_mode(app.state(), mode.into()).await
            }
        };
        if let Err(error) = result {
            emit_shell_error(&app, "tray_network_change_failed", error);
        }
        if let Err(error) = refresh_tray_from_controller(&app).await {
            emit_shell_error(&app, "tray_menu_refresh_failed", error);
        }
    });
}

fn handle_tray_proxy_event(app: &AppHandle, id: &str) {
    if let Err(error) = app
        .state::<crate::startup_state::NativeStartup>()
        .require_ready()
    {
        emit_shell_error(app, "native_initialization_pending", error);
        return;
    }
    if !id.starts_with(TRAY_PROXY_ID_PREFIX) {
        return;
    }
    let Some(selection) = app.state::<TrayMenuState>().resolve(id) else {
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let selected = async {
            crate::commands::select_proxy_with_persistence(
                &app.state::<crate::engine::ManagedEngine>(),
                &app.state::<crate::commands::ManagedProfiles>(),
                None,
                selection.group,
                selection.proxy,
            )
            .await
        }
        .await;
        match selected {
            Ok(()) => {
                if let Err(error) = refresh_tray_from_controller(&app).await {
                    emit_shell_error(&app, "tray_menu_refresh_failed", error);
                }
            }
            Err(error) => emit_shell_error(&app, "tray_proxy_selection_failed", error),
        }
    });
}

pub(crate) fn apply_silent_start(app: &AppHandle) -> Result<(), String> {
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
    app.set_activation_policy(tauri::ActivationPolicy::Regular)
        .map_err(|error| error.to_string())?;
    app.set_dock_visibility(true)
        .map_err(|error| error.to_string())?;
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable".to_string())?;
    window.show().map_err(|error| error.to_string())?;
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
mod tests {
    use std::collections::BTreeSet;

    use cfw_controller::{ProxyGroup, ProxyNode};

    use super::*;

    fn group(name: &str, now: Option<&str>, options: &[&str]) -> ProxyGroup {
        ProxyGroup {
            name: name.to_owned(),
            kind: "Selector".into(),
            now: now.map(ToOwned::to_owned),
            options: options.iter().map(|option| (*option).to_owned()).collect(),
            history: Vec::new(),
        }
    }

    fn snapshot(groups: Vec<ProxyGroup>) -> ProxiesSnapshot {
        ProxiesSnapshot {
            groups,
            proxies: Vec::<ProxyNode>::new(),
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RendererPageContract {
        id: String,
        title: String,
        summary: String,
    }

    fn renderer_page_ids() -> BTreeSet<String> {
        let pages: Vec<RendererPageContract> =
            serde_json::from_str(include_str!("../ui/src/pages.json"))
                .expect("renderer page contract must be strict JSON");
        assert!(
            !pages.is_empty(),
            "renderer page contract must not be empty"
        );
        for page in &pages {
            assert!(
                page.id.split('-').all(|segment| {
                    !segment.is_empty()
                        && segment
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                }),
                "renderer page id must be canonical lowercase kebab-case"
            );
            assert!(
                !page.title.trim().is_empty() && !page.summary.trim().is_empty(),
                "renderer page title and summary must not be empty"
            );
        }
        let unique = pages
            .iter()
            .map(|page| page.id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            pages.len(),
            "renderer page ids must be unique"
        );
        unique
    }

    #[test]
    fn every_native_page_is_part_of_the_renderer_page_contract() {
        let renderer_pages = renderer_page_ids();

        for page in MainPage::ALL {
            assert!(
                renderer_pages.contains(page.id()),
                "native page '{}' is absent from renderer PAGES",
                page.id()
            );
        }
    }

    #[test]
    fn about_and_update_actions_open_the_feedback_page() {
        assert_eq!(
            app_menu_action(APP_MENU_ABOUT_ID),
            Some(AppMenuAction::OpenPage(MainPage::Feedback))
        );
        assert_eq!(
            app_menu_action(APP_MENU_CHECK_UPDATE_ID),
            Some(AppMenuAction::CheckForUpdates(MainPage::Feedback))
        );
        assert_eq!(
            tray_action(TRAY_ABOUT_ID),
            TrayAction::OpenPage(MainPage::Feedback)
        );
    }

    #[test]
    fn tray_groups_are_bounded_and_sanitised() {
        let long = "n".repeat(MAX_TRAY_LABEL_CHARS + 1);
        let groups = tray_proxy_groups(snapshot(vec![
            group("Proxy", Some("HK"), &["HK", "JP"]),
            group("Control\u{7}", None, &["HK"]),
            group(&long, None, &["HK"]),
            group("Empty", None, &[]),
            group("Filtered", None, &["ok", "bad\nname"]),
        ]));

        assert_eq!(
            groups,
            vec![
                TrayProxyGroup {
                    name: "Proxy".into(),
                    now: Some("HK".into()),
                    options: vec!["HK".into(), "JP".into()],
                    selectable: true,
                },
                TrayProxyGroup {
                    name: "Filtered".into(),
                    now: None,
                    options: vec!["ok".into()],
                    selectable: true,
                },
            ]
        );

        let oversized = tray_proxy_groups(snapshot(
            (0..MAX_TRAY_GROUPS + 5)
                .map(|index| group(&format!("Group {index}"), None, &["HK"]))
                .collect(),
        ));
        assert_eq!(oversized.len(), MAX_TRAY_GROUPS);

        let wide = tray_proxy_groups(snapshot(vec![ProxyGroup {
            options: (0..MAX_TRAY_GROUP_OPTIONS + 5)
                .map(|index| format!("node-{index}"))
                .collect(),
            ..group("Wide", None, &[])
        }]));
        assert_eq!(wide[0].options.len(), MAX_TRAY_GROUP_OPTIONS);
    }

    #[test]
    fn tray_selection_is_resolved_by_generated_id_only() {
        let state = TrayMenuState::default();
        assert!(state.resolve("cfw-proxy-0").is_none());
        state
            .replace(BTreeMap::from([(
                "cfw-proxy-0".to_owned(),
                TrayProxySelection {
                    group: "Proxy".into(),
                    proxy: "HK".into(),
                },
            )]))
            .expect("store selections");

        assert_eq!(
            state.resolve("cfw-proxy-0"),
            Some(TrayProxySelection {
                group: "Proxy".into(),
                proxy: "HK".into(),
            })
        );
        // A renderer-chosen or stale id resolves to nothing, so no proxy change
        // can be triggered by an id the menu did not generate.
        assert!(state.resolve("cfw-proxy-1").is_none());
        assert!(state.resolve("dashboard").is_none());
        state.replace(BTreeMap::new()).expect("clear selections");
        assert!(state.resolve("cfw-proxy-0").is_none());
    }

    #[test]
    fn stale_selection_marker_is_dropped_when_it_is_not_an_option() {
        let groups = tray_proxy_groups(snapshot(vec![group("Proxy", Some("Gone"), &["HK"])]));
        assert_eq!(groups[0].now, None);
    }

    #[test]
    fn tray_network_actions_keep_explicit_intent_and_automatic_groups_are_read_only() {
        for (id, expected) in [
            ("core-start", TrayEngineAction::StartCore),
            ("core-stop", TrayEngineAction::StopCore),
            ("proxy-enable", TrayEngineAction::SystemProxy(true)),
            ("proxy-disable", TrayEngineAction::SystemProxy(false)),
            ("tun-enable", TrayEngineAction::Tunnel(true)),
            ("tun-disable", TrayEngineAction::Tunnel(false)),
            ("route-rule", TrayEngineAction::RouteMode("rule")),
            ("route-global", TrayEngineAction::RouteMode("global")),
            ("route-direct", TrayEngineAction::RouteMode("direct")),
        ] {
            assert_eq!(tray_action(id), TrayAction::Engine(expected));
        }
        for kind in ["URLTest", "Fallback", "LoadBalance"] {
            let mut automatic = group("Auto", Some("HK"), &["HK", "JP"]);
            automatic.kind = kind.into();
            let groups = tray_proxy_groups(snapshot(vec![automatic]));
            assert!(!groups[0].selectable);
            assert_eq!(groups[0].now.as_deref(), Some("HK"));
        }
    }

    #[test]
    fn tray_never_marks_failed_or_pending_intent_as_connected() {
        use cfw_engine_api::{EngineCommandContext, EngineOwner, RuntimeIdentity};
        let runtime = RuntimeIdentity {
            owner: EngineOwner::ProxyAgent,
            context: EngineCommandContext {
                installation_id: "fixture".into(),
                config_epoch: 1,
                generation: 2,
            },
            config_digest: "ab".repeat(32),
            ready: true,
        };
        let mut snapshot = EngineSnapshot {
            desired_mode: EngineMode::SystemProxy,
            state: EngineState::ProxyActive {
                runtime: runtime.clone(),
            },
            generation: 2,
            config_digest: Some(runtime.config_digest.clone()),
        };
        assert_eq!(ready_mode(&snapshot), Some(EngineMode::SystemProxy));
        for state in [
            EngineState::Off,
            EngineState::ProxyStarting { generation: 2 },
            EngineState::Failed {
                generation: 2,
                target: EngineMode::SystemProxy,
                error: "fixture failure".into(),
            },
            EngineState::ProxyActive {
                runtime: RuntimeIdentity {
                    ready: false,
                    ..runtime.clone()
                },
            },
            EngineState::ProxyActive {
                runtime: RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    ..runtime.clone()
                },
            },
        ] {
            snapshot.state = state;
            assert_eq!(ready_mode(&snapshot), None);
        }
        snapshot.state = EngineState::ProxyActive { runtime };
        snapshot.generation += 1;
        assert_eq!(ready_mode(&snapshot), None);
        snapshot.generation -= 1;
        snapshot.config_digest = Some("cd".repeat(32));
        assert_eq!(ready_mode(&snapshot), None);
    }
}
