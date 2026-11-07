//! The menu bar tray: its actions, its proxy groups and the menu built from
//! the engine's state.

use super::*;

pub(crate) const TRAY_ID: &str = "cfw-tray";

pub(super) const TRAY_DASHBOARD_ID: &str = "dashboard";
pub(super) const TRAY_ABOUT_ID: &str = "tray-about";
pub(super) const TRAY_QUIT_ID: &str = "tray-quit";
pub(super) const TRAY_DIAGNOSTICS_ID: &str = "tray-diagnostic-logs";
pub(super) const TRAY_RELOAD_ID: &str = "tray-reload-dashboard";
/// Bounds on what a controller response may add to the menu bar. A hostile or
/// broken controller cannot grow the tray without limit.
pub(super) const MAX_TRAY_GROUPS: usize = 24;
pub(super) const MAX_TRAY_GROUP_OPTIONS: usize = 64;
pub(super) const MAX_TRAY_LABEL_CHARS: usize = 64;
/// Prefix of generated proxy menu ids. Group and node names never appear in an
/// id, so a name cannot be parsed back out of one or smuggle a separator.
pub(super) const TRAY_PROXY_ID_PREFIX: &str = "cfw-proxy-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrayAction {
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

pub(super) fn tray_action(id: &str) -> TrayAction {
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
pub(super) struct TrayProxySelection {
    pub(super) group: String,
    pub(super) proxy: String,
}

impl TrayMenuState {
    pub(super) fn replace(
        &self,
        selections: BTreeMap<String, TrayProxySelection>,
    ) -> Result<(), String> {
        let mut stored = self
            .selections
            .lock()
            .map_err(|_| "tray menu state is unavailable".to_owned())?;
        *stored = selections;
        Ok(())
    }

    pub(super) fn resolve(&self, id: &str) -> Option<TrayProxySelection> {
        self.selections.lock().ok()?.get(id).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TrayProxyGroup {
    pub(super) name: String,
    pub(super) now: Option<String>,
    pub(super) options: Vec<String>,
    pub(super) selectable: bool,
}

/// Bounded, sanitised tray view of a controller proxies snapshot.
pub(super) fn tray_proxy_groups(snapshot: ProxiesSnapshot) -> Vec<TrayProxyGroup> {
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
pub(super) fn is_tray_label(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_TRAY_LABEL_CHARS
        && !value.chars().any(char::is_control)
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

pub(super) fn build_tray_menu(
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
    let ready = ready_mode(
        app.state::<crate::engine::ManagedEngine>()
            .coordinator
            .runtime_platform(),
        snapshot,
    );
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
