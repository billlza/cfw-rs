use std::collections::BTreeMap;
use std::sync::Mutex;

use cfw_controller::ProxiesSnapshot;
use cfw_engine_api::EngineEvent;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::commands::{controller_client_for_app, silent_start_enabled};
use crate::lifecycle::request_shutdown;
use crate::updater::check_for_updates;

const PRODUCT_NAME: &str = "Clash for Mac";
const TRAY_ID: &str = "cfw-tray";
/// Bounds on what a controller response may add to the menu bar. A hostile or
/// broken controller cannot grow the tray without limit.
const MAX_TRAY_GROUPS: usize = 24;
const MAX_TRAY_GROUP_OPTIONS: usize = 64;
const MAX_TRAY_LABEL_CHARS: usize = 64;
/// Prefix of generated proxy menu ids. Group and node names never appear in an
/// id, so a name cannot be parsed back out of one or smuggle a separator.
const TRAY_PROXY_ID_PREFIX: &str = "cfw-proxy-";

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
}

/// Bounded, sanitised tray view of a controller proxies snapshot.
fn tray_proxy_groups(snapshot: ProxiesSnapshot) -> Vec<TrayProxyGroup> {
    snapshot
        .groups
        .into_iter()
        .filter(|group| is_tray_label(&group.name))
        .take(MAX_TRAY_GROUPS)
        .map(|group| TrayProxyGroup {
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
    let menu = build_tray_menu(app, &[])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip(PRODUCT_NAME)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "dashboard" => show_main_page(app, "general"),
            "tray-about" => show_main_page(app, "about"),
            "tray-quit" => request_shutdown(app.clone(), 0),
            id => handle_tray_proxy_event(app, id),
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

fn build_tray_menu(app: &AppHandle, groups: &[TrayProxyGroup]) -> tauri::Result<Menu<Wry>> {
    let dashboard = MenuItem::with_id(app, "dashboard", "Dashboard", true, None::<&str>)?;
    let about = MenuItem::with_id(app, "tray-about", "About", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "tray-quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    let mut items: Vec<Box<dyn IsMenuItem<Wry>>> = vec![Box::new(dashboard)];
    let mut selections = BTreeMap::new();
    let mut next_id = 0_usize;
    for group in groups {
        let mut options: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::with_capacity(group.options.len());
        for option in &group.options {
            let id = format!("{TRAY_PROXY_ID_PREFIX}{next_id}");
            next_id += 1;
            options.push(Box::new(CheckMenuItem::with_id(
                app,
                &id,
                option,
                true,
                group.now.as_deref() == Some(option.as_str()),
                None::<&str>,
            )?));
            selections.insert(
                id,
                TrayProxySelection {
                    group: group.name.clone(),
                    proxy: option.clone(),
                },
            );
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
/// This only reads proxy groups and selects one of the options the controller
/// itself reported; it cannot start, stop, or reconfigure an engine.
pub(crate) async fn refresh_tray_from_controller(app: &AppHandle) -> Result<(), String> {
    let client = controller_client_for_app(app)?;
    let proxies = client.proxies().await.map_err(|error| error.to_string())?;
    let groups = tray_proxy_groups(proxies);
    let menu = build_tray_menu(app, &groups).map_err(|error| error.to_string())?;
    app.tray_by_id(TRAY_ID)
        .ok_or_else(|| "tray icon is unavailable".to_owned())?
        .set_menu(Some(menu))
        .map_err(|error| error.to_string())
}

fn handle_tray_proxy_event(app: &AppHandle, id: &str) {
    if !id.starts_with(TRAY_PROXY_ID_PREFIX) {
        return;
    }
    let Some(selection) = app.state::<TrayMenuState>().resolve(id) else {
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let selected = async {
            controller_client_for_app(&app)?
                .select_proxy(&selection.group, &selection.proxy)
                .await
                .map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
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
                },
                TrayProxyGroup {
                    name: "Filtered".into(),
                    now: None,
                    options: vec!["ok".into()],
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
}
