//! Keeping the tray current: refreshes from the controller and the handling
//! of its engine and proxy items.

use super::*;

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
    if ready_mode(
        app.state::<crate::engine::ManagedEngine>()
            .coordinator
            .runtime_platform(),
        &snapshot,
    )
    .is_some()
    {
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

pub(super) fn ready_mode(
    platform: cfw_engine_api::EngineRuntimePlatform,
    snapshot: &EngineSnapshot,
) -> Option<EngineMode> {
    crate::engine::ready_runtime(platform, snapshot).map(|_| snapshot.desired_mode)
}

pub(super) fn start_tray_state_updates(app: AppHandle) {
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

pub(super) fn handle_tray_proxy_event(app: &AppHandle, id: &str) {
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
