mod commands;
mod engine;
mod legacy;
mod lifecycle;
mod shell;
mod updater;

use cfw_apple_network::NativeFrameworkBridge;
use cfw_core::SettingsStore;
use cfw_engine_api::EngineEvent;
use commands::{
    LiveStreams, automatic_updates_enabled, build_managed_profiles, cancel_credential_gc,
    close_all_connections, close_connection, commit_credential_gc, controller_snapshot,
    controller_version, delete_profile, dns_query, flush_fake_ip_cache,
    health_check_all_proxy_providers, health_check_proxy_provider, import_profile_text,
    preview_credential_gc, profile_credential_presence, profile_credential_requirements,
    profiles_snapshot, providers_snapshot, provision_profile_credentials, read_settings_snapshot,
    rules_snapshot, select_profile, select_proxy, set_launch_at_login_enabled,
    start_connections_stream, start_log_stream, test_proxy_delays, update_all_proxy_providers,
    update_all_rule_providers, update_proxy_provider, update_rule_provider,
    write_settings_snapshot,
};
use engine::{
    boot_payload, build_managed_engine, engine_snapshot, prepare_legacy_cutover, set_engine_mode,
    start_engine_event_forwarder,
};
use legacy::{
    LegacyRetirementGate, MigrationHandoffLease, disable_service_mode, legacy_retirement_status,
    recover_legacy_cutover, run_launch_preflight,
};
use lifecycle::{AppLifecycle, quit_app, request_shutdown};
use shell::{
    apply_silent_start, build_app_menu, build_tray, focus_main_window, handle_app_menu_event,
};
use tauri::{Emitter, Manager, RunEvent, WindowEvent};
use updater::{
    UpdaterSecurityState, cancel_update_install, check_for_updates, install_available_update,
};

#[derive(Debug)]
pub(crate) struct LaunchContext {
    pub(crate) migration_handoff: bool,
    _handoff_lease: Option<MigrationHandoffLease>,
}

fn settings_store() -> Result<SettingsStore, String> {
    SettingsStore::default_for_current_user().map_err(|error| error.to_string())
}

fn emit_startup_error(app: &tauri::AppHandle, kind: &str, message: String) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(kind, message),
    ) {
        eprintln!("failed to publish startup error: {error}");
    }
}

fn main() {
    let migration_handoff = std::env::args_os()
        .skip(1)
        .any(|argument| argument == "--migration-handoff");
    let handoff_lease = if migration_handoff {
        let lease = settings_store().and_then(|store| {
            store.ensure_layout().map_err(|error| error.to_string())?;
            MigrationHandoffLease::acquire(&store.paths().app_home)
        });
        match lease {
            Ok(lease) => Some(lease),
            Err(error) => {
                eprintln!("migration handoff admission failed: {error}");
                return;
            }
        }
    } else {
        None
    };
    let builder = tauri::Builder::default()
        .manage(LaunchContext {
            migration_handoff,
            _handoff_lease: handoff_lease,
        })
        .manage(LegacyRetirementGate::default())
        .manage(AppLifecycle::default())
        .manage(LiveStreams::default())
        .manage(UpdaterSecurityState::default());
    // The explicit handoff instance must coexist with the still-running 0.3.5
    // GUI so it can validate 0.4.0 without asking the user to quit and trigger
    // old cleanup_runtime. Every destructive command still requires the full
    // receipt/journal/confirmation gates.
    let builder = if migration_handoff {
        builder
    } else {
        builder.plugin(tauri_plugin_single_instance::init(
            |app, _arguments, _cwd| {
                focus_main_window(app);
            },
        ))
    };
    let application = builder
        .invoke_handler(tauri::generate_handler![
            engine_snapshot,
            set_engine_mode,
            boot_payload,
            quit_app,
            read_settings_snapshot,
            write_settings_snapshot,
            legacy_retirement_status,
            prepare_legacy_cutover,
            disable_service_mode,
            recover_legacy_cutover,
            set_launch_at_login_enabled,
            import_profile_text,
            profiles_snapshot,
            profile_credential_requirements,
            profile_credential_presence,
            provision_profile_credentials,
            preview_credential_gc,
            commit_credential_gc,
            cancel_credential_gc,
            select_profile,
            delete_profile,
            check_for_updates,
            install_available_update,
            cancel_update_install,
            controller_snapshot,
            controller_version,
            providers_snapshot,
            rules_snapshot,
            select_proxy,
            test_proxy_delays,
            health_check_proxy_provider,
            health_check_all_proxy_providers,
            update_proxy_provider,
            update_all_proxy_providers,
            update_rule_provider,
            update_all_rule_providers,
            start_log_stream,
            start_connections_stream,
            close_connection,
            close_all_connections,
            dns_query,
            flush_fake_ip_cache,
        ])
        .setup(|app| {
            let native_bridge = NativeFrameworkBridge::load();
            let managed_profiles =
                build_managed_profiles(native_bridge.clone()).map_err(std::io::Error::other)?;
            if !app.manage(managed_profiles) {
                return Err(std::io::Error::other("managed profiles were registered twice").into());
            }
            let managed_engine =
                build_managed_engine(native_bridge).map_err(std::io::Error::other)?;
            if !app.manage(managed_engine) {
                return Err(std::io::Error::other("managed engine was registered twice").into());
            }
            start_engine_event_forwarder(app.handle().clone());

            app.set_menu(build_app_menu(app.handle())?)?;
            build_tray(app.handle())?;
            run_launch_preflight(app.handle()).map_err(std::io::Error::other)?;

            if let Err(error) = apply_silent_start(app.handle()) {
                emit_startup_error(app.handle(), "silent_start_failed", error);
            }

            let update_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match automatic_updates_enabled() {
                    Ok(true) => {
                        if let Err(error) = check_for_updates(update_app.clone()).await {
                            emit_startup_error(&update_app, "update_check_failed", error);
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        emit_startup_error(&update_app, "update_preference_unreadable", error);
                    }
                }
            });
            Ok(())
        })
        .on_menu_event(|app, event| handle_app_menu_event(app, event.id().as_ref()))
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if let Err(error) = window.hide() {
                    emit_startup_error(
                        window.app_handle(),
                        "window_hide_failed",
                        error.to_string(),
                    );
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build Clash for Mac");

    application.run(|app, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            let lifecycle = app.state::<AppLifecycle>();
            if !lifecycle.exit_ready() {
                api.prevent_exit();
                request_shutdown(app.clone(), 0);
            }
        }
    });
}
