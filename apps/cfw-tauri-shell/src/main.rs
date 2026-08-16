mod bootstrap;
mod commands;
mod engine;
mod launch;
mod legacy;
mod lifecycle;
#[cfg(feature = "physical-release-evidence")]
mod packet_evidence_transport;
mod release_observation;
mod shell;
mod subscription_import;
mod updater;
mod window_state;

#[cfg(feature = "physical-release-evidence")]
pub use engine::{ManagedEngine, packet_evidence};

use bootstrap::{LaunchContext, acknowledge_migration_handoff_renderer_ready, boot_payload};
use cfw_apple_network::NativeFrameworkBridge;
use cfw_core::SettingsStore;
use cfw_engine_api::EngineEvent;
use commands::{
    LiveStreams, apply_active_profile, apply_restore_dns_servers, build_managed_profiles,
    cancel_credential_gc, close_all_connections, close_connection, commit_credential_gc,
    commit_legacy_cfw_profile_migration, controller_snapshot, controller_version,
    current_platform_design, delete_profile, dns_query, flush_fake_ip_cache, force_quit_app,
    geoip_database_status, health_check_all_proxy_providers, health_check_proxy_provider,
    import_profile_file, import_profile_text, import_profile_url,
    move_dashboard_to_nearest_monitor, network_diagnostics, open_login_items_settings, open_page,
    open_profile_externally, parse_deep_links, preview_credential_gc,
    preview_legacy_cfw_profile_migration, profile_credential_presence,
    profile_credential_requirements, profile_qrcode_svg, profiles_snapshot, providers_snapshot,
    provision_profile_credentials, read_profile_text, read_runtime_config_text,
    read_settings_snapshot, refresh_tray_menu, reset_settings_snapshot, reveal_home_directory,
    reveal_logs_directory, reveal_profile, rules_snapshot, save_profile_text, select_profile,
    select_proxy, set_allow_lan, set_bind_address, set_launch_at_login_enabled, set_log_level,
    set_mixin_enabled, set_proxy_mode, set_system_proxy_enabled, set_tun_enabled,
    start_connections_stream, start_log_stream, stop_connections_stream, stop_log_stream,
    system_proxy_state, test_proxy_delays, toggle_devtools, tun_runtime_state,
    update_all_proxy_providers, update_all_rule_providers, update_geoip_database, update_profile,
    update_profile_info, update_proxy_provider, update_rule_provider, write_settings_snapshot,
};
use engine::{
    build_managed_engine, engine_snapshot, prepare_legacy_cutover, start_engine_event_forwarder,
};
use launch::{LaunchMode, parse_launch_mode};

const STARTUP_USAGE_EXIT_CODE: i32 = 64;
const STARTUP_ADMISSION_EXIT_CODE: i32 = 78;
use legacy::{
    ConsumedHandoffTicket, LegacyRetirementGate, MigrationHandoffLease, begin_migration_handoff,
    disable_service_mode, legacy_retirement_status, recover_legacy_cutover, run_launch_preflight,
};
use lifecycle::{AppLifecycle, quit_app, request_shutdown};
use shell::{
    TrayMenuState, apply_silent_start, build_app_menu, build_tray, focus_main_window,
    handle_app_menu_event, prepare_migration_handoff_window,
};
use tauri::{Emitter, Manager, RunEvent, WindowEvent};
use updater::{UpdaterSecurityState, check_for_updates, open_available_update};
use window_state::{WindowBoundsManager, handle_window_bounds_event, initialize_window_bounds};

fn settings_store() -> Result<SettingsStore, String> {
    SettingsStore::default_for_current_user().map_err(|error| error.to_string())
}

type AppInvokeHandler = Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static>;

fn migration_handoff_command_allowed(command: &str) -> bool {
    matches!(
        command,
        "acknowledge_migration_handoff_renderer_ready"
            | "boot_payload"
            | "engine_snapshot"
            | "legacy_retirement_status"
            | "prepare_legacy_cutover"
            | "disable_service_mode"
            | "recover_legacy_cutover"
            | "quit_app"
            | "force_quit_app"
            | "read_settings_snapshot"
            | "profiles_snapshot"
            | "profile_credential_requirements"
            | "profile_credential_presence"
            | "controller_snapshot"
            | "controller_version"
            | "providers_snapshot"
            | "rules_snapshot"
            | "read_profile_text"
            | "read_runtime_config_text"
            | "geoip_database_status"
            | "system_proxy_state"
            | "tun_runtime_state"
            | "current_platform_design"
            | "open_page"
            | "move_dashboard_to_nearest_monitor"
            | "parse_deep_links"
            | "network_diagnostics"
    )
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
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let launch_arguments = match parse_launch_mode(&arguments) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("startup argument admission failed: {error}");
            std::process::exit(STARTUP_USAGE_EXIT_CODE);
        }
    };
    let launch = match launch_arguments {
        LaunchMode::Dashboard => {
            let available = settings_store().and_then(|store| {
                store.ensure_layout().map_err(|error| error.to_string())?;
                MigrationHandoffLease::acquire(&store.paths().app_home).map(std::mem::drop)
            });
            if let Err(error) = available {
                eprintln!("dashboard launch blocked while migration handoff is active: {error}");
                std::process::exit(STARTUP_ADMISSION_EXIT_CODE);
            }
            LaunchContext::dashboard()
        }
        LaunchMode::MigrationHandoff { token } => {
            let admitted = settings_store().and_then(|store| {
                store.ensure_layout().map_err(|error| error.to_string())?;
                let executable = std::env::current_exe()
                    .map_err(|error| format!("cannot resolve handoff executable: {error}"))?;
                let ticket = ConsumedHandoffTicket::consume(
                    &store.paths().app_home,
                    &token,
                    &executable,
                    &arguments,
                )?;
                let lease = MigrationHandoffLease::acquire(&store.paths().app_home)?;
                legacy::require_canonical_handoff_candidate()?;
                Ok((ticket, lease))
            });
            match admitted {
                Ok((ticket, lease)) => LaunchContext::handoff(ticket, lease),
                Err(error) => {
                    eprintln!("migration handoff admission failed: {error}");
                    std::process::exit(STARTUP_ADMISSION_EXIT_CODE);
                }
            }
        }
        #[cfg(feature = "physical-release-evidence")]
        LaunchMode::PacketEvidence => {
            if let Err(error) = packet_evidence_transport::run_packet_evidence_proxy() {
                eprintln!("physical Packet evidence Host control failed: {error}");
                std::process::exit(70);
            }
            return;
        }
    };
    let migration_handoff = launch.is_migration_handoff();
    let builder = tauri::Builder::default()
        .manage(launch)
        .manage(LegacyRetirementGate::default())
        .manage(AppLifecycle::default())
        .manage(LiveStreams::default())
        .manage(TrayMenuState::default())
        .manage(WindowBoundsManager::default())
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
    let invoke_handler: AppInvokeHandler = Box::new(tauri::generate_handler![
        acknowledge_migration_handoff_renderer_ready,
        engine_snapshot,
        boot_payload,
        quit_app,
        read_settings_snapshot,
        write_settings_snapshot,
        legacy_retirement_status,
        begin_migration_handoff,
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
        open_available_update,
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
        stop_log_stream,
        stop_connections_stream,
        close_connection,
        close_all_connections,
        dns_query,
        flush_fake_ip_cache,
        read_profile_text,
        save_profile_text,
        read_runtime_config_text,
        apply_active_profile,
        import_profile_url,
        import_profile_file,
        update_profile,
        update_profile_info,
        profile_qrcode_svg,
        reveal_profile,
        open_profile_externally,
        geoip_database_status,
        update_geoip_database,
        preview_legacy_cfw_profile_migration,
        commit_legacy_cfw_profile_migration,
        set_system_proxy_enabled,
        system_proxy_state,
        set_tun_enabled,
        tun_runtime_state,
        set_proxy_mode,
        set_allow_lan,
        set_bind_address,
        set_log_level,
        set_mixin_enabled,
        apply_restore_dns_servers,
        reset_settings_snapshot,
        current_platform_design,
        open_page,
        reveal_home_directory,
        reveal_logs_directory,
        open_login_items_settings,
        move_dashboard_to_nearest_monitor,
        refresh_tray_menu,
        toggle_devtools,
        force_quit_app,
        parse_deep_links,
        network_diagnostics,
    ]);
    let application = builder
        .invoke_handler(move |invoke: tauri::ipc::Invoke<tauri::Wry>| {
            if migration_handoff && !migration_handoff_command_allowed(invoke.message.command()) {
                let command = invoke.message.command().to_owned();
                invoke.resolver.reject(format!(
                    "command {command} is unavailable during migration handoff"
                ));
                true
            } else {
                invoke_handler(invoke)
            }
        })
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
            run_launch_preflight(app.handle()).map_err(std::io::Error::other)?;

            #[cfg(feature = "physical-release-evidence")]
            if !app.state::<LaunchContext>().is_migration_handoff()
                && let Err(error) =
                    packet_evidence_transport::run_packet_evidence_transaction(app.handle().clone())
            {
                eprintln!("physical Packet evidence control is unavailable: {error}");
            }

            if app.state::<LaunchContext>().is_migration_handoff() {
                prepare_migration_handoff_window(app.handle()).map_err(std::io::Error::other)?;
                app.state::<LaunchContext>()
                    .mark_renderer_native_ready()
                    .map_err(std::io::Error::other)?;
            } else {
                build_tray(app.handle())?;
                if let Err(error) = initialize_window_bounds(app.handle()) {
                    emit_startup_error(app.handle(), "window_bounds_restore_failed", error);
                }
                if let Err(error) = apply_silent_start(app.handle()) {
                    emit_startup_error(app.handle(), "silent_start_failed", error);
                }
            }
            Ok(())
        })
        .on_menu_event(|app, event| handle_app_menu_event(app, event.id().as_ref()))
        .on_window_event(|window, event| {
            if let Err(error) =
                handle_window_bounds_event(window.app_handle(), window.label(), event)
            {
                emit_startup_error(window.app_handle(), "window_bounds_schedule_failed", error);
            }
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
                if let Err(error) = request_shutdown(app.clone(), 0) {
                    emit_startup_error(app, "shutdown_rejected", error);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::migration_handoff_command_allowed;

    #[test]
    fn migration_handoff_backend_exposes_only_read_and_cutover_commands() {
        for command in [
            "acknowledge_migration_handoff_renderer_ready",
            "boot_payload",
            "engine_snapshot",
            "prepare_legacy_cutover",
            "disable_service_mode",
            "recover_legacy_cutover",
            "quit_app",
        ] {
            assert!(migration_handoff_command_allowed(command), "{command}");
        }
        for command in [
            "apply_active_profile",
            "write_settings_snapshot",
            "select_profile",
            "set_system_proxy_enabled",
            "set_tun_enabled",
            "check_for_updates",
            "open_available_update",
            "refresh_tray_menu",
            "begin_migration_handoff",
        ] {
            assert!(!migration_handoff_command_allowed(command), "{command}");
        }
    }
}
