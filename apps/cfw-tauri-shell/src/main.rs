mod automation;
mod bootstrap;
mod commands;
mod diagnostics;
use automation::{read_automation_settings, request_wifi_name_access, write_automation_settings};
use diagnostics::{Diagnostics, report_dashboard_startup};
mod engine;
mod engine_controls;
mod i18n;
mod launch;
mod legacy;
mod lifecycle;
#[cfg(target_os = "macos")]
mod main_run_loop_driver;
mod native_components;
#[cfg(feature = "native-dashboard")]
mod native_dashboard;
#[cfg(feature = "physical-release-evidence")]
mod packet_evidence_transport;
mod release_observation;
mod service_maintenance;
mod shell;
mod startup;
mod startup_state;
mod subscription_import;
mod transport_security;
mod updater;
mod window_state;

#[cfg(feature = "physical-release-evidence")]
pub use engine::{ManagedEngine, packet_evidence};

use bootstrap::{
    LaunchContext, acknowledge_migration_handoff_renderer_ready, boot_payload, reload_dashboard,
    reopen_main_window,
};
use cfw_core::SettingsStore;
use cfw_engine_api::EngineEvent;
use commands::{
    LiveStreams, apply_active_profile, apply_restore_dns_servers, cancel_credential_gc,
    close_all_connections, close_connection, commit_credential_gc,
    commit_legacy_cfw_profile_migration, controller_snapshot, controller_version,
    current_platform_design, delete_profile, dns_query, flush_fake_ip_cache, force_quit_app,
    geoip_database_status, health_check_all_proxy_providers, health_check_proxy_provider,
    import_profile_file, import_profile_text, import_profile_url,
    move_dashboard_to_nearest_monitor, network_diagnostics, open_login_items_settings, open_page,
    open_profile_externally, parse_deep_links, preview_credential_gc,
    preview_legacy_cfw_profile_migration, profile_credential_presence,
    profile_credential_requirements, profile_qrcode_svg, profiles_snapshot, providers_snapshot,
    provision_profile_credentials, read_profile_text, read_runtime_config_text,
    read_runtime_settings_snapshot, read_settings_snapshot, refresh_tray_menu,
    reset_settings_snapshot, reveal_home_directory, reveal_logs_directory, reveal_profile,
    rules_snapshot, save_profile_text, select_profile, select_proxy, set_allow_lan,
    set_bind_address, set_core_enabled, set_launch_at_login_enabled, set_log_level,
    set_mixin_enabled, set_proxy_mode, set_system_proxy_enabled, set_tun_enabled,
    start_connections_stream, start_log_stream, stop_connections_stream, stop_log_stream,
    system_proxy_state, test_proxy_delays, toggle_devtools, tun_runtime_state,
    update_all_providers, update_all_proxy_providers, update_all_rule_providers,
    update_geoip_database, update_profile, update_profile_info, update_proxy_provider,
    update_rule_provider, write_runtime_settings_snapshot, write_settings_snapshot,
};
use engine::{engine_snapshot, prepare_legacy_cutover};
use launch::{LaunchMode, STARTUP_ADMISSION_EXIT_CODE, STARTUP_USAGE_EXIT_CODE, parse_launch_mode};
use legacy::{
    ConsumedHandoffTicket, LegacyRetirementGate, MigrationHandoffLease, begin_migration_handoff,
    disable_service_mode, legacy_retirement_status, recover_legacy_cutover,
};
use lifecycle::{AppLifecycle, quit_app, request_shutdown};
use native_components::general_switches::{
    dismiss_native_general_switches, focus_native_general_switch, sync_native_general_switches,
};
use native_components::runtime_settings::{
    dismiss_native_runtime_settings, present_native_runtime_settings,
    update_native_runtime_settings,
};
use native_components::{
    dismiss_native_profile_menu, present_native_profile_menu, update_native_profile_menu,
};
use shell::{TrayMenuState, build_app_menu, focus_main_window, handle_app_menu_event};
use tauri::{Emitter, Manager, RunEvent, WindowEvent};
use updater::{UpdaterSecurityState, check_for_updates, open_available_update};
use window_state::{WindowBoundsManager, handle_window_bounds_event};

fn settings_store() -> Result<SettingsStore, String> {
    SettingsStore::default_for_current_user().map_err(|error| error.to_string())
}

type AppInvokeHandler = Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static>;

fn migration_handoff_command_allowed(command: &str) -> bool {
    matches!(
        command,
        "acknowledge_migration_handoff_renderer_ready"
            | "boot_payload"
            | "report_dashboard_startup"
            | "reveal_logs_directory"
            | "engine_snapshot"
            | "legacy_retirement_status"
            | "prepare_legacy_cutover"
            | "disable_service_mode"
            | "recover_legacy_cutover"
            | "quit_app"
            | "force_quit_app"
            | "read_settings_snapshot"
            | "read_runtime_settings_snapshot"
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
    diagnostics::record(app, cfw_core::DiagnosticTopic::Startup, kind, &message);
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
        LaunchMode::ServiceMaintenance(action) => {
            if let Err(error) = service_maintenance::run(action) {
                eprintln!("service maintenance failed: {error}");
                std::process::exit(70);
            }
            return;
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
    let diagnostics = Diagnostics::start();
    diagnostics.record(
        cfw_core::DiagnosticTopic::Startup,
        "process_started",
        &format!(
            "version={} target={}-{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS
        ),
    );
    let builder = tauri::Builder::default()
        .manage(diagnostics)
        .manage(i18n::NativeLanguage::default())
        .manage(startup_state::NativeStartup::default())
        .manage(launch)
        .manage(LegacyRetirementGate::default())
        .manage(AppLifecycle::default())
        .manage(LiveStreams::default())
        .manage(commands::ManagedProviders::default())
        .manage(commands::NetworkDiagnosticsGate::default())
        .manage(TrayMenuState::default())
        .manage(automation::ManagedAutomation::default())
        .manage(WindowBoundsManager::default())
        .manage(commands::UiSettingsMutations::default())
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
        report_dashboard_startup,
        reload_dashboard,
        quit_app,
        read_settings_snapshot,
        read_runtime_settings_snapshot,
        write_runtime_settings_snapshot,
        read_automation_settings,
        write_automation_settings,
        request_wifi_name_access,
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
        update_all_providers,
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
        set_core_enabled,
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
        present_native_profile_menu,
        update_native_profile_menu,
        dismiss_native_profile_menu,
        present_native_runtime_settings,
        update_native_runtime_settings,
        dismiss_native_runtime_settings,
        sync_native_general_switches,
        focus_native_general_switch,
        dismiss_native_general_switches,
    ]);
    #[cfg(feature = "native-ui")]
    let builder = builder
        .manage(native_components::NativeProfileMenuState::default())
        .manage(native_components::runtime_settings::RuntimeSettingsState::default())
        .manage(native_components::general_switches::GeneralSwitchesState::default());
    let application = builder
        .invoke_handler(move |invoke: tauri::ipc::Invoke<tauri::Wry>| {
            if migration_handoff && !migration_handoff_command_allowed(invoke.message.command()) {
                let command = invoke.message.command().to_owned();
                invoke.resolver.reject(format!(
                    "command {command} is unavailable during migration handoff"
                ));
                true
            } else if !startup::command_available_before_ready(invoke.message.command())
                && let Err(error) = invoke
                    .message
                    .webview_ref()
                    .state::<startup_state::NativeStartup>()
                    .require_ready()
            {
                invoke.resolver.reject(error);
                true
            } else {
                invoke_handler(invoke)
            }
        })
        .setup(|app| {
            diagnostics::record(
                app.handle(),
                cfw_core::DiagnosticTopic::Startup,
                "native_setup_started",
                "",
            );
            app.set_menu(build_app_menu(app.handle())?)?;
            startup::start(app.handle().clone());
            Ok(())
        })
        .on_page_load(|webview, payload| {
            #[cfg(feature = "native-ui")]
            if payload.event() == tauri::webview::PageLoadEvent::Started {
                native_components::cancel_for_window(webview.app_handle(), webview.label());
                native_components::runtime_settings::cancel_for_reload(
                    webview.app_handle(),
                    webview.label(),
                );
                native_components::general_switches::cancel_for_reload(
                    webview.app_handle(),
                    webview.label(),
                );
            }
            if webview.label() == "main"
                && payload.event() == tauri::webview::PageLoadEvent::Finished
            {
                let app = webview.app_handle();
                diagnostics::record(app, cfw_core::DiagnosticTopic::Startup, "page_loaded", "");
                if let Some(window) = app.get_webview_window("main") {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(error) = bootstrap::present_loaded_dashboard(&window).await {
                            emit_startup_error(&app, "window_presentation_failed", error);
                        }
                    });
                }
            }
        })
        .on_menu_event(|app, event| handle_app_menu_event(app, event.id().as_ref()))
        .on_window_event(|window, event| {
            if let Err(error) =
                handle_window_bounds_event(window.app_handle(), window.label(), event)
            {
                emit_startup_error(window.app_handle(), "window_bounds_schedule_failed", error);
            }
            if let WindowEvent::CloseRequested { api, .. } = event {
                #[cfg(feature = "native-ui")]
                native_components::cancel_for_window(window.app_handle(), window.label());
                api.prevent_close();
                window
                    .app_handle()
                    .state::<LaunchContext>()
                    .note_window_hidden();
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

    application.run(|app, event| match event {
        RunEvent::Exit => {
            if let Err(error) = app.state::<Diagnostics>().flush() {
                eprintln!("final diagnostic flush failed: {error}");
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            let lifecycle = app.state::<AppLifecycle>();
            if !lifecycle.exit_ready() {
                api.prevent_exit();
                if let Err(error) = request_shutdown(app.clone(), 0) {
                    emit_startup_error(app, "shutdown_rejected", error);
                }
            }
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => {
            if let Err(error) = reopen_main_window(app) {
                emit_startup_error(app, "window_reopen_rejected", error);
            }
        }
        _ => {}
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
            "report_dashboard_startup",
            "reveal_logs_directory",
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
            "set_core_enabled",
            "set_system_proxy_enabled",
            "set_tun_enabled",
            "check_for_updates",
            "open_available_update",
            "refresh_tray_menu",
            "begin_migration_handoff",
            "reload_dashboard",
        ] {
            assert!(!migration_handoff_command_allowed(command), "{command}");
        }
    }
}
