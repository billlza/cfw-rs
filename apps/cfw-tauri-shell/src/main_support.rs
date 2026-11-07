//! Startup admission and the startup error boundary.
use super::*;

#[cfg(target_os = "macos")]
pub(super) fn migration_handoff_command_allowed(command: &str) -> bool {
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

pub(super) fn emit_startup_error(app: &tauri::AppHandle, kind: &str, message: String) {
    diagnostics::record(app, cfw_core::DiagnosticTopic::Startup, kind, &message);
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(kind, message),
    ) {
        eprintln!("failed to publish startup error: {error}");
    }
}

pub(super) fn admit_dashboard_launch() -> LaunchContext {
    let available = settings_store().and_then(|store| {
        store.ensure_layout().map_err(|error| error.to_string())?;
        #[cfg(target_os = "macos")]
        MigrationHandoffLease::acquire(&store.paths().app_home).map(std::mem::drop)?;
        // No dashboard may start underneath a platform installation. Windows
        // also observes durable intent: a crashed finisher releases its lock
        // while the system MSI transaction may still be running.
        #[cfg(target_os = "macos")]
        {
            UpdateInstallLease::acquire(&store.paths().app_home)
                .map(std::mem::drop)
                .map_err(|error| error.to_string())
        }
        #[cfg(windows)]
        {
            updater::admit_dashboard_startup(&store.paths().app_home)
        }
    });
    if let Err(error) = available {
        eprintln!(
            "dashboard launch blocked while a migration handoff or update installation is active: {error}"
        );
        std::process::exit(STARTUP_ADMISSION_EXIT_CODE);
    }
    LaunchContext::dashboard()
}
