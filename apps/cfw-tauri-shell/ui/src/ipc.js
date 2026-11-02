// The IPC boundary of the dashboard: the only commands it may invoke and the
// only events it may subscribe to.
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

/// Every command this dashboard is allowed to invoke. The list exists so a typo
/// or a resurrected retired command fails in the renderer instead of reaching
/// the IPC boundary, and so `ui/tests/contract.test.mjs` can prove the whole
/// surface against `generate_handler!` mechanically.
export const UI_COMMANDS = Object.freeze([
  "acknowledge_migration_handoff_renderer_ready",
  "apply_active_profile",
  "begin_migration_handoff",
  "boot_payload",
  "report_dashboard_startup",
  "reload_dashboard",
  "resolve_update_install",
  "cancel_credential_gc",
  "cancel_update_install",
  "check_for_updates",
  "close_all_connections",
  "close_connection",
  "commit_credential_gc",
  "commit_legacy_cfw_profile_migration",
  "commit_update_install",
  "controller_snapshot",
  "controller_version",
  "current_platform_design",
  "delete_profile",
  "disable_service_mode",
  "dns_query",
  "engine_snapshot",
  "flush_fake_ip_cache",
  "force_quit_app",
  "geoip_database_status",
  "health_check_all_proxy_providers",
  "health_check_proxy_provider",
  "import_profile_file",
  "import_profile_text",
  "import_profile_url",
  "legacy_retirement_status",
  "network_diagnostics",
  "present_native_runtime_settings",
  "update_native_runtime_settings",
  "dismiss_native_runtime_settings",
  "sync_native_general_switches",
  "focus_native_general_switch",
  "dismiss_native_general_switches",
  "present_native_prompt_dialog",
  "update_native_prompt_dialog",
  "dismiss_native_prompt_dialog",
  "present_native_window_glass",
  "update_native_window_glass",
  "dismiss_native_window_glass",
  "present_native_profile_menu",
  "update_native_profile_menu",
  "dismiss_native_profile_menu",
  "open_login_items_settings",
  "open_available_update",
  "open_page",
  "open_profile_externally",
  "prepare_update_install",
  "preview_credential_gc",
  "preview_legacy_cfw_profile_migration",
  "prepare_legacy_cutover",
  "profile_credential_presence",
  "profile_credential_requirements",
  "profile_qrcode_svg",
  "profiles_snapshot",
  "providers_snapshot",
  "provision_profile_credentials",
  "quit_app",
  "read_profile_source_url",
  "read_profile_text",
  "read_runtime_config_text",
  "read_settings_snapshot",
  "read_runtime_settings_snapshot",
  "read_automation_settings",
  "request_wifi_name_access",
  "recover_legacy_cutover",
  "reconcile_startup_services",
  "refresh_tray_menu",
  "reset_settings_snapshot",
  "reveal_home_directory",
  "reveal_logs_directory",
  "reveal_profile",
  "rules_snapshot",
  "save_profile_text",
  "select_profile",
  "select_proxy",
  "set_launch_at_login_enabled",
  "set_proxy_mode",
  "set_core_enabled",
  "set_system_proxy_enabled",
  "set_tun_enabled",
  "start_connections_stream",
  "start_log_stream",
  "stop_connections_stream",
  "stop_log_stream",
  "test_proxy_delays",
  "update_all_providers",
  "update_profile",
  "update_profile_info",
  "update_proxy_provider",
  "update_rule_provider",
  "write_settings_snapshot",
  "write_runtime_settings_snapshot",
  "write_automation_settings",
]);

/// Every event this dashboard subscribes to. `tauri://drag-drop` is emitted by
/// the webview itself; the rest are emitted by this application.
export const UI_EVENTS = Object.freeze([
  "cfw://connections-snapshot",
  "cfw://engine-event",
  "cfw://engine-snapshot",
  "cfw://log-lines",
  "cfw://page",
  "cfw://settings-changed",
  "cfw://stream-error",
  "cfw://update-available",
  "cfw://update-progress",
  "tauri://drag-drop",
]);

const COMMANDS = new Set(UI_COMMANDS);

const EVENTS = new Set(UI_EVENTS);

export const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

export const invoke = async (command, args = {}) => {
  if (!COMMANDS.has(command)) {
    throw new Error(`${command} is not a command this dashboard may invoke`);
  }
  return tauriInvoke(command, args);
};

export const listen = async (event, handler) => {
  if (!EVENTS.has(event)) {
    throw new Error(`${event} is not an event this dashboard may subscribe to`);
  }
  return tauriListen(event, handler);
};
