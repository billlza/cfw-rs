mod controller;
mod profiles;
mod runtime;
mod settings;
mod shell_ops;
mod subscriptions;
mod toggles;

pub(crate) use controller::{
    LiveStreams, client_from_app as controller_client_for_app, close_all_connections,
    close_connection, controller_snapshot, controller_version, dns_query, flush_fake_ip_cache,
    health_check_all_proxy_providers, health_check_proxy_provider, providers_snapshot,
    rules_snapshot, select_proxy, start_connections_stream, start_log_stream,
    stop_connections_stream, stop_log_stream, test_proxy_delays, update_all_proxy_providers,
    update_all_rule_providers, update_proxy_provider, update_rule_provider,
};
pub(crate) use profiles::{
    ManagedProfiles, build_managed_profiles, cancel_credential_gc, commit_credential_gc,
    delete_profile, import_profile_text, preview_credential_gc, profile_credential_presence,
    profile_credential_requirements, profiles_snapshot, provision_profile_credentials,
    select_profile,
};
pub(crate) use runtime::{
    apply_active_profile, geoip_database_status, read_runtime_config_text, update_geoip_database,
};
pub(crate) use settings::{
    read_settings_snapshot, sanitize_legacy_preferences, set_launch_at_login_enabled,
    silent_start_enabled, write_settings_snapshot,
};
pub(crate) use shell_ops::{
    force_quit_app, move_dashboard_to_nearest_monitor, network_diagnostics,
    open_login_items_settings, open_page, open_trusted_external_url, parse_deep_links,
    refresh_tray_menu, reveal_home_directory, reveal_logs_directory, toggle_devtools,
};
pub(crate) use subscriptions::{
    import_profile_file, import_profile_url, migrate_legacy_cfw_profiles, open_profile_externally,
    profile_qrcode_svg, read_profile_text, reveal_profile, save_profile_text, update_profile,
    update_profile_info,
};
pub(crate) use toggles::{
    apply_restore_dns_servers, current_platform_design, reset_settings_snapshot, set_allow_lan,
    set_bind_address, set_log_level, set_mixin_enabled, set_proxy_mode, set_system_proxy_enabled,
    set_tun_enabled, system_proxy_state, tun_runtime_state,
};
