mod controller;
pub(crate) use controller::select_proxy_with_persistence;
mod imported_credentials;
mod legacy_profiles;
mod profiles;
mod providers;
mod runtime;
mod runtime_settings;
pub(crate) use runtime_settings::{
    read_runtime_settings_snapshot, write_runtime_settings_snapshot,
};
mod settings;
mod shell_ops;
mod subscriptions;
mod toggles;

pub(crate) use controller::{
    LiveStreams, client_from_app as controller_client_for_app, close_all_connections,
    close_connection, controller_snapshot, controller_version, dns_query, flush_fake_ip_cache,
    rules_snapshot, select_proxy, start_connections_stream, start_log_stream,
    stop_connections_stream, stop_log_stream, test_proxy_delays,
};
pub(crate) use legacy_profiles::{
    commit_legacy_cfw_profile_migration, preview_legacy_cfw_profile_migration,
};
pub(crate) use profiles::{
    ManagedProfiles, build_managed_profiles, cancel_credential_gc, commit_credential_gc,
    delete_profile, preview_credential_gc, profile_credential_presence,
    profile_credential_requirements, profiles_snapshot, provision_profile_credentials,
    select_profile,
};
pub(crate) use runtime::{
    apply_active_profile, geoip_database_status, read_runtime_config_text, update_geoip_database,
};
pub(crate) use settings::{
    UiSettingsMutations, read_settings_snapshot, sanitize_legacy_preferences,
    set_launch_at_login_enabled, write_settings_snapshot,
};
pub(crate) use shell_ops::{
    NetworkDiagnosticsGate, force_quit_app, move_dashboard_to_nearest_monitor, network_diagnostics,
    open_login_items_settings, open_page, open_trusted_external_url, parse_deep_links,
    refresh_tray_menu, reveal_home_directory, reveal_logs_directory, toggle_devtools,
};
pub(crate) use subscriptions::{
    import_profile_file, import_profile_text, import_profile_url, open_profile_externally,
    profile_qrcode_svg, read_profile_text, reveal_profile, save_profile_text, update_profile,
    update_profile_info,
};
pub(crate) use toggles::{
    apply_restore_dns_servers, current_platform_design, reconcile_startup_services,
    reset_settings_snapshot, set_allow_lan, set_bind_address, set_core_enabled, set_log_level,
    set_mixin_enabled, set_proxy_mode, set_system_proxy_enabled, set_tun_enabled,
    system_proxy_state, tun_runtime_state,
};

pub(crate) use providers::{
    ManagedProviders, health_check_all_proxy_providers, health_check_proxy_provider,
    providers_snapshot, start_provider_refresh, update_all_providers, update_all_proxy_providers,
    update_all_rule_providers, update_proxy_provider, update_rule_provider,
};
