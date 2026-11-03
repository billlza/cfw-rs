//! Engine and settings switches restored from 0.3.5.
//!
//! Network mode switches and runtime preferences share the serialized engine
//! path. Online settings changes replace a validated projection and restore the
//! previous runtime if start or commit fails. UI-only preferences remain local.

use cfw_core::UiPreferences;
use cfw_engine_api::{EngineMode, EngineState};
use serde::Serialize;
use tauri::{AppHandle, State};

use super::controller::{controller_client, ipc_error};
use super::settings::{UiSettingsSnapshot, settings_snapshot_with_live_status};
use crate::engine::{EngineStatusPayload, ManagedEngine};
use crate::platform_maintenance::PlatformMaintenanceGate;
use crate::window_state::WindowBoundsManager;
use crate::{commands::ManagedProfiles, settings_store};

/// Upper bound on a restore-DNS request, matching the legacy settings reader.
const MAX_RESTORE_DNS_SERVERS: usize = 32;

/// 0.3.5 returned this bare enum from `system_proxy_state`, and the renderer
/// compares it against `"Enabled"`. The variants keep that wire shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum SystemProxyState {
    Enabled,
    Disabled,
}

/// Runtime view of the Packet Tunnel, keeping the 0.3.5 key set.
///
/// `managed_core_pid` is always `null`: there is no child core process in this
/// architecture, and `service_mode` reports the Login Item registration state
/// rather than a privileged helper, which no longer exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TunRuntimeState {
    tun_mode: bool,
    service_mode: String,
    want_core: bool,
    managed_core_pid: Option<u32>,
    tun_enable: bool,
    active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg(target_os = "macos")]
pub(crate) struct PlatformDesign {
    target: &'static str,
    system_proxy_strategy: &'static str,
    helper_strategy: &'static str,
    launchd_strategy: &'static str,
    tun_strategy: &'static str,
    intel_supported: bool,
    minimum_macos: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg(windows)]
pub(crate) struct PlatformDesign {
    target: &'static str,
    system_proxy_strategy: &'static str,
    helper_strategy: &'static str,
    startup_strategy: &'static str,
    tun_strategy: &'static str,
}

#[tauri::command]
pub(crate) fn current_platform_design() -> PlatformDesign {
    #[cfg(target_os = "macos")]
    {
        PlatformDesign {
            target: "macos-arm64",
            system_proxy_strategy: "signed ProxyAgent under Global Authority; app-owned loopback listener only",
            helper_strategy: "no privileged helper; the 0.3.x root helper is retired and tombstoned",
            launchd_strategy: "SMAppService Login Item only; no ad-hoc launchd jobs or shell scripts",
            tun_strategy: "NetworkExtension Packet Tunnel System Extension, ticket-only start",
            intel_supported: false,
            minimum_macos: "15.0",
        }
    }
    #[cfg(windows)]
    {
        PlatformDesign {
            target: "windows-x64",
            system_proxy_strategy: "Current-user Windows proxy with owned restoration",
            helper_strategy: "Windows authority service and ordinary-user Agent",
            startup_strategy: "Current-user sign-in registration; Windows controls startup approval",
            tun_strategy: "Not available in this development build",
        }
    }
}

fn engine_state_is_ready(state: &EngineState, mode: EngineMode) -> bool {
    match (state, mode) {
        (EngineState::ProxyActive { runtime }, EngineMode::SystemProxy)
        | (EngineState::TunnelActive { runtime }, EngineMode::Tunnel)
        | (
            EngineState::TunnelSystemProxyActive { runtime },
            EngineMode::SystemProxy | EngineMode::Tunnel | EngineMode::TunnelSystemProxy,
        ) => runtime.ready,
        _ => false,
    }
}

#[tauri::command]
pub(crate) fn system_proxy_state(engine: State<'_, ManagedEngine>) -> SystemProxyState {
    if engine_state_is_ready(
        &engine.coordinator.snapshot().state,
        EngineMode::SystemProxy,
    ) {
        SystemProxyState::Enabled
    } else {
        SystemProxyState::Disabled
    }
}

#[tauri::command]
pub(crate) fn tun_runtime_state(engine: State<'_, ManagedEngine>) -> TunRuntimeState {
    let snapshot = engine.coordinator.snapshot();
    let tunnel_running = matches!(
        snapshot.state,
        EngineState::TunnelActive { .. } | EngineState::TunnelSystemProxyActive { .. }
    );
    TunRuntimeState {
        tun_mode: snapshot.desired_mode.tunnel_enabled(),
        service_mode: tunnel_authority_state(&snapshot.state).to_owned(),
        want_core: snapshot.desired_mode != EngineMode::Off,
        managed_core_pid: None,
        tun_enable: tunnel_running,
        active: engine_state_is_ready(&snapshot.state, EngineMode::Tunnel),
    }
}

/// Where the Packet Tunnel is in its Authority-mediated lifecycle.
///
/// 0.3.5 filled this field with an `SMAppService` status for a privileged
/// helper. That mechanism is retired, so the value is derived from the engine
/// state machine instead, keeping the approval case the UI needs to surface.
fn tunnel_authority_state(state: &EngineState) -> &'static str {
    match state {
        EngineState::TunnelInstalling { .. } => "Installing",
        EngineState::AwaitingApproval { .. } => "RequiresApproval",
        EngineState::TunnelStarting { .. } => "Starting",
        EngineState::TunnelActive { .. } | EngineState::TunnelSystemProxyActive { .. } => "Enabled",
        EngineState::TunnelStopping { .. } => "Stopping",
        EngineState::Failed {
            target: EngineMode::Tunnel | EngineMode::TunnelSystemProxy,
            ..
        } => "Failed",
        _ => "NotRegistered",
    }
}

/// System Proxy switch, delegated to the shared admitted network controls.
#[tauri::command]
pub(crate) async fn set_system_proxy_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_system_proxy_enabled(&engine, &retirement, &profiles, enabled).await
}

/// Packet Tunnel switch, delegated to the shared admitted network controls.
#[tauri::command]
pub(crate) async fn set_tun_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_tun_enabled(&engine, &retirement, &profiles, enabled).await
}

/// Core switch, delegated to the shared admitted network controls.
#[tauri::command]
pub(crate) async fn set_core_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_core_enabled(&engine, &retirement, &profiles, enabled).await
}

/// User-requested recovery of the current background services after startup failed.
#[tauri::command]
pub(crate) async fn reconcile_startup_services(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::reconcile_startup_services(&engine, &retirement).await
}

/// Live proxy mode of the running engine.
///
/// This is the one runtime switch the clash-compatible controller of a sing-box
/// engine accepts, so it is pushed to the engine that is actually running and
/// fails closed when none is. `script` is rejected: this engine has no script
/// mode.
#[tauri::command]
pub(crate) async fn set_proxy_mode(
    engine: State<'_, ManagedEngine>,
    mode: String,
) -> Result<(), String> {
    let normalized = normalize_proxy_mode(&mode)?;
    let (_, lease) = engine
        .begin_current_mode_change()
        .await
        .map_err(|error| error.to_string())?;
    let client = controller_client(&engine).map_err(|error| error.to_ipc())?;
    let (result, lease) = lease
        .run_to_completion(async move {
            client
                .patch_configs(cfw_controller::ConfigPatch {
                    mode: Some(normalized.to_owned()),
                    ..cfw_controller::ConfigPatch::default()
                })
                .await
                .map_err(ipc_error)?;
            let observed = client.configs().await.map_err(ipc_error)?;
            if !observed
                .mode
                .as_deref()
                .is_some_and(|mode| mode.eq_ignore_ascii_case(normalized))
            {
                return Err("routing mode change was not confirmed by the running engine".into());
            }
            Ok(())
        })
        .await
        .map_err(|_| "routing mode task ended without a response".to_owned())?;
    drop(lease);
    result
}

fn normalize_proxy_mode(mode: &str) -> Result<&'static str, String> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "global" => Ok("Global"),
        "rule" => Ok("Rule"),
        "direct" => Ok("Direct"),
        other => Err(format!(
            "unsupported proxy mode: {other}; this engine accepts global, rule, or direct"
        )),
    }
}

/// Scalar entrypoints retain the common runtime settings transaction.
#[tauri::command]
pub(crate) async fn set_allow_lan(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<super::runtime_settings::RuntimeSettingsView, String> {
    super::runtime_settings::update(&engine, &retirement, &profiles, move |settings| {
        settings.allow_lan = enabled;
        settings.validate().map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub(crate) async fn set_bind_address(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    address: String,
) -> Result<super::runtime_settings::RuntimeSettingsView, String> {
    let address = address
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "LAN listener address must be a numeric IPv4 address")?;
    super::runtime_settings::update(&engine, &retirement, &profiles, move |settings| {
        let lan = settings
            .lan_proxy
            .as_mut()
            .ok_or("configure LAN sharing and trusted source ranges first")?;
        lan.listen = address;
        settings.validate().map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub(crate) async fn set_log_level(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    level: String,
) -> Result<super::runtime_settings::RuntimeSettingsView, String> {
    let level = super::runtime_settings::log_level(&level)?;
    super::runtime_settings::update(&engine, &retirement, &profiles, move |settings| {
        settings.log_level = level;
        Ok(())
    })
    .await
}

/// Profile mixin. Merging arbitrary user documents into the engine
/// configuration is exactly what the validated projection forbids, so mixin can
/// only be off.
#[tauri::command]
pub(crate) async fn set_mixin_enabled(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    if enabled {
        return Err(
            "profile mixin cannot be honoured: the engine configuration is projected by the app, and an imported document may only describe routing and outbound policy, so nothing was changed"
                .into(),
        );
    }
    crate::startup_state::prepare_off_main(settings_snapshot).await
}

/// Validates a restore-DNS request without touching host DNS.
///
/// The legacy `restore-dns-servers` value carries no per-service ownership
/// identity, so this product never writes DNS on the user's behalf; the cutover
/// path requires an explicit manual review for the same reason. The request is
/// still parsed so a malformed list is reported as malformed rather than as a
/// policy refusal.
#[tauri::command]
pub(crate) fn apply_restore_dns_servers(servers: String) -> Result<String, String> {
    let requested = parse_restore_dns_servers(&servers)?;
    Err(match requested {
        RestoreDnsRequest::Clear => "no DNS setting was changed: this app never writes host DNS, because the legacy restore value carries no per-service ownership identity. Clear custom DNS per service in System Settings › Network › Details › DNS".to_owned(),
        RestoreDnsRequest::Servers(servers) => format!(
            "no DNS setting was changed: this app never writes host DNS, because the legacy restore value carries no per-service ownership identity. Apply {} manually per service in System Settings › Network › Details › DNS",
            servers.join(", ")
        ),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RestoreDnsRequest {
    Clear,
    Servers(Vec<String>),
}

fn parse_restore_dns_servers(servers: &str) -> Result<RestoreDnsRequest, String> {
    let requested = servers
        .split(['\n', ',', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Err("provide at least one DNS server (or 'Empty' to clear)".into());
    }
    if requested.len() > MAX_RESTORE_DNS_SERVERS {
        return Err(format!(
            "at most {MAX_RESTORE_DNS_SERVERS} DNS servers can be requested"
        ));
    }
    if requested
        .iter()
        .any(|value| value.eq_ignore_ascii_case("empty"))
    {
        if requested.len() != 1 {
            return Err("'Empty' cannot be combined with DNS server addresses".into());
        }
        return Ok(RestoreDnsRequest::Clear);
    }
    let mut parsed = Vec::with_capacity(requested.len());
    for value in requested {
        let address = value
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("{value} is not a DNS server IP address"))?;
        parsed.push(address.to_string());
    }
    Ok(RestoreDnsRequest::Servers(parsed))
}

/// Restores renderer-owned preferences to their defaults.
///
/// `launch_at_login` is deliberately preserved: it mirrors a native registration
/// that only the transactional startup command may change, so resetting it
/// here would leave the stored preference and the system state disagreeing.
#[tauri::command]
pub(crate) async fn reset_settings_snapshot(
    app: AppHandle,
    window_bounds: State<'_, WindowBoundsManager>,
    mutations: State<'_, super::UiSettingsMutations>,
) -> Result<UiSettingsSnapshot, String> {
    let _mutation = mutations.reserve()?;
    let snapshot = window_bounds
        .commit_retention(
            &app,
            UiPreferences::default().retain_window_bounds,
            move || {
                let store = settings_store()?;
                let current = store.read_or_default().map_err(|error| error.to_string())?;
                let defaults = UiPreferences {
                    launch_at_login: current.launch_at_login,
                    ..UiPreferences::default()
                };
                store.write(&defaults).map_err(|error| error.to_string())?;
                store.snapshot().map_err(|error| error.to_string())
            },
        )
        .await?;
    crate::i18n::apply(&app, snapshot.settings.language)
        .await
        .map_err(|error| {
            format!("preferences were reset, but language application failed: {error}")
        })?;
    crate::startup_state::prepare_off_main(move || {
        super::settings::live_login_item_status()
            .and_then(|status| super::settings::with_login_item_status(snapshot, status))
            .map_err(|error| {
                format!("preferences were reset, but their display status is unavailable: {error}")
            })
    })
    .await
}

fn settings_snapshot() -> Result<UiSettingsSnapshot, String> {
    settings_snapshot_with_live_status(&settings_store()?)
}

#[cfg(test)]
mod tests;
