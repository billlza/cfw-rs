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
use crate::legacy::LegacyRetirementGate;
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
pub(crate) struct PlatformDesign {
    target: &'static str,
    system_proxy_strategy: &'static str,
    helper_strategy: &'static str,
    launchd_strategy: &'static str,
    tun_strategy: &'static str,
    intel_supported: bool,
    minimum_macos: &'static str,
}

#[tauri::command]
pub(crate) fn current_platform_design() -> PlatformDesign {
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
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_system_proxy_enabled(&engine, &retirement, &profiles, enabled).await
}

/// Packet Tunnel switch, delegated to the shared admitted network controls.
#[tauri::command]
pub(crate) async fn set_tun_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_tun_enabled(&engine, &retirement, &profiles, enabled).await
}

/// Core switch, delegated to the shared admitted network controls.
#[tauri::command]
pub(crate) async fn set_core_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    crate::engine_controls::set_core_enabled(&engine, &retirement, &profiles, enabled).await
}

/// User-requested recovery of the current background services after startup failed.
#[tauri::command]
pub(crate) async fn reconcile_startup_services(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
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
    retirement: State<'_, LegacyRetirementGate>,
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
    retirement: State<'_, LegacyRetirementGate>,
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
    retirement: State<'_, LegacyRetirementGate>,
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
/// `launch_at_login` is deliberately preserved: it mirrors a macOS registration
/// that only the transactional Login Item command may change, so resetting it
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
    crate::i18n::apply(&app, snapshot.settings.language).await?;
    crate::startup_state::prepare_off_main(move || {
        Ok(super::settings::with_login_item_status(
            snapshot,
            cfw_platform::MacOsPlatformService.login_item_status(),
        ))
    })
    .await
}

fn settings_snapshot() -> Result<UiSettingsSnapshot, String> {
    settings_snapshot_with_live_status(&settings_store()?)
}

#[cfg(test)]
mod tests {
    use cfw_engine_api::{EngineCommandContext, EngineOwner, RuntimeIdentity};

    use super::*;

    fn runtime(ready: bool) -> RuntimeIdentity {
        RuntimeIdentity {
            owner: EngineOwner::ProxyAgent,
            context: EngineCommandContext {
                installation_id: "installation".into(),
                config_epoch: 1,
                generation: 3,
            },
            config_digest: "digest".into(),
            ready,
        }
    }

    #[test]
    fn readiness_is_required_before_a_switch_reports_active() {
        for (state, mode, expected) in [
            (
                EngineState::ProxyActive {
                    runtime: runtime(true),
                },
                EngineMode::SystemProxy,
                true,
            ),
            (
                EngineState::ProxyActive {
                    runtime: runtime(false),
                },
                EngineMode::SystemProxy,
                false,
            ),
            (
                EngineState::TunnelActive {
                    runtime: runtime(true),
                },
                EngineMode::SystemProxy,
                false,
            ),
            (
                EngineState::TunnelActive {
                    runtime: runtime(true),
                },
                EngineMode::Tunnel,
                true,
            ),
            (
                EngineState::TunnelStarting { generation: 1 },
                EngineMode::Tunnel,
                false,
            ),
            (
                EngineState::AwaitingApproval { generation: 1 },
                EngineMode::Tunnel,
                false,
            ),
            (
                EngineState::TunnelSystemProxyActive {
                    runtime: runtime(true),
                },
                EngineMode::SystemProxy,
                true,
            ),
            (
                EngineState::TunnelSystemProxyActive {
                    runtime: runtime(true),
                },
                EngineMode::Tunnel,
                true,
            ),
            (EngineState::Off, EngineMode::SystemProxy, false),
        ] {
            assert_eq!(
                engine_state_is_ready(&state, mode),
                expected,
                "unexpected readiness for {state:?} as {mode:?}"
            );
        }
    }

    #[test]
    fn system_proxy_state_serializes_with_the_0_3_5_wire_values() {
        assert_eq!(
            serde_json::to_value(SystemProxyState::Enabled).expect("serialize"),
            serde_json::json!("Enabled")
        );
        assert_eq!(
            serde_json::to_value(SystemProxyState::Disabled).expect("serialize"),
            serde_json::json!("Disabled")
        );
    }

    #[test]
    fn tun_runtime_state_keeps_the_0_3_5_key_set() {
        let payload = serde_json::to_value(TunRuntimeState {
            tun_mode: true,
            service_mode: "Enabled".into(),
            want_core: true,
            managed_core_pid: None,
            tun_enable: true,
            active: true,
        })
        .expect("serialize");
        let keys = payload
            .as_object()
            .expect("object payload")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "active",
                "managed_core_pid",
                "service_mode",
                "tun_enable",
                "tun_mode",
                "want_core",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(payload["managed_core_pid"].is_null());
    }

    #[test]
    fn tunnel_authority_state_surfaces_approval_and_never_a_helper_status() {
        for (state, expected) in [
            (EngineState::Off, "NotRegistered"),
            (
                EngineState::TunnelInstalling { generation: 1 },
                "Installing",
            ),
            (
                EngineState::AwaitingApproval { generation: 1 },
                "RequiresApproval",
            ),
            (EngineState::TunnelStarting { generation: 1 }, "Starting"),
            (
                EngineState::TunnelActive {
                    runtime: runtime(true),
                },
                "Enabled",
            ),
            (EngineState::TunnelStopping { generation: 1 }, "Stopping"),
            (
                EngineState::Failed {
                    generation: 1,
                    target: EngineMode::Tunnel,
                    error: "native failure".into(),
                },
                "Failed",
            ),
            (
                EngineState::Failed {
                    generation: 1,
                    target: EngineMode::SystemProxy,
                    error: "native failure".into(),
                },
                "NotRegistered",
            ),
            (
                EngineState::ProxyActive {
                    runtime: runtime(true),
                },
                "NotRegistered",
            ),
        ] {
            assert_eq!(
                tunnel_authority_state(&state),
                expected,
                "unexpected tunnel authority state for {state:?}"
            );
        }
    }

    #[test]
    fn proxy_mode_accepts_only_the_three_engine_modes() {
        assert_eq!(normalize_proxy_mode(" Global ").expect("global"), "Global");
        assert_eq!(normalize_proxy_mode("rule").expect("rule"), "Rule");
        assert_eq!(normalize_proxy_mode("DIRECT").expect("direct"), "Direct");
        for rejected in ["script", "", "rule;drop", "globalish"] {
            assert!(
                normalize_proxy_mode(rejected).is_err(),
                "accepted unsupported mode: {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn runtime_levels_are_supported_while_untyped_mixin_remains_rejected() {
        let mixin = set_mixin_enabled(true)
            .await
            .expect_err("untyped mixin must be refused");
        assert!(mixin.contains("nothing was changed"));
        assert_eq!(
            super::super::runtime_settings::log_level(" INFO ").unwrap(),
            cfw_singbox_config::EngineLogLevel::Info
        );
        assert_eq!(
            super::super::runtime_settings::log_level("debug").unwrap(),
            cfw_singbox_config::EngineLogLevel::Debug
        );
        assert!(super::super::runtime_settings::log_level("verbose").is_err());
    }

    #[test]
    fn restore_dns_validates_input_and_never_applies_it() {
        assert_eq!(
            parse_restore_dns_servers(" Empty ").expect("clear request"),
            RestoreDnsRequest::Clear
        );
        assert_eq!(
            parse_restore_dns_servers("1.1.1.1, 2606:4700:4700::1111").expect("server request"),
            RestoreDnsRequest::Servers(vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()])
        );
        for rejected in [
            "",
            "   ",
            "empty, 1.1.1.1",
            "not-an-address",
            "1.1.1.1;evil",
        ] {
            assert!(
                parse_restore_dns_servers(rejected).is_err(),
                "accepted malformed DNS request: {rejected}"
            );
        }
        assert!(
            parse_restore_dns_servers(&vec!["1.1.1.1"; MAX_RESTORE_DNS_SERVERS + 1].join(" "))
                .is_err()
        );

        let refusal = apply_restore_dns_servers("1.1.1.1".into())
            .expect_err("a DNS change request must be refused");
        assert!(refusal.contains("no DNS setting was changed"));
        assert!(refusal.contains("1.1.1.1"));
        assert!(
            apply_restore_dns_servers("Empty".into())
                .expect_err("clearing must be refused too")
                .contains("no DNS setting was changed")
        );
    }

    /// Production source of this module, with the test module removed so the
    /// needles below cannot match this test's own text.
    fn production_source() -> &'static str {
        include_str!("toggles.rs")
            .rsplit_once("\n#[cfg(test)]\nmod tests")
            .map(|(production, _)| production)
            .expect("module source has a production section")
    }

    #[test]
    fn switch_commands_reach_the_data_plane_only_through_the_shared_transition() {
        let source = production_source();
        for command in [
            "set_core_enabled",
            "set_system_proxy_enabled",
            "set_tun_enabled",
        ] {
            let delegate = format!(
                "crate::engine_controls::{command}(&engine, &retirement, &profiles, enabled).await"
            );
            assert!(
                source.contains(&delegate),
                "{command} must delegate to the shared admitted controls"
            );
        }
        // Neither switch may drive the coordinator, the cutover, or the native
        // backend directly: doing so would skip the maintenance lease, the
        // retirement gate, and the capability check.
        for forbidden in [
            concat!("coordinator", ".set_mode"),
            concat!("coordinator", ".shutdown"),
            concat!("prepare_", "cutover"),
            concat!("preflight_", "backend"),
            concat!("take_cutover_", "authority"),
        ] {
            assert!(
                !source.contains(forbidden),
                "a switch bypasses the shared engine transition via {forbidden}"
            );
        }
    }

    #[test]
    fn switch_commands_contain_no_retired_privileged_or_preference_writing_path() {
        let source = production_source();
        for forbidden in [
            concat!("network", "setup"),
            concat!("install_", "tun_runtime"),
            concat!("start_", "tun"),
            concat!("stop_", "tun"),
            concat!("service_mode_", "status"),
            concat!("install_", "helper"),
            concat!("set_system_proxy_", "mode"),
            concat!("apply_dns_servers", "_sc"),
            concat!("Control", "Session"),
            concat!("Command", "::new"),
        ] {
            assert!(
                !source.contains(forbidden),
                "a switch still references the retired mechanism {forbidden}"
            );
        }
    }

    #[test]
    fn platform_design_describes_the_authority_mediated_architecture() {
        let design = serde_json::to_value(current_platform_design()).expect("serialize design");
        let rendered = design.to_string();
        assert_eq!(design["intel_supported"], false);
        assert_eq!(design["minimum_macos"], "15.0");
        assert!(rendered.contains("Global Authority"));
        assert!(rendered.contains("System Extension"));
        for retired in ["privileged helper daemon", "networksetup", "root helper"] {
            assert!(
                !design["tun_strategy"]
                    .as_str()
                    .unwrap_or_default()
                    .contains(retired),
                "tunnel strategy must not describe a retired mechanism"
            );
        }
    }
}
