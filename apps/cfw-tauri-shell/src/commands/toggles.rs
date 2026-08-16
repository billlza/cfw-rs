//! Engine and settings switches restored from 0.3.5.
//!
//! Two rules shape every command here.
//!
//! * The System Proxy and TUN switches are Authority-mediated. They own no
//!   network state of their own: each one is translated into an engine mode and
//!   handed to [`crate::engine::apply_admitted_engine_mode`], the single transition path
//!   that takes the maintenance lease, the legacy-retirement gate, the
//!   capability check and the app-owned engine settings. Nothing in this module
//!   writes a system proxy, a DNS server, a route, or a network preference, and
//!   nothing here can reach a privileged helper: that surface no longer exists.
//! * A switch that the running engine cannot honour without a fresh projection
//!   fails closed with an explicit reason instead of being persisted as an
//!   intent the product would never apply. The 0.4.0 projection pins the mixed
//!   inbound to loopback and the engine log level to `info`, and the
//!   clash-compatible controller of a sing-box engine only accepts `mode`
//!   patches, so LAN exposure, bind address changes, log-level changes and
//!   profile mixin are rejected rather than silently dropped.

use cfw_core::{SettingsStore, UiPreferences};
#[cfg(test)]
use cfw_engine_api::EngineSnapshot;
use cfw_engine_api::{EngineMode, EngineState};
use serde::Serialize;
use tauri::{AppHandle, State};

use super::controller::{controller_client, ipc_error};
use super::settings::{UiSettingsSnapshot, settings_snapshot_with_live_status};
#[cfg(test)]
use crate::engine::switch_transition;
use crate::engine::{
    EngineStatusPayload, ManagedEngine, apply_admitted_engine_mode, serialized_switch_transition,
};
use crate::legacy::LegacyRetirementGate;
use crate::window_state::WindowBoundsManager;
use crate::{commands::ManagedProfiles, settings_store};

/// Loopback host the projected mixed inbound listens on. Changing it requires a
/// new projection, which this release does not produce.
const PROJECTED_LISTEN_ADDRESS: &str = "127.0.0.1";
/// Engine log level the projection pins.
const PROJECTED_LOG_LEVEL: &str = "info";
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
        | (EngineState::TunnelActive { runtime }, EngineMode::Tunnel) => runtime.ready,
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
    let tunnel_running = matches!(snapshot.state, EngineState::TunnelActive { .. });
    TunRuntimeState {
        tun_mode: snapshot.desired_mode == EngineMode::Tunnel,
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
        EngineState::TunnelActive { .. } => "Enabled",
        EngineState::TunnelStopping { .. } => "Stopping",
        EngineState::Failed {
            target: EngineMode::Tunnel,
            ..
        } => "Failed",
        _ => "NotRegistered",
    }
}

/// System Proxy switch. `enabled` selects the ProxyAgent mode; disabling it
/// stops the engine only when System Proxy is the mode that is actually desired,
/// so it can never tear down a running Packet Tunnel.
#[tauri::command]
pub(crate) async fn set_system_proxy_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    apply_switch(
        &engine,
        &retirement,
        &profiles,
        EngineMode::SystemProxy,
        enabled,
    )
    .await
}

/// Packet Tunnel switch, expressed exactly like the System Proxy switch: the
/// System Extension is started only by the Authority-mediated mode transition.
#[tauri::command]
pub(crate) async fn set_tun_enabled(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    apply_switch(&engine, &retirement, &profiles, EngineMode::Tunnel, enabled).await
}

async fn apply_switch(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    switch: EngineMode,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    let observed = engine.coordinator.snapshot();
    // Queue every switch intent, including Off, before reading state. The
    // single-flight permit makes this snapshot current relative to all earlier
    // retries and stops; maintenance sees the queued registration throughout.
    let requested_mode = if enabled { switch } else { EngineMode::Off };
    let mode_lease = engine
        .begin_mode_change(requested_mode)
        .await
        .map_err(|error| error.to_string())?;
    let snapshot = engine.coordinator.snapshot();
    match serialized_switch_transition(&observed, &snapshot, switch, enabled)? {
        Some(mode) => {
            apply_admitted_engine_mode(engine, retirement, profiles, mode, mode_lease).await
        }
        None => engine.status_payload(retirement),
    }
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
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .patch_configs(cfw_controller::ConfigPatch {
            mode: Some(normalized.to_owned()),
            ..cfw_controller::ConfigPatch::default()
        })
        .await
        .map_err(ipc_error)
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

/// LAN exposure of the local listener.
///
/// The projection binds the mixed inbound to loopback, and the running engine
/// cannot be rebound through its controller, so only the state the product
/// actually provides is accepted.
#[tauri::command]
pub(crate) fn set_allow_lan(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    if enabled {
        return Err(format!(
            "allow-lan cannot be honoured: the projected mixed inbound is bound to {PROJECTED_LISTEN_ADDRESS} and the engine cannot be rebound while running, so nothing was changed"
        ));
    }
    settings_snapshot()
}

/// Bind address of the local listener. Only the projected loopback address is
/// accepted; anything else would need a projection this release does not build.
#[tauri::command]
pub(crate) fn set_bind_address(address: String) -> Result<UiSettingsSnapshot, String> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err("bind-address must not be empty".into());
    }
    if !matches!(trimmed, PROJECTED_LISTEN_ADDRESS | "localhost") {
        return Err(format!(
            "bind-address {trimmed} cannot be honoured: the projected mixed inbound is bound to {PROJECTED_LISTEN_ADDRESS}, so nothing was changed"
        ));
    }
    settings_snapshot()
}

/// Engine log level. The projection pins `info`, and the controller of a
/// sing-box engine accepts no log-level patch, so any other level is refused
/// instead of being accepted and ignored.
#[tauri::command]
pub(crate) fn set_log_level(level: String) -> Result<(), String> {
    let normalized = level.trim().to_ascii_lowercase();
    if !matches!(
        normalized.as_str(),
        "trace" | "debug" | "info" | "warning" | "warn" | "error" | "silent"
    ) {
        return Err(format!("unsupported engine log level: {level}"));
    }
    if normalized == PROJECTED_LOG_LEVEL {
        return Ok(());
    }
    Err(format!(
        "engine log level {normalized} cannot be honoured: the projected configuration pins {PROJECTED_LOG_LEVEL} and the engine controller accepts no log-level change, so nothing was changed"
    ))
}

/// Profile mixin. Merging arbitrary user documents into the engine
/// configuration is exactly what the validated projection forbids, so mixin can
/// only be off.
#[tauri::command]
pub(crate) fn set_mixin_enabled(enabled: bool) -> Result<UiSettingsSnapshot, String> {
    if enabled {
        return Err(
            "profile mixin cannot be honoured: the engine configuration is projected by the app, and an imported document may only describe routing and outbound policy, so nothing was changed"
                .into(),
        );
    }
    settings_snapshot()
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
pub(crate) fn reset_settings_snapshot(
    app: AppHandle,
    window_bounds: State<'_, WindowBoundsManager>,
) -> Result<UiSettingsSnapshot, String> {
    let store = settings_store()?;
    if !store
        .legacy_retirement_completed()
        .map_err(|error| error.to_string())?
    {
        return Err(
            "legacy settings migration is still pending; preferences remain read-only".into(),
        );
    }
    let current = store.read_or_default().map_err(|error| error.to_string())?;
    let defaults = UiPreferences {
        launch_at_login: current.launch_at_login,
        ..UiPreferences::default()
    };
    window_bounds.commit_retention(&app, defaults.retain_window_bounds, || {
        write_defaults(&store, defaults)
    })
}

fn write_defaults(
    store: &SettingsStore,
    preferences: UiPreferences,
) -> Result<UiSettingsSnapshot, String> {
    store
        .write(&preferences)
        .map_err(|error| error.to_string())?;
    settings_snapshot_with_live_status(store)
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

    fn snapshot(desired_mode: EngineMode, state: EngineState) -> EngineSnapshot {
        EngineSnapshot {
            desired_mode,
            state,
            generation: 3,
            config_digest: Some("digest".into()),
        }
    }

    #[test]
    fn switches_never_stop_the_other_mode_or_restart_in_flight_and_active_modes() {
        // Enabling a switch that is not the desired mode is the only case that
        // starts it; disabling one that does not own the desired mode is inert.
        assert_eq!(
            switch_transition(
                &snapshot(EngineMode::Off, EngineState::Off),
                EngineMode::SystemProxy,
                true,
            ),
            Some(EngineMode::SystemProxy)
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::Tunnel,
                    EngineState::TunnelActive {
                        runtime: runtime(true),
                    },
                ),
                EngineMode::SystemProxy,
                true,
            ),
            Some(EngineMode::SystemProxy)
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::SystemProxy,
                    EngineState::ProxyActive {
                        runtime: runtime(true),
                    },
                ),
                EngineMode::SystemProxy,
                false,
            ),
            Some(EngineMode::Off)
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::Tunnel,
                    EngineState::TunnelActive {
                        runtime: runtime(true),
                    },
                ),
                EngineMode::SystemProxy,
                false,
            ),
            None,
            "disabling System Proxy must not stop a running Packet Tunnel"
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::SystemProxy,
                    EngineState::ProxyActive {
                        runtime: runtime(true),
                    },
                ),
                EngineMode::Tunnel,
                false,
            ),
            None,
            "disabling TUN must not stop a running System Proxy"
        );
        assert_eq!(
            switch_transition(
                &snapshot(EngineMode::Off, EngineState::Off),
                EngineMode::Tunnel,
                false,
            ),
            None
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::SystemProxy,
                    EngineState::ProxyActive {
                        runtime: runtime(true),
                    },
                ),
                EngineMode::SystemProxy,
                true,
            ),
            None,
            "an already desired mode must not be restarted by its own switch"
        );
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::Tunnel,
                    EngineState::TunnelInstalling { generation: 3 },
                ),
                EngineMode::Tunnel,
                true,
            ),
            None,
            "an in-flight mode must not allocate a concurrent generation"
        );
    }

    #[test]
    fn explicit_retry_is_admitted_only_from_the_same_retryable_mode() {
        for state in [
            EngineState::Off,
            EngineState::AwaitingApproval { generation: 3 },
            EngineState::Failed {
                generation: 3,
                target: EngineMode::Tunnel,
                error: "approval was not complete".into(),
            },
        ] {
            assert_eq!(
                switch_transition(
                    &snapshot(EngineMode::Tunnel, state),
                    EngineMode::Tunnel,
                    true,
                ),
                Some(EngineMode::Tunnel)
            );
        }
        assert_eq!(
            switch_transition(
                &snapshot(
                    EngineMode::Tunnel,
                    EngineState::Failed {
                        generation: 3,
                        target: EngineMode::SystemProxy,
                        error: "inconsistent target".into(),
                    },
                ),
                EngineMode::Tunnel,
                true,
            ),
            None,
            "a mismatched failure target must remain fail closed"
        );
    }

    #[test]
    fn queued_enable_is_generation_sensitive_but_owned_off_supersedes_retry() {
        let observed = snapshot(
            EngineMode::Tunnel,
            EngineState::AwaitingApproval { generation: 3 },
        );
        let after_prior_retry = snapshot(
            EngineMode::Tunnel,
            EngineState::AwaitingApproval { generation: 4 },
        );
        assert!(
            serialized_switch_transition(&observed, &after_prior_retry, EngineMode::Tunnel, true,)
                .is_err(),
            "an overlapping retry must not allocate another generation"
        );
        assert_eq!(
            serialized_switch_transition(&observed, &after_prior_retry, EngineMode::Tunnel, false,)
                .expect("owned Off remains a superseding intent"),
            Some(EngineMode::Off)
        );

        let non_owner_observation = snapshot(
            EngineMode::SystemProxy,
            EngineState::ProxyActive {
                runtime: runtime(true),
            },
        );
        assert_eq!(
            serialized_switch_transition(
                &non_owner_observation,
                &after_prior_retry,
                EngineMode::Tunnel,
                false,
            )
            .expect("a stale non-owner disable is a no-op"),
            None
        );
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

    #[test]
    fn projection_bound_switches_fail_closed_instead_of_pretending() {
        let allow_lan = set_allow_lan(true).expect_err("LAN exposure must be refused");
        assert!(allow_lan.contains("nothing was changed"));
        let bind = set_bind_address("0.0.0.0".into()).expect_err("wildcard bind must be refused");
        assert!(bind.contains("nothing was changed"));
        assert!(set_bind_address("   ".into()).is_err());
        let mixin = set_mixin_enabled(true).expect_err("mixin must be refused");
        assert!(mixin.contains("nothing was changed"));

        set_log_level("info".into()).expect("the projected level is a no-op");
        set_log_level(" INFO ".into()).expect("the projected level is normalized");
        let level = set_log_level("debug".into()).expect_err("other levels must be refused");
        assert!(level.contains("nothing was changed"));
        assert!(set_log_level("verbose".into()).is_err());
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
            .split("#[cfg(test)]")
            .next()
            .expect("module source has a production section")
    }

    #[test]
    fn switch_commands_reach_the_data_plane_only_through_the_shared_transition() {
        let source = production_source();
        assert!(
            source.contains("apply_admitted_engine_mode"),
            "the switches must use the shared transition"
        );
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
