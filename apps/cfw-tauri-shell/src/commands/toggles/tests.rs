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
                recheck_pending: false,
            },
            "Failed",
        ),
        (
            EngineState::Failed {
                generation: 1,
                target: EngineMode::SystemProxy,
                error: "native failure".into(),
                recheck_pending: false,
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
        parse_restore_dns_servers(&vec!["1.1.1.1"; MAX_RESTORE_DNS_SERVERS + 1].join(" ")).is_err()
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
    include_str!("../toggles.rs")
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

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
#[test]
fn windows_platform_design_does_not_claim_apple_services_or_tunnel_support() {
    let design = serde_json::to_value(current_platform_design()).unwrap();
    assert_eq!(design["target"], "windows-x64");
    assert_eq!(design.as_object().unwrap().len(), 5);
    assert_eq!(
        design["tun_strategy"],
        "Not available in this development build"
    );
    assert!(
        design["startup_strategy"]
            .as_str()
            .unwrap()
            .contains("Windows controls startup approval")
    );
    for name in ["minimum_macos", "intel_supported", "launchd_strategy"] {
        assert!(design.get(name).is_none());
    }
}
