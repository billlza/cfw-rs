use cfw_engine_api::{
    EngineCommandContext, EngineOwner, EngineSnapshot, EngineState, RuntimeIdentity,
};

use super::*;
use crate::engine::switch_transition;

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
        Some(EngineMode::TunnelSystemProxy)
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
        Some(EngineMode::LocalProxy)
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
fn combined_switches_preserve_the_other_enabled_integration() {
    let combined = snapshot(
        EngineMode::TunnelSystemProxy,
        EngineState::TunnelSystemProxyActive {
            runtime: runtime(true),
        },
    );
    assert_eq!(
        switch_transition(&combined, EngineMode::SystemProxy, false),
        Some(EngineMode::Tunnel)
    );
    assert_eq!(
        switch_transition(&combined, EngineMode::Tunnel, false),
        Some(EngineMode::SystemProxy)
    );
    assert_eq!(
        switch_transition(&combined, EngineMode::SystemProxy, true),
        None
    );
    assert_eq!(switch_transition(&combined, EngineMode::Tunnel, true), None);
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
fn shared_controls_reach_the_data_plane_only_through_admitted_transitions() {
    let source = include_str!("../engine_controls.rs");
    assert!(source.contains("apply_admitted_engine_mode"));
    for forbidden in [
        concat!("coordinator", ".set_mode"),
        concat!("coordinator", ".shutdown"),
        concat!("prepare_", "cutover"),
        concat!("preflight_", "backend"),
        concat!("take_cutover_", "authority"),
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
            "a shared control bypasses admission via {forbidden}"
        );
    }
}

#[test]
fn a_callers_observed_snapshot_remains_the_enable_admission_boundary() {
    let observed = snapshot(EngineMode::Off, EngineState::Off);
    let current = EngineSnapshot {
        generation: observed.generation + 1,
        ..observed.clone()
    };
    for (control, expected) in [
        (EngineControl::Core, EngineMode::LocalProxy),
        (EngineControl::SystemProxy, EngineMode::SystemProxy),
        (EngineControl::Tunnel, EngineMode::Tunnel),
    ] {
        assert!(
            control_transition(&observed, &current, control, true).is_err(),
            "a stale window must not start {control:?} after a newer generation"
        );
        assert_eq!(
            control_transition(&current, &current, control, true),
            Ok(Some(expected)),
            "an explicit retry against the current snapshot remains admitted"
        );
    }
    assert_eq!(
        control_transition(&observed, &current, EngineControl::Core, false),
        Ok(Some(EngineMode::Off)),
        "Core stop still supersedes changes since the window's last snapshot"
    );
}

#[test]
fn observed_controls_keep_owned_disable_and_existing_core_semantics() {
    let active = snapshot(
        EngineMode::TunnelSystemProxy,
        EngineState::TunnelSystemProxyActive {
            runtime: runtime(true),
        },
    );
    assert_eq!(
        control_transition(&active, &active, EngineControl::Core, true),
        Ok(Some(EngineMode::TunnelSystemProxy)),
        "starting an already requested core preserves both integrations"
    );
    assert_eq!(
        control_transition(&active, &active, EngineControl::SystemProxy, false),
        Ok(Some(EngineMode::Tunnel))
    );
    assert_eq!(
        control_transition(&active, &active, EngineControl::Tunnel, false),
        Ok(Some(EngineMode::SystemProxy))
    );
    let stopped = EngineSnapshot {
        generation: active.generation + 1,
        ..EngineSnapshot::default()
    };
    for control in [EngineControl::SystemProxy, EngineControl::Tunnel] {
        assert_eq!(
            control_transition(&active, &stopped, control, false),
            Ok(None),
            "a delayed disable must not restart a newer stopped core"
        );
    }
}
