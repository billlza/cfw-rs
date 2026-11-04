use super::*;
use crate::{EngineOwner, test_support::context};

fn runtime() -> RuntimeIdentity {
    RuntimeIdentity {
        owner: EngineOwner::PacketTunnelSystemExtension,
        context: context(),
        config_digest: "02".repeat(32),
        ready: true,
    }
}

#[test]
fn only_an_active_state_reports_a_running_mode() {
    for (state, mode) in [
        (
            EngineState::LocalProxyActive { runtime: runtime() },
            EngineMode::LocalProxy,
        ),
        (
            EngineState::ProxyActive { runtime: runtime() },
            EngineMode::SystemProxy,
        ),
        (
            EngineState::TunnelActive { runtime: runtime() },
            EngineMode::Tunnel,
        ),
        (
            EngineState::TunnelSystemProxyActive { runtime: runtime() },
            EngineMode::TunnelSystemProxy,
        ),
    ] {
        assert_eq!(state.active_mode(), mode);
    }
    for state in [
        EngineState::Off,
        EngineState::LocalProxyStarting { generation: 1 },
        EngineState::ProxyStarting { generation: 1 },
        EngineState::LocalProxyStopping { generation: 1 },
        EngineState::ProxyStopping { generation: 1 },
        EngineState::TunnelInstalling { generation: 1 },
        EngineState::AwaitingApproval { generation: 1 },
        EngineState::TunnelStarting { generation: 1 },
        EngineState::TunnelStopping { generation: 1 },
        EngineState::Failed {
            generation: 1,
            target: EngineMode::Tunnel,
            error: "failed".into(),
            recheck_pending: true,
        },
    ] {
        assert_eq!(state.active_mode(), EngineMode::Off, "{state:?}");
    }
}

#[test]
fn the_default_snapshot_is_off_without_a_configuration() {
    assert_eq!(
        EngineSnapshot::default(),
        EngineSnapshot {
            desired_mode: EngineMode::Off,
            state: EngineState::Off,
            generation: 0,
            config_digest: None,
        }
    );
}

#[test]
fn a_failed_state_recorded_without_a_recheck_decodes_as_not_pending() {
    let state: EngineState = serde_json::from_value(serde_json::json!({
        "state": "failed", "generation": 2, "target": "tunnel", "error": "failed"
    }))
    .expect("failed state");
    assert_eq!(
        state,
        EngineState::Failed {
            generation: 2,
            target: EngineMode::Tunnel,
            error: "failed".into(),
            recheck_pending: false,
        }
    );
}

#[test]
fn engine_events_have_one_tagged_wire_shape() {
    let failure = EngineEvent::boundary_failure("engine_unavailable", "The engine is unavailable.");
    assert_eq!(
        serde_json::to_value(&failure).expect("failure event"),
        serde_json::json!({
            "type": "boundary_failure",
            "code": "engine_unavailable",
            "message": "The engine is unavailable."
        })
    );
    let changed = EngineEvent::SnapshotChanged {
        snapshot: EngineSnapshot::default(),
    };
    let wire = serde_json::to_value(&changed).expect("snapshot event");
    assert_eq!(wire["type"], "snapshot_changed");
    assert_eq!(
        serde_json::from_value::<EngineEvent>(wire).expect("decode"),
        changed
    );
}

#[test]
fn a_native_status_defaults_to_off_and_tags_its_running_owner() {
    assert_eq!(NativeEngineStatus::default(), NativeEngineStatus::Off);
    let status = NativeEngineStatus::Tunnel { runtime: runtime() };
    let wire = serde_json::to_value(&status).expect("status");
    assert_eq!(wire["status"], "tunnel");
    assert_eq!(
        serde_json::from_value::<NativeEngineStatus>(wire).expect("decode"),
        status
    );
}
