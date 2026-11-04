use super::*;
use cfw_engine_api::{EngineCommandContext, EngineMode, EngineOwner, RuntimeIdentity};

#[test]
fn swift_fixture_matches_actual_rust_serialization() {
    let snapshot = EngineSnapshot::default();
    let actual: serde_json::Value =
        serde_json::from_slice(&Frame::from_snapshot(&snapshot, "en", 1).encode().unwrap())
            .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../native/dashboard/Tests/CFMNativeDashboardTests/Fixtures/off.json"
    ))
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn failed_observation_is_unknown_and_preserves_the_failure() {
    let snapshot = EngineSnapshot {
        state: EngineState::Failed {
            generation: 1,
            target: EngineMode::Off,
            error: "Unavailable".into(),
            recheck_pending: false,
        },
        ..EngineSnapshot::default()
    };
    let frame = Frame::from_snapshot(&snapshot, "en", 1);
    assert_eq!(frame.core, Status::Unknown);
    assert_eq!(frame.system_proxy, Status::Unknown);
    assert_eq!(frame.tunnel, Status::Unknown);
    assert_eq!(frame.failure, Some("Unavailable"));
}

#[test]
fn active_modes_project_each_integration_separately() {
    let runtime = RuntimeIdentity {
        owner: EngineOwner::ProxyAgent,
        context: EngineCommandContext {
            installation_id: "test".into(),
            config_epoch: 1,
            generation: 1,
        },
        config_digest: "ab".repeat(32),
        ready: true,
    };
    for (state, proxy, tunnel) in [
        (
            EngineState::LocalProxyActive {
                runtime: runtime.clone(),
            },
            Status::Inactive,
            Status::Inactive,
        ),
        (
            EngineState::ProxyActive {
                runtime: runtime.clone(),
            },
            Status::Active,
            Status::Inactive,
        ),
        (
            EngineState::TunnelActive {
                runtime: runtime.clone(),
            },
            Status::Inactive,
            Status::Active,
        ),
        (
            EngineState::TunnelSystemProxyActive { runtime },
            Status::Active,
            Status::Active,
        ),
    ] {
        let snapshot = EngineSnapshot {
            state,
            ..EngineSnapshot::default()
        };
        let frame = Frame::from_snapshot(&snapshot, "en", 1);
        assert_eq!(frame.core, Status::Active);
        assert_eq!((frame.system_proxy, frame.tunnel), (proxy, tunnel));
    }
}

#[test]
fn a_nonready_runtime_never_projects_a_connected_state() {
    let runtime = RuntimeIdentity {
        owner: EngineOwner::PacketTunnelSystemExtension,
        context: EngineCommandContext {
            installation_id: "test".into(),
            config_epoch: 1,
            generation: 1,
        },
        config_digest: "ab".repeat(32),
        ready: false,
    };
    for state in [
        EngineState::LocalProxyActive {
            runtime: runtime.clone(),
        },
        EngineState::ProxyActive {
            runtime: runtime.clone(),
        },
        EngineState::TunnelActive {
            runtime: runtime.clone(),
        },
        EngineState::TunnelSystemProxyActive { runtime },
    ] {
        let snapshot = EngineSnapshot {
            state,
            desired_mode: EngineMode::TunnelSystemProxy,
            ..EngineSnapshot::default()
        };
        let frame = Frame::from_snapshot(&snapshot, "en", 1);
        assert_eq!(frame.phase, "changing");
        assert_eq!(
            (frame.core, frame.system_proxy, frame.tunnel),
            (Status::Pending, Status::Pending, Status::Pending)
        );
        assert_eq!(
            retry_target(&snapshot, EngineControl::Core),
            Some(EngineMode::TunnelSystemProxy)
        );
    }
}

#[test]
fn oversized_error_is_rejected_without_a_truncated_success() {
    let snapshot = EngineSnapshot {
        state: EngineState::Failed {
            generation: 1,
            target: EngineMode::Off,
            error: "x".repeat(MAX_FRAME_BYTES),
            recheck_pending: false,
        },
        ..EngineSnapshot::default()
    };
    assert!(Frame::from_snapshot(&snapshot, "en", 1).encode().is_err());
}
