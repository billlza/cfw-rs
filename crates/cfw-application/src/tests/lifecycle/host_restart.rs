//! Host restarts and recovered owners.

use super::*;

#[tokio::test]
async fn host_restart_never_equates_stop_acknowledgement_with_global_off() {
    let backend = Arc::new(FakeBackend::default());
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: recovered_runtime(EngineOwner::ProxyAgent, 7),
    });
    *backend
        .stop_leaves_owner_present
        .lock()
        .expect("stop observation lock") = true;
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(7)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::GlobalOffUnproven { .. })
    ));
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert_eq!(backend.query_count(), 2);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert!(
        coordinator
            .set_mode(
                EngineMode::SystemProxy,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn host_restart_stops_active_owner_before_accepting_a_fresh_controller_session() {
    for (status, target, expected_operations) in [
        (
            NativeEngineStatus::SystemProxy {
                runtime: recovered_runtime(EngineOwner::ProxyAgent, 7),
            },
            EngineMode::SystemProxy,
            vec!["stop_proxy", "start_proxy"],
        ),
        (
            NativeEngineStatus::Tunnel {
                runtime: recovered_runtime(EngineOwner::PacketTunnelSystemExtension, 7),
            },
            EngineMode::Tunnel,
            vec!["stop_tunnel", "install_tunnel", "start_tunnel"],
        ),
    ] {
        let backend = Arc::new(FakeBackend::default());
        backend.set_native_status(status);
        let store = Arc::new(MemoryGenerationStore::new(7));
        let coordinator = EngineModeCoordinator::spawn_persisted(
            backend.clone(),
            store,
            Duration::from_millis(100),
        )
        .expect("persisted coordinator");
        let reconciled = coordinator
            .wait_for_reconciliation()
            .await
            .expect("stale controller owner is stopped exactly");
        assert_eq!(reconciled.state, EngineState::Off);
        assert_eq!(backend.query_count(), 2);

        let restarted = coordinator
            .set_mode(
                target,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("fresh Host process starts a new controller generation");
        assert_eq!(restarted.state.active_mode(), target);
        assert_eq!(restarted.generation, 8);
        assert_eq!(backend.operations(), expected_operations);
        coordinator
            .shutdown()
            .await
            .expect("fresh exact stop barrier");
    }
}

#[tokio::test]
async fn recovered_owner_mismatch_stops_exact_endpoint_and_blocks_new_starts() {
    let backend = Arc::new(FakeBackend::default());
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: recovered_runtime(EngineOwner::PacketTunnelSystemExtension, 7),
    });
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(7)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::RecoveredRuntimeMismatch { .. })
    ));
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert!(matches!(
        coordinator
            .set_mode(
                EngineMode::Tunnel,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await,
        Err(EngineCoordinatorError::RecoveredRuntimeMismatch { .. })
    ));
    coordinator
        .shutdown()
        .await
        .expect("cleaned mismatch permits safe shutdown");
}

#[tokio::test]
async fn recovered_owner_mismatch_requires_independent_global_off_proof_after_stop() {
    let backend = Arc::new(FakeBackend::default());
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: recovered_runtime(EngineOwner::PacketTunnelSystemExtension, 7),
    });
    *backend
        .stop_leaves_owner_present
        .lock()
        .expect("stop observation lock") = true;
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(7)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::ValidationAndOffProofFailed { .. })
    ));
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert_eq!(backend.query_count(), 2);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert!(coordinator.shutdown().await.is_err());
}
