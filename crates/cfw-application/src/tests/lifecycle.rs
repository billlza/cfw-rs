use std::{sync::Arc, time::Duration};

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext, EngineMode,
    EngineOwner, EngineStartRequest, EngineState, NativeEngineStatus, RuntimeIdentity,
    TunnelInstallOutcome,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::sync::Notify;

use crate::{
    CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator,
    coordinator::COMMAND_QUEUE_CAPACITY,
};

use super::support::{FakeBackend, MemoryGenerationStore, coordinator, test_session};

#[tokio::test]
async fn dropped_request_waiter_does_not_cancel_native_transition() {
    let backend = Arc::new(FakeBackend::default());
    *backend.proxy_start_delay.lock().expect("start delay lock") = Duration::from_millis(30);
    let coordinator = coordinator(backend.clone());
    let mut snapshots = coordinator.subscribe();
    let waiter = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::SystemProxy,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        })
    };
    while backend.operations().is_empty() {
        tokio::task::yield_now().await;
    }
    waiter.abort();
    tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if matches!(snapshots.borrow().state, EngineState::ProxyActive { .. }) {
                break;
            }
            snapshots.changed().await.expect("coordinator stays alive");
        }
    })
    .await
    .expect("native transition completes after caller cancellation");

    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::ProxyActive { .. }
    ));
    coordinator.shutdown().await.expect("shutdown barrier");
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn shutdown_stops_runtime_and_closes_coordinator() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    let snapshot = coordinator.shutdown().await.expect("shutdown");
    assert_eq!(snapshot.state, EngineState::Off);
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);

    let error = coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("coordinator is closed");
    assert_eq!(error, EngineCoordinatorError::CoordinatorClosed);
}

#[tokio::test]
async fn initial_generation_is_never_reused() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_millis(20),
            initial_generation: 41,
        },
    );
    let snapshot = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    assert_eq!(snapshot.generation, 42);
}

#[tokio::test]
async fn persisted_generation_survives_coordinator_restart() {
    let store = Arc::new(MemoryGenerationStore::new(41));
    let first_backend = Arc::new(FakeBackend::default());
    let first = EngineModeCoordinator::spawn_persisted(
        first_backend,
        store.clone(),
        Duration::from_millis(100),
    )
    .expect("first coordinator");
    let active = first
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("first start");
    assert_eq!(active.generation, 42);
    let stopped = first.shutdown().await.expect("first shutdown");
    assert_eq!(stopped.generation, 43);

    let second_backend = Arc::new(FakeBackend::default());
    let second =
        EngineModeCoordinator::spawn_persisted(second_backend, store, Duration::from_millis(100))
            .expect("second coordinator");
    let restarted = second
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("second start");
    assert_eq!(restarted.generation, 44);
}

#[tokio::test]
async fn shutdown_stops_exact_runtime_before_reporting_generation_failure() {
    let store = Arc::new(MemoryGenerationStore::new(0));
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        store.clone(),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("active proxy");
    let active_context = match active.state {
        EngineState::ProxyActive { runtime } => runtime.context,
        state => panic!("expected active proxy, received {state:?}"),
    };

    store.set_fail_reserve(true);
    let error = coordinator
        .shutdown()
        .await
        .expect_err("post-stop lineage failure remains observable");
    assert!(matches!(error, EngineCoordinatorError::Journal(_)));
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert_eq!(backend.proxy_stop_contexts(), vec![active_context]);
    assert!(matches!(
        coordinator
            .set_mode(
                EngineMode::Off,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await,
        Err(EngineCoordinatorError::CoordinatorClosed)
    ));
}

#[tokio::test]
async fn explicit_off_stops_exact_runtime_before_reporting_generation_failure() {
    let store = Arc::new(MemoryGenerationStore::new(0));
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        store.clone(),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("active proxy");
    let active_context = match active.state {
        EngineState::ProxyActive { runtime } => runtime.context,
        state => panic!("expected active proxy, received {state:?}"),
    };

    store.set_fail_reserve(true);
    let error = coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("post-stop lineage failure remains observable");
    assert!(matches!(error, EngineCoordinatorError::Journal(_)));
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert_eq!(backend.proxy_stop_contexts(), vec![active_context]);

    let repeated = coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("already-Off request needs no new generation");
    assert_eq!(repeated.state, EngineState::Off);
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn unavailable_lineage_starts_off_only_and_still_allows_safe_shutdown() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
        backend.clone(),
        "Data Protection Keychain is unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    );
    let error = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("network start must remain blocked");
    assert!(matches!(error, EngineCoordinatorError::Journal(_)));
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert!(backend.operations().is_empty());
    assert_eq!(backend.query_count(), 1);

    assert_eq!(
        coordinator
            .shutdown()
            .await
            .expect("safe Off shutdown")
            .state,
        EngineState::Off
    );
}

#[tokio::test]
async fn unavailable_lineage_stops_reported_runtimes_instead_of_adopting_them() {
    for (status, expected_stop) in [
        (
            NativeEngineStatus::SystemProxy {
                runtime: cleanup_only_runtime(EngineOwner::ProxyAgent, 9),
            },
            "stop_proxy",
        ),
        (
            NativeEngineStatus::Tunnel {
                runtime: cleanup_only_runtime(EngineOwner::PacketTunnelSystemExtension, 11),
            },
            "stop_tunnel",
        ),
    ] {
        let expected_context = match &status {
            NativeEngineStatus::SystemProxy { runtime }
            | NativeEngineStatus::Tunnel { runtime } => runtime.context.clone(),
            NativeEngineStatus::Off => unreachable!("test status is active"),
        };
        let backend = Arc::new(FakeBackend::default());
        backend.set_native_status(status);
        let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
            backend.clone(),
            "Data Protection Keychain is unavailable",
            Duration::from_millis(100),
            |task| {
                tokio::spawn(task);
            },
        );

        let reconciled = coordinator
            .wait_for_reconciliation()
            .await
            .expect("untrusted active runtime is stopped");
        assert_eq!(reconciled.state, EngineState::Off);
        assert_eq!(backend.operations(), vec![expected_stop]);
        assert_eq!(backend.query_count(), 2);
        match expected_stop {
            "stop_proxy" => assert_eq!(backend.proxy_stop_contexts(), vec![expected_context]),
            "stop_tunnel" => assert_eq!(backend.tunnel_stop_contexts(), vec![expected_context]),
            _ => unreachable!("known stop operation"),
        }

        assert!(matches!(
            coordinator
                .set_mode(
                    EngineMode::SystemProxy,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await,
            Err(EngineCoordinatorError::Journal(_))
        ));
        coordinator.shutdown().await.expect("safe shutdown barrier");
    }
}

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
async fn unavailable_lineage_keeps_query_failure_failed_and_not_safely_off() {
    let backend = Arc::new(FakeBackend::default());
    *backend.fail_query.lock().expect("query failure lock") = true;
    let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
        backend.clone(),
        "Data Protection Keychain is unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    );

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::QueryStatus,
            ..
        })
    ));
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert!(coordinator.shutdown().await.is_err());
    assert_eq!(backend.query_count(), 1);
    assert!(backend.operations().is_empty());
}

#[tokio::test]
async fn unavailable_lineage_reports_invalid_identity_after_successful_exact_cleanup() {
    let backend = Arc::new(FakeBackend::default());
    let mut runtime = cleanup_only_runtime(EngineOwner::ProxyAgent, 9);
    runtime.context.installation_id = "not-a-canonical-uuid".to_owned();
    let expected_context = runtime.context.clone();
    backend.set_native_status(NativeEngineStatus::SystemProxy { runtime });
    let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
        backend.clone(),
        "Data Protection Keychain is unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    );

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::RecoveredRuntimeMismatch {
            mismatch: crate::RecoveredRuntimeMismatch::InvalidInstallation,
            ..
        })
    ));
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert_eq!(backend.proxy_stop_contexts(), vec![expected_context]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert_eq!(
        coordinator
            .shutdown()
            .await
            .expect("successful cleanup permits shutdown")
            .state,
        EngineState::Off
    );
}

#[tokio::test]
async fn unavailable_lineage_stop_failure_remains_failed_and_cannot_exit() {
    let backend = Arc::new(FakeBackend::default());
    *backend.fail_proxy_stop.lock().expect("stop failure lock") = true;
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: cleanup_only_runtime(EngineOwner::ProxyAgent, 9),
    });
    let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
        backend.clone(),
        "Data Protection Keychain is unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    );

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::StopSystemProxy,
            ..
        })
    ));
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert!(coordinator.shutdown().await.is_err());
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
}

#[tokio::test]
async fn sender_drop_publishes_post_stop_lineage_failure() {
    let store = Arc::new(MemoryGenerationStore::new(0));
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        store.clone(),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("active proxy");
    let mut snapshots = coordinator.subscribe();
    store.set_fail_reserve(true);

    drop(coordinator);

    tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if matches!(snapshots.borrow().state, EngineState::Failed { .. }) {
                break;
            }
            snapshots
                .changed()
                .await
                .expect("worker publishes terminal cleanup state");
        }
    })
    .await
    .expect("sender-drop cleanup failure is observable");
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

fn recovered_runtime(owner: EngineOwner, generation: u64) -> RuntimeIdentity {
    let session = test_session();
    RuntimeIdentity {
        owner,
        context: EngineCommandContext::new(&session, generation),
        config_digest: "a".repeat(64),
        ready: true,
    }
}

fn cleanup_only_runtime(owner: EngineOwner, generation: u64) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: EngineCommandContext {
            installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
            config_epoch: 4,
            generation,
        },
        config_digest: "a".repeat(64),
        ready: true,
    }
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

#[tokio::test]
async fn bounded_command_queue_reports_backpressure() {
    let backend = Arc::new(FakeBackend::default());
    let gate = Arc::new(Notify::new());
    *backend.proxy_start_gate.lock().expect("start gate lock") = Some(gate.clone());
    let coordinator = coordinator(backend);
    let mut requests = Vec::new();
    for _ in 0..(COMMAND_QUEUE_CAPACITY + 8) {
        let coordinator = coordinator.clone();
        requests.push(tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::SystemProxy,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        }));
    }

    tokio::time::timeout(Duration::from_millis(200), async {
        while requests.iter().all(|request| !request.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queue saturation is observable");
    gate.notify_one();

    let mut full = 0;
    for request in requests {
        match request.await.expect("request task") {
            Ok(_) => {}
            Err(EngineCoordinatorError::CommandQueueFull) => full += 1,
            Err(error) => panic!("unexpected queue result: {error}"),
        }
    }
    assert!(full > 0);
}

#[tokio::test]
async fn concurrent_requests_are_executed_serially() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let proxy = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::SystemProxy,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        })
    };
    let tunnel = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::Tunnel,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        })
    };

    proxy.await.expect("proxy task").expect("proxy transition");
    tunnel
        .await
        .expect("tunnel task")
        .expect("tunnel transition");
    assert_eq!(
        backend.operations(),
        vec![
            "start_proxy",
            "stop_proxy",
            "install_tunnel",
            "start_tunnel"
        ]
    );
}

#[tokio::test]
async fn backend_errors_do_not_fallback_to_another_mode() {
    struct FailingBackend;

    impl EngineBackend for FailingBackend {
        fn query_status(&self) -> BackendFuture<'_, cfw_engine_api::NativeEngineStatus> {
            Box::pin(async { Ok(cfw_engine_api::NativeEngineStatus::Off) })
        }

        fn start_system_proxy(
            &self,
            _request: EngineStartRequest,
        ) -> BackendFuture<'_, RuntimeIdentity> {
            Box::pin(async {
                Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "proxy agent unavailable",
                ))
            })
        }

        fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn install_tunnel(
            &self,
            _context: EngineCommandContext,
        ) -> BackendFuture<'_, TunnelInstallOutcome> {
            panic!("tunnel fallback must not be attempted")
        }

        fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            panic!("tunnel fallback must not be attempted")
        }

        fn start_tunnel(&self, _request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
            panic!("tunnel fallback must not be attempted")
        }

        fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            panic!("tunnel fallback must not be attempted")
        }
    }

    let coordinator = EngineModeCoordinator::spawn(Arc::new(FailingBackend), test_session());
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("proxy failure");
    assert!(matches!(error, EngineCoordinatorError::Backend { .. }));
}
