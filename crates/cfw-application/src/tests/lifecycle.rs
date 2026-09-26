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
            authorization_timeout: Duration::from_millis(100),
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
            NativeEngineStatus::LocalProxy { runtime }
            | NativeEngineStatus::SystemProxy { runtime }
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
async fn unavailable_lineage_startup_query_failure_allows_process_exit_without_native_lease() {
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
    assert_eq!(
        coordinator
            .shutdown()
            .await
            .expect("startup failure without a native lease must not trap process exit")
            .state,
        EngineState::Off
    );
    assert_eq!(
        backend.query_count(),
        1,
        "exit does not retry an unavailable status read"
    );
    assert!(backend.operations().is_empty());
}

#[tokio::test]
async fn explicit_command_retries_startup_after_proxy_agent_approval_changes() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error lock") =
        Some(BackendErrorKind::ProxyAgentApprovalRequired);
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(0)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    assert!(matches!(
        coordinator.wait_for_reconciliation().await,
        Err(EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::QueryStatus,
            source: BackendError {
                kind: BackendErrorKind::ProxyAgentApprovalRequired,
                ..
            },
        })
    ));
    assert_eq!(backend.query_count(), 1);
    for _ in 0..3 {
        assert!(matches!(
            coordinator.startup_failure(),
            Some(EngineCoordinatorError::Backend {
                operation: crate::EngineOperation::QueryStatus,
                source: BackendError {
                    kind: BackendErrorKind::ProxyAgentApprovalRequired,
                    ..
                },
            })
        ));
    }
    assert_eq!(
        backend.query_count(),
        1,
        "presentation reads must not query services"
    );
    assert!(backend.operations().is_empty());

    *backend.query_error.lock().expect("query error lock") = None;
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("explicit request observes the approved registration and starts");
    assert!(matches!(active.state, EngineState::ProxyActive { .. }));
    assert_eq!(backend.query_count(), 2);
    assert_eq!(backend.operations(), vec!["start_proxy"]);
    assert_eq!(coordinator.startup_failure(), None);
    coordinator.shutdown().await.expect("shutdown barrier");
}

#[tokio::test]
async fn failed_startup_status_read_does_not_reenter_native_reconciliation() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error lock") = Some(BackendErrorKind::Unavailable);
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(0)),
        Duration::from_secs(5),
    )
    .expect("persisted coordinator");
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    let mut snapshots = coordinator.subscribe();
    snapshots.borrow_and_update();

    // The actual shell forwarder reads this after each snapshot event. A read
    // must not query the failed service and publish another event back to it.
    for _ in 0..4 {
        assert!(
            coordinator
                .restart_spec()
                .await
                .expect("actor-owned source read")
                .is_none()
        );
        assert_eq!(
            backend.query_count(),
            1,
            "a presentation read retried the native service"
        );
        assert!(
            !snapshots.has_changed().expect("snapshot channel"),
            "a read re-published the failure"
        );
    }
    assert!(backend.operations().is_empty());
    coordinator.shutdown().await.expect("process exit");
}

#[tokio::test]
async fn failed_startup_shutdown_does_not_requery_an_unavailable_service() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error lock") = Some(BackendErrorKind::Unavailable);
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(0)),
        Duration::from_secs(5),
    )
    .expect("persisted coordinator");
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    let gate = Arc::new(Notify::new());
    *backend.query_gate.lock().expect("query gate lock") = Some(gate.clone());
    let mut shutdown = Box::pin(coordinator.shutdown());
    let result = tokio::time::timeout(Duration::from_millis(200), &mut shutdown).await;
    if result.is_err() {
        gate.notify_one();
        shutdown
            .await
            .expect("release the test's blocked observation");
    }
    assert_eq!(
        result
            .expect("an unowned startup failure must not delay exit for another status read")
            .expect("process exit")
            .state,
        EngineState::Off,
    );
    assert_eq!(backend.query_count(), 1);
    assert!(
        backend.operations().is_empty(),
        "no native owner was acquired or stopped"
    );
}

#[tokio::test]
async fn permanent_startup_failure_is_not_retried_by_later_commands() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error lock") =
        Some(BackendErrorKind::IdentityRejected);
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(0)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    assert!(coordinator.wait_for_reconciliation().await.is_err());
    *backend.query_error.lock().expect("query error lock") = None;
    assert!(matches!(
        coordinator
            .set_mode(
                EngineMode::SystemProxy,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await,
        Err(EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::QueryStatus,
            source: BackendError {
                kind: BackendErrorKind::IdentityRejected,
                ..
            },
        })
    ));
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
        fn check_configuration(&self, _request: EngineStartRequest) -> BackendFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn start_local_proxy(
            &self,
            request: EngineStartRequest,
        ) -> BackendFuture<'_, RuntimeIdentity> {
            self.start_system_proxy(request)
        }

        fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
            self.stop_system_proxy(context)
        }

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

        fn authorize_tunnel_configuration(
            &self,
            _request: EngineStartRequest,
        ) -> BackendFuture<'_, ()> {
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

#[tokio::test(start_paused = true)]
async fn startup_cleanup_unproven_is_sticky_for_reads_polling_and_ordinary_modes() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());
    let initial = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("startup failure");
    assert!(coordinator.can_reconcile_startup());
    *backend.query_error.lock().expect("query error") = None;
    for target in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert_eq!(coordinator.startup_failure(), Some(initial.clone()));
        assert!(matches!(
            coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
        assert!(coordinator.restart_spec().await.expect("read").is_none());
        assert_eq!(
            coordinator
                .set_mode(
                    target,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default()
                )
                .await,
            Err(initial.clone())
        );
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(backend.query_count(), 1);
    assert!(backend.operations().is_empty());
    coordinator.shutdown().await.expect("unowned exit");
}

#[tokio::test]
async fn explicit_startup_reconciliation_settles_off_without_start_or_duplicate_io() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    *backend.query_error.lock().expect("query error") = None;
    let (first, second) = tokio::join!(
        coordinator.reconcile_startup(),
        coordinator.reconcile_startup()
    );
    assert_eq!(
        first.expect("explicit observation proves Off").state,
        EngineState::Off
    );
    assert_eq!(
        second,
        Err(EngineCoordinatorError::SnapshotPreconditionChanged)
    );
    assert_eq!(
        coordinator
            .wait_for_reconciliation()
            .await
            .expect("updated channel")
            .state,
        EngineState::Off
    );
    assert_eq!(coordinator.startup_failure(), None);
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(
        coordinator.reconcile_startup().await,
        Err(EngineCoordinatorError::SnapshotPreconditionChanged)
    );
    assert_eq!(backend.query_count(), 2);
    assert!(backend.operations().is_empty());
    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn concurrent_failed_startup_reconciliation_cannot_replay_the_same_offer() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());
    let initial = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("startup failure");
    let (first, second) = tokio::join!(
        coordinator.reconcile_startup(),
        coordinator.reconcile_startup()
    );
    assert_eq!(first, Err(initial.clone()));
    assert_eq!(second, Err(initial.clone()));
    assert_eq!(coordinator.startup_failure(), Some(initial));
    assert_eq!(
        backend.query_count(),
        2,
        "queued duplicate must not replay a fresh failure"
    );
    assert!(backend.operations().is_empty());
    assert!(
        coordinator.can_reconcile_startup(),
        "a later explicit action gets a new offer"
    );
    *backend.query_error.lock().expect("query error") = None;
    assert_eq!(
        coordinator
            .reconcile_startup()
            .await
            .expect("fresh offer")
            .state,
        EngineState::Off
    );
    assert_eq!(backend.query_count(), 3);
    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn explicit_startup_reconciliation_rejects_other_failure_and_unavailable_lineage() {
    for kind in [
        BackendErrorKind::IdentityRejected,
        BackendErrorKind::Unavailable,
        BackendErrorKind::ProxyAgentApprovalRequired,
    ] {
        let backend = Arc::new(FakeBackend::default());
        *backend.query_error.lock().expect("query error") = Some(kind);
        let coordinator = coordinator(backend.clone());
        let failure = coordinator
            .wait_for_reconciliation()
            .await
            .expect_err("startup failure");
        assert!(!coordinator.can_reconcile_startup());
        *backend.query_error.lock().expect("query error") = None;
        assert_eq!(coordinator.reconcile_startup().await, Err(failure));
        assert_eq!(backend.query_count(), 1);
        assert!(backend.operations().is_empty());
        coordinator.shutdown().await.expect("unowned exit");
    }
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
        backend.clone(),
        "journal unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    );
    let failure = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("startup failure");
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(coordinator.reconcile_startup().await, Err(failure));
    assert_eq!(backend.query_count(), 1);
    assert!(backend.operations().is_empty());
    coordinator.shutdown().await.expect("unowned exit");
}

#[tokio::test]
async fn explicit_startup_reconciliation_rejects_normal_active_state() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .wait_for_reconciliation()
        .await
        .expect("initial Off");
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("active");
    let queries = backend.query_count();
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(
        coordinator.reconcile_startup().await,
        Err(EngineCoordinatorError::SnapshotPreconditionChanged)
    );
    assert_eq!(backend.query_count(), queries);
    assert_eq!(backend.operations(), vec!["start_proxy"]);
    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn startup_reconciliation_cleanup_failure_retains_native_lease_and_error() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            initial_generation: 1,
            ..CoordinatorOptions::default()
        },
    );
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    *backend.query_error.lock().expect("query error") = None;
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: recovered_runtime(EngineOwner::ProxyAgent, 1),
    });
    *backend.fail_proxy_stop.lock().expect("stop error") = true;
    let failure = coordinator
        .reconcile_startup()
        .await
        .expect_err("cleanup remains unproven");
    assert!(matches!(
        failure,
        EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::StopSystemProxy,
            ..
        }
    ));
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(coordinator.startup_failure(), Some(failure.clone()));
    assert_eq!(coordinator.reconcile_startup().await, Err(failure));
    assert_eq!(backend.query_count(), 2);
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert!(
        coordinator.shutdown().await.is_err(),
        "owned cleanup cannot be bypassed"
    );
}

#[test]
fn startup_service_reconciliation_admission_rejects_leases_and_quarantine() {
    use crate::coordinator_actor::StartupReconciliation;
    use crate::coordinator_startup::ReconciliationFailure;
    use crate::runtime::{CoordinatorState, NativeLease, NativeLeaseKind};
    let failure = ReconciliationFailure {
        error: EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::QueryStatus,
            source: BackendError::new(BackendErrorKind::CleanupUnproven, "typed"),
        },
        safely_off: false,
    };
    let snapshot = cfw_engine_api::EngineSnapshot {
        state: EngineState::Failed {
            generation: 0,
            target: EngineMode::Off,
            error: "typed".into(),
        },
        ..Default::default()
    };
    let mut state = CoordinatorState {
        snapshot,
        native_lease: None,
        quarantine: None,
        restart_spec: None,
        status_recheck: None,
    };
    assert!(
        failure.allows_service_reconciliation(&state, StartupReconciliation::CleanupKnownLineage)
    );
    state.native_lease = Some(NativeLease {
        kind: NativeLeaseKind::SystemProxy,
        context: EngineCommandContext::new(&test_session(), 1),
    });
    assert!(
        !failure.allows_service_reconciliation(&state, StartupReconciliation::CleanupKnownLineage)
    );
    state.native_lease = None;
    state.quarantine = Some(failure.error.clone());
    assert!(
        !failure.allows_service_reconciliation(&state, StartupReconciliation::CleanupKnownLineage)
    );
    state.quarantine = None;
    state.snapshot.desired_mode = EngineMode::Tunnel;
    assert!(
        !failure.allows_service_reconciliation(&state, StartupReconciliation::CleanupKnownLineage)
    );
}

#[tokio::test]
async fn explicit_startup_reconciliation_preserves_recovered_identity_failure() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            initial_generation: 1,
            ..CoordinatorOptions::default()
        },
    );
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    *backend.query_error.lock().expect("query error") = None;
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: recovered_runtime(EngineOwner::PacketTunnelSystemExtension, 1),
    });
    let failure = coordinator
        .reconcile_startup()
        .await
        .expect_err("wrong owner is not recovery success");
    assert!(matches!(
        failure,
        EngineCoordinatorError::RecoveredRuntimeMismatch { .. }
    ));
    assert_eq!(coordinator.startup_failure(), Some(failure.clone()));
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(coordinator.reconcile_startup().await, Err(failure));
    assert_eq!(backend.query_count(), 3);
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    coordinator
        .shutdown()
        .await
        .expect("safe cleanup permits exit");
}

#[tokio::test]
async fn accepted_startup_reconciliation_finishes_after_caller_cancellation() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());
    assert!(coordinator.wait_for_reconciliation().await.is_err());
    *backend.query_error.lock().expect("query error") = None;
    let gate = Arc::new(Notify::new());
    *backend.query_gate.lock().expect("query gate") = Some(gate.clone());
    let mut snapshots = coordinator.subscribe();
    let task = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move { coordinator.reconcile_startup().await })
    };
    tokio::time::timeout(Duration::from_millis(200), async {
        while backend.query_count() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("explicit query entered");
    assert!(
        !coordinator.can_reconcile_startup(),
        "in-flight offer withdrawn"
    );
    task.abort();
    assert!(task.await.expect_err("caller cancelled").is_cancelled());
    gate.notify_one();
    tokio::time::timeout(Duration::from_millis(200), async {
        while snapshots.borrow_and_update().state != EngineState::Off {
            snapshots.changed().await.expect("coordinator alive");
        }
        coordinator
            .restart_spec()
            .await
            .expect("actor publication barrier");
    })
    .await
    .expect("accepted recovery completed");
    assert_eq!(coordinator.startup_failure(), None);
    assert!(!coordinator.can_reconcile_startup());
    assert_eq!(backend.query_count(), 2);
    assert!(backend.operations().is_empty());
    *backend.query_gate.lock().expect("query gate") = None;
    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn startup_recovery_offer_is_captured_before_host_queue_await() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());
    let initial = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("startup failure");
    let cancelled_before_host_admission = coordinator.reconcile_startup();
    drop(cancelled_before_host_admission);
    coordinator
        .restart_spec()
        .await
        .expect("actor queue barrier");
    assert_eq!(
        backend.query_count(),
        1,
        "capturing and cancelling before Host admission must not perform native I/O"
    );
    let delayed_by_host_queue = {
        let temporary_handle = coordinator.clone();
        temporary_handle.reconcile_startup()
    };
    assert_eq!(coordinator.reconcile_startup().await, Err(initial.clone()));
    assert_eq!(backend.query_count(), 2);
    assert_eq!(delayed_by_host_queue.await, Err(initial));
    assert_eq!(
        backend.query_count(),
        2,
        "a delayed Host request must retain its original offer"
    );
    assert!(backend.operations().is_empty());
    coordinator.shutdown().await.expect("unowned exit");
}
