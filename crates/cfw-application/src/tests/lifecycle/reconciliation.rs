//! Explicit startup reconciliation and its admission rules.

use super::*;

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
        BackendErrorKind::JournalCorrupt,
        BackendErrorKind::Internal,
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
            recheck_pending: false,
        },
        ..Default::default()
    };
    let mut state = CoordinatorState {
        runtime_platform: cfw_engine_api::EngineRuntimePlatform::MacOs,
        snapshot,
        native_lease: None,
        quarantine: None,
        restart_spec: None,
        status_recheck: None,
        missed_observations: 0,
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

#[tokio::test]
async fn explicit_startup_reconciliation_reobserves_reads_the_services_could_not_answer() {
    for kind in [
        BackendErrorKind::Unavailable,
        BackendErrorKind::Timeout,
        BackendErrorKind::Busy,
        BackendErrorKind::ProxyAgentApprovalRequired,
    ] {
        let backend = Arc::new(FakeBackend::default());
        *backend.query_error.lock().expect("query error") = Some(kind);
        let coordinator = coordinator(backend.clone());
        coordinator
            .wait_for_reconciliation()
            .await
            .expect_err("startup failure");
        assert!(
            coordinator.can_reconcile_startup(),
            "{kind:?} is settled by a fresh observation once the services answer"
        );
        *backend.query_error.lock().expect("query error") = None;
        assert_eq!(
            coordinator
                .reconcile_startup()
                .await
                .expect("the fresh observation settles at Off")
                .state,
            EngineState::Off
        );
        assert_eq!(
            backend.query_count(),
            2,
            "{kind:?} re-observes exactly once"
        );
        assert!(
            backend.operations().is_empty(),
            "recovery never starts a core"
        );
        assert_eq!(coordinator.startup_failure(), None);
        coordinator.shutdown().await.expect("unowned exit");
    }
}
