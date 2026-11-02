//! Startup retries after approvals, busy authorities and failed reads.

use super::*;

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
async fn explicit_command_retries_startup_after_a_busy_authority_settles() {
    let backend = Arc::new(FakeBackend::default());
    *backend.query_error.lock().expect("query error lock") = Some(BackendErrorKind::Busy);
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
                kind: BackendErrorKind::Busy,
                ..
            },
        })
    ));
    assert_eq!(backend.query_count(), 1);
    assert!(
        coordinator.can_reconcile_startup(),
        "a busy authority at startup is re-observed on request"
    );

    *backend.query_error.lock().expect("query error lock") = None;
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("explicit request re-observes the settled authority and starts");
    assert!(matches!(active.state, EngineState::ProxyActive { .. }));
    assert_eq!(backend.query_count(), 2);
    assert_eq!(backend.operations(), vec!["start_proxy"]);
    assert_eq!(coordinator.startup_failure(), None);
    coordinator.shutdown().await.expect("shutdown barrier");
}
