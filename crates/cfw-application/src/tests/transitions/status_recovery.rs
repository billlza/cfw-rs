//! Status observation failures: which ones recover, which fail the runtime, and
//! how a recheck keeps an attested runtime published.

use super::*;

#[tokio::test]
async fn periodic_query_failure_invalidates_active_snapshot_without_releasing_ownership() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    let expected_context = match active.state {
        EngineState::ProxyActive { runtime } => runtime.context,
        state => panic!("expected active proxy, received {state:?}"),
    };
    *backend.fail_query.lock().expect("query failure lock") = true;
    let before = backend.query_count();

    let failed = wait_for_failed(&coordinator).await;
    let error = match failed.state {
        EngineState::Failed {
            error,
            recheck_pending: true,
            ..
        } => error,
        state => panic!("expected a failed state pending its recheck, received {state:?}"),
    };
    assert!(error.contains("query_status"));
    assert!(
        backend.query_count() >= before + crate::runtime::OBSERVATION_GRACE_MISSES as usize,
        "the attested runtime is only published as failed after the observation grace"
    );

    *backend.fail_query.lock().expect("query failure lock") = false;
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("query failure retains the exact stop lease");
    assert_eq!(backend.proxy_stop_contexts(), vec![expected_context]);
}

#[tokio::test]
async fn periodic_read_only_status_failure_recovers_without_native_restart() {
    for mode in [
        EngineMode::LocalProxy,
        EngineMode::SystemProxy,
        EngineMode::Tunnel,
        EngineMode::TunnelSystemProxy,
    ] {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend.clone());
        let active = coordinator
            .set_mode(
                mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .unwrap();
        *backend.fail_query.lock().unwrap() = true;
        wait_for_failed(&coordinator).await;
        *backend.fail_query.lock().unwrap() = false;
        let mut changes = coordinator.subscribe();
        let recovered = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                let current = changes.borrow_and_update().clone();
                if current.state.active_mode() == mode {
                    break current;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .expect("a read-only observation must resume after its transient failure");
        assert_eq!(
            recovered, active,
            "only the previously attested runtime may recover"
        );
        assert_eq!(
            backend.proxy_requests().len() + backend.tunnel_requests().len(),
            1,
            "observation recovery cannot start a replacement core"
        );
        assert!(backend.proxy_stop_contexts().is_empty());
        assert!(backend.tunnel_stop_contexts().is_empty());
    }
}

#[tokio::test]
async fn status_observation_does_not_retry_identity_or_policy_failures() {
    for kind in [
        BackendErrorKind::IdentityRejected,
        BackendErrorKind::PermissionDenied,
        BackendErrorKind::JournalCorrupt,
        BackendErrorKind::Internal,
    ] {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend.clone());
        coordinator
            .set_mode(
                EngineMode::SystemProxy,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .unwrap();
        *backend.query_error.lock().unwrap() = Some(kind);
        let failed = wait_for_failed(&coordinator).await;
        assert!(
            matches!(
                failed.state,
                EngineState::Failed {
                    recheck_pending: false,
                    ..
                }
            ),
            "{kind:?} is a definitive answer and is never rechecked"
        );
        let queries = backend.query_count();
        *backend.query_error.lock().unwrap() = None;
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(matches!(
            coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
        assert_eq!(
            backend.query_count(),
            queries,
            "{kind:?} is not read-only retry authorization"
        );
    }
}

#[tokio::test]
async fn transient_status_recovery_rejects_another_generation_and_stays_failed() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let EngineState::ProxyActive { runtime } = active.state else {
        panic!("proxy must be active")
    };
    *backend.fail_query.lock().unwrap() = true;
    wait_for_failed(&coordinator).await;
    let mut foreign = runtime.clone();
    foreign.context.generation += 1;
    backend.set_native_status(NativeEngineStatus::SystemProxy { runtime: foreign });
    *backend.fail_query.lock().unwrap() = false;
    let mut changes = coordinator.subscribe();
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if matches!(&changes.borrow_and_update().state, EngineState::Failed { error, .. } if error.contains("identity mismatch")) { break; }
            changes.changed().await.unwrap();
        }
    }).await.expect("foreign runtime must be rejected");
    let queries = backend.query_count();
    backend.set_native_status(NativeEngineStatus::SystemProxy { runtime });
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    assert_eq!(
        backend.query_count(),
        queries,
        "identity drift terminates automatic status recovery"
    );
    assert_eq!(backend.proxy_requests().len(), 1);
    assert!(backend.proxy_stop_contexts().is_empty());
}

#[tokio::test]
async fn explicit_off_discards_pending_status_recovery_and_retains_its_stop_barrier() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    *backend.fail_query.lock().unwrap() = true;
    wait_for_failed(&coordinator).await;
    assert!(
        coordinator
            .set_mode(
                EngineMode::Off,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default()
            )
            .await
            .is_err()
    );
    *backend.fail_query.lock().unwrap() = false;
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(coordinator.snapshot().desired_mode, EngineMode::Off);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert_eq!(backend.proxy_requests().len(), 1);
}

#[tokio::test]
async fn observation_misses_within_the_grace_keep_the_attested_runtime_published() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let mut changes = coordinator.subscribe();
    changes.borrow_and_update();
    let before = backend.query_count();
    let misses = crate::runtime::OBSERVATION_GRACE_MISSES as usize - 1;
    *backend.query_error_budget.lock().unwrap() = Some((BackendErrorKind::Timeout, misses));
    tokio::time::timeout(Duration::from_millis(500), async {
        while backend.query_count() < before + misses + 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the periodic observation keeps running through the misses");
    assert!(
        !changes.has_changed().unwrap(),
        "fewer misses than the grace must not publish any snapshot"
    );
    assert_eq!(coordinator.snapshot(), active);
    assert_eq!(
        backend
            .query_error_budget
            .lock()
            .unwrap()
            .map(|(_, left)| left),
        Some(0)
    );
    assert_eq!(backend.proxy_requests().len(), 1);
    assert!(backend.proxy_stop_contexts().is_empty());
}

#[tokio::test]
async fn a_busy_answer_during_a_recheck_keeps_rechecking_until_the_runtime_is_attested_again() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    *backend.fail_query.lock().unwrap() = true;
    let failed = wait_for_failed(&coordinator).await;
    assert!(
        matches!(
            failed.state,
            EngineState::Failed {
                recheck_pending: true,
                ..
            }
        ),
        "a missed observation of a leased runtime is published as pending its recheck"
    );
    *backend.query_error_budget.lock().unwrap() = Some((BackendErrorKind::Busy, 3));
    *backend.fail_query.lock().unwrap() = false;
    let mut changes = coordinator.subscribe();
    let recovered = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let current = changes.borrow_and_update().clone();
            if current.state.active_mode() == EngineMode::SystemProxy {
                break current;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("Busy is a transient answer to a read-only observation: the recheck continues");
    assert_eq!(recovered, active);
    assert_eq!(
        backend
            .query_error_budget
            .lock()
            .unwrap()
            .map(|(_, left)| left),
        Some(0),
        "every Busy answer was consumed by a recheck"
    );
    assert_eq!(
        backend.proxy_requests().len(),
        1,
        "observation recovery cannot start a replacement core"
    );
    assert!(backend.proxy_stop_contexts().is_empty());
}
