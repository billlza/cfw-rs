//! Shutdown, explicit Off and generation numbering.

use super::*;

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
