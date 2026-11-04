//! Periodic reconciliation: disconnects are recorded without replaying a
//! completed stop, native Off allows a reconnect, and missed ticks are skipped.

use super::*;

#[tokio::test]
async fn periodic_reconciliation_records_proxy_disconnect_without_replaying_completed_stop() {
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
    assert!(matches!(active.state, EngineState::ProxyActive { .. }));

    backend.set_native_status(NativeEngineStatus::Off);
    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(
        failed.state,
        EngineState::Failed {
            target: EngineMode::SystemProxy,
            ..
        }
    ));

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("the native authority has already completed the proxy stop");
    assert!(backend.proxy_stop_contexts().is_empty());
}

#[tokio::test]
async fn periodic_reconciliation_records_tunnel_disconnect_without_replaying_completed_stop() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start tunnel");
    assert!(matches!(active.state, EngineState::TunnelActive { .. }));

    backend.set_native_status(NativeEngineStatus::Off);
    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(
        failed.state,
        EngineState::Failed {
            target: EngineMode::Tunnel,
            ..
        }
    ));

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("the native authority has already completed the tunnel stop");
    assert!(backend.tunnel_stop_contexts().is_empty());
}

#[tokio::test]
async fn authoritative_native_off_allows_reconnect_without_stopping_a_released_owner() {
    for mode in [
        EngineMode::Tunnel,
        EngineMode::TunnelSystemProxy,
        EngineMode::LocalProxy,
        EngineMode::SystemProxy,
    ] {
        let backend = Arc::new(FakeBackend::default());
        *backend
            .reject_stop_after_native_off
            .lock()
            .expect("stop owner policy lock") = true;
        let coordinator = coordinator(backend.clone());
        let active = coordinator
            .set_mode(
                mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("initial native owner is active");

        backend.set_native_status(NativeEngineStatus::Off);
        let observed = wait_for_failed(&coordinator).await;
        assert!(matches!(observed.state, EngineState::Failed { target, .. } if target == mode));
        assert_eq!(observed.generation, active.generation);

        let reconnected = coordinator
            .set_mode(
                mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("authoritative native Off has already released the old owner");
        assert_eq!(reconnected.state.active_mode(), mode);
        assert!(reconnected.generation > active.generation);
        assert!(backend.proxy_stop_contexts().is_empty());
        assert!(backend.tunnel_stop_contexts().is_empty());

        coordinator
            .set_mode(
                EngineMode::Off,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("the new active owner still uses the ordinary stop barrier");
        assert_eq!(
            backend.proxy_stop_contexts().len() + backend.tunnel_stop_contexts().len(),
            1
        );
    }
}

#[tokio::test(start_paused = true)]
async fn reconciliation_skips_missed_ticks_and_resumes_after_suspension() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            authorization_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(2),
            initial_generation: 0,
        },
    );
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    assert_eq!(backend.query_count(), 1);

    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        backend.query_count(),
        2,
        "a suspended actor performs one skipped-tick reconciliation, not a burst"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(backend.query_count(), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.query_count(), 3, "the regular cadence resumes");

    coordinator.shutdown().await.expect("stop proxy");
}
