//! Runtime identity: drift, a mismatched identity and the wrong owner fail
//! closed and stop the runtime they found.

use super::*;

#[tokio::test]
async fn late_tunnel_identity_drift_fails_and_stops_the_original_context() {
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
    let expected_runtime = match active.state {
        EngineState::TunnelActive { runtime } => runtime,
        state => panic!("expected active tunnel, received {state:?}"),
    };
    let mut late_runtime = expected_runtime.clone();
    late_runtime.owner = EngineOwner::ProxyAgent;
    backend.set_native_status(NativeEngineStatus::Tunnel {
        runtime: late_runtime,
    });

    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(failed.state, EngineState::Failed { .. }));
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("late drift retains original stop ownership");
    assert_eq!(
        backend.tunnel_stop_contexts(),
        vec![expected_runtime.context]
    );
}

#[tokio::test]
async fn runtime_identity_mismatch_fails_closed_and_stops_proxy() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .wrong_proxy_digest
        .lock()
        .expect("wrong digest lock") = true;
    let coordinator = coordinator(backend.clone());
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("identity mismatch must fail");

    assert!(matches!(
        error,
        EngineCoordinatorError::RuntimeIdentityMismatch { .. }
    ));
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn wrong_owner_is_cleaned_up_using_the_attempted_proxy_mode() {
    let backend = Arc::new(FakeBackend::default());
    *backend.wrong_proxy_owner.lock().expect("wrong owner lock") = true;
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("wrong owner must fail");

    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}
