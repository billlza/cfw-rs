use std::sync::Arc;

use cfw_engine_api::{EngineMode, EngineOwner, EngineStartMode, EngineState, NativeEngineStatus};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::support::{FakeBackend, coordinator};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[tokio::test]
async fn local_proxy_is_ready_without_claiming_system_proxy_and_stops_explicitly() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("local proxy start");
    let EngineState::LocalProxyActive { runtime } = snapshot.state else {
        panic!("local proxy must be independently active")
    };
    assert_eq!(runtime.owner, EngineOwner::ProxyAgent);
    assert!(!snapshot.desired_mode.system_proxy_enabled());
    assert!(!snapshot.desired_mode.tunnel_enabled());
    assert!(backend.tunnel_requests().is_empty());
    assert!(backend.tunnel_install_contexts().is_empty());
    let requests = backend.proxy_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].mode, EngineStartMode::LocalProxy);
    assert!(requests[0].tunnel_options.is_none());
    assert!(
        coordinator
            .restart_spec()
            .await
            .unwrap()
            .unwrap()
            .matches_ready_snapshot(&coordinator.snapshot())
    );

    let stopped = coordinator
        .set_mode(
            EngineMode::Off,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("explicit core stop");
    assert_eq!(stopped.state, EngineState::Off);
    assert_eq!(backend.proxy_stop_contexts(), vec![runtime.context]);
}

#[tokio::test]
async fn switches_between_local_and_os_integrations_bind_distinct_generations() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let mut generation = 0;
    for target in [
        EngineMode::LocalProxy,
        EngineMode::SystemProxy,
        EngineMode::LocalProxy,
        EngineMode::Tunnel,
        EngineMode::LocalProxy,
    ] {
        let snapshot = coordinator
            .set_mode(
                target,
                PROFILE.into(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(snapshot.state.active_mode(), target);
        assert!(snapshot.generation > generation);
        generation = snapshot.generation;
    }
    assert_eq!(backend.tunnel_requests().len(), 1);
    assert_eq!(backend.tunnel_stop_contexts().len(), 1);
    assert_eq!(backend.proxy_requests().len(), 4);
    assert_ne!(
        backend.proxy_requests()[0].config_digest,
        backend.proxy_requests()[1].config_digest
    );
}

#[tokio::test]
async fn system_proxy_observation_cannot_attest_a_local_proxy_request() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let EngineState::LocalProxyActive { runtime } = active.state else {
        panic!("local active")
    };
    backend.set_native_status(NativeEngineStatus::SystemProxy { runtime });
    let error = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        crate::EngineCoordinatorError::ActiveRuntimeStatusMismatch {
            expected_mode: EngineMode::LocalProxy,
            ..
        }
    ));
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}
