use std::{sync::Arc, time::Duration};

use cfw_engine_api::{BackendErrorKind, EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::sync::Notify;

use super::support::{FakeBackend, test_session};
use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator, EngineOperation};

fn coordinator(
    backend: Arc<FakeBackend>,
    authorization_timeout: Duration,
) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(10),
            authorization_timeout,
            ..CoordinatorOptions::default()
        },
    )
}

async fn start(
    coordinator: EngineModeCoordinator,
) -> Result<cfw_engine_api::EngineSnapshot, EngineCoordinatorError> {
    coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
}

#[tokio::test]
async fn user_consent_outlives_runtime_budget_without_starting_a_tunnel() {
    let backend = Arc::new(FakeBackend::default());
    let consent = Arc::new(Notify::new());
    *backend
        .tunnel_authorization_gate
        .lock()
        .expect("consent gate") = Some(consent.clone());
    let coordinator = coordinator(backend.clone(), Duration::from_secs(1));
    let pending = tokio::spawn(start(coordinator.clone()));
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend
            .tunnel_authorization_requests
            .lock()
            .expect("consent requests")
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("consent phase entered");
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!pending.is_finished());
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::AwaitingApproval { .. }
    ));
    assert!(backend.tunnel_requests().is_empty());
    assert!(backend.proxy_requests().is_empty());
    consent.notify_one();
    let result = pending.await.expect("task").expect("authorized start");
    assert!(matches!(result.state, EngineState::TunnelActive { .. }));
    let authorized = backend
        .tunnel_authorization_requests
        .lock()
        .expect("consent requests");
    assert_eq!(authorized.len(), 1);
    assert_eq!(authorized[0].context, backend.tunnel_requests()[0].context);
}

#[tokio::test]
async fn rejected_consent_never_starts_the_runtime() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_authorization_error
        .lock()
        .expect("consent error") = Some(BackendErrorKind::PermissionDenied);
    let error = start(coordinator(backend.clone(), Duration::from_millis(50)))
        .await
        .expect_err("consent denied");
    assert!(matches!(
        error,
        EngineCoordinatorError::Backend {
            operation: EngineOperation::AuthorizeTunnelConfiguration,
            source: cfw_engine_api::BackendError {
                kind: BackendErrorKind::PermissionDenied,
                ..
            }
        }
    ));
    assert!(backend.tunnel_requests().is_empty());
    assert!(backend.proxy_requests().is_empty());
}

#[tokio::test]
async fn unanswered_consent_has_its_own_bounded_timeout_and_cleanup() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_authorization_gate
        .lock()
        .expect("consent gate") = Some(Arc::new(Notify::new()));
    let coordinator = coordinator(backend.clone(), Duration::from_millis(40));
    let error = start(coordinator.clone())
        .await
        .expect_err("consent timed out");
    assert!(matches!(
        error,
        EngineCoordinatorError::Backend {
            operation: EngineOperation::AuthorizeTunnelConfiguration,
            source: cfw_engine_api::BackendError {
                kind: BackendErrorKind::Timeout,
                ..
            }
        }
    ));
    assert!(backend.tunnel_requests().is_empty());
    assert!(backend.proxy_requests().is_empty());
    assert_eq!(backend.tunnel_stop_contexts().len(), 1);
}
