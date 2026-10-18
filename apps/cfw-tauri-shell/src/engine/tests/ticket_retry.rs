use super::*;

const PROFILE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn expired_backend(failures: usize) -> EndpointRetryBackend {
    EndpointRetryBackend {
        tunnel_failures_before_success: failures,
        ..EndpointRetryBackend::new(0)
    }
}

#[tokio::test]
async fn expired_ticket_retries_once_with_a_fresh_generation_and_unchanged_endpoints() {
    for failures in [1, 2] {
        let backend = Arc::new(expired_backend(failures));
        let coordinator = endpoint_retry_coordinator(backend.clone());
        let original = EngineSettings::default();
        let endpoints = std::sync::RwLock::new(endpoint_binding(original.clone()));
        let result = set_mode_with_endpoint_rebind(
            &coordinator,
            &endpoints,
            EngineMode::Tunnel,
            PROFILE_ID,
            &ValidatedSingBoxProfile::direct(),
            || Ok(()),
            |_| panic!("ticket expiry must not change endpoints"),
        )
        .await;
        assert_eq!(backend.starts(), vec![(1, 0), (2, 0)]);
        assert_eq!(backend.stops.load(Ordering::Acquire), failures);
        assert_eq!(
            super::super::read_engine_settings(&endpoints).expect("settings"),
            original
        );
        if failures == 1 {
            let active = result.expect("one fresh attempt succeeds");
            assert!(matches!(active.state, EngineState::TunnelActive { .. }));
            assert_eq!(active.generation, 2);
        } else {
            assert!(
                result
                    .expect_err("no third start")
                    .contains("ticket expired")
            );
            assert_eq!(coordinator.snapshot().state, EngineState::Off);
        }
    }
}

#[tokio::test]
async fn cleanup_or_off_proof_failure_prevents_ticket_retry() {
    for fail_cleanup in [true, false] {
        let mut fixture = expired_backend(1);
        if fail_cleanup {
            fixture.tunnel_cleanup_error = Some(BackendErrorKind::CleanupUnproven);
        } else {
            fixture.tunnel_off_proof_error = true;
        }
        let backend = Arc::new(fixture);
        let coordinator = endpoint_retry_coordinator(backend.clone());
        let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
        let result = set_mode_with_endpoint_rebind(
            &coordinator,
            &endpoints,
            EngineMode::Tunnel,
            PROFILE_ID,
            &ValidatedSingBoxProfile::direct(),
            || panic!("unproven cleanup cannot offer a retry"),
            |_| panic!("no endpoint change"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(backend.starts(), vec![(1, 0)]);
        assert!(matches!(
            coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
    }
}

#[tokio::test]
async fn invalid_replayed_and_unauthorized_tickets_never_retry_automatically() {
    for kind in [
        BackendErrorKind::TicketInvalid,
        BackendErrorKind::TicketAlreadyRedeemed,
        BackendErrorKind::ReplayRejected,
        BackendErrorKind::IdentityRejected,
    ] {
        let backend = Arc::new(EndpointRetryBackend {
            tunnel_failure: kind,
            ..expired_backend(1)
        });
        let coordinator = endpoint_retry_coordinator(backend.clone());
        let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
        let result = set_mode_with_endpoint_rebind(
            &coordinator,
            &endpoints,
            EngineMode::Tunnel,
            PROFILE_ID,
            &ValidatedSingBoxProfile::direct(),
            || panic!("security rejection cannot offer a retry"),
            |_| panic!("no endpoint change"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(backend.starts(), vec![(1, 0)]);
    }
}

#[tokio::test]
async fn newer_user_intent_stops_the_retry_after_compensated_off() {
    let backend = Arc::new(expired_backend(1));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let result = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::Tunnel,
        PROFILE_ID,
        &ValidatedSingBoxProfile::direct(),
        || Err(EngineMaintenanceError::StaleIntent.to_string()),
        |_| panic!("no endpoint change"),
    )
    .await;
    assert_eq!(
        result.expect_err("newer intent wins"),
        EngineMaintenanceError::StaleIntent.to_string()
    );
    assert_eq!(backend.starts(), vec![(1, 0)]);
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
}

#[tokio::test]
async fn queued_off_invalidates_the_running_mode_retry_guard() {
    let gate = EngineMaintenanceGate::default();
    let current = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("start admission");
    let guard = current.retry_guard();
    assert_eq!(guard(), Ok(()));
    let stop = gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off));
    tokio::pin!(stop);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut stop)
            .await
            .is_err()
    );
    assert_eq!(guard(), Err(EngineMaintenanceError::StaleIntent));
    drop(current);
    stop.await
        .expect("queued Off is admitted when failed start settles");
}
