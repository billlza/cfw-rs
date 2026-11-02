//! An unavailable lineage: Off-only starts, exact cleanup and safe exit.

use super::*;

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
