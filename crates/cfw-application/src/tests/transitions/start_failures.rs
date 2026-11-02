//! Start failures: a failed cleanup blocks later starts, and backend and
//! engine start timeouts stop the owner without an automatic retry.

use super::*;

#[tokio::test]
async fn failed_cleanup_blocks_all_subsequent_starts() {
    let backend = Arc::new(FakeBackend::default());
    *backend.fail_proxy_start.lock().expect("fail start lock") = true;
    *backend.fail_proxy_stop.lock().expect("fail stop lock") = true;
    let coordinator = coordinator(backend.clone());
    let first_error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("start and cleanup must fail");
    assert!(matches!(
        first_error,
        EngineCoordinatorError::StartAndCleanupFailed { .. }
    ));

    *backend.fail_proxy_start.lock().expect("fail start lock") = false;
    let second_error = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("uncertain proxy ownership must block tunnel");
    assert!(matches!(
        second_error,
        EngineCoordinatorError::Backend {
            operation: EngineOperation::StopSystemProxy,
            ..
        }
    ));
    assert_eq!(
        backend.operations(),
        vec!["start_proxy", "stop_proxy", "stop_proxy"]
    );
}

#[tokio::test]
async fn backend_timeout_is_explicit_and_cleanup_is_attempted() {
    let backend = Arc::new(FakeBackend::default());
    *backend.hang_proxy_start.lock().expect("hang start lock") = true;
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(10),
            authorization_timeout: Duration::from_millis(10),
            status_query_timeout: Duration::from_millis(10),
            status_reconciliation_interval: Duration::from_millis(20),
            initial_generation: 0,
        },
    );
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("hung start must time out");

    assert!(matches!(
        error,
        EngineCoordinatorError::Backend {
            source: BackendError {
                kind: BackendErrorKind::Timeout,
                ..
            },
            ..
        }
    ));
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn engine_start_timeout_stops_the_owner_and_fails_without_quarantine_or_automatic_retry() {
    // Both engine owners interrupt a libbox start that outlives their own
    // deadline and report one typed cause. It is a definitive start failure:
    // exact cleanup and an Off proof, but neither a quarantine nor a retry.
    for (target, start_operation, owner_start, owner_stop) in [
        (
            EngineMode::SystemProxy,
            EngineOperation::StartSystemProxy,
            &["start_proxy"][..],
            "stop_proxy",
        ),
        (
            EngineMode::LocalProxy,
            EngineOperation::StartLocalProxy,
            &["start_proxy"][..],
            "stop_proxy",
        ),
        (
            EngineMode::Tunnel,
            EngineOperation::StartTunnel,
            &["install_tunnel", "start_tunnel"][..],
            "stop_tunnel",
        ),
        (
            EngineMode::TunnelSystemProxy,
            EngineOperation::StartTunnel,
            &["install_tunnel", "start_tunnel"][..],
            "stop_tunnel",
        ),
    ] {
        let backend = Arc::new(FakeBackend::default());
        *backend
            .proxy_start_error
            .lock()
            .expect("proxy start error lock") = Some(BackendErrorKind::EngineStartTimedOut);
        *backend
            .tunnel_start_error
            .lock()
            .expect("tunnel start error lock") = Some(BackendErrorKind::EngineStartTimedOut);
        let coordinator = coordinator(backend.clone());

        let error = coordinator
            .set_mode(
                target,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("a start interrupted at the owner deadline fails");
        let EngineCoordinatorError::Backend { operation, source } = &error else {
            panic!("{target:?}: expected the typed start failure, received {error:?}");
        };
        assert_eq!(*operation, start_operation, "{target:?}");
        assert_eq!(
            source.kind,
            BackendErrorKind::EngineStartTimedOut,
            "{target:?}: the caller receives the owner's typed cause"
        );

        let failed = coordinator.snapshot();
        let EngineState::Failed {
            generation,
            target: failed_target,
            error: published_error,
            recheck_pending,
        } = failed.state.clone()
        else {
            panic!("{target:?}: expected a published failure, received {failed:?}");
        };
        assert_eq!(failed_target, target, "Failed keeps the requested target");
        assert_eq!(published_error, error.to_string(), "{target:?}");
        assert!(
            !recheck_pending,
            "{target:?}: a definitive start failure is not rechecked"
        );

        // One start, then one stop bound to that start's exact context.
        let starts = [backend.proxy_requests(), backend.tunnel_requests()].concat();
        assert_eq!(starts.len(), 1, "{target:?}: the start is attempted once");
        assert_eq!(starts[0].context.generation, generation, "{target:?}");
        let stops = [
            backend.proxy_stop_contexts(),
            backend.tunnel_stop_contexts(),
        ]
        .concat();
        assert_eq!(
            stops,
            vec![starts[0].context.clone()],
            "{target:?}: the failed owner is stopped exactly once"
        );
        let attempted = [owner_start, &[owner_stop]].concat();
        assert_eq!(backend.operations(), attempted, "{target:?}");
        // The startup reconciliation plus one independent Off observation
        // after the stop; without the Off proof only the first would run.
        assert_eq!(backend.query_count(), 2, "{target:?}: Off is proven once");

        // Several status ticks later nothing was retried or observed again.
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(coordinator.snapshot(), failed, "{target:?}: still Failed");
        assert_eq!(backend.operations(), attempted, "{target:?}: no retry");
        assert_eq!(backend.query_count(), 2, "{target:?}: no recheck");

        // No quarantine: the user's next start runs at a fresh generation and
        // needs no further stop.
        *backend
            .proxy_start_error
            .lock()
            .expect("proxy start error lock") = None;
        *backend
            .tunnel_start_error
            .lock()
            .expect("tunnel start error lock") = None;
        let restarted = coordinator
            .set_mode(
                target,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("a timed-out start leaves an explicit retry open");
        assert_eq!(restarted.state.active_mode(), target);
        assert!(restarted.generation > generation, "{target:?}");
        assert_eq!(
            backend.operations(),
            [attempted.as_slice(), owner_start].concat(),
            "{target:?}"
        );
    }
}
