//! The bounded command queue, serial execution and mode errors.

use super::*;

#[tokio::test]
async fn bounded_command_queue_reports_backpressure() {
    let backend = Arc::new(FakeBackend::default());
    let gate = Arc::new(Notify::new());
    *backend.proxy_start_gate.lock().expect("start gate lock") = Some(gate.clone());
    let coordinator = coordinator(backend);
    let mut requests = Vec::new();
    for _ in 0..(COMMAND_QUEUE_CAPACITY + 8) {
        let coordinator = coordinator.clone();
        requests.push(tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::SystemProxy,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        }));
    }

    tokio::time::timeout(Duration::from_millis(200), async {
        while requests.iter().all(|request| !request.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queue saturation is observable");
    gate.notify_one();

    let mut full = 0;
    for request in requests {
        match request.await.expect("request task") {
            Ok(_) => {}
            Err(EngineCoordinatorError::CommandQueueFull) => full += 1,
            Err(error) => panic!("unexpected queue result: {error}"),
        }
    }
    assert!(full > 0);
}

#[tokio::test]
async fn concurrent_requests_are_executed_serially() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let proxy = {
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
    let tunnel = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            coordinator
                .set_mode(
                    EngineMode::Tunnel,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    ValidatedSingBoxProfile::direct(),
                    EngineSettings::default(),
                )
                .await
        })
    };

    proxy.await.expect("proxy task").expect("proxy transition");
    tunnel
        .await
        .expect("tunnel task")
        .expect("tunnel transition");
    assert_eq!(
        backend.operations(),
        vec![
            "start_proxy",
            "stop_proxy",
            "install_tunnel",
            "start_tunnel"
        ]
    );
}

#[tokio::test]
async fn backend_errors_do_not_fallback_to_another_mode() {
    struct FailingBackend;

    impl EngineBackend for FailingBackend {
        fn runtime_platform(&self) -> cfw_engine_api::EngineRuntimePlatform {
            cfw_engine_api::EngineRuntimePlatform::MacOs
        }

        fn check_configuration(&self, _request: EngineStartRequest) -> BackendFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn start_local_proxy(
            &self,
            request: EngineStartRequest,
        ) -> BackendFuture<'_, RuntimeIdentity> {
            self.start_system_proxy(request)
        }

        fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
            self.stop_system_proxy(context)
        }

        fn query_status(&self) -> BackendFuture<'_, cfw_engine_api::NativeEngineStatus> {
            Box::pin(async { Ok(cfw_engine_api::NativeEngineStatus::Off) })
        }

        fn start_system_proxy(
            &self,
            _request: EngineStartRequest,
        ) -> BackendFuture<'_, RuntimeIdentity> {
            Box::pin(async {
                Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "proxy agent unavailable",
                ))
            })
        }

        fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn install_tunnel(
            &self,
            _context: EngineCommandContext,
        ) -> BackendFuture<'_, TunnelInstallOutcome> {
            panic!("tunnel fallback must not be attempted")
        }

        fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            panic!("tunnel fallback must not be attempted")
        }

        fn authorize_tunnel_configuration(
            &self,
            _request: EngineStartRequest,
        ) -> BackendFuture<'_, ()> {
            panic!("tunnel fallback must not be attempted")
        }

        fn start_tunnel(&self, _request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
            panic!("tunnel fallback must not be attempted")
        }

        fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            panic!("tunnel fallback must not be attempted")
        }
    }

    let coordinator = EngineModeCoordinator::spawn(Arc::new(FailingBackend), test_session());
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("proxy failure");
    assert!(matches!(error, EngineCoordinatorError::Backend { .. }));
}
