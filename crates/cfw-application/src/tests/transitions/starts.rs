//! Starting a runtime: the starting state comes first, saved choices are read
//! back, combined integrations share one runtime, and a repeated request is
//! idempotent.

use super::*;

#[tokio::test]
async fn starts_proxy_only_after_publishing_starting_state() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");

    assert!(matches!(snapshot.state, EngineState::ProxyActive { .. }));
    assert_eq!(backend.operations(), vec!["start_proxy"]);
}

#[tokio::test]
async fn saved_choices_require_controller_readback_or_the_new_runtime_is_stopped() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    for confirmed in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("controller listener");
        listener.set_nonblocking(true).expect("bounded accept");
        let settings = EngineSettings {
            controller_port: listener.local_addr().expect("address").port(),
            ..EngineSettings::default()
        };
        let expected_secret = crate::EngineControllerAccess::resolve(settings.clone())
            .expect("access")
            .client_endpoint()
            .secret
            .expect("secret");
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            for step in 0..2 {
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "controller request deadline"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                // Darwin inherits the listener's nonblocking flag. The HTTP
                // stream uses bounded blocking reads after the bounded accept.
                socket
                    .set_nonblocking(false)
                    .expect("blocking request stream");
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read deadline");
                let mut reader = BufReader::new(socket.try_clone().expect("reader"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("request line");
                assert!(line.starts_with(if step == 0 {
                    "PUT /proxies/PROXY "
                } else {
                    "GET /proxies "
                }));
                let mut length = 0;
                let mut authenticated = false;
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).expect("header") > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().expect("body length");
                    }
                    if line.to_ascii_lowercase().starts_with("authorization:") {
                        authenticated = line
                            .trim_end()
                            .ends_with(&format!("Bearer {expected_secret}"));
                    }
                }
                assert!(authenticated);
                assert!(length < 1_024);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).expect("request body");
                if step == 0 {
                    assert_eq!(body, br#"{"name":"REJECT"}"#);
                }
                let response = if step == 0 {
                    String::new()
                } else {
                    format!(
                        r#"{{"proxies":{{"PROXY":{{"type":"Selector","all":["DIRECT","REJECT"],"now":"{}"}}}}}}"#,
                        if confirmed { "REJECT" } else { "DIRECT" }
                    )
                };
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .expect("response");
            }
        });
        let profile = ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"DIRECT"},{"type":"block","tag":"REJECT"},{"type":"selector","tag":"PROXY","outbounds":["DIRECT","REJECT"]}],"route":{"final":"PROXY"}}"#).expect("profile").with_selected_outbound("PROXY", "REJECT").expect("saved choice");
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend.clone());
        let result = coordinator
            .set_mode(
                EngineMode::SystemProxy,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                profile,
                settings,
            )
            .await;
        if confirmed {
            assert!(matches!(
                result.expect("confirmed start").state,
                EngineState::ProxyActive { .. }
            ));
            assert_eq!(backend.operations(), vec!["start_proxy"]);
        } else {
            assert!(matches!(
                result,
                Err(EngineCoordinatorError::ProxySelectionInitialization(_))
            ));
            assert!(matches!(
                coordinator.snapshot().state,
                EngineState::Failed { .. }
            ));
            assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
        }
        server.join().expect("controller server");
    }
}

#[tokio::test]
async fn combined_integrations_share_one_runtime_and_can_be_disabled_independently() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let profile_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let mut previous = None;
    for mode in [
        EngineMode::TunnelSystemProxy,
        EngineMode::TunnelSystemProxy,
        EngineMode::Tunnel,
        EngineMode::SystemProxy,
        EngineMode::Off,
    ] {
        let snapshot = coordinator
            .set_mode(
                mode,
                profile_id.to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("mode transition");
        assert_eq!(snapshot.state.active_mode(), mode);
        assert_eq!(snapshot.desired_mode, mode);
        if mode == EngineMode::TunnelSystemProxy {
            if let Some(generation) = previous {
                assert_eq!(snapshot.generation, generation);
            }
            previous = Some(snapshot.generation);
            assert!(backend.proxy_requests().is_empty());
        }
    }
    assert_eq!(
        backend.operations(),
        vec![
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel",
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel",
            "start_proxy",
            "stop_proxy"
        ]
    );
    let requests = backend.tunnel_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0]
            .tunnel_options
            .as_ref()
            .expect("combined options")
            .system_proxy_port,
        Some(EngineSettings::default().mixed_port)
    );
    assert_eq!(
        requests[1]
            .tunnel_options
            .as_ref()
            .expect("TUN options")
            .system_proxy_port,
        None
    );
    assert_ne!(requests[0].config_digest, requests[1].config_digest);
}

#[tokio::test]
async fn combined_start_failure_cleans_up_and_never_reports_proxy_active() {
    let backend = Arc::new(FakeBackend::default());
    *backend.tunnel_start_error.lock().expect("failure setting") =
        Some(BackendErrorKind::ConfigurationRejected);
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::TunnelSystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("native startup fails");
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed {
            target: EngineMode::TunnelSystemProxy,
            ..
        }
    ));
    assert!(backend.proxy_requests().is_empty());
    assert_eq!(backend.tunnel_stop_contexts().len(), 1);
    assert_eq!(coordinator.snapshot().state.active_mode(), EngineMode::Off);
}

#[tokio::test]
async fn same_digest_request_reconciles_immediately_before_idempotent_success() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            authorization_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(30),
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
    assert_eq!(backend.query_count(), 1, "startup query only");
    backend.set_native_status(NativeEngineStatus::Off);

    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("stale same-digest snapshot must not return success");
    assert!(matches!(
        error,
        EngineCoordinatorError::ActiveRuntimeStatusMismatch {
            expected_mode: EngineMode::SystemProxy,
            ..
        }
    ));
    assert_eq!(
        backend.query_count(),
        2,
        "same-digest request queried native state"
    );
    assert_eq!(backend.operations(), vec!["start_proxy"]);

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("cleanup retained ownership");
}
