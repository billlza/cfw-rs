//! Connection policy: proxies, redirects, the bearer secret and the endpoint.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::test_support::Reply;

#[test]
fn controller_http_builder_disables_all_proxy_discovery() {
    let source = include_str!("../../client.rs");
    let builder = source
        .split("let http = reqwest::Client::builder()")
        .nth(1)
        .expect("controller HTTP builder")
        .split(".build()?")
        .next()
        .expect("bounded controller HTTP builder");
    assert!(builder.contains(".no_proxy()"));
    assert!(builder.contains(".redirect(Policy::none())"));
}

#[tokio::test]
async fn controller_never_follows_an_authenticated_redirect() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
    let redirect_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect target");
    let target_address = redirect_target
        .local_addr()
        .expect("redirect target address");
    let controller = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind controller fixture");
    let controller_address = controller.local_addr().expect("controller address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = controller
            .accept()
            .await
            .expect("accept controller request");
        let mut request = [0_u8; 2048];
        let read = stream
            .read(&mut request)
            .await
            .expect("read controller request");
        assert!(
            String::from_utf8_lossy(&request[..read])
                .to_ascii_lowercase()
                .contains("authorization: bearer ")
        );
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/version\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write redirect response");
    });

    let client = ControllerClient::new(ControllerEndpoint::new(
        controller_address.ip().to_string(),
        controller_address.port(),
        Some("must-not-cross-redirect".into()),
    ))
    .expect("controller client");
    let error = client
        .version()
        .await
        .expect_err("controller redirects must be rejected");
    assert!(matches!(error, ControllerError::Status { status: 302, .. }));
    server.await.expect("controller fixture completes");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
            .await
            .is_err(),
        "redirect target unexpectedly received the bearer request"
    );
}

#[test]
fn client_debug_redacts_the_controller_secret() {
    let client = ControllerClient::new(ControllerEndpoint::new(
        "127.0.0.1",
        9090,
        Some("app-owned".into()),
    ))
    .expect("controller client");
    let rendered = format!("{client:?}");
    assert!(!rendered.contains("app-owned"), "{rendered}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
}

#[test]
fn a_secret_that_cannot_be_a_header_value_is_rejected() {
    let error = ControllerClient::new(ControllerEndpoint::new(
        "127.0.0.1",
        9090,
        Some("line\nbreak".into()),
    ))
    .expect_err("a header-unsafe secret");
    assert!(matches!(error, ControllerError::InvalidEndpoint(_)));
}

#[test]
fn stream_urls_authenticate_with_the_controller_token() {
    let client = ControllerClient::new(ControllerEndpoint::new(
        "127.0.0.1",
        9090,
        Some("s3cret".into()),
    ))
    .expect("controller client");
    assert_eq!(
        client.connections_stream_url().unwrap(),
        "ws://127.0.0.1:9090/connections?token=s3cret"
    );
    assert_eq!(
        client.logs_stream_url("debug").unwrap(),
        "ws://127.0.0.1:9090/logs?token=s3cret&level=debug&format=structured"
    );
}

#[tokio::test]
async fn requests_carry_the_bearer_secret_only_when_one_is_set() {
    let fixture =
        FakeController::start(|_| Reply::json(200, r#"{"version":"sing-box 1.14.4"}"#)).await;
    for secret in [Some("s3cret"), Some(""), None] {
        fixture
            .client(secret)
            .version()
            .await
            .expect("controller version");
    }
    let requests = fixture.requests();
    let authorization: Vec<_> = requests
        .iter()
        .map(|request| request.header("authorization"))
        .collect();
    assert_eq!(authorization, [Some("Bearer s3cret"), None, None]);
    assert!(
        requests
            .iter()
            .all(|request| request.header("content-type") == Some("application/json"))
    );
}

#[tokio::test]
async fn a_non_loopback_endpoint_fails_every_request_before_connecting() {
    let client = ControllerClient::new(ControllerEndpoint::new("localhost", 9090, None))
        .expect("construction does not resolve the endpoint");
    let invalid = |result: Result<(), ControllerError>| {
        matches!(result, Err(ControllerError::InvalidEndpoint(_)))
    };
    assert!(invalid(client.version().await.map(drop)));
    assert!(invalid(client.patch_configs(ConfigPatch::default()).await));
    assert!(invalid(client.reload_config("/profile.json", false).await));
    assert!(invalid(client.flush_fake_ip_cache().await));
    assert!(invalid(client.close_all_connections().await));
    assert!(invalid(
        client.proxy_delay("HK", PROBE_URL, 100).await.map(drop)
    ));
    assert!(invalid(client.connections_stream_url().map(drop)));
    assert!(invalid(client.logs_stream_url("info").map(drop)));
    let results = client
        .proxy_delays(vec!["HK".into()], PROBE_URL.into(), 100, 4)
        .await;
    assert_eq!(
        results[0].error_kind,
        Some(ProxyDelayFailureKind::InvalidRequest)
    );
}
