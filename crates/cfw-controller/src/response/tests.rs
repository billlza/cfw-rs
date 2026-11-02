use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::test_support::{FakeController, Reply};
use crate::{ControllerClient, ControllerEndpoint};

#[tokio::test]
async fn rejected_response_body_read_failure_preserves_the_status() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback fixture server");
    let address = listener.local_addr().expect("fixture server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept fixture request");
        let mut request = [0_u8; 1024];
        let _read = stream
            .read(&mut request)
            .await
            .expect("read fixture request");
        stream
            .write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 32\r\nConnection: close\r\n\r\nshort",
            )
            .await
            .expect("write truncated fixture response");
    });

    let response = reqwest::Client::new()
        .get(format!("http://{address}/failure"))
        .send()
        .await
        .expect("receive fixture response headers");
    let error = decode_empty(response)
        .await
        .expect_err("a truncated rejected response body must fail");
    assert!(matches!(
        error,
        ControllerError::ResponseBodyRead { status: 500, .. }
    ));
    server.await.expect("fixture server completes");
}

#[tokio::test]
async fn declared_oversized_controller_response_is_rejected_before_body_read() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized-response server");
    let address = listener.local_addr().expect("fixture server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept fixture request");
        let mut request = [0_u8; 1024];
        let _read = stream
            .read(&mut request)
            .await
            .expect("read fixture request");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_CONTROLLER_JSON_BYTES + 1
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write oversized response headers");
    });

    let client = ControllerClient::new(ControllerEndpoint::new(
        address.ip().to_string(),
        address.port(),
        None,
    ))
    .expect("controller client");
    let error = client
        .version()
        .await
        .expect_err("oversized response must fail before allocation");
    assert_eq!(
        error.to_string(),
        format!("controller HTTP 200 response exceeds the {MAX_CONTROLLER_JSON_BYTES}-byte limit")
    );
    server.await.expect("fixture server completes");
}

#[tokio::test]
async fn rejections_keep_their_status_and_a_lossy_body() {
    let fixture = FakeController::start(|request| match request.target.as_str() {
        "/version" => Reply::undeclared(502, b"bad \xff gateway".to_vec()),
        "/cache/fakeip/flush" => Reply::json(409, "fake-ip is disabled"),
        other => panic!("unexpected fixture request {other}"),
    })
    .await;
    let client = fixture.client(None);
    assert!(matches!(
        client.version().await,
        Err(ControllerError::Status { status: 502, body }) if body == "bad \u{fffd} gateway"
    ));
    assert!(matches!(
        client.flush_fake_ip_cache().await,
        Err(ControllerError::Status { status: 409, body }) if body == "fake-ip is disabled"
    ));
}

#[tokio::test]
async fn declared_oversized_rejections_are_refused_before_their_body() {
    let fixture =
        FakeController::start(|_| Reply::json(500, "").declaring(MAX_CONTROLLER_ERROR_BYTES + 1))
            .await;
    let client = fixture.client(None);
    for error in [
        client
            .version()
            .await
            .map(drop)
            .expect_err("decoded request"),
        client
            .flush_fake_ip_cache()
            .await
            .expect_err("empty-result request"),
    ] {
        assert!(matches!(
            error,
            ControllerError::ResponseTooLarge {
                status: 500,
                maximum: MAX_CONTROLLER_ERROR_BYTES
            }
        ));
    }
}

#[tokio::test]
async fn an_undeclared_body_is_bounded_while_it_streams() {
    let fixture = FakeController::start(|request| match request.target.as_str() {
        "/connections" => Reply::undeclared(500, vec![b'x'; MAX_CONTROLLER_ERROR_BYTES + 1]),
        "/version" => Reply::undeclared(503, vec![b'x'; MAX_CONTROLLER_ERROR_BYTES]),
        "/configs" => Reply::undeclared(200, br#"{"mode":"rule"}"#.to_vec()),
        other => panic!("unexpected fixture request {other}"),
    })
    .await;
    let client = fixture.client(None);
    assert!(matches!(
        client.close_all_connections().await,
        Err(ControllerError::ResponseTooLarge {
            status: 500,
            maximum: MAX_CONTROLLER_ERROR_BYTES
        })
    ));
    assert!(matches!(
        client.version().await,
        Err(ControllerError::Status { status: 503, body }) if body.len() == MAX_CONTROLLER_ERROR_BYTES
    ));
    assert_eq!(
        client
            .configs()
            .await
            .expect("undeclared JSON")
            .mode
            .as_deref(),
        Some("rule")
    );
}

#[tokio::test]
async fn a_success_body_that_is_not_the_expected_json_fails_to_decode() {
    let fixture = FakeController::start(|_| Reply::json(200, "not json")).await;
    assert!(matches!(
        fixture.client(None).version().await,
        Err(ControllerError::Json(_))
    ));
}

#[tokio::test]
async fn an_empty_result_success_ignores_its_body() {
    let fixture = FakeController::start(|_| Reply::json(200, r#"{"ignored":true}"#)).await;
    fixture
        .client(None)
        .flush_fake_ip_cache()
        .await
        .expect("a 2xx empty-result request succeeds");
}
