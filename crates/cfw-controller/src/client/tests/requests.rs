//! Each controller operation's method, path, body and decoded result.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::test_support::Reply;

#[tokio::test]
async fn snapshot_fails_when_any_component_request_fails() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback snapshot server");
    let address = listener.local_addr().expect("snapshot server address");
    let server = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.expect("accept snapshot request");
            handlers.push(tokio::spawn(async move {
                let mut request = [0_u8; 2048];
                let read = stream
                    .read(&mut request)
                    .await
                    .expect("read snapshot request");
                let request = String::from_utf8_lossy(&request[..read]);
                let (status, body) = if request.starts_with("GET /configs ") {
                    ("200 OK", r#"{"mode":"rule"}"#)
                } else if request.starts_with("GET /proxies ") {
                    ("200 OK", r#"{"proxies":{}}"#)
                } else if request.starts_with("GET /connections ") {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    ("503 Service Unavailable", r#"{"message":"not ready"}"#)
                } else {
                    ("404 Not Found", r#"{"message":"unexpected path"}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write snapshot response");
            }));
        }
        for handler in handlers {
            handler.await.expect("snapshot request handler completes");
        }
    });

    let client = ControllerClient::new(ControllerEndpoint::new(
        address.ip().to_string(),
        address.port(),
        None,
    ))
    .expect("snapshot client");
    let error = client
        .snapshot()
        .await
        .expect_err("a failed connections component must fail the full snapshot");
    assert!(matches!(error, ControllerError::Status { status: 503, .. }));
    server.await.expect("snapshot server completes");
}

#[tokio::test]
async fn snapshot_combines_config_proxies_and_connections() {
    let fixture = FakeController::start(|request| match request.target.as_str() {
        "/configs" => Reply::json(
            200,
            r#"{"mode":"rule","mixed-port":7890,"allow-lan":false,"log-level":"warning","ipv6":true,"tun":{"enable":false}}"#,
        ),
        "/proxies" => Reply::json(
            200,
            r#"{"proxies":{"Proxy":{"type":"Selector","all":["HK"],"now":"HK"},"HK":{"type":"Shadowsocks","udp":true}}}"#,
        ),
        "/connections" => Reply::json(
            200,
            r#"{"uploadTotal":5,"downloadTotal":7,"connections":[{"id":"c1","chains":["HK"]}]}"#,
        ),
        other => panic!("unexpected snapshot request {other}"),
    })
    .await;
    let snapshot = fixture
        .client(None)
        .snapshot()
        .await
        .expect("controller snapshot");

    assert_eq!(snapshot.config.mode.as_deref(), Some("rule"));
    assert_eq!(snapshot.config.mixed_port, Some(7890));
    assert_eq!(snapshot.config.allow_lan, Some(false));
    assert_eq!(snapshot.config.log_level.as_deref(), Some("warning"));
    assert_eq!(snapshot.config.ipv6, Some(true));
    assert_eq!(
        snapshot.config.extra["tun"],
        serde_json::json!({"enable": false})
    );
    assert_eq!(snapshot.proxies.groups[0].now.as_deref(), Some("HK"));
    assert_eq!(snapshot.proxies.proxies[0].udp, Some(true));
    assert_eq!(snapshot.connections.upload, 5);
    assert_eq!(snapshot.connections.download, 7);
    assert_eq!(snapshot.connections.connections[0].chains, ["HK"]);
    let mut lines = request_lines(&fixture);
    lines.sort();
    assert_eq!(lines, ["GET /configs", "GET /connections", "GET /proxies"]);
}

#[tokio::test]
async fn reads_use_their_controller_paths() {
    let fixture = FakeController::start(|request| match request.target.as_str() {
        "/configs" => Reply::json(200, r#"{"mode":"global"}"#),
        "/version" => Reply::json(200, r#"{"version":"sing-box 1.14.4"}"#),
        "/dns/query?name=a%20b%26c.example&type=AAAA" => Reply::json(200, r#"{"Status":0}"#),
        "/rules" => Reply::json(
            200,
            r#"{"rules":[{"type":"Default","payload":"","proxy":"DIRECT"}]}"#,
        ),
        "/connections" => Reply::json(200, r#"{"connections":null}"#),
        "/proxies" => Reply::json(200, r#"{"proxies":{}}"#),
        other => panic!("unexpected read request {other}"),
    })
    .await;
    let client = fixture.client(None);

    assert_eq!(
        client.configs().await.unwrap().mode.as_deref(),
        Some("global")
    );
    assert_eq!(
        client.version().await.unwrap(),
        ControllerVersion {
            version: "sing-box 1.14.4".into(),
            meta: false
        }
    );
    assert_eq!(
        client.dns_query("a b&c.example", "AAAA").await.unwrap(),
        serde_json::json!({"Status": 0})
    );
    assert_eq!(client.rules().await.unwrap().rules[0].proxy, "DIRECT");
    assert!(client.connections().await.unwrap().connections.is_empty());
    assert_eq!(
        client.proxies().await.unwrap(),
        ProxiesSnapshot {
            groups: Vec::new(),
            proxies: Vec::new()
        }
    );
    assert!(
        fixture
            .requests()
            .iter()
            .all(|request| request.method == "GET")
    );
}

#[tokio::test]
async fn writes_send_their_methods_paths_and_bodies() {
    let fixture = FakeController::start(|_| Reply::no_content()).await;
    let client = fixture.client(None);
    client
        .patch_configs(ConfigPatch {
            mode: Some("direct".into()),
            ..ConfigPatch::default()
        })
        .await
        .expect("patch configs");
    client
        .reload_config("/Users/me/profile.json", true)
        .await
        .expect("forced reload");
    client
        .reload_config("/Users/me/profile.json", false)
        .await
        .expect("reload");
    client
        .select_proxy("Auto/HK", "HK 01")
        .await
        .expect("select proxy");
    client
        .close_all_connections()
        .await
        .expect("close all connections");
    client
        .close_connection("abc/1")
        .await
        .expect("close one connection");
    client
        .flush_fake_ip_cache()
        .await
        .expect("flush fake-ip cache");

    assert_eq!(
        request_lines(&fixture),
        [
            "PATCH /configs",
            "PUT /configs?force=true",
            "PUT /configs?force=false",
            "PUT /proxies/Auto%2FHK",
            "DELETE /connections",
            "DELETE /connections/abc%2F1",
            "POST /cache/fakeip/flush",
        ]
    );
    let requests = fixture.requests();
    assert_eq!(requests[0].json(), serde_json::json!({"mode": "direct"}));
    assert_eq!(
        requests[1].json(),
        serde_json::json!({"path": "/Users/me/profile.json"})
    );
    assert_eq!(requests[2].json(), requests[1].json());
    assert_eq!(requests[3].json(), serde_json::json!({"name": "HK 01"}));
    assert!(requests[4..].iter().all(|request| request.body.is_empty()));
}

#[tokio::test]
async fn rejected_writes_carry_the_controller_status_and_message() {
    let fixture =
        FakeController::start(|_| Reply::json(400, r#"{"message":"Body invalid"}"#)).await;
    let error = fixture
        .client(None)
        .select_proxy("Proxy", "missing")
        .await
        .expect_err("rejected selection");
    assert!(matches!(
        error,
        ControllerError::Status { status: 400, ref body } if body == r#"{"message":"Body invalid"}"#
    ));
}

#[tokio::test]
async fn provider_operations_are_refused_without_contacting_the_engine() {
    let fixture = FakeController::start(|request| {
        panic!(
            "provider stubs must not reach the engine: {}",
            request.target
        )
    })
    .await;
    let client = fixture.client(None);
    let refused = |error: ControllerError| {
        matches!(
            error,
            ControllerError::UnsupportedByPinnedEngine {
                capability: "provider management"
            }
        )
    };
    assert!(refused(client.providers().await.unwrap_err()));
    assert!(refused(client.proxy_providers().await.unwrap_err()));
    assert!(refused(client.rule_providers().await.unwrap_err()));
    assert!(refused(
        client.update_proxy_provider("p").await.unwrap_err()
    ));
    assert!(refused(client.update_rule_provider("r").await.unwrap_err()));
    assert!(refused(
        client.health_check_proxy_provider("p").await.unwrap_err()
    ));
    assert!(refused(
        client.update_all_proxy_providers().await.unwrap_err()
    ));
    assert!(refused(
        client.update_all_rule_providers().await.unwrap_err()
    ));
    assert!(refused(
        client.health_check_all_proxy_providers().await.unwrap_err()
    ));
    assert!(fixture.requests().is_empty());
}
