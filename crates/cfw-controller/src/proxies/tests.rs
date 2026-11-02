use std::time::Duration;

use tokio::net::TcpListener;

use super::*;
use crate::test_support::{FakeController, Reply};

#[test]
fn proxies_response_splits_groups_and_nodes() {
    let raw = r#"
        {
          "proxies": {
            "Proxy": {"type":"Selector","all":["HK","DIRECT"],"now":"HK","history":[]},
            "HK": {"type":"Shadowsocks","udp":true,"history":[{"time":"now","delay":23}]}
          }
        }
        "#;
    let response: ProxiesResponse = serde_json::from_str(raw).unwrap();
    let snapshot = ProxiesSnapshot::from(response);
    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].options, vec!["HK", "DIRECT"]);
    assert_eq!(snapshot.proxies.len(), 1);
    assert_eq!(snapshot.proxies[0].history[0].delay, 23);
}

#[test]
fn hidden_entries_are_omitted_and_both_lists_are_sorted() {
    let raw = r#"
        {
          "proxies": {
            "Zeta": {"type":"Selector","all":["b"],"now":"b"},
            "Alpha": {"type":"URLTest","all":["a"]},
            "GLOBAL": {"type":"Selector","all":["Zeta"],"hidden":true},
            "b": {"type":"Shadowsocks","udp":false},
            "a": {}
          }
        }
        "#;
    let snapshot = ProxiesSnapshot::from(serde_json::from_str::<ProxiesResponse>(raw).unwrap());
    let groups: Vec<_> = snapshot
        .groups
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    let nodes: Vec<_> = snapshot
        .proxies
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(groups, ["Alpha", "Zeta"]);
    assert_eq!(nodes, ["a", "b"]);
    assert_eq!(snapshot.groups[0].now, None);
    assert_eq!(snapshot.groups[1].now.as_deref(), Some("b"));
    assert_eq!(snapshot.proxies[0].kind, "Unknown");
    assert_eq!(snapshot.proxies[0].udp, None);
    assert!(snapshot.proxies[0].history.is_empty());
    assert_eq!(snapshot.proxies[1].udp, Some(false));
}

#[test]
fn groups_and_nodes_come_out_in_name_order() {
    // The controller answers with a JSON object, so the response map carries
    // no order; sixteen names make an accidentally sorted result implausible.
    let entries = (0..16)
        .rev()
        .flat_map(|index| {
            [
                format!(r#""group-{index:02}":{{"type":"Selector","all":["node-{index:02}"]}}"#),
                format!(r#""node-{index:02}":{{"type":"Direct"}}"#),
            ]
        })
        .collect::<Vec<_>>()
        .join(",");
    let response: ProxiesResponse =
        serde_json::from_str(&format!(r#"{{"proxies":{{{entries}}}}}"#)).unwrap();
    let snapshot = ProxiesSnapshot::from(response);

    let expected = |prefix: &str| {
        (0..16)
            .map(|index| format!("{prefix}-{index:02}"))
            .collect::<Vec<_>>()
    };
    let groups: Vec<_> = snapshot
        .groups
        .iter()
        .map(|group| group.name.clone())
        .collect();
    let nodes: Vec<_> = snapshot
        .proxies
        .iter()
        .map(|node| node.name.clone())
        .collect();
    assert_eq!(groups, expected("group"));
    assert_eq!(nodes, expected("node"));
}

#[test]
fn delay_failures_keep_their_distinct_contract() {
    let cases = [
        (
            ControllerError::Status {
                status: 504,
                body: "timeout".into(),
            },
            ProxyDelayFailureKind::Timeout,
        ),
        (
            ControllerError::Status {
                status: 404,
                body: "not found".into(),
            },
            ProxyDelayFailureKind::NotFound,
        ),
        (
            ControllerError::Status {
                status: 503,
                body: "probe failed".into(),
            },
            ProxyDelayFailureKind::ProbeFailed,
        ),
        (
            ControllerError::Status {
                status: 401,
                body: "unauthorized".into(),
            },
            ProxyDelayFailureKind::Rejected,
        ),
        (
            ControllerError::InvalidEndpoint("bad target".into()),
            ProxyDelayFailureKind::InvalidRequest,
        ),
        (
            ControllerError::UnsupportedByPinnedEngine {
                capability: "provider management",
            },
            ProxyDelayFailureKind::Unsupported,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(ProxyDelayFailureKind::from(&error), expected);
    }
}

#[tokio::test]
async fn transport_and_response_failures_keep_their_delay_kinds() {
    let _already_installed = rustls::crypto::ring::default_provider().install_default();
    let fixture = FakeController::start(|request| match request.target.as_str() {
        "/slow" => Reply::json(200, "{}").after(Duration::from_secs(5)),
        "/truncated" => Reply::json(200, "{").declaring(64),
        other => panic!("unexpected fixture request {other}"),
    })
    .await;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(100))
        .build()
        .expect("probe client");
    // A peer that accepts and closes before answering fails the same way on
    // every platform. A released port does not: Windows loopback retries the
    // refused connection past this client's timeout.
    let hangs_up = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a peer that hangs up");
    let hang_up_address = hangs_up.local_addr().expect("hang-up peer address");
    let hang_up = tokio::spawn(async move {
        let (stream, _) = hangs_up
            .accept()
            .await
            .expect("accept the request connection");
        drop(stream);
    });
    let truncated_body = || async {
        http.get(fixture.url("/truncated"))
            .send()
            .await
            .expect("truncated response head")
            .bytes()
            .await
            .expect_err("truncated response body")
    };

    let timeout = http
        .get(fixture.url("/slow"))
        .send()
        .await
        .expect_err("the slow reply outlives the request timeout");
    assert!(timeout.is_timeout());
    let closed = http
        .get(format!("http://{hang_up_address}/"))
        .send()
        .await
        .expect_err("the peer closes before it answers");
    assert!(closed.is_request() && !closed.is_timeout(), "{closed:?}");
    hang_up.await.expect("hang-up peer completes");
    // reqwest 0.13 reports a failed response body as a decode error; its
    // body-kind errors only come from polling a request `Body` directly.
    let truncated = truncated_body().await;
    assert!(truncated.is_decode(), "{truncated:?}");

    let cases = [
        (
            ControllerError::Http(timeout),
            ProxyDelayFailureKind::Timeout,
        ),
        (
            ControllerError::Http(closed),
            ProxyDelayFailureKind::Transport,
        ),
        (
            ControllerError::Http(truncated),
            ProxyDelayFailureKind::InvalidResponse,
        ),
        (
            ControllerError::ResponseBodyRead {
                status: 200,
                source: truncated_body().await,
            },
            ProxyDelayFailureKind::InvalidResponse,
        ),
        (
            ControllerError::Json(serde_json::from_str::<u32>("x").expect_err("not a number")),
            ProxyDelayFailureKind::InvalidResponse,
        ),
        (
            ControllerError::ResponseTooLarge {
                status: 200,
                maximum: 1,
            },
            ProxyDelayFailureKind::InvalidResponse,
        ),
        (
            ControllerError::PayloadLimit {
                resource: "proxy set",
                maximum: 1,
            },
            ProxyDelayFailureKind::InvalidResponse,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(ProxyDelayFailureKind::from(&error), expected, "{error}");
    }
}
