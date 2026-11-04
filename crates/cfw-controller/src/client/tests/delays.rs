//! Delay probes: query encoding, per-probe timeouts and bounded concurrency.

use std::time::Duration;

use super::*;
use crate::test_support::Reply;

#[tokio::test]
async fn proxy_delay_encodes_the_probe_and_returns_the_measured_delay() {
    let fixture = FakeController::start(|_| Reply::json(200, r#"{"delay":87}"#)).await;
    let client = fixture.client(None);
    assert_eq!(
        client.proxy_delay("HK 01", PROBE_URL, 1500).await.unwrap(),
        87
    );
    assert_eq!(
        client
            .proxy_delay_matching("JP/2", "http://example.com/?a=1&b=2", 800, "204,200-299")
            .await
            .unwrap(),
        87
    );
    assert_eq!(
        request_lines(&fixture),
        [
            "GET /proxies/HK%2001/delay?url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=1500&expected=",
            "GET /proxies/JP%2F2/delay?url=http%3A%2F%2Fexample.com%2F%3Fa%3D1%26b%3D2&timeout=800&expected=204%2C200-299",
        ]
    );
}

#[tokio::test]
async fn a_slow_delay_probe_outlives_the_client_wide_timeout() {
    let fixture = FakeController::start(|request| {
        let body = if request.target.starts_with("/proxies/") {
            r#"{"delay":2100}"#
        } else {
            r#"{"version":"sing-box 1.14.4"}"#
        };
        Reply::json(200, body).after(Duration::from_millis(2_300))
    })
    .await;
    let client = fixture.client(None);
    let (delay, version) = tokio::join!(
        client.proxy_delay("Slow", PROBE_URL, 1_000),
        client.version()
    );
    assert_eq!(
        delay.expect("the probe budget extends the request timeout"),
        2100
    );
    assert!(matches!(version, Err(ControllerError::Http(ref error)) if error.is_timeout()));
}

#[tokio::test]
async fn proxy_delays_report_every_node_with_its_failure_kind() {
    let fixture = FakeController::start(|request| {
        let node = request
            .target
            .strip_prefix("/proxies/")
            .and_then(|rest| rest.split_once('/'))
            .map(|(node, _)| node);
        match node {
            Some("HK") => Reply::json(200, r#"{"delay":42}"#),
            Some("Gone") => Reply::json(404, r#"{"message":"resource not found"}"#),
            Some("Dead") => Reply::json(503, r#"{"message":"probe failed"}"#),
            _ => panic!("unexpected delay request {}", request.target),
        }
    })
    .await;
    let mut results = fixture
        .client(None)
        .proxy_delays(
            vec!["HK".into(), "Gone".into(), "Dead".into()],
            PROBE_URL.into(),
            500,
            2,
        )
        .await;
    results.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        results,
        [
            ProxyDelayResult {
                name: "Dead".into(),
                delay: None,
                error_kind: Some(ProxyDelayFailureKind::ProbeFailed),
                error: Some(
                    r#"controller rejected request with HTTP 503: {"message":"probe failed"}"#
                        .into()
                ),
            },
            ProxyDelayResult {
                name: "Gone".into(),
                delay: None,
                error_kind: Some(ProxyDelayFailureKind::NotFound),
                error: Some(
                    r#"controller rejected request with HTTP 404: {"message":"resource not found"}"#
                        .into()
                ),
            },
            ProxyDelayResult {
                name: "HK".into(),
                delay: Some(42),
                error_kind: None,
                error: None,
            },
        ]
    );
}

#[tokio::test]
async fn proxy_delays_probe_one_node_at_a_time_when_asked_for_none() {
    let fixture = FakeController::start(|_| {
        Reply::json(200, r#"{"delay":1}"#).after(Duration::from_millis(20))
    })
    .await;
    let nodes = vec!["a".into(), "b".into(), "c".into()];
    let results = tokio::time::timeout(
        Duration::from_secs(5),
        fixture
            .client(None)
            .proxy_delays(nodes, PROBE_URL.into(), 100, 0),
    )
    .await
    .expect("a zero concurrency still probes every node");
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|result| result.delay == Some(1)));
    assert_eq!(fixture.max_in_flight(), 1);
}

#[tokio::test]
async fn proxy_delays_cap_concurrent_probes_at_32() {
    let fixture =
        FakeController::start(|_| Reply::json(200, r#"{"delay":1}"#).held_until_in_flight(32))
            .await;
    let nodes = (0..40).map(|index| format!("node-{index}")).collect();
    let results = fixture
        .client(None)
        .proxy_delays(nodes, PROBE_URL.into(), 100, 1_000)
        .await;
    assert_eq!(results.len(), 40);
    assert!(results.iter().all(|result| result.delay == Some(1)));
    assert_eq!(fixture.max_in_flight(), 32);
}
