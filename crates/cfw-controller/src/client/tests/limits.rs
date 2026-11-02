//! Cardinality bounds of decoded collections and stream messages.

use super::*;
use crate::response::validate_connections;
use crate::test_support::Reply;
use crate::{Connection, MAX_CONTROLLER_CONNECTIONS};

#[test]
fn stream_collection_cardinality_is_bounded() {
    let oversized_connections = ConnectionsSnapshot {
        connections: vec![Connection::default(); MAX_CONTROLLER_CONNECTIONS + 1],
        ..ConnectionsSnapshot::default()
    };
    assert!(matches!(
        validate_connections(&oversized_connections),
        Err(ControllerError::PayloadLimit {
            resource: "connection set",
            maximum: MAX_CONTROLLER_CONNECTIONS,
        })
    ));

    let fields = (0..=MAX_CONTROLLER_LOG_FIELDS)
        .map(|index| serde_json::json!({"key": index.to_string(), "value": index}))
        .collect::<Vec<_>>();
    let log = serde_json::json!({"level": "info", "message": "bounded", "fields": fields});
    assert!(matches!(
        ControllerClient::decode_log_stream_message(&log.to_string()),
        Err(ControllerError::PayloadLimit {
            resource: "structured log field set",
            maximum: MAX_CONTROLLER_LOG_FIELDS,
        })
    ));
}

#[test]
fn stream_messages_at_their_limits_are_accepted() {
    let connections = serde_json::json!({
        "connections": vec![serde_json::json!({"id": "c"}); MAX_CONTROLLER_CONNECTIONS]
    });
    assert_eq!(
        ControllerClient::decode_connections_stream_message(&connections.to_string())
            .expect("a full connection set")
            .connections
            .len(),
        MAX_CONTROLLER_CONNECTIONS
    );
    let fields = (0..MAX_CONTROLLER_LOG_FIELDS)
        .map(|index| serde_json::json!({"key": index.to_string(), "value": index}))
        .collect::<Vec<_>>();
    let log = serde_json::json!({"level": "debug", "message": "full", "fields": fields});
    assert_eq!(
        ControllerClient::decode_log_stream_message(&log.to_string())
            .expect("a full field set")
            .fields
            .len(),
        MAX_CONTROLLER_LOG_FIELDS
    );
    assert!(matches!(
        ControllerClient::decode_connections_stream_message("{"),
        Err(ControllerError::Json(_))
    ));
    assert!(matches!(
        ControllerClient::decode_log_stream_message("[]"),
        Err(ControllerError::Json(_))
    ));
}

/// A controller whose proxy, rule and connection sets each hold `limit + extra` entries.
async fn collection_fixture(extra: usize) -> FakeController {
    let proxies = (0..MAX_CONTROLLER_PROXIES + extra)
        .map(|index| format!(r#""node-{index}":{{"type":"Direct"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let rules =
        vec![r#"{"type":"Default","payload":"","proxy":"DIRECT"}"#; MAX_CONTROLLER_RULES + extra]
            .join(",");
    let connections = vec![r#"{"id":"c"}"#; MAX_CONTROLLER_CONNECTIONS + extra].join(",");
    let proxies = format!(r#"{{"proxies":{{{proxies}}}}}"#);
    let rules = format!(r#"{{"rules":[{rules}]}}"#);
    let connections = format!(r#"{{"connections":[{connections}]}}"#);
    FakeController::start(move |request| match request.target.as_str() {
        "/proxies" => Reply::json(200, proxies.clone()),
        "/rules" => Reply::json(200, rules.clone()),
        "/connections" => Reply::json(200, connections.clone()),
        other => panic!("unexpected collection request {other}"),
    })
    .await
}

#[tokio::test]
async fn collections_up_to_their_limits_are_accepted() {
    let fixture = collection_fixture(0).await;
    let client = fixture.client(None);
    assert_eq!(
        client
            .proxies()
            .await
            .expect("full proxy set")
            .proxies
            .len(),
        MAX_CONTROLLER_PROXIES
    );
    assert_eq!(
        client.rules().await.expect("full rule set").rules.len(),
        MAX_CONTROLLER_RULES
    );
    assert_eq!(
        client
            .connections()
            .await
            .expect("full connection set")
            .connections
            .len(),
        MAX_CONTROLLER_CONNECTIONS
    );
}

#[tokio::test]
async fn collections_beyond_their_limits_are_refused() {
    let fixture = collection_fixture(1).await;
    let client = fixture.client(None);
    assert!(matches!(
        client.proxies().await,
        Err(ControllerError::PayloadLimit {
            resource: "proxy set",
            maximum: MAX_CONTROLLER_PROXIES
        })
    ));
    assert!(matches!(
        client.rules().await,
        Err(ControllerError::PayloadLimit {
            resource: "rule set",
            maximum: MAX_CONTROLLER_RULES
        })
    ));
    assert!(matches!(
        client.connections().await,
        Err(ControllerError::PayloadLimit {
            resource: "connection set",
            maximum: MAX_CONTROLLER_CONNECTIONS
        })
    ));
}
