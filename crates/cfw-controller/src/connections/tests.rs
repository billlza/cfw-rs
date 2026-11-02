use serde_json::json;

use super::*;
use crate::ControllerClient;

#[test]
fn connections_snapshot_accepts_clash_total_aliases() {
    let raw = r#"
        {
          "uploadTotal": 1024,
          "downloadTotal": 2048,
          "connections": [
            {
              "id": "1",
              "upload": 8,
              "download": 16,
              "start": "2026-05-13T01:02:03Z",
              "chains": ["Proxy"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {"host": "example.com", "processPath": "/Applications/Safari.app"}
            }
          ]
        }
        "#;
    let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
    assert_eq!(snapshot.upload, 1024);
    assert_eq!(snapshot.download, 2048);
    assert_eq!(
        snapshot.connections[0].metadata.process_path,
        "/Applications/Safari.app"
    );
}

#[test]
fn connections_snapshot_treats_null_connections_as_empty() {
    let raw = r#"{"uploadTotal":0,"downloadTotal":0,"connections":null,"memory":0}"#;
    let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
    assert_eq!(snapshot.upload, 0);
    assert!(snapshot.connections.is_empty());
}

#[test]
fn connections_snapshot_accepts_integer_ports_from_clash_rs() {
    let raw = r#"
        {
          "uploadTotal": 1,
          "downloadTotal": 2,
          "connections": [
            {
              "id": "1",
              "upload": 8,
              "download": 16,
              "start": "2026-07-21T12:03:07.517274Z",
              "chains": ["Proxy"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {
                "network": "Tcp",
                "type": "HttpConnect",
                "sourceIP": "127.0.0.1",
                "destinationIP": "",
                "sourcePort": 52724,
                "destinationPort": 443,
                "host": "example.com"
              }
            },
            {
              "id": "2",
              "upload": 1,
              "download": 2,
              "start": "2026-07-21T12:03:08Z",
              "chains": ["DIRECT"],
              "rule": "MATCH",
              "rulePayload": "",
              "metadata": {
                "network": "Udp",
                "type": "Socks5",
                "sourceIP": "127.0.0.1",
                "destinationIP": "1.1.1.1",
                "sourcePort": "12345",
                "destinationPort": "53",
                "host": "dns"
              }
            }
          ]
        }
        "#;
    let snapshot = ControllerClient::decode_connections_stream_message(raw).unwrap();
    assert_eq!(snapshot.connections[0].metadata.source_port, "52724");
    assert_eq!(snapshot.connections[0].metadata.destination_port, "443");
    assert_eq!(snapshot.connections[1].metadata.source_port, "12345");
    assert_eq!(snapshot.connections[1].metadata.destination_port, "53");
}

#[test]
fn ports_accept_every_json_scalar_an_engine_emits() {
    let port = |value: serde_json::Value| {
        serde_json::from_value::<ConnectionMetadata>(json!({ "destinationPort": value }))
            .expect("lenient port")
            .destination_port
    };
    assert_eq!(port(json!(443)), "443");
    assert_eq!(port(json!(-1)), "-1");
    assert_eq!(port(json!(8080.0)), "8080");
    assert_eq!(port(json!(80.5)), "80.5");
    assert_eq!(port(json!(-2.0)), "-2");
    assert_eq!(port(json!(1e20)), "100000000000000000000");
    assert_eq!(port(json!("53")), "53");
    assert_eq!(port(json!(null)), "");

    let borrowed: ConnectionMetadata =
        serde_json::from_str(r#"{"destinationPort":"5353"}"#).expect("borrowed string port");
    assert_eq!(borrowed.destination_port, "5353");
    let error = serde_json::from_value::<ConnectionMetadata>(json!({ "destinationPort": true }))
        .expect_err("a boolean is not a port");
    assert!(
        error.to_string().contains("expected a string or number"),
        "{error}"
    );
}
