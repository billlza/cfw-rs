use super::*;
use crate::ControllerClient;

#[test]
fn structured_logs_decode_request_fields() {
    let raw = r#"
        {
          "time": "2026-05-13T01:02:03Z",
          "level": "info",
          "message": "request accepted",
          "fields": [{"key": "rAddr", "value": "api.openai.com:443"}]
        }
        "#;
    let log = ControllerClient::decode_log_stream_message(raw).unwrap();
    assert_eq!(log.level, "info");
    assert_eq!(log.fields[0].key, "rAddr");
}

#[test]
fn structured_logs_default_their_level_and_keep_unknown_fields() {
    let log: StructuredLogEntry =
        serde_json::from_str(r#"{"msg":"dial ok","module":"outbound/direct"}"#).unwrap();
    assert_eq!(
        log,
        StructuredLogEntry {
            time: None,
            level: "info".into(),
            message: "dial ok".into(),
            fields: Vec::new(),
            extra: HashMap::from([("module".into(), serde_json::json!("outbound/direct"))]),
        }
    );
}
