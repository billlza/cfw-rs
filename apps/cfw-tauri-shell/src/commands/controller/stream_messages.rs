//! Decoding controller stream messages into dashboard payloads, and which
//! stream errors are reported.

use super::*;

/// `cfw://stream-error` payload.
#[derive(Debug, Clone, Serialize)]
pub(super) struct StreamError {
    pub(super) stream: String,
    pub(super) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) level: Option<String>,
}

/// `cfw://log-lines` payload element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct LogLinePayload {
    pub(super) time: String,
    pub(super) level: String,
    pub(super) source: String,
    pub(super) message: String,
    pub(super) fields: Vec<LogFieldPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct LogFieldPayload {
    pub(super) key: String,
    pub(super) value: String,
}

pub(super) fn controller_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(STREAM_READ_BUFFER_BYTES)
        .write_buffer_size(STREAM_WRITE_BUFFER_BYTES)
        .max_write_buffer_size(STREAM_MAX_WRITE_BUFFER_BYTES)
        .max_message_size(Some(STREAM_MAX_MESSAGE_BYTES))
        .max_frame_size(Some(STREAM_MAX_FRAME_BYTES))
}

/// Websocket transport failures can quote the handshake URL, which carries the
/// controller token, so they are redacted before they can be emitted.
pub(super) fn transport_error(error: tokio_tungstenite::tungstenite::Error) -> String {
    redact_controller_secret(&error.to_string())
}

pub(super) fn decode_connections_message(
    message: &Message,
) -> Result<Option<ConnectionsSnapshot>, String> {
    if message.is_close() || message.is_ping() || message.is_pong() {
        return Ok(None);
    }
    let text = message.to_text().map_err(transport_error)?;
    ControllerClient::decode_connections_stream_message(text)
        .map(Some)
        .map_err(ipc_error)
}

pub(super) fn decode_log_message(message: &Message) -> Result<Option<StructuredLogEntry>, String> {
    if message.is_close() || message.is_ping() || message.is_pong() {
        return Ok(None);
    }
    let text = message.to_text().map_err(transport_error)?;
    ControllerClient::decode_log_stream_message(text)
        .map(Some)
        .map_err(ipc_error)
}

/// Normalises a controller log entry into the `cfw://log-lines` payload.
///
/// The clash-compatible controller of this engine emits `{"type": <level>,
/// "payload": <message>}`, which [`StructuredLogEntry`] keeps in `extra`; a
/// mihomo-style structured entry populates `level`/`msg`/`fields` directly.
/// Both shapes normalise into one payload here.
pub(super) fn log_line_from_structured(entry: StructuredLogEntry) -> LogLinePayload {
    let clash_level = entry
        .extra
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let clash_message = entry
        .extra
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let message = if entry.message.trim().is_empty() {
        clash_message.unwrap_or_default()
    } else {
        entry.message
    };

    LogLinePayload {
        time: entry
            .time
            .as_deref()
            .map(display_time)
            .unwrap_or_else(|| "live".into()),
        level: normalize_log_level(&clash_level.unwrap_or(entry.level)),
        source: "request".into(),
        message,
        fields: entry
            .fields
            .into_iter()
            .map(|field| LogFieldPayload {
                key: field.key,
                value: display_json_value(field.value),
            })
            .collect(),
    }
}

pub(super) fn normalize_log_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "warn" | "wrn" | "warning" => "warning".into(),
        "err" | "error" | "fatal" | "ftl" => "error".into(),
        "dbg" | "debug" => "debug".into(),
        "trc" | "trace" => "debug".into(),
        _ => "info".into(),
    }
}

pub(super) fn display_time(value: &str) -> String {
    value
        .split('T')
        .nth(1)
        .and_then(|time| time.get(0..8))
        .unwrap_or(value)
        .to_string()
}

pub(super) fn display_json_value(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Expected quiet conditions of a loopback controller subscription: the engine
/// is off, or its listener went away while a mode change or interface flap is in
/// flight. The supervisor reconnects instead of reporting these to Diagnostics.
pub(super) fn is_transient_controller_disconnect(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "no engine is running",
        "connection reset",
        "connection refused",
        "broken pipe",
        "network is unreachable",
        "host is down",
        "temporarily unavailable",
        "timed out",
        "timeout",
        "error sending request",
        "error reading",
        "os error 54", // ECONNRESET on macOS
        "os error 61", // ECONNREFUSED
        "os error 57", // ENOTCONN
        "os error 32", // EPIPE
        "websocket protocol error",
        "failed to lookup address",
        "dns error",
        "stream closed",
        "connection closed",
    ];
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

/// Decides whether a stream failure reaches Diagnostics, recording it as the
/// supervisor's last failure either way. Quiet reconnect conditions and repeats
/// of the failure already reported are suppressed.
pub(super) fn stream_error_to_report(
    last_error: &mut Option<String>,
    message: String,
) -> Option<String> {
    if is_transient_controller_disconnect(&message) {
        *last_error = Some(message);
        return None;
    }
    if last_error.as_deref() == Some(message.as_str()) {
        return None;
    }
    *last_error = Some(message.clone());
    Some(message)
}

pub(super) fn emit_unique_stream_error(
    app: &AppHandle,
    binding: &StreamBinding,
    last_error: &mut Option<String>,
    message: String,
) {
    if let Some(message) = stream_error_to_report(last_error, message) {
        let _ = app.emit(
            STREAM_ERROR_EVENT,
            StreamEvent {
                provenance: binding.clone(),
                payload: stream_error_payload(&binding.stream, message),
            },
        );
    }
}

pub(super) fn stream_error_payload(stream: &str, message: String) -> StreamError {
    StreamError {
        stream: stream.to_string(),
        message: redact_controller_secret(&message),
        level: Some("warning".into()),
    }
}
