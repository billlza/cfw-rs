//! Controller-backed read, query, and stream commands.
//!
//! Every command in this module talks to the clash-compatible controller of the
//! engine *this process started*. The host, port, and per-run secret are taken
//! from the managed engine's [`cfw_application::EngineControllerAccess`]; they
//! are never read from user settings, never read from a profile, and never
//! logged or returned.
//!
//! Nothing here can start, stop, or reconfigure an engine, so no Global
//! Authority decision is bypassed: these are read/query operations against the
//! loopback controller of an already-running engine. When no engine is running
//! there is nothing to talk to and the commands fail closed with the same
//! unreachable-controller error shape 0.3.5 surfaced, so the restored UI keeps
//! classifying it exactly as it always did.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use cfw_controller::{
    ConnectionsSnapshot, ControllerClient, ControllerEndpoint, ControllerError, ControllerSnapshot,
    ControllerVersion, ProviderBatchResult, ProvidersSnapshot, ProxyDelayResult, RulesSnapshot,
    StructuredLogEntry,
};
use cfw_engine_api::{EngineSnapshot, EngineState};
use futures_util::StreamExt;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use thiserror::Error;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::engine::ManagedEngine;

/// Delay probe target used when the caller passes none. 0.3.5 kept this in its
/// settings file; the 0.4.0 preference model carries no controller-facing
/// fields, so the renderer either passes a URL or gets this default.
const DEFAULT_DELAY_TEST_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_DELAY_TIMEOUT_MS: u16 = 5_000;
const DEFAULT_DELAY_CONCURRENCY: usize = 8;
const MAX_DELAY_CONCURRENCY: usize = 32;

/// Level the controller log stream subscribes with. The controller filters
/// server-side, and no preference selects a level in this release.
const LOG_STREAM_LEVEL: &str = "info";
/// Reconnect pause of the stream supervisors, matching 0.3.5.
const STREAM_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Event names the restored UI subscribes to. They are part of the product
/// contract and must not change.
const CONNECTIONS_SNAPSHOT_EVENT: &str = "cfw://connections-snapshot";
const LOG_LINES_EVENT: &str = "cfw://log-lines";
const STREAM_ERROR_EVENT: &str = "cfw://stream-error";

/// Stream identifiers carried in `cfw://stream-error` payloads, unchanged from
/// 0.3.5.
const CONNECTIONS_STREAM: &str = "connections";
const REQUEST_LOG_STREAM: &str = "request-logs";

/// Failure surface of the controller-backed commands.
///
/// Commands hand the renderer `Result<_, String>` exactly as 0.3.5 did, so this
/// type is the internal typed failure and [`ControllerCommandError::to_ipc`] is
/// the single place that renders it for IPC.
#[derive(Debug, Error)]
pub(crate) enum ControllerCommandError {
    /// No engine is running, so the app-owned loopback controller does not
    /// exist. This deliberately renders with the `controller HTTP request
    /// failed:` prefix 0.3.5 produced for an unreachable controller.
    #[error(
        "controller HTTP request failed: no engine is running, so its loopback controller is unreachable"
    )]
    EngineNotRunning,
    /// No client can be produced because process-wide support state — the client
    /// cache, a stream ownership flag, or the TLS crypto provider — is
    /// unavailable. The detail never carries endpoint data.
    #[error("controller client is unavailable: {0}")]
    ClientUnavailable(String),
    #[error(transparent)]
    Controller(#[from] ControllerError),
}

impl ControllerCommandError {
    /// Renders the failure for IPC. Redaction is applied here so no path can
    /// return a message that still carries the controller secret.
    fn to_ipc(&self) -> String {
        redact_controller_secret(&self.to_string())
    }
}

fn ipc_error(error: impl Into<ControllerCommandError>) -> String {
    error.into().to_ipc()
}

/// Removes the controller token from any message before it reaches the UI, an
/// event payload, or stderr.
///
/// The clash-compatible websocket handshake authenticates with a
/// `token=<secret>` query parameter, and transport errors can quote the URL they
/// failed on, so every message leaving this module passes through here.
fn redact_controller_secret(message: &str) -> String {
    const NEEDLE: &str = "token=";
    const REPLACEMENT: &str = "token=[REDACTED]";
    const TERMINATORS: [char; 8] = ['&', '#', '"', '\'', ' ', ')', ',', '\n'];

    let mut redacted = String::with_capacity(message.len());
    let mut remainder = message;
    while let Some(index) = remainder.find(NEEDLE) {
        redacted.push_str(&remainder[..index]);
        redacted.push_str(REPLACEMENT);
        let value = &remainder[index + NEEDLE.len()..];
        let end = value.find(TERMINATORS).unwrap_or(value.len());
        remainder = &value[end..];
    }
    redacted.push_str(remainder);
    redacted
}

/// Process-wide controller HTTP client cache keyed by endpoint. The endpoint is
/// stable for the lifetime of the process, so this keeps every invoke and every
/// stream reconnect on one connection pool instead of rebuilding it.
fn controller_client_cache() -> &'static Mutex<Option<(ControllerEndpoint, ControllerClient)>> {
    static CACHE: OnceLock<Mutex<Option<(ControllerEndpoint, ControllerClient)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Only an engine this process observes as active and ready has a controller to
/// talk to. Every other state fails closed: there is no start path, no probe of
/// an unknown listener, and no fallback here.
fn require_running_controller(snapshot: &EngineSnapshot) -> Result<(), ControllerCommandError> {
    match &snapshot.state {
        EngineState::ProxyActive { runtime } | EngineState::TunnelActive { runtime }
            if runtime.ready =>
        {
            Ok(())
        }
        _ => Err(ControllerCommandError::EngineNotRunning),
    }
}

/// reqwest is built with `rustls-no-provider`, so constructing any client — this
/// plain-HTTP loopback one included — requires a process-global crypto provider.
/// Installation is idempotent and process-global, so this and the updater's own
/// bootstrap cooperate rather than compete.
fn ensure_tls_crypto_provider() -> Result<(), ControllerCommandError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A concurrent initializer may win this one-time process-global race;
        // re-read below instead of treating that benign race as a failure.
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(ControllerCommandError::ClientUnavailable(
            "the process TLS crypto provider is unavailable".into(),
        ));
    }
    Ok(())
}

fn client_for_endpoint(
    endpoint: ControllerEndpoint,
) -> Result<ControllerClient, ControllerCommandError> {
    let mut cache = controller_client_cache()
        .lock()
        .map_err(|error| ControllerCommandError::ClientUnavailable(error.to_string()))?;
    if let Some((cached_endpoint, client)) = cache.as_ref()
        && cached_endpoint == &endpoint
    {
        return Ok(client.clone());
    }
    ensure_tls_crypto_provider()?;
    let client = ControllerClient::new(endpoint.clone())?;
    *cache = Some((endpoint, client.clone()));
    Ok(client)
}

/// The one way a command obtains a controller client.
fn controller_client(engine: &ManagedEngine) -> Result<ControllerClient, ControllerCommandError> {
    require_running_controller(&engine.coordinator.snapshot())?;
    client_for_endpoint(engine.controller_access().client_endpoint())
}

fn client_from_app(app: &AppHandle) -> Result<ControllerClient, String> {
    controller_client(&app.state::<ManagedEngine>()).map_err(|error| error.to_ipc())
}

#[tauri::command]
pub(crate) async fn controller_snapshot(
    engine: State<'_, ManagedEngine>,
) -> Result<ControllerSnapshot, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .snapshot()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn controller_version(
    engine: State<'_, ManagedEngine>,
) -> Result<ControllerVersion, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .version()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn providers_snapshot(
    engine: State<'_, ManagedEngine>,
) -> Result<ProvidersSnapshot, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .providers()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn rules_snapshot(
    engine: State<'_, ManagedEngine>,
) -> Result<RulesSnapshot, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .rules()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn select_proxy(
    engine: State<'_, ManagedEngine>,
    group: String,
    proxy: String,
) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .select_proxy(&group, &proxy)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn test_proxy_delays(
    engine: State<'_, ManagedEngine>,
    proxies: Vec<String>,
    url: Option<String>,
    timeout_ms: Option<u16>,
    concurrency: Option<usize>,
) -> Result<Vec<ProxyDelayResult>, String> {
    let client = controller_client(&engine).map_err(|error| error.to_ipc())?;
    let target_url = url
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_DELAY_TEST_URL.to_owned());
    let timeout = timeout_ms.unwrap_or(DEFAULT_DELAY_TIMEOUT_MS);
    let limit = concurrency
        .unwrap_or(DEFAULT_DELAY_CONCURRENCY)
        .clamp(1, MAX_DELAY_CONCURRENCY);
    Ok(client
        .proxy_delays(proxies, target_url, timeout, limit)
        .await)
}

#[tauri::command]
pub(crate) async fn health_check_proxy_provider(
    engine: State<'_, ManagedEngine>,
    name: String,
) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .health_check_proxy_provider(&name)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn health_check_all_proxy_providers(
    engine: State<'_, ManagedEngine>,
) -> Result<ProviderBatchResult, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .health_check_all_proxy_providers()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn update_proxy_provider(
    engine: State<'_, ManagedEngine>,
    name: String,
) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .update_proxy_provider(&name)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn update_all_proxy_providers(
    engine: State<'_, ManagedEngine>,
) -> Result<ProviderBatchResult, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .update_all_proxy_providers()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn update_rule_provider(
    engine: State<'_, ManagedEngine>,
    name: String,
) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .update_rule_provider(&name)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn update_all_rule_providers(
    engine: State<'_, ManagedEngine>,
) -> Result<ProviderBatchResult, String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .update_all_rule_providers()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn close_connection(
    engine: State<'_, ManagedEngine>,
    id: String,
) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .close_connection(&id)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn close_all_connections(engine: State<'_, ManagedEngine>) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .close_all_connections()
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn dns_query(
    engine: State<'_, ManagedEngine>,
    name: String,
    record_type: Option<String>,
) -> Result<serde_json::Value, String> {
    let host = name.trim();
    if host.is_empty() {
        return Err("DNS query name is required".into());
    }
    let kind = record_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("A")
        .to_owned();
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .dns_query(host, &kind)
        .await
        .map_err(ipc_error)
}

#[tauri::command]
pub(crate) async fn flush_fake_ip_cache(engine: State<'_, ManagedEngine>) -> Result<(), String> {
    controller_client(&engine)
        .map_err(|error| error.to_ipc())?
        .flush_fake_ip_cache()
        .await
        .map_err(ipc_error)
}

/// One-shot ownership flags for the two controller event streams, so repeated
/// renderer calls cannot spawn duplicate supervisors.
#[derive(Default)]
pub(crate) struct LiveStreams {
    connections_started: Mutex<bool>,
    logs_started: Mutex<bool>,
}

/// Claims a stream for the caller, returning `false` when a supervisor already
/// owns it.
fn claim_stream(flag: &Mutex<bool>) -> Result<bool, String> {
    let mut started = flag
        .lock()
        .map_err(|error| ControllerCommandError::ClientUnavailable(error.to_string()).to_ipc())?;
    if *started {
        return Ok(false);
    }
    *started = true;
    Ok(true)
}

/// `cfw://stream-error` payload.
#[derive(Debug, Clone, Serialize)]
struct StreamError {
    stream: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
}

/// `cfw://log-lines` payload element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LogLinePayload {
    time: String,
    level: String,
    source: String,
    message: String,
    fields: Vec<LogFieldPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LogFieldPayload {
    key: String,
    value: String,
}

#[tauri::command]
pub(crate) fn start_connections_stream(
    app: AppHandle,
    streams: State<'_, LiveStreams>,
) -> Result<(), String> {
    if !claim_stream(&streams.connections_started)? {
        return Ok(());
    }

    tauri::async_runtime::spawn(async move {
        let mut last_error: Option<String> = None;
        loop {
            match run_connections_stream(&app).await {
                // Clean close: the controller ended the subscription, so
                // reconnect quietly.
                Ok(()) => last_error = None,
                Err(error) => {
                    emit_unique_stream_error(&app, CONNECTIONS_STREAM, &mut last_error, error);
                }
            }
            tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
        }
    });

    Ok(())
}

#[tauri::command]
pub(crate) fn start_log_stream(
    app: AppHandle,
    streams: State<'_, LiveStreams>,
) -> Result<(), String> {
    if !claim_stream(&streams.logs_started)? {
        return Ok(());
    }

    tauri::async_runtime::spawn(async move {
        let mut last_error: Option<String> = None;
        loop {
            match run_log_stream(&app).await {
                Ok(()) => last_error = None,
                Err(error) => {
                    emit_unique_stream_error(&app, REQUEST_LOG_STREAM, &mut last_error, error);
                }
            }
            tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
        }
    });

    Ok(())
}

async fn run_connections_stream(app: &AppHandle) -> Result<(), String> {
    let client = client_from_app(app)?;
    let url = client.connections_stream_url().map_err(ipc_error)?;
    let (socket, _response) = connect_async(url).await.map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    while let Some(message) = read.next().await {
        let message = message.map_err(transport_error)?;
        if let Some(snapshot) = decode_connections_message(&message)? {
            let _ = app.emit(CONNECTIONS_SNAPSHOT_EVENT, snapshot);
        }
    }
    Ok(())
}

async fn run_log_stream(app: &AppHandle) -> Result<(), String> {
    let client = client_from_app(app)?;
    let url = client
        .logs_stream_url(LOG_STREAM_LEVEL)
        .map_err(ipc_error)?;
    let (socket, _response) = connect_async(url).await.map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    while let Some(message) = read.next().await {
        let message = message.map_err(transport_error)?;
        if let Some(entry) = decode_log_message(&message)? {
            let _ = app.emit(LOG_LINES_EVENT, vec![log_line_from_structured(entry)]);
        }
    }
    Ok(())
}

/// Websocket transport failures can quote the handshake URL, which carries the
/// controller token, so they are redacted before they can be emitted.
fn transport_error(error: tokio_tungstenite::tungstenite::Error) -> String {
    redact_controller_secret(&error.to_string())
}

fn decode_connections_message(message: &Message) -> Result<Option<ConnectionsSnapshot>, String> {
    if message.is_close() || message.is_ping() || message.is_pong() {
        return Ok(None);
    }
    let text = message.to_text().map_err(transport_error)?;
    ControllerClient::decode_connections_stream_message(text)
        .map(Some)
        .map_err(ipc_error)
}

fn decode_log_message(message: &Message) -> Result<Option<StructuredLogEntry>, String> {
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
fn log_line_from_structured(entry: StructuredLogEntry) -> LogLinePayload {
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

fn normalize_log_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "warn" | "wrn" | "warning" => "warning".into(),
        "err" | "error" | "fatal" | "ftl" => "error".into(),
        "dbg" | "debug" => "debug".into(),
        "trc" | "trace" => "debug".into(),
        _ => "info".into(),
    }
}

fn display_time(value: &str) -> String {
    value
        .split('T')
        .nth(1)
        .and_then(|time| time.get(0..8))
        .unwrap_or(value)
        .to_string()
}

fn display_json_value(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Expected quiet conditions of a loopback controller subscription: the engine
/// is off, or its listener went away while a mode change or interface flap is in
/// flight. The supervisor reconnects instead of reporting these to Diagnostics.
fn is_transient_controller_disconnect(message: &str) -> bool {
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
fn stream_error_to_report(last_error: &mut Option<String>, message: String) -> Option<String> {
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

fn emit_unique_stream_error(
    app: &AppHandle,
    stream: &str,
    last_error: &mut Option<String>,
    message: String,
) {
    if let Some(message) = stream_error_to_report(last_error, message) {
        let _ = app.emit(STREAM_ERROR_EVENT, stream_error_payload(stream, message));
    }
}

fn stream_error_payload(stream: &str, message: String) -> StreamError {
    StreamError {
        stream: stream.to_string(),
        message: redact_controller_secret(&message),
        level: Some("warning".into()),
    }
}

#[cfg(test)]
mod tests {
    use cfw_application::EngineControllerAccess;
    use cfw_engine_api::{
        EngineCommandContext, EngineMode, EngineOwner, EngineSettings, RuntimeIdentity,
    };

    use super::*;

    fn runtime(ready: bool) -> RuntimeIdentity {
        RuntimeIdentity {
            owner: EngineOwner::ProxyAgent,
            context: EngineCommandContext {
                installation_id: "installation".into(),
                config_epoch: 1,
                generation: 7,
            },
            config_digest: "digest".into(),
            ready,
        }
    }

    fn snapshot(state: EngineState) -> EngineSnapshot {
        EngineSnapshot {
            desired_mode: EngineMode::Off,
            state,
            generation: 7,
            config_digest: None,
        }
    }

    /// The endpoint of the engine this process would start, including the
    /// per-run secret. Only tests read it back, and only to prove it never
    /// escapes.
    fn process_endpoint() -> (ControllerEndpoint, String) {
        let access = EngineControllerAccess::resolve(EngineSettings::default())
            .expect("default engine settings resolve a controller");
        let endpoint = access.client_endpoint();
        let secret = endpoint
            .secret
            .clone()
            .expect("the app-owned controller is authenticated");
        assert!(!secret.is_empty());
        (endpoint, secret)
    }

    #[test]
    fn controller_access_requires_a_running_ready_engine() {
        for state in [
            EngineState::Off,
            EngineState::ProxyStarting { generation: 1 },
            EngineState::ProxyStopping { generation: 1 },
            EngineState::TunnelInstalling { generation: 1 },
            EngineState::AwaitingApproval { generation: 1 },
            EngineState::TunnelStarting { generation: 1 },
            EngineState::TunnelStopping { generation: 1 },
            EngineState::Failed {
                generation: 1,
                target: EngineMode::Tunnel,
                error: "native failure".into(),
            },
            EngineState::ProxyActive {
                runtime: runtime(false),
            },
            EngineState::TunnelActive {
                runtime: runtime(false),
            },
        ] {
            let error = require_running_controller(&snapshot(state.clone()))
                .expect_err("a controller must not be reachable without a ready engine");
            assert!(
                matches!(error, ControllerCommandError::EngineNotRunning),
                "unexpected error for {state:?}: {error:?}"
            );
        }

        for state in [
            EngineState::ProxyActive {
                runtime: runtime(true),
            },
            EngineState::TunnelActive {
                runtime: runtime(true),
            },
        ] {
            require_running_controller(&snapshot(state))
                .expect("a ready engine exposes its loopback controller");
        }
    }

    #[test]
    fn engine_not_running_keeps_the_unreachable_controller_error_shape() {
        let rendered = ControllerCommandError::EngineNotRunning.to_ipc();
        assert!(
            rendered.starts_with("controller HTTP request failed: "),
            "unexpected shape: {rendered}"
        );
        assert!(is_transient_controller_disconnect(&rendered));
    }

    #[test]
    fn command_errors_never_carry_the_controller_secret() {
        let (endpoint, secret) = process_endpoint();
        let client = client_for_endpoint(endpoint).expect("loopback client");
        let websocket_url = client
            .logs_stream_url(LOG_STREAM_LEVEL)
            .expect("loopback log stream url");
        assert!(
            websocket_url.contains(&secret),
            "the handshake url is expected to authenticate with the token"
        );

        // Every message shape that could quote the handshake url.
        let quoted = format!("unable to connect to {websocket_url}");
        for rendered in [
            redact_controller_secret(&quoted),
            ipc_error(ControllerError::InvalidEndpoint(quoted.clone())),
            ControllerCommandError::ClientUnavailable(quoted.clone()).to_ipc(),
            transport_error(tokio_tungstenite::tungstenite::Error::Url(
                tokio_tungstenite::tungstenite::error::UrlError::UnableToConnect(quoted.clone()),
            )),
            stream_error_payload(CONNECTIONS_STREAM, quoted.clone()).message,
            serde_json::to_string(&stream_error_payload(CONNECTIONS_STREAM, quoted.clone()))
                .expect("serialize stream error payload"),
        ] {
            assert!(!rendered.contains(&secret), "leaked secret: {rendered}");
            assert!(
                rendered.contains("token=[REDACTED]"),
                "not redacted: {rendered}"
            );
            assert!(rendered.contains("level=info"), "lost context: {rendered}");
        }
    }

    #[test]
    fn debug_output_never_carries_the_controller_secret() {
        let (endpoint, secret) = process_endpoint();
        let access = EngineControllerAccess::resolve(EngineSettings::default())
            .expect("default engine settings resolve a controller");
        let client = client_for_endpoint(endpoint.clone()).expect("loopback client");
        for rendered in [
            format!("{endpoint:?}"),
            format!("{access:?}"),
            format!("{client:?}"),
            format!("{:?}", ControllerCommandError::EngineNotRunning),
            format!(
                "{:?}",
                ControllerCommandError::Controller(ControllerError::InvalidEndpoint(
                    "host is empty".into()
                ))
            ),
        ] {
            assert!(!rendered.contains(&secret), "leaked secret: {rendered}");
        }
    }

    #[test]
    fn redaction_preserves_messages_without_a_token() {
        assert_eq!(
            redact_controller_secret("controller rejected request with HTTP 404: not found"),
            "controller rejected request with HTTP 404: not found"
        );
        assert_eq!(
            redact_controller_secret("ws://127.0.0.1:9090/connections?token=abc"),
            "ws://127.0.0.1:9090/connections?token=[REDACTED]"
        );
        assert_eq!(
            redact_controller_secret("first token=a&x=1 second token=b"),
            "first token=[REDACTED]&x=1 second token=[REDACTED]"
        );
    }

    #[test]
    fn log_lines_normalize_both_controller_log_shapes() {
        let clash = ControllerClient::decode_log_stream_message(
            r#"{"type":"warn","payload":"inbound/mixed: started"}"#,
        )
        .expect("clash-compatible log entry");
        assert_eq!(
            log_line_from_structured(clash),
            LogLinePayload {
                time: "live".into(),
                level: "warning".into(),
                source: "request".into(),
                message: "inbound/mixed: started".into(),
                fields: Vec::new(),
            }
        );

        let structured = ControllerClient::decode_log_stream_message(
            r#"{"time":"2026-05-13T04:05:06Z","level":"ERR","msg":"dns failed","fields":[{"key":"host","value":"example.com"},{"key":"attempt","value":2}]}"#,
        )
        .expect("structured log entry");
        assert_eq!(
            log_line_from_structured(structured),
            LogLinePayload {
                time: "04:05:06".into(),
                level: "error".into(),
                source: "request".into(),
                message: "dns failed".into(),
                fields: vec![
                    LogFieldPayload {
                        key: "host".into(),
                        value: "example.com".into(),
                    },
                    LogFieldPayload {
                        key: "attempt".into(),
                        value: "2".into(),
                    },
                ],
            }
        );
    }

    #[test]
    fn each_stream_is_claimed_once() {
        let streams = LiveStreams::default();
        assert!(claim_stream(&streams.connections_started).expect("first claim"));
        assert!(!claim_stream(&streams.connections_started).expect("second claim"));
        assert!(claim_stream(&streams.logs_started).expect("independent claim"));
    }

    #[test]
    fn stream_errors_report_only_unexpected_failures_once() {
        let mut last_error = None;
        let reported = [
            ControllerCommandError::EngineNotRunning.to_ipc(),
            "controller rejected request with HTTP 401: unauthorized".to_owned(),
            "controller rejected request with HTTP 401: unauthorized".to_owned(),
            "Connection refused (os error 61)".to_owned(),
        ]
        .into_iter()
        .filter_map(|message| stream_error_to_report(&mut last_error, message))
        .collect::<Vec<_>>();
        assert_eq!(
            reported,
            vec!["controller rejected request with HTTP 401: unauthorized".to_owned()]
        );
    }
}
