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
    StructuredLogEntry, require_provider_management,
};
use cfw_engine_api::{EngineSnapshot, EngineState};
use futures_util::StreamExt;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use thiserror::Error;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::engine::ManagedEngine;

/// HTTPS-only probe target owned by a stable connectivity-check service. The
/// renderer has no arbitrary URL preference, and the command rejects any other
/// target so a compromised webview cannot turn the engine probe into SSRF.
const DEFAULT_DELAY_TEST_URL: &str = "https://www.gstatic.com/generate_204";
const DEFAULT_DELAY_TIMEOUT_MS: u16 = 5_000;
const DEFAULT_DELAY_CONCURRENCY: usize = 8;
const MAX_DELAY_CONCURRENCY: usize = 32;
const MAX_DELAY_PROXIES: usize = 4_096;
const MAX_CONTROLLER_NAME_BYTES: usize = 512;

/// Level the controller log stream subscribes with. The controller filters
/// server-side, and no preference selects a level in this release.
const LOG_STREAM_LEVEL: &str = "info";
/// Reconnect pause of the stream supervisors, matching 0.3.5.
const STREAM_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const STREAM_READ_BUFFER_BYTES: usize = 64 * 1024;
const STREAM_WRITE_BUFFER_BYTES: usize = 16 * 1024;
const STREAM_MAX_WRITE_BUFFER_BYTES: usize = 64 * 1024;
const STREAM_MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const STREAM_MAX_FRAME_BYTES: usize = 1024 * 1024;

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
    #[error(
        "delay test target is not allowed; this build permits only https://www.gstatic.com/generate_204"
    )]
    DelayTargetNotAllowed,
    #[error("controller command input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error(transparent)]
    Controller(#[from] ControllerError),
}

impl ControllerCommandError {
    /// Renders the failure for IPC. Redaction is applied here so no path can
    /// return a message that still carries the controller secret.
    pub(super) fn to_ipc(&self) -> String {
        redact_controller_secret(&self.to_string())
    }
}

pub(super) fn ipc_error(error: impl Into<ControllerCommandError>) -> String {
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
pub(super) fn controller_client(
    engine: &ManagedEngine,
) -> Result<ControllerClient, ControllerCommandError> {
    require_running_controller(&engine.coordinator.snapshot())?;
    client_for_endpoint(engine.controller_access().client_endpoint())
}

/// Controller client of the engine this process started, resolved from an app
/// handle. Shared with the tray, which reads proxy groups and applies a
/// selection the controller itself reported.
pub(crate) fn client_from_app(app: &AppHandle) -> Result<ControllerClient, String> {
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
    require_provider_management().map_err(ipc_error)?;
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
    if proxies.is_empty()
        || proxies.len() > MAX_DELAY_PROXIES
        || proxies
            .iter()
            .any(|name| name.is_empty() || name.len() > MAX_CONTROLLER_NAME_BYTES)
    {
        return Err(ControllerCommandError::InvalidInput(
            "proxy delay target set is outside its bounds",
        )
        .to_ipc());
    }
    let client = controller_client(&engine).map_err(|error| error.to_ipc())?;
    let target_url = resolve_delay_test_url(url).map_err(|error| error.to_ipc())?;
    let timeout = timeout_ms.unwrap_or(DEFAULT_DELAY_TIMEOUT_MS);
    let limit = concurrency
        .unwrap_or(DEFAULT_DELAY_CONCURRENCY)
        .clamp(1, MAX_DELAY_CONCURRENCY);
    Ok(client
        .proxy_delays(proxies, target_url, timeout, limit)
        .await)
}

fn resolve_delay_test_url(url: Option<String>) -> Result<String, ControllerCommandError> {
    match url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None | Some(DEFAULT_DELAY_TEST_URL) => Ok(DEFAULT_DELAY_TEST_URL.to_owned()),
        Some(_) => Err(ControllerCommandError::DelayTargetNotAllowed),
    }
}

#[tauri::command]
pub(crate) async fn health_check_proxy_provider(
    engine: State<'_, ManagedEngine>,
    name: String,
) -> Result<(), String> {
    require_provider_management().map_err(ipc_error)?;
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
    require_provider_management().map_err(ipc_error)?;
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
    require_provider_management().map_err(ipc_error)?;
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
    require_provider_management().map_err(ipc_error)?;
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
    require_provider_management().map_err(ipc_error)?;
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
    require_provider_management().map_err(ipc_error)?;
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

/// Cancellable ownership for the two controller event streams. A reservation
/// closes the race between task creation and task completion, so stop/restart
/// cannot leave a stale "started" flag behind.
#[derive(Default)]
pub(crate) struct LiveStreams {
    connections: Mutex<StreamSlot>,
    logs: Mutex<StreamSlot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Connections,
    Logs,
}

#[derive(Default)]
struct StreamSlot {
    next_id: u64,
    task: Option<StreamTask>,
}

enum StreamTask {
    Starting {
        id: u64,
    },
    Running {
        id: u64,
        handle: tauri::async_runtime::JoinHandle<()>,
    },
}

impl LiveStreams {
    fn slot(&self, kind: StreamKind) -> &Mutex<StreamSlot> {
        match kind {
            StreamKind::Connections => &self.connections,
            StreamKind::Logs => &self.logs,
        }
    }

    pub(crate) fn stop_all(&self) {
        stop_stream_silently(&self.connections);
        stop_stream_silently(&self.logs);
    }
}

impl Drop for LiveStreams {
    fn drop(&mut self) {
        self.stop_all();
    }
}

fn lock_stream_slot(
    slot: &Mutex<StreamSlot>,
) -> Result<std::sync::MutexGuard<'_, StreamSlot>, String> {
    slot.lock()
        .map_err(|error| ControllerCommandError::ClientUnavailable(error.to_string()).to_ipc())
}

/// Reserves a stream for a task that has not yet been attached. `None` means a
/// live or starting supervisor already owns the stream.
fn reserve_stream(slot: &Mutex<StreamSlot>) -> Result<Option<u64>, String> {
    let mut slot = lock_stream_slot(slot)?;
    if slot.task.is_some() {
        return Ok(None);
    }
    slot.next_id = slot.next_id.wrapping_add(1).max(1);
    let id = slot.next_id;
    slot.task = Some(StreamTask::Starting { id });
    Ok(Some(id))
}

fn attach_stream(
    slot: &Mutex<StreamSlot>,
    id: u64,
    handle: tauri::async_runtime::JoinHandle<()>,
) -> Result<(), String> {
    let mut slot = match lock_stream_slot(slot) {
        Ok(slot) => slot,
        Err(error) => {
            handle.abort();
            return Err(error);
        }
    };
    if matches!(slot.task, Some(StreamTask::Starting { id: current }) if current == id) {
        slot.task = Some(StreamTask::Running { id, handle });
    } else {
        // Stop or task completion won the race while spawn was being attached.
        handle.abort();
    }
    Ok(())
}

fn release_stream(slot: &Mutex<StreamSlot>, id: u64) {
    let mut slot = match slot.lock() {
        Ok(slot) => slot,
        Err(error) => {
            eprintln!("controller stream ownership release failed: {error}");
            return;
        }
    };
    let owned = match slot.task.as_ref() {
        Some(StreamTask::Starting { id: current }) => *current == id,
        Some(StreamTask::Running { id: current, .. }) => *current == id,
        None => false,
    };
    if owned {
        slot.task = None;
    }
}

fn stop_stream(slot: &Mutex<StreamSlot>) -> Result<(), String> {
    let task = lock_stream_slot(slot)?.task.take();
    if let Some(StreamTask::Running { handle, .. }) = task {
        handle.abort();
    }
    Ok(())
}

fn stop_stream_silently(slot: &Mutex<StreamSlot>) {
    let mut slot = match slot.lock() {
        Ok(slot) => slot,
        Err(error) => {
            eprintln!("controller stream shutdown failed: {error}");
            return;
        }
    };
    if let Some(StreamTask::Running { handle, .. }) = slot.task.take() {
        handle.abort();
    }
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
    start_stream(app, &streams, StreamKind::Connections)
}

#[tauri::command]
pub(crate) fn start_log_stream(
    app: AppHandle,
    streams: State<'_, LiveStreams>,
) -> Result<(), String> {
    start_stream(app, &streams, StreamKind::Logs)
}

#[tauri::command]
pub(crate) fn stop_connections_stream(streams: State<'_, LiveStreams>) -> Result<(), String> {
    stop_stream(streams.slot(StreamKind::Connections))
}

#[tauri::command]
pub(crate) fn stop_log_stream(streams: State<'_, LiveStreams>) -> Result<(), String> {
    stop_stream(streams.slot(StreamKind::Logs))
}

fn start_stream(app: AppHandle, streams: &LiveStreams, kind: StreamKind) -> Result<(), String> {
    require_running_controller(&app.state::<ManagedEngine>().coordinator.snapshot())
        .map_err(|error| error.to_ipc())?;
    let Some(id) = reserve_stream(streams.slot(kind))? else {
        return Ok(());
    };
    let task_app = app.clone();
    let handle = tauri::async_runtime::spawn(async move {
        supervise_stream(&task_app, kind).await;
        release_stream(task_app.state::<LiveStreams>().slot(kind), id);
    });
    attach_stream(streams.slot(kind), id, handle)
}

async fn supervise_stream(app: &AppHandle, kind: StreamKind) {
    let mut last_error: Option<String> = None;
    loop {
        if !running_controller_available(app) {
            return;
        }
        let result = match kind {
            StreamKind::Connections => run_connections_stream(app).await,
            StreamKind::Logs => run_log_stream(app).await,
        };
        if !running_controller_available(app) {
            return;
        }
        match result {
            // A clean close while the engine remains active is reconnectable.
            Ok(()) => last_error = None,
            Err(error) => emit_unique_stream_error(
                app,
                match kind {
                    StreamKind::Connections => CONNECTIONS_STREAM,
                    StreamKind::Logs => REQUEST_LOG_STREAM,
                },
                &mut last_error,
                error,
            ),
        }
        tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
    }
}

fn running_controller_available(app: &AppHandle) -> bool {
    require_running_controller(&app.state::<ManagedEngine>().coordinator.snapshot()).is_ok()
}

async fn run_connections_stream(app: &AppHandle) -> Result<(), String> {
    let client = client_from_app(app)?;
    let url = client.connections_stream_url().map_err(ipc_error)?;
    let (socket, _response) =
        connect_async_with_config(url, Some(controller_websocket_config()), false)
            .await
            .map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    let mut engine_check = tokio::time::interval(Duration::from_millis(250));
    engine_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            message = read.next() => {
                let Some(message) = message else {
                    return Ok(());
                };
                let message = message.map_err(transport_error)?;
                if let Some(snapshot) = decode_connections_message(&message)? {
                    app.emit(CONNECTIONS_SNAPSHOT_EVENT, snapshot)
                        .map_err(|error| format!("failed to publish connections snapshot: {error}"))?;
                }
            }
            _ = engine_check.tick() => {
                if !running_controller_available(app) {
                    return Ok(());
                }
            }
        }
    }
}

async fn run_log_stream(app: &AppHandle) -> Result<(), String> {
    let client = client_from_app(app)?;
    let url = client
        .logs_stream_url(LOG_STREAM_LEVEL)
        .map_err(ipc_error)?;
    let (socket, _response) =
        connect_async_with_config(url, Some(controller_websocket_config()), false)
            .await
            .map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    let mut engine_check = tokio::time::interval(Duration::from_millis(250));
    engine_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            message = read.next() => {
                let Some(message) = message else {
                    return Ok(());
                };
                let message = message.map_err(transport_error)?;
                if let Some(entry) = decode_log_message(&message)? {
                    app.emit(LOG_LINES_EVENT, vec![log_line_from_structured(entry)])
                        .map_err(|error| format!("failed to publish log line: {error}"))?;
                }
            }
            _ = engine_check.tick() => {
                if !running_controller_available(app) {
                    return Ok(());
                }
            }
        }
    }
}

fn controller_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(STREAM_READ_BUFFER_BYTES)
        .write_buffer_size(STREAM_WRITE_BUFFER_BYTES)
        .max_write_buffer_size(STREAM_MAX_WRITE_BUFFER_BYTES)
        .max_message_size(Some(STREAM_MAX_MESSAGE_BYTES))
        .max_frame_size(Some(STREAM_MAX_FRAME_BYTES))
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
    fn controller_websocket_buffers_and_messages_are_bounded() {
        let config = controller_websocket_config();
        assert_eq!(config.read_buffer_size, STREAM_READ_BUFFER_BYTES);
        assert_eq!(config.write_buffer_size, STREAM_WRITE_BUFFER_BYTES);
        assert_eq!(config.max_write_buffer_size, STREAM_MAX_WRITE_BUFFER_BYTES);
        assert_eq!(config.max_message_size, Some(STREAM_MAX_MESSAGE_BYTES));
        assert_eq!(config.max_frame_size, Some(STREAM_MAX_FRAME_BYTES));
        assert!(!config.accept_unmasked_frames);
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
    fn each_stream_can_be_stopped_and_started_again() {
        let streams = LiveStreams::default();
        let connections = streams.slot(StreamKind::Connections);
        let logs = streams.slot(StreamKind::Logs);

        assert!(reserve_stream(connections).expect("first claim").is_some());
        assert!(
            reserve_stream(connections)
                .expect("duplicate claim")
                .is_none()
        );
        assert!(reserve_stream(logs).expect("independent claim").is_some());

        stop_stream(connections).expect("stop connections reservation");
        assert!(
            reserve_stream(connections)
                .expect("restart after stop")
                .is_some()
        );
    }

    #[test]
    fn stale_stream_completion_cannot_release_a_new_owner() {
        let streams = LiveStreams::default();
        let slot = streams.slot(StreamKind::Connections);
        let stale_id = reserve_stream(slot).expect("stale reservation").unwrap();
        stop_stream(slot).expect("cancel stale reservation");
        let current_id = reserve_stream(slot).expect("current reservation").unwrap();
        assert_ne!(stale_id, current_id);

        release_stream(slot, stale_id);
        assert!(
            reserve_stream(slot)
                .expect("current ownership check")
                .is_none(),
            "a stale completion must not clear the current reservation"
        );
    }

    #[test]
    fn delay_test_target_is_https_and_fixed() {
        assert_eq!(
            resolve_delay_test_url(None).expect("default target"),
            DEFAULT_DELAY_TEST_URL
        );
        assert_eq!(
            resolve_delay_test_url(Some(DEFAULT_DELAY_TEST_URL.into()))
                .expect("explicit pinned target"),
            DEFAULT_DELAY_TEST_URL
        );
        for rejected in [
            "http://www.gstatic.com/generate_204",
            "https://127.0.0.1/private",
            "https://example.com/",
        ] {
            assert!(matches!(
                resolve_delay_test_url(Some(rejected.into())),
                Err(ControllerCommandError::DelayTargetNotAllowed)
            ));
        }
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
