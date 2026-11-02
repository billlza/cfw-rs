//! Controller-backed read, query, and stream commands.
//!
//! Live commands talk to the clash-compatible controller of the
//! engine *this process started*. The host, port, and per-run secret are taken
//! from the managed engine's [`cfw_application::EngineControllerAccess`]; they
//! are never read from user settings, never read from a profile, and never
//! logged or returned.
//!
//! Runtime policy changes use that same authenticated controller. While the
//! engine is proven Off, selector choices instead go through the profile use
//! case and its maintenance lease; they do not start an engine or write any
//! OS integration. Explicit offline probes use a transient outbound-only libbox.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use cfw_controller::{
    ConnectionsSnapshot, ControllerClient, ControllerEndpoint, ControllerError, ControllerSnapshot,
    ControllerVersion, ProxyDelayResult, RulesSnapshot, StructuredLogEntry,
};
use cfw_engine_api::{EngineRuntimePlatform, EngineSnapshot, EngineState, RuntimeIdentity};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use thiserror::Error;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::engine::ManagedEngine;
use crate::transport_security::ensure_tls_crypto_provider;

mod probes;
mod stream_messages;
mod streams;
use probes::resolve_delay_test_url;
pub(super) use probes::{ProbePolicy, probe_saved_nodes};
use stream_messages::{
    controller_websocket_config, decode_connections_message, decode_log_message,
    emit_unique_stream_error, log_line_from_structured, transport_error,
};
pub(crate) use streams::{LiveStreams, StreamBinding};
use streams::{StreamEvent, StreamKind, start_stream, stop_stream};
#[cfg(test)]
mod tests;
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
pub(super) fn running_runtime_identity(
    platform: EngineRuntimePlatform,
    snapshot: &EngineSnapshot,
) -> Result<&RuntimeIdentity, ControllerCommandError> {
    crate::engine::ready_runtime(platform, snapshot).ok_or(ControllerCommandError::EngineNotRunning)
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
    ensure_tls_crypto_provider()
        .map_err(|error| ControllerCommandError::ClientUnavailable(error.to_string()))?;
    let client = ControllerClient::new(endpoint.clone())?;
    *cache = Some((endpoint, client.clone()));
    Ok(client)
}

/// The one way a command obtains a controller client.
pub(super) fn controller_client(
    engine: &ManagedEngine,
) -> Result<ControllerClient, ControllerCommandError> {
    let snapshot = engine.coordinator.snapshot();
    let runtime = running_runtime_identity(engine.coordinator.runtime_platform(), &snapshot)?;
    let controller = engine
        .active_controller_access(runtime.context.generation, &runtime.config_digest)
        .map_err(ControllerCommandError::ClientUnavailable)?;
    client_for_endpoint(controller.client_endpoint())
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
    profiles: State<'_, super::ManagedProfiles>,
    profile_id: Option<String>,
    group: String,
    proxy: String,
) -> Result<(), String> {
    select_proxy_with_persistence(&engine, &profiles, profile_id, group, proxy).await
}

pub(crate) async fn select_proxy_with_persistence(
    engine: &ManagedEngine,
    profiles: &super::ManagedProfiles,
    profile_id: Option<String>,
    group: String,
    proxy: String,
) -> Result<(), String> {
    let observed = engine.coordinator.snapshot();
    let (_, lease) = engine
        .begin_current_mode_change()
        .await
        .map_err(|error| error.to_string())?;
    if engine.coordinator.snapshot() != observed {
        return Err(
            "the runtime changed before node selection; refresh the proxy groups and retry".into(),
        );
    }
    let offline = observed.state == EngineState::Off
        && observed.desired_mode == cfw_engine_api::EngineMode::Off;
    if offline && profile_id.is_none() {
        return Err("saved proxy selection requires the displayed profile identity".into());
    }
    let client = if offline {
        None
    } else {
        Some(controller_client(engine).map_err(|error| error.to_ipc())?)
    };
    let repository = profiles.repository().clone();
    let coordinator = engine.coordinator.clone();
    let (result, lease) = lease.run_to_completion(async move {
        let mutation = repository.begin_credential_profile_mutation().map_err(|error| error.to_string())?;
        let stored = mutation.selected_profile().and_then(cfw_profiles::ProfileSelectionState::into_loaded).map_err(|error| error.to_string())?.ok_or("no active profile is selected")?;
        if profile_id.as_deref().is_some_and(|id| id != stored.record.id) {
            return Err("the displayed profile is no longer selected".into());
        }
        let selected = stored.profile.with_selected_outbound(&group, &proxy).map_err(|error| error.to_string())?;
        if let Some(client) = client {
            let spec = coordinator.restart_spec().await.map_err(|error| error.to_string())?.ok_or("the runtime has no accepted profile source")?;
            if !spec.matches_ready_snapshot(&coordinator.snapshot()) || spec.profile_id() != stored.record.id || spec.profile().digest() != stored.profile.digest() {
                return Err("the selected profile does not match the running core".into());
            }
            client.select_proxy(&group, &proxy).await.map_err(ipc_error)?;
            let observed = client.proxies().await.map_err(|error| format!("node selection was sent but could not be confirmed: {}", ipc_error(error)))?;
            if !observed.groups.iter().any(|value| value.name == group && value.now.as_deref() == Some(proxy.as_str())) {
                return Err("the controller did not confirm the requested node; the saved selection was unchanged".into());
            }
        }
        mutation.commit_replace_if_unchanged(&stored, None, &selected, stored.source_url.as_deref())
            .map(|_| ())
            .map_err(|error| if offline { error.to_string() } else { format!("node selection is active, but could not be saved: {error}") })
    }).await.map_err(|_| "node selection task ended without a response".to_owned())?;
    drop(lease);
    result
}

#[tauri::command]
pub(crate) async fn test_proxy_delays(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, super::ManagedProfiles>,
    profile_id: Option<String>,
    proxies: Vec<String>,
    url: Option<String>,
    timeout_ms: Option<u16>,
    concurrency: Option<usize>,
) -> Result<Vec<ProxyDelayResult>, String> {
    let target_url = resolve_delay_test_url(url).map_err(|error| error.to_ipc())?;
    probe_saved_nodes(
        &engine,
        &profiles,
        profile_id,
        proxies,
        ProbePolicy {
            url: target_url,
            timeout_ms: timeout_ms.unwrap_or(DEFAULT_DELAY_TIMEOUT_MS),
            concurrency: concurrency.unwrap_or(DEFAULT_DELAY_CONCURRENCY),
            expected_status: String::new(),
        },
    )
    .await
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

#[tauri::command]
pub(crate) fn start_connections_stream(
    app: AppHandle,
    streams: State<'_, LiveStreams>,
) -> Result<StreamBinding, String> {
    start_stream(app, &streams, StreamKind::Connections)
}

#[tauri::command]
pub(crate) fn start_log_stream(
    app: AppHandle,
    streams: State<'_, LiveStreams>,
) -> Result<StreamBinding, String> {
    start_stream(app, &streams, StreamKind::Logs)
}

#[tauri::command]
pub(crate) fn stop_connections_stream(
    expected: StreamBinding,
    streams: State<'_, LiveStreams>,
) -> Result<(), String> {
    stop_stream(streams.slot(StreamKind::Connections), &expected)
}

#[tauri::command]
pub(crate) fn stop_log_stream(
    expected: StreamBinding,
    streams: State<'_, LiveStreams>,
) -> Result<(), String> {
    stop_stream(streams.slot(StreamKind::Logs), &expected)
}
