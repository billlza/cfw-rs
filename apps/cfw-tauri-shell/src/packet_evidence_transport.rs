use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::future::Future;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cfw_engine_api::{EngineMode, EngineOwner};
use cfw_singbox_config::ReleasePacketEvidenceCase;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use security_framework::os::macos::code_signing::{
    Flags as CodeSigningFlags, GuestAttributes, SecCode, SecRequirement,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tauri::{AppHandle, Manager};
use thiserror::Error;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::sync::Mutex;

use crate::engine::ManagedEngine;
use crate::engine::packet_evidence::{
    PacketEvidenceAbortReason, PacketEvidenceBaselineReady, PacketEvidenceCaptureAborted,
    PacketEvidenceCaptureFailure, PacketEvidenceCaptureFinalizing, PacketEvidenceCaptureTerminal,
    PacketEvidenceSnapshotReceipt, PacketEvidenceStages, PacketEvidenceTestReady,
    PacketEvidenceTransactionError, PacketEvidenceTransactionOutcome,
};
use crate::platform_maintenance::PlatformMaintenanceGate;

mod app;
mod channel;
mod control_socket;
mod launcher_ticket;
mod proxy;
mod session;
use app::{capture_failure_code, host_failed, serve_control_endpoint};
use channel::{
    AsyncPacketEvidenceChannel, PacketEvidenceChannel, canonical_body, decode_canonical,
    validate_connected_unix_stream,
};
use control_socket::{
    ControlSocketGuard, bind_control_endpoint, control_socket_path, packet_evidence_app_home,
    process_bsd_info, process_start_time_unix_us, register_control_endpoint, validate_app_request,
    validate_launcher_binding, validate_launcher_binding_shape, validate_same_executable_peer,
    validate_signed_peer, validate_ticket_issued, validate_ticket_request,
};
use launcher_ticket::LauncherTicketStore;
use proxy::{proxy_authenticated_transaction, proxy_failure_code};
use session::{
    SessionReplayGuard, canonical_session_id, encode_identity, now_unix_ms, parse_case,
    random_launcher_ticket_id, stage_result, validate_collector_hello, validate_collector_request,
    validate_session_window,
};
#[cfg(test)]
mod tests;
const CONTROL_FD: RawFd = 3;
const CONTROL_SOCKET_NAME: &str = ".packet-evidence-control-v5.sock";
const LAUNCHER_TICKET_DIRECTORY: &str = ".packet-evidence-launcher-tickets-v5";
const PROTOCOL_VERSION: u32 = 5;
const TICKET_SEQUENCE: u32 = 0;
const REQUEST_SEQUENCE: u32 = 1;
const BASELINE_SEQUENCE: u32 = 2;
const CAPTURE_STARTED_SEQUENCE: u32 = 3;
const TEST_SEQUENCE: u32 = 4;
const TEST_SUBMITTED_SEQUENCE: u32 = 5;
const RESTORED_SEQUENCE: u32 = 6;
const CAPTURE_COMPLETED_SEQUENCE: u32 = 7;
const RESULT_SEQUENCE: u32 = 8;
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_SESSIONS: usize = 64;
const MAX_TICKET_DOCUMENTS: usize = 64;
const MAX_TICKET_DIRECTORY_ENTRIES: usize = MAX_TICKET_DOCUMENTS + 1;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSACTION_IO_TIMEOUT: Duration = Duration::from_secs(180);
// Admission remains valid longer than the complete 180-second staged I/O
// budget; expiry is checked once at admission and never extended mid-session.
const SESSION_LIFETIME_MS: u64 = 300_000;
const SESSION_CLOCK_SKEW_MS: u64 = 5_000;
const HOST_CODE_REQUIREMENT: &str = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"YKUPL7Z869\" and (identifier \"com.bill.clashformac\")";

#[derive(Debug, Error)]
pub(crate) enum PacketEvidenceTransportError {
    #[error("physical Packet control descriptor is invalid")]
    InvalidDescriptor,
    #[error("physical Packet control peer identity is invalid")]
    InvalidPeer,
    #[error("physical Packet control peer is not the exact installed Host executable")]
    InvalidPeerExecutable,
    #[error("physical Packet control peer does not satisfy the release Host code requirement")]
    InvalidPeerCodeIdentity,
    #[error("physical Packet control requires the canonical signed installed Host")]
    InvalidCandidate,
    #[error("physical Packet control endpoint is unavailable")]
    EndpointUnavailable,
    #[error("physical Packet control endpoint metadata is unsafe")]
    EndpointUnsafe,
    #[error("physical Packet control endpoint is already active")]
    EndpointActive,
    #[error("physical Packet control endpoint cleanup is unresolved")]
    EndpointCleanupFailed,
    #[error("physical Packet control frame is unavailable or truncated")]
    TruncatedFrame,
    #[error("physical Packet control frame is outside its byte bound")]
    FrameBound,
    #[error("physical Packet control frame carried ancillary descriptors")]
    AncillaryData,
    #[error("physical Packet ancillary descriptors could not be closed")]
    AncillaryCleanup,
    #[error("physical Packet control frame is not exact canonical JSON")]
    InvalidFrame,
    #[error("physical Packet control write failed")]
    WriteFailed,
    #[error("physical Packet control session is invalid or expired")]
    InvalidSession,
    #[error("physical Packet control session was already admitted")]
    ReplayedSession,
    #[error("physical Packet control session capacity is exhausted")]
    SessionCapacity,
    #[error("physical Packet launcher ticket store is unsafe")]
    LauncherTicketUnsafe,
    #[error("physical Packet launcher ticket was already consumed")]
    LauncherTicketReplayed,
    #[error("physical Packet launcher ticket capacity is exhausted")]
    LauncherTicketCapacity,
    #[error("physical Packet launcher ticket durable commit is uncertain")]
    LauncherTicketCommitUncertain,
    #[error("physical Packet control case is not source-owned")]
    InvalidCase,
    #[error("physical Packet control response is inconsistent")]
    InvalidResponse,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerIdentity {
    audit_token: [u8; 32],
    pid: u32,
    start_time_unix_us: u64,
    uid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostHello {
    collector_pid: u32,
    collector_uid: u32,
    document: String,
    host_pid: u32,
    host_uid: u32,
    schema_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorHello {
    collector_pid: u32,
    collector_uid: u32,
    document: String,
    expires_at_unix_ms: u64,
    issued_at_unix_ms: u64,
    schema_version: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorRequest {
    case_id: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherBinding {
    case_id: String,
    collector_audit_token: String,
    collector_pid: u32,
    collector_start_time_unix_us: u64,
    collector_uid: u32,
    expires_at_unix_ms: u64,
    issued_at_unix_ms: u64,
    proxy_pid: u32,
    proxy_start_time_unix_us: u64,
    proxy_uid: u32,
    session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppTicketRequest {
    binding: LauncherBinding,
    document: String,
    schema_version: u32,
    sequence: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostTicketIssued {
    binding: LauncherBinding,
    document: String,
    schema_version: u32,
    sequence: u32,
    ticket_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum HostTicketResponse {
    Issued(HostTicketIssued),
    Failed(HostFailed),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppRequest {
    binding: LauncherBinding,
    document: String,
    schema_version: u32,
    sequence: u32,
    ticket_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedLauncherTicket {
    binding: LauncherBinding,
    document: String,
    schema_version: u32,
    ticket_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    config_digest: Option<String>,
    desired_mode: EngineMode,
    generation: u64,
    ipv6_enabled: bool,
    owner: Option<EngineOwner>,
    phase: String,
    ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostBaselineObserved {
    baseline: WireSnapshot,
    baseline_observation_sequence: u64,
    case_id: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostTestObserved {
    case_id: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
    test: WireSnapshot,
    test_observation_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostBaselineRestored {
    baseline: WireSnapshot,
    baseline_observation_sequence: u64,
    case_id: String,
    document: String,
    restore: WireSnapshot,
    restore_observation_sequence: u64,
    schema_version: u32,
    sequence: u32,
    session_id: String,
    test: Option<WireSnapshot>,
    test_observation_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCaptureAborted {
    baseline: WireSnapshot,
    baseline_observation_sequence: u64,
    case_id: String,
    code: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorStageComplete {
    case_id: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorStageFailed {
    case_id: String,
    code: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CollectorStageResponse {
    Complete(CollectorStageComplete),
    Failed(CollectorStageFailed),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCompleted {
    baseline: WireSnapshot,
    baseline_observation_sequence: u64,
    candidate_observation_sequence: u64,
    case_id: String,
    document: String,
    restore: WireSnapshot,
    restore_observation_sequence: u64,
    schema_version: u32,
    sequence: u32,
    session_id: String,
    test: WireSnapshot,
    test_observation_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFailed {
    case_id: String,
    code: String,
    document: String,
    schema_version: u32,
    sequence: u32,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum HostBaselineResponse {
    Observed(HostBaselineObserved),
    Failed(HostFailed),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum HostTestResponse {
    Observed(HostTestObserved),
    Restored(HostBaselineRestored),
    Aborted(HostCaptureAborted),
    Failed(HostFailed),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum HostRestoreResponse {
    Restored(HostBaselineRestored),
    Aborted(HostCaptureAborted),
    Failed(HostFailed),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum HostFinalResponse {
    Completed(HostCompleted),
    Failed(HostFailed),
}

/// Starts the only transaction executor, inside the already-running product
/// Host after its ordinary setup and legacy launch preflight have completed.
/// The fixed sibling mode never constructs another coordinator: a fresh
/// coordinator intentionally tears down recovered native state and has no
/// process-memory `EngineRestartSpec`, so it cannot safely own this evidence.
pub(crate) fn run_packet_evidence_transaction(
    app: AppHandle,
) -> Result<(), PacketEvidenceTransportError> {
    let ticket_store = LauncherTicketStore::open(&packet_evidence_app_home()?)?;
    let (listener, guard) = bind_control_endpoint()?;
    let listener = register_control_endpoint(listener)?;
    std::mem::drop(tauri::async_runtime::spawn(serve_control_endpoint(
        app,
        listener,
        guard,
        ticket_store,
    )));
    Ok(())
}

/// Authenticates the inherited collector channel, then proxies its closed
/// protocol to the already-running signed Host. It owns no engine, profile,
/// path, argv, DNS address or native authority.
pub(crate) fn run_packet_evidence_proxy() -> Result<(), PacketEvidenceTransportError> {
    crate::legacy::require_canonical_handoff_candidate()
        .map_err(|_| PacketEvidenceTransportError::InvalidCandidate)?;
    let mut collector = PacketEvidenceChannel::from_inherited_fd()?;
    collector.send(&HostHello {
        collector_pid: collector.peer.pid,
        collector_uid: collector.peer.uid,
        document: "cfw-packet-host-hello-v5".to_owned(),
        host_pid: std::process::id(),
        host_uid: unsafe { libc::geteuid() },
        schema_version: PROTOCOL_VERSION,
    })?;
    let hello: CollectorHello = collector.receive()?;
    validate_collector_hello(&hello, collector.peer, now_unix_ms()?)?;
    let request: CollectorRequest = collector.receive()?;
    let (case_id, _case) = validate_collector_request(&request, &hello)?;
    match proxy_authenticated_transaction(&mut collector, &hello, case_id) {
        Ok(()) => Ok(()),
        Err(error) => {
            let failure = host_failed(&hello.session_id, case_id, proxy_failure_code(&error));
            collector.send(&failure)?;
            Err(error)
        }
    }
}
