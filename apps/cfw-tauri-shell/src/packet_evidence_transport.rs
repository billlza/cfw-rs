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
use crate::legacy::LegacyRetirementGate;

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

struct PacketEvidenceChannel {
    stream: UnixStream,
    peer: PeerIdentity,
}

impl PacketEvidenceChannel {
    fn from_inherited_fd() -> Result<Self, PacketEvidenceTransportError> {
        Self::from_fd(CONTROL_FD)
    }

    fn from_fd(fd: RawFd) -> Result<Self, PacketEvidenceTransportError> {
        let peer = validate_connected_unix_stream(fd)?;
        // SAFETY: validation above proves `fd` is one owned connected Unix
        // stream. This constructor is the sole owner after launch admission.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        Self::from_validated_stream(stream, peer)
    }

    fn connect(path: &Path) -> Result<Self, PacketEvidenceTransportError> {
        let stream = UnixStream::connect(path)
            .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
        let peer = validate_connected_unix_stream(stream.as_raw_fd())?;
        Self::from_validated_stream(stream, peer)
    }

    fn from_validated_stream(
        stream: UnixStream,
        peer: PeerIdentity,
    ) -> Result<Self, PacketEvidenceTransportError> {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        Ok(Self { stream, peer })
    }

    fn set_transaction_timeout(&self) -> Result<(), PacketEvidenceTransportError> {
        self.stream
            .set_read_timeout(Some(TRANSACTION_IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        self.stream
            .set_write_timeout(Some(TRANSACTION_IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)
    }

    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), PacketEvidenceTransportError> {
        let body = canonical_body(value)?;
        let length = frame_length(body.len())?;
        self.stream
            .write_all(&length)
            .and_then(|()| self.stream.write_all(&body))
            .map_err(|_| PacketEvidenceTransportError::WriteFailed)
    }

    fn receive<T>(&mut self) -> Result<T, PacketEvidenceTransportError>
    where
        T: DeserializeOwned + Serialize,
    {
        let mut length = [0_u8; 4];
        read_exact_no_ancillary(self.stream.as_raw_fd(), &mut length)?;
        let length = checked_frame_length(length)?;
        let mut body = vec![0_u8; length];
        read_exact_no_ancillary(self.stream.as_raw_fd(), &mut body)?;
        decode_canonical(&body)
    }
}

struct AsyncPacketEvidenceChannel {
    stream: tokio::net::UnixStream,
}

impl AsyncPacketEvidenceChannel {
    fn new(stream: tokio::net::UnixStream) -> Self {
        Self { stream }
    }

    async fn send<T: Serialize>(&mut self, value: &T) -> Result<(), PacketEvidenceTransportError> {
        let body = canonical_body(value)?;
        let length = frame_length(body.len())?;
        self.stream
            .write_all(&length)
            .await
            .map_err(|_| PacketEvidenceTransportError::WriteFailed)?;
        async_write_body(&mut self.stream, &body).await
    }

    async fn receive<T>(&mut self) -> Result<T, PacketEvidenceTransportError>
    where
        T: DeserializeOwned + Serialize,
    {
        let mut length = [0_u8; 4];
        read_exact_no_ancillary_async(&self.stream, &mut length).await?;
        let length = checked_frame_length(length)?;
        let mut body = vec![0_u8; length];
        read_exact_no_ancillary_async(&self.stream, &mut body).await?;
        decode_canonical(&body)
    }
}

async fn async_write_body(
    stream: &mut tokio::net::UnixStream,
    body: &[u8],
) -> Result<(), PacketEvidenceTransportError> {
    stream
        .write_all(body)
        .await
        .map_err(|_| PacketEvidenceTransportError::WriteFailed)
}

fn canonical_body<T: Serialize>(value: &T) -> Result<Vec<u8>, PacketEvidenceTransportError> {
    let body = serde_json::to_vec(value).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(body)
}

fn frame_length(length: usize) -> Result<[u8; 4], PacketEvidenceTransportError> {
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(u32::try_from(length)
        .map_err(|_| PacketEvidenceTransportError::FrameBound)?
        .to_be_bytes())
}

fn checked_frame_length(bytes: [u8; 4]) -> Result<usize, PacketEvidenceTransportError> {
    let length = usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| PacketEvidenceTransportError::FrameBound)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(length)
}

fn decode_canonical<T>(body: &[u8]) -> Result<T, PacketEvidenceTransportError>
where
    T: DeserializeOwned + Serialize,
{
    let parsed: T =
        serde_json::from_slice(body).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    let canonical =
        serde_json::to_vec(&parsed).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    if canonical != body {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    Ok(parsed)
}

fn validate_connected_unix_stream(fd: RawFd) -> Result<PeerIdentity, PacketEvidenceTransportError> {
    // SAFETY: every call receives valid output pointers and their exact sizes;
    // errors are checked before any output value is consumed.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut metadata: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut metadata) != 0 || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut socket_type: libc::c_int = 0;
        let mut socket_type_length = size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            &mut socket_type_length,
        ) != 0
            || socket_type != libc::SOCK_STREAM
            || socket_type_length as usize != size_of::<libc::c_int>()
        {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut peer_uid: libc::uid_t = 0;
        let mut peer_gid: libc::gid_t = 0;
        if libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) != 0 || peer_uid != libc::geteuid() {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let mut peer_pid: libc::pid_t = 0;
        let mut peer_pid_length = size_of::<libc::pid_t>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(peer_pid).cast(),
            &mut peer_pid_length,
        ) != 0
            || peer_pid <= 0
            || peer_pid_length as usize != size_of::<libc::pid_t>()
        {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let mut audit_token = [0_u8; 32];
        let mut audit_token_length = size_of::<[u8; 32]>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            audit_token.as_mut_ptr().cast(),
            &mut audit_token_length,
        ) != 0
            || audit_token_length as usize != size_of::<[u8; 32]>()
        {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let process = process_bsd_info(peer_pid)?;
        let peer_pid =
            u32::try_from(peer_pid).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
        if process.pbi_pid != peer_pid || process.pbi_uid != peer_uid {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        Ok(PeerIdentity {
            audit_token,
            pid: peer_pid,
            start_time_unix_us: process_start_time_unix_us(&process)?,
            uid: peer_uid,
        })
    }
}

fn read_exact_no_ancillary(
    fd: RawFd,
    output: &mut [u8],
) -> Result<(), PacketEvidenceTransportError> {
    let mut offset = 0;
    while offset < output.len() {
        let mut control = [0_usize; 32];
        let mut iovec = libc::iovec {
            iov_base: output[offset..].as_mut_ptr().cast(),
            iov_len: output.len() - offset,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of::<[usize; 32]>() as _;
        // SAFETY: `message` points only to the live output slice and aligned
        // ancillary buffer above. The returned count is checked before use.
        let count = unsafe { libc::recvmsg(fd, &mut message, 0) };
        if count == 0 {
            return Err(PacketEvidenceTransportError::TruncatedFrame);
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PacketEvidenceTransportError::TruncatedFrame);
        }
        reject_and_close_ancillary(&message)?;
        offset +=
            usize::try_from(count).map_err(|_| PacketEvidenceTransportError::TruncatedFrame)?;
    }
    Ok(())
}

async fn read_exact_no_ancillary_async(
    stream: &tokio::net::UnixStream,
    output: &mut [u8],
) -> Result<(), PacketEvidenceTransportError> {
    enum ReadOutcome {
        Bytes(usize),
        End,
        Ancillary,
        AncillaryCleanup,
    }

    let mut offset = 0;
    while offset < output.len() {
        stream
            .readable()
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)?;
        let attempted = stream.try_io(Interest::READABLE, || {
            let mut control = [0_usize; 32];
            let mut iovec = libc::iovec {
                iov_base: output[offset..].as_mut_ptr().cast(),
                iov_len: output.len() - offset,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of::<[usize; 32]>() as _;
            // SAFETY: the stream remains live for the call and the buffers
            // above exactly describe initialized writable memory.
            let count =
                unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count == 0 {
                return Ok(ReadOutcome::End);
            }
            match reject_and_close_ancillary(&message) {
                Ok(()) => Ok(ReadOutcome::Bytes(count as usize)),
                Err(PacketEvidenceTransportError::AncillaryCleanup) => {
                    Ok(ReadOutcome::AncillaryCleanup)
                }
                Err(_) => Ok(ReadOutcome::Ancillary),
            }
        });
        match attempted {
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(_) | Ok(ReadOutcome::End) => {
                return Err(PacketEvidenceTransportError::TruncatedFrame);
            }
            Ok(ReadOutcome::Ancillary) => {
                return Err(PacketEvidenceTransportError::AncillaryData);
            }
            Ok(ReadOutcome::AncillaryCleanup) => {
                return Err(PacketEvidenceTransportError::AncillaryCleanup);
            }
            Ok(ReadOutcome::Bytes(count)) => offset += count,
        }
    }
    Ok(())
}

fn reject_and_close_ancillary(message: &libc::msghdr) -> Result<(), PacketEvidenceTransportError> {
    let has_ancillary = message.msg_controllen != 0 || message.msg_flags & libc::MSG_CTRUNC != 0;
    if !has_ancillary {
        return Ok(());
    }
    let mut cleanup_failed = false;
    // SAFETY: the kernel initialized the control region described by `message`.
    // CMSG iteration stays within `msg_controllen`; each SCM_RIGHTS payload is
    // truncated to a whole descriptor before it is read and closed.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let header_bytes = libc::CMSG_LEN(0) as usize;
                let payload_bytes = ((*header).cmsg_len as usize).saturating_sub(header_bytes);
                let descriptor_count = payload_bytes / size_of::<RawFd>();
                let descriptors = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..descriptor_count {
                    if libc::close(*descriptors.add(index)) != 0 {
                        cleanup_failed = true;
                    }
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    if cleanup_failed {
        Err(PacketEvidenceTransportError::AncillaryCleanup)
    } else {
        Err(PacketEvidenceTransportError::AncillaryData)
    }
}

fn now_unix_ms() -> Result<u64, PacketEvidenceTransportError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PacketEvidenceTransportError::InvalidSession)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| PacketEvidenceTransportError::InvalidSession)
}

fn canonical_session_id(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn encode_identity(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn random_launcher_ticket_id() -> String {
    let mut bytes = [0_u8; 32];
    // SAFETY: `bytes` is live writable storage of the exact length passed to
    // macOS' cryptographic `arc4random_buf`; that API has no partial-success
    // state or caller-controlled source.
    unsafe {
        libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len());
    }
    encode_identity(&bytes)
}

fn validate_session_window(
    session_id: &str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    now: u64,
) -> Result<(), PacketEvidenceTransportError> {
    if !canonical_session_id(session_id)
        || expires_at_unix_ms.checked_sub(issued_at_unix_ms) != Some(SESSION_LIFETIME_MS)
        || issued_at_unix_ms > now.saturating_add(SESSION_CLOCK_SKEW_MS)
        || now > expires_at_unix_ms
    {
        return Err(PacketEvidenceTransportError::InvalidSession);
    }
    Ok(())
}

fn parse_case(
    case_id: &str,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    match case_id {
        "tcp-ipv4" => Ok(("tcp-ipv4", ReleasePacketEvidenceCase::TcpIpv4)),
        "tcp-ipv6" => Ok(("tcp-ipv6", ReleasePacketEvidenceCase::TcpIpv6)),
        "udp" => Ok(("udp", ReleasePacketEvidenceCase::Udp)),
        "quic" => Ok(("quic", ReleasePacketEvidenceCase::Quic)),
        "dns-a-primary" => Ok(("dns-a-primary", ReleasePacketEvidenceCase::DnsAPrimary)),
        "dns-a-secondary" => Ok(("dns-a-secondary", ReleasePacketEvidenceCase::DnsASecondary)),
        "dns-aaaa-primary" => Ok((
            "dns-aaaa-primary",
            ReleasePacketEvidenceCase::DnsAaaaPrimary,
        )),
        "dns-aaaa-secondary" => Ok((
            "dns-aaaa-secondary",
            ReleasePacketEvidenceCase::DnsAaaaSecondary,
        )),
        "lan-bypass" => Ok(("lan-bypass", ReleasePacketEvidenceCase::LanBypass)),
        "included-routes" => Ok(("included-routes", ReleasePacketEvidenceCase::IncludedRoutes)),
        "excluded-routes" => Ok(("excluded-routes", ReleasePacketEvidenceCase::ExcludedRoutes)),
        "stop-cleanup" => Ok(("stop-cleanup", ReleasePacketEvidenceCase::StopCleanup)),
        "ipv6-disabled-absence" => Ok((
            "ipv6-disabled-absence",
            ReleasePacketEvidenceCase::Ipv6DisabledAbsence,
        )),
        _ => Err(PacketEvidenceTransportError::InvalidCase),
    }
}

fn validate_collector_hello(
    hello: &CollectorHello,
    peer: PeerIdentity,
    now: u64,
) -> Result<(), PacketEvidenceTransportError> {
    if hello.schema_version != PROTOCOL_VERSION
        || hello.document != "cfw-packet-collector-hello-v5"
        || hello.collector_pid != peer.pid
        || hello.collector_uid != peer.uid
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_session_window(
        &hello.session_id,
        hello.issued_at_unix_ms,
        hello.expires_at_unix_ms,
        now,
    )
}

fn validate_collector_request(
    request: &CollectorRequest,
    hello: &CollectorHello,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if request.schema_version != PROTOCOL_VERSION
        || request.document != "cfw-packet-collector-request-v5"
        || request.sequence != REQUEST_SEQUENCE
        || request.session_id != hello.session_id
    {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    parse_case(&request.case_id)
}

fn validate_stage_response(
    response: &CollectorStageResponse,
    session_id: &str,
    case_id: &str,
    sequence: u32,
    complete_document: &str,
    failed_document: &str,
) -> Result<PacketEvidenceCaptureFailure, PacketEvidenceTransportError> {
    match response {
        CollectorStageResponse::Complete(complete) => {
            if complete.schema_version != PROTOCOL_VERSION
                || complete.document != complete_document
                || complete.sequence != sequence
                || complete.session_id != session_id
                || complete.case_id != case_id
            {
                return Err(PacketEvidenceTransportError::InvalidFrame);
            }
            Err(PacketEvidenceTransportError::InvalidResponse)
        }
        CollectorStageResponse::Failed(failed) => {
            if failed.schema_version != PROTOCOL_VERSION
                || failed.document != failed_document
                || failed.sequence != sequence
                || failed.session_id != session_id
                || failed.case_id != case_id
            {
                return Err(PacketEvidenceTransportError::InvalidFrame);
            }
            match failed.code.as_str() {
                "command_failed" => Ok(PacketEvidenceCaptureFailure::CommandFailed),
                "evidence_rejected" => Ok(PacketEvidenceCaptureFailure::EvidenceRejected),
                "archive_failed" => Ok(PacketEvidenceCaptureFailure::ArchiveFailed),
                "cancelled" => Ok(PacketEvidenceCaptureFailure::Cancelled),
                _ => Err(PacketEvidenceTransportError::InvalidFrame),
            }
        }
    }
}

fn stage_result(
    response: &CollectorStageResponse,
    session_id: &str,
    case_id: &str,
    sequence: u32,
    complete_document: &str,
    failed_document: &str,
) -> Result<(), PacketEvidenceCaptureFailure> {
    if let CollectorStageResponse::Complete(complete) = response
        && complete.schema_version == PROTOCOL_VERSION
        && complete.document == complete_document
        && complete.sequence == sequence
        && complete.session_id == session_id
        && complete.case_id == case_id
    {
        return Ok(());
    }
    match validate_stage_response(
        response,
        session_id,
        case_id,
        sequence,
        complete_document,
        failed_document,
    ) {
        Ok(failure) => Err(failure),
        Err(_) => Err(PacketEvidenceCaptureFailure::ControlChannelFailed),
    }
}

#[derive(Default)]
struct SessionReplayGuard {
    expirations: BTreeMap<String, u64>,
}

impl SessionReplayGuard {
    fn admit(
        &mut self,
        session_id: &str,
        expires_at_unix_ms: u64,
        now: u64,
    ) -> Result<(), PacketEvidenceTransportError> {
        self.expirations.retain(|_, expires| *expires >= now);
        if self.expirations.contains_key(session_id) {
            return Err(PacketEvidenceTransportError::ReplayedSession);
        }
        if self.expirations.len() >= MAX_ACTIVE_SESSIONS {
            return Err(PacketEvidenceTransportError::SessionCapacity);
        }
        self.expirations
            .insert(session_id.to_owned(), expires_at_unix_ms);
        Ok(())
    }
}

struct LauncherTicketStore {
    directory: File,
}

struct LauncherTicketDirectoryLock<'a> {
    directory: &'a File,
}

impl Drop for LauncherTicketDirectoryLock<'_> {
    fn drop(&mut self) {
        // This releases only the cross-process filesystem mutex. Evidence
        // restoration and terminal cleanup never depend on Drop.
        unsafe {
            libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl LauncherTicketStore {
    fn open(app_home: &Path) -> Result<Self, PacketEvidenceTransportError> {
        let root_path = CString::new(app_home.as_os_str().as_bytes())
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        // SAFETY: `root_path` is NUL-terminated and the returned descriptor is
        // checked before ownership is transferred to `File`.
        let root_descriptor = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let root = unsafe { File::from_raw_fd(root_descriptor) };
        validate_private_ticket_directory(&root)?;

        let directory_name = CString::new(LAUNCHER_TICKET_DIRECTORY)
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        // SAFETY: both the directory descriptor and fixed relative name are
        // valid for the duration of the call.
        let created =
            if unsafe { libc::mkdirat(root.as_raw_fd(), directory_name.as_ptr(), 0o700) } == 0 {
                true
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    false
                } else {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
            };
        let descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                directory_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        validate_private_ticket_directory(&directory)?;
        if created {
            root.sync_all()
                .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)?;
        }
        Ok(Self { directory })
    }

    fn lock(&self) -> Result<LauncherTicketDirectoryLock<'_>, PacketEvidenceTransportError> {
        // SAFETY: `directory` remains live while the returned guard exists.
        if unsafe { libc::flock(self.directory.as_raw_fd(), libc::LOCK_EX) } == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        Ok(LauncherTicketDirectoryLock {
            directory: &self.directory,
        })
    }

    fn consume(
        &self,
        binding: &LauncherBinding,
        ticket_id: &str,
        now: u64,
    ) -> Result<(), PacketEvidenceTransportError> {
        validate_launcher_binding(binding, now)?;
        if !canonical_session_id(ticket_id) {
            return Err(PacketEvidenceTransportError::InvalidSession);
        }
        let _lock = self.lock()?;
        let active_sessions = self.sweep_locked(now)?;
        if active_sessions
            .iter()
            .any(|session| session == &binding.session_id)
        {
            return Err(PacketEvidenceTransportError::LauncherTicketReplayed);
        }
        if active_sessions.len() >= MAX_TICKET_DOCUMENTS {
            return Err(PacketEvidenceTransportError::LauncherTicketCapacity);
        }
        let record = ConsumedLauncherTicket {
            binding: binding.clone(),
            document: "cfw-packet-launcher-ticket-consumed-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            ticket_id: ticket_id.to_owned(),
        };
        let bytes = canonical_body(&record)?;
        let final_name = launcher_ticket_filename(&binding.session_id)?;
        let pending_name = launcher_ticket_pending_filename(ticket_id)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                pending_name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_EXLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_ticket_file(&file)?;
        let persisted = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain);
        drop(file);
        if let Err(error) = persisted {
            return match self.unlink_name_locked(&pending_name) {
                Ok(()) => Err(error),
                Err(_) => Err(PacketEvidenceTransportError::LauncherTicketCommitUncertain),
            };
        }
        // macOS RENAME_EXCL publishes the complete fsync'd record without ever
        // replacing a prior consumed session. A crash before this operation
        // leaves only a disposable pending file; a crash after it leaves the
        // complete replay tombstone.
        let renamed = unsafe {
            libc::renameatx_np(
                self.directory.as_raw_fd(),
                pending_name.as_ptr(),
                self.directory.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if renamed == -1 {
            let error = io::Error::last_os_error();
            let cleanup = self.unlink_name_locked(&pending_name);
            return match (error.kind(), cleanup) {
                (io::ErrorKind::AlreadyExists, Ok(())) => {
                    Err(PacketEvidenceTransportError::LauncherTicketReplayed)
                }
                (_, Ok(())) => Err(PacketEvidenceTransportError::LauncherTicketUnsafe),
                (_, Err(_)) => Err(PacketEvidenceTransportError::LauncherTicketCommitUncertain),
            };
        }
        self.directory
            .sync_all()
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)
    }

    fn sweep_locked(&self, now: u64) -> Result<Vec<String>, PacketEvidenceTransportError> {
        let mut active_sessions = Vec::new();
        let mut removed = false;
        for name in self.entry_names_locked()? {
            if launcher_ticket_pending_id_from_name(&name).is_ok() {
                let name = CString::new(name)
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
                if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
                removed = true;
                continue;
            }
            let session_id = launcher_ticket_session_from_name(&name)?;
            let record = self.read_record_locked(&name)?;
            if record.schema_version != PROTOCOL_VERSION
                || record.document != "cfw-packet-launcher-ticket-consumed-v5"
                || record.binding.session_id != session_id
                || !canonical_session_id(&record.ticket_id)
                || validate_launcher_binding_shape(&record.binding).is_err()
            {
                return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
            }
            if now
                > record
                    .binding
                    .expires_at_unix_ms
                    .saturating_add(SESSION_CLOCK_SKEW_MS)
            {
                let name = CString::new(name)
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
                if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
                removed = true;
            } else {
                active_sessions.push(session_id);
            }
        }
        if removed {
            self.directory
                .sync_all()
                .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)?;
        }
        Ok(active_sessions)
    }

    fn entry_names_locked(&self) -> Result<Vec<String>, PacketEvidenceTransportError> {
        let current =
            CString::new(".").map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                current.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        // SAFETY: ownership of `descriptor` transfers to DIR on success and is
        // otherwise closed explicitly below.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            unsafe {
                libc::close(descriptor);
            }
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let result = (|| {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    return if unsafe { *libc::__error() } == 0 {
                        Ok(names)
                    } else {
                        Err(PacketEvidenceTransportError::LauncherTicketUnsafe)
                    };
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = name
                    .to_str()
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?
                    .to_owned();
                names.push(name);
                if names.len() > MAX_TICKET_DIRECTORY_ENTRIES {
                    return Err(PacketEvidenceTransportError::LauncherTicketCapacity);
                }
            }
        })();
        let closed = unsafe { libc::closedir(stream) };
        if closed != 0 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        result
    }

    fn read_record_locked(
        &self,
        name: &str,
    ) -> Result<ConsumedLauncherTicket, PacketEvidenceTransportError> {
        let name =
            CString::new(name).map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let before = validate_private_ticket_file(&file)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let after = validate_private_ticket_file(&file)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || u64::try_from(bytes.len()).ok() != Some(before.len())
        {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        decode_canonical(&bytes).map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
    }

    fn unlink_name_locked(&self, name: &CStr) -> Result<(), PacketEvidenceTransportError> {
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        self.directory
            .sync_all()
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)
    }
}

fn validate_private_ticket_directory(file: &File) -> Result<(), PacketEvidenceTransportError> {
    let metadata = file
        .metadata()
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(())
}

fn validate_private_ticket_file(file: &File) -> Result<fs::Metadata, PacketEvidenceTransportError> {
    let metadata = file
        .metadata()
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_FRAME_BYTES as u64
    {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(metadata)
}

fn launcher_ticket_filename(session_id: &str) -> Result<CString, PacketEvidenceTransportError> {
    if !canonical_session_id(session_id) {
        return Err(PacketEvidenceTransportError::InvalidSession);
    }
    CString::new(format!("consumed-{session_id}.json"))
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
}

fn launcher_ticket_pending_filename(
    ticket_id: &str,
) -> Result<CString, PacketEvidenceTransportError> {
    if !canonical_session_id(ticket_id) {
        return Err(PacketEvidenceTransportError::InvalidSession);
    }
    CString::new(format!("pending-{ticket_id}.json"))
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
}

fn launcher_ticket_pending_id_from_name(name: &str) -> Result<&str, PacketEvidenceTransportError> {
    let ticket_id = name
        .strip_prefix("pending-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or(PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !canonical_session_id(ticket_id) {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(ticket_id)
}

fn launcher_ticket_session_from_name(name: &str) -> Result<String, PacketEvidenceTransportError> {
    let session_id = name
        .strip_prefix("consumed-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or(PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !canonical_session_id(session_id) {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(session_id.to_owned())
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct ControlSocketGuard {
    identity: SocketIdentity,
    path: PathBuf,
}

fn unlink_exact_socket_with<F>(path: &Path, identity: SocketIdentity, unlink: F) -> io::Result<bool>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.dev() != identity.device || metadata.ino() != identity.inode {
        return Ok(false);
    }
    unlink(path)?;
    Ok(true)
}

fn unlink_exact_socket(path: &Path, identity: SocketIdentity) -> io::Result<bool> {
    unlink_exact_socket_with(path, identity, |target| fs::remove_file(target))
}

fn remove_stale_control_socket_with<F>(
    path: &Path,
    identity: SocketIdentity,
    unlink: F,
) -> Result<(), PacketEvidenceTransportError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    match unlink_exact_socket_with(path, identity, unlink) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PacketEvidenceTransportError::EndpointUnsafe),
        Err(_) => Err(PacketEvidenceTransportError::EndpointCleanupFailed),
    }
}

impl Drop for ControlSocketGuard {
    fn drop(&mut self) {
        if let Err(error) = unlink_exact_socket(&self.path, self.identity) {
            // Drop cannot report an error to its caller. Keep the exact socket
            // inode in place for typed diagnosis on the next startup and emit
            // a bounded diagnostic for the current process instead.
            eprintln!(
                "physical Packet evidence exact control endpoint cleanup failed: {:?}",
                error.kind()
            );
        }
    }
}

fn packet_evidence_app_home() -> Result<PathBuf, PacketEvidenceTransportError> {
    let store =
        crate::settings_store().map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    store
        .ensure_layout()
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    let root = &store.paths().app_home;
    let metadata =
        fs::symlink_metadata(root).map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    Ok(root.clone())
}

fn control_socket_path() -> Result<PathBuf, PacketEvidenceTransportError> {
    Ok(packet_evidence_app_home()?.join(CONTROL_SOCKET_NAME))
}

fn bind_control_endpoint()
-> Result<(UnixListener, ControlSocketGuard), PacketEvidenceTransportError> {
    let path = control_socket_path()?;
    let existing = match fs::symlink_metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(PacketEvidenceTransportError::EndpointUnsafe),
    };
    if let Some(metadata) = existing {
        if !metadata.file_type().is_socket()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(PacketEvidenceTransportError::EndpointUnsafe);
        }
        if UnixStream::connect(&path).is_ok() {
            return Err(PacketEvidenceTransportError::EndpointActive);
        }
        let stale = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        remove_stale_control_socket_with(&path, stale, |target| fs::remove_file(target))?;
    }

    let listener =
        UnixListener::bind(&path).map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
    let initial =
        fs::symlink_metadata(&path).map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !initial.file_type().is_socket() || initial.uid() != unsafe { libc::geteuid() } {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: initial.dev(),
            inode: initial.ino(),
        },
        path,
    };
    fs::set_permissions(&guard.path, fs::Permissions::from_mode(0o600))
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    let metadata = fs::symlink_metadata(&guard.path)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.dev() != guard.identity.device
        || metadata.ino() != guard.identity.inode
    {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
    Ok((listener, guard))
}

fn register_control_endpoint(
    listener: UnixListener,
) -> Result<tokio::net::UnixListener, PacketEvidenceTransportError> {
    // Tauri setup runs on the AppKit main thread, outside a Tokio reactor.
    // Enter the application runtime explicitly so Tokio can register the
    // nonblocking descriptor without panicking across the AppKit FFI boundary.
    let runtime = tauri::async_runtime::handle();
    let _runtime_guard = runtime.inner().enter();
    tokio::net::UnixListener::from_std(listener)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)
}

fn process_bsd_info(pid: libc::pid_t) -> Result<libc::proc_bsdinfo, PacketEvidenceTransportError> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = size_of::<libc::proc_bsdinfo>();
    // SAFETY: `info` has the exact size requested and is initialized only after
    // the kernel reports the complete structure.
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
        )
    };
    if result as usize != expected {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    Ok(unsafe { info.assume_init() })
}

fn process_start_time_unix_us(
    info: &libc::proc_bsdinfo,
) -> Result<u64, PacketEvidenceTransportError> {
    let seconds = info.pbi_start_tvsec;
    let microseconds = info.pbi_start_tvusec;
    if microseconds >= 1_000_000 {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(microseconds))
        .filter(|value| *value > 0)
        .ok_or(PacketEvidenceTransportError::InvalidPeer)
}

fn validate_same_executable_peer(peer: PeerIdentity) -> Result<(), PacketEvidenceTransportError> {
    let pid = libc::pid_t::try_from(peer.pid)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerExecutable)?;
    let before = process_bsd_info(pid)?;
    if before.pbi_pid != peer.pid
        || before.pbi_uid != peer.uid
        || process_start_time_unix_us(&before)? != peer.start_time_unix_us
    {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `path` is live writable storage and the bound is its exact size.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
        )
    };
    if length <= 0 || length as usize >= path.len() {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    path.truncate(length as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    let observed = PathBuf::from(OsString::from_vec(path));
    let expected =
        std::env::current_exe().map_err(|_| PacketEvidenceTransportError::InvalidPeerExecutable)?;
    let after = process_bsd_info(pid)?;
    if observed != expected
        || before.pbi_pid != after.pbi_pid
        || before.pbi_uid != after.pbi_uid
        || before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
    {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    Ok(())
}

fn validate_signed_peer(peer: PeerIdentity) -> Result<(), PacketEvidenceTransportError> {
    let token = CFData::from_buffer(&peer.audit_token);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, CodeSigningFlags::NONE)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)?;
    let requirement: SecRequirement = HOST_CODE_REQUIREMENT
        .parse()
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)?;
    code.check_validity(CodeSigningFlags::NONE, &requirement)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)
}

fn validate_launcher_binding_shape(
    binding: &LauncherBinding,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if !canonical_session_id(&binding.collector_audit_token)
        || binding.collector_pid == 0
        || binding.collector_start_time_unix_us == 0
        || binding.proxy_pid == 0
        || binding.proxy_start_time_unix_us == 0
        || binding.collector_pid == binding.proxy_pid
        || binding.collector_uid != binding.proxy_uid
        || binding
            .expires_at_unix_ms
            .checked_sub(binding.issued_at_unix_ms)
            != Some(SESSION_LIFETIME_MS)
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    parse_case(&binding.case_id)
}

fn validate_launcher_binding(
    binding: &LauncherBinding,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    let parsed = validate_launcher_binding_shape(binding)?;
    validate_session_window(
        &binding.session_id,
        binding.issued_at_unix_ms,
        binding.expires_at_unix_ms,
        now,
    )?;
    Ok(parsed)
}

fn validate_live_launcher_binding(
    binding: &LauncherBinding,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    let parsed = validate_launcher_binding(binding, now)?;
    if binding.proxy_pid != peer.pid
        || binding.proxy_uid != peer.uid
        || binding.proxy_start_time_unix_us != peer.start_time_unix_us
        || binding.collector_uid != peer.uid
        || binding.collector_pid == host_pid
        || peer.pid == host_pid
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    let collector_pid = libc::pid_t::try_from(binding.collector_pid)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
    let collector =
        process_bsd_info(collector_pid).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
    if collector.pbi_pid != binding.collector_pid
        || collector.pbi_uid != binding.collector_uid
        || process_start_time_unix_us(&collector)? != binding.collector_start_time_unix_us
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    Ok(parsed)
}

fn validate_ticket_request(
    request: &AppTicketRequest,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if request.schema_version != PROTOCOL_VERSION
        || request.document != "cfw-packet-app-ticket-request-v5"
        || request.sequence != TICKET_SEQUENCE
    {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    validate_live_launcher_binding(&request.binding, peer, host_pid, now)
}

fn validate_ticket_issued(
    issued: &HostTicketIssued,
    binding: &LauncherBinding,
) -> Result<(), PacketEvidenceTransportError> {
    if issued.schema_version != PROTOCOL_VERSION
        || issued.document != "cfw-packet-host-ticket-issued-v5"
        || issued.sequence != TICKET_SEQUENCE
        || &issued.binding != binding
        || !canonical_session_id(&issued.ticket_id)
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_app_request(
    request: &AppRequest,
    issued: &HostTicketIssued,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if request.schema_version != PROTOCOL_VERSION
        || request.document != "cfw-packet-app-request-v5"
        || request.sequence != REQUEST_SEQUENCE
        || request.binding != issued.binding
        || request.ticket_id != issued.ticket_id
    {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    validate_live_launcher_binding(&request.binding, peer, host_pid, now)
}

fn wire_snapshot(receipt: &PacketEvidenceSnapshotReceipt) -> WireSnapshot {
    WireSnapshot {
        config_digest: receipt.config_digest().map(str::to_owned),
        desired_mode: receipt.desired_mode(),
        generation: receipt.generation(),
        ipv6_enabled: receipt.ipv6_enabled(),
        owner: receipt.owner(),
        phase: receipt.phase().as_str().to_owned(),
        ready: receipt.ready(),
    }
}

fn host_baseline(
    session_id: &str,
    case_id: &str,
    ready: &PacketEvidenceBaselineReady,
) -> HostBaselineObserved {
    HostBaselineObserved {
        baseline: wire_snapshot(&ready.baseline),
        baseline_observation_sequence: ready.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-baseline-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: BASELINE_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

fn host_test(session_id: &str, case_id: &str, ready: &PacketEvidenceTestReady) -> HostTestObserved {
    HostTestObserved {
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-test-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TEST_SEQUENCE,
        session_id: session_id.to_owned(),
        test: wire_snapshot(&ready.test),
        test_observation_sequence: ready.test_observation_sequence,
    }
}

fn host_restored(
    session_id: &str,
    case_id: &str,
    ready: &PacketEvidenceCaptureFinalizing,
) -> HostBaselineRestored {
    HostBaselineRestored {
        baseline: wire_snapshot(&ready.baseline),
        baseline_observation_sequence: ready.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-baseline-restored-v5".to_owned(),
        restore: wire_snapshot(&ready.restore),
        restore_observation_sequence: ready.restore_observation_sequence,
        schema_version: PROTOCOL_VERSION,
        sequence: RESTORED_SEQUENCE,
        session_id: session_id.to_owned(),
        test: ready.test.as_ref().map(wire_snapshot),
        test_observation_sequence: ready.test_observation_sequence,
    }
}

fn abort_reason_code(reason: PacketEvidenceAbortReason) -> &'static str {
    match reason {
        PacketEvidenceAbortReason::TestApplyFailed => "test_apply_failed",
        PacketEvidenceAbortReason::TestSnapshotInvalid => "test_snapshot_invalid",
        PacketEvidenceAbortReason::RestoreUnproven => "restore_unproven_quarantined",
        PacketEvidenceAbortReason::RestoreMismatch => "restore_mismatch_quarantined",
        PacketEvidenceAbortReason::RestoreQuarantineFailed => "restore_quarantine_failed",
        PacketEvidenceAbortReason::ObservationFailed => "observation_failed",
    }
}

fn host_aborted(
    session_id: &str,
    case_id: &str,
    aborted: &PacketEvidenceCaptureAborted,
) -> HostCaptureAborted {
    HostCaptureAborted {
        baseline: wire_snapshot(&aborted.baseline),
        baseline_observation_sequence: aborted.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        code: abort_reason_code(aborted.reason).to_owned(),
        document: "cfw-packet-host-capture-aborted-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: RESTORED_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

fn host_completed(
    session_id: &str,
    case_id: &str,
    outcome: PacketEvidenceTransactionOutcome,
) -> HostCompleted {
    HostCompleted {
        baseline: wire_snapshot(&outcome.baseline),
        baseline_observation_sequence: outcome.baseline_observation_sequence,
        candidate_observation_sequence: outcome.candidate_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-completed-v5".to_owned(),
        restore: wire_snapshot(&outcome.restore),
        restore_observation_sequence: outcome.restore_observation_sequence,
        schema_version: PROTOCOL_VERSION,
        sequence: RESULT_SEQUENCE,
        session_id: session_id.to_owned(),
        test: wire_snapshot(&outcome.test),
        test_observation_sequence: outcome.test_observation_sequence,
    }
}

fn host_failed(session_id: &str, case_id: &str, code: &str) -> HostFailed {
    HostFailed {
        case_id: case_id.to_owned(),
        code: code.to_owned(),
        document: "cfw-packet-host-failed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: RESULT_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

fn transaction_failure_code(error: &PacketEvidenceTransactionError) -> &'static str {
    match error {
        PacketEvidenceTransactionError::Maintenance(_) => "maintenance_busy",
        PacketEvidenceTransactionError::LegacyRetirement(_) => "legacy_retirement_blocked",
        PacketEvidenceTransactionError::TunnelUnavailable(_) => "tunnel_unavailable",
        PacketEvidenceTransactionError::BaselineUnavailable => "baseline_unavailable",
        PacketEvidenceTransactionError::BaselineMismatch => "baseline_mismatch",
        PacketEvidenceTransactionError::Projection(_) => "projection_failed",
        PacketEvidenceTransactionError::TestApply(_) => "test_apply_failed",
        PacketEvidenceTransactionError::TestSnapshot(_) => "test_snapshot_invalid",
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::CommandFailed) => {
            "capture_command_failed"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::EvidenceRejected) => {
            "capture_evidence_rejected"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::ArchiveFailed) => {
            "capture_archive_failed"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::Cancelled) => {
            "capture_cancelled"
        }
        PacketEvidenceTransactionError::Capture(
            PacketEvidenceCaptureFailure::ControlChannelFailed,
        ) => "capture_control_failed",
        PacketEvidenceTransactionError::CaptureTimeout => "capture_timeout",
        PacketEvidenceTransactionError::CapturePanicked => "capture_panicked",
        PacketEvidenceTransactionError::Restore(_) => "restore_unproven_quarantined",
        PacketEvidenceTransactionError::RestoreMismatch(_) => "restore_mismatch_quarantined",
        PacketEvidenceTransactionError::Quarantine(_) => "restore_quarantine_failed",
        PacketEvidenceTransactionError::Observation(_) => "observation_failed",
        PacketEvidenceTransactionError::CompletionClosed => "completion_closed",
    }
}

fn capture_failure_code(error: PacketEvidenceCaptureFailure) -> &'static str {
    match error {
        PacketEvidenceCaptureFailure::CommandFailed => "capture_command_failed",
        PacketEvidenceCaptureFailure::EvidenceRejected => "capture_evidence_rejected",
        PacketEvidenceCaptureFailure::ArchiveFailed => "capture_archive_failed",
        PacketEvidenceCaptureFailure::Cancelled => "capture_cancelled",
        PacketEvidenceCaptureFailure::ControlChannelFailed => "capture_control_failed",
    }
}

async fn run_app_protocol<Execute, Transaction>(
    channel: AsyncPacketEvidenceChannel,
    peer: PeerIdentity,
    replay: &mut SessionReplayGuard,
    ticket_store: &LauncherTicketStore,
    host_pid: u32,
    execute: Execute,
) -> Result<(), PacketEvidenceTransportError>
where
    Execute: FnOnce(ReleasePacketEvidenceCase, PacketEvidenceStages) -> Transaction,
    Transaction:
        Future<Output = Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>>,
{
    let channel = Arc::new(Mutex::new(channel));
    let ticket_request: AppTicketRequest = {
        let mut locked = channel.lock().await;
        tokio::time::timeout(IO_TIMEOUT, locked.receive())
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)??
    };
    let now = now_unix_ms()?;
    let (case_id, _case) = validate_ticket_request(&ticket_request, peer, host_pid, now)?;
    // The physical evidence operator is explicitly a same-UID trust boundary:
    // the live collector is PID/start/audit-token bound by the signed proxy,
    // but this does not turn an arbitrary same-UID Python process into a
    // separately authenticated principal. The Host-issued ticket closes
    // cross-restart replay and request substitution within that boundary.
    let issued = HostTicketIssued {
        binding: ticket_request.binding.clone(),
        document: "cfw-packet-host-ticket-issued-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
        ticket_id: random_launcher_ticket_id(),
    };
    channel.lock().await.send(&issued).await?;
    let request: AppRequest = {
        let mut locked = channel.lock().await;
        tokio::time::timeout(IO_TIMEOUT, locked.receive())
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)??
    };
    let now = now_unix_ms()?;
    let (validated_case_id, case) = validate_app_request(&request, &issued, peer, host_pid, now)?;
    if validated_case_id != case_id {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    if let Err(error) = ticket_store.consume(&request.binding, &request.ticket_id, now) {
        let code = match error {
            PacketEvidenceTransportError::LauncherTicketReplayed => "launcher_ticket_replayed",
            PacketEvidenceTransportError::LauncherTicketCapacity => {
                "launcher_ticket_capacity_exhausted"
            }
            PacketEvidenceTransportError::InvalidSession
            | PacketEvidenceTransportError::InvalidPeer
            | PacketEvidenceTransportError::InvalidCase => "launcher_ticket_invalid",
            _ => "launcher_ticket_store_unavailable",
        };
        channel
            .lock()
            .await
            .send(&host_failed(&request.binding.session_id, case_id, code))
            .await?;
        return Ok(());
    }
    if let Err(error) = replay.admit(
        &request.binding.session_id,
        request.binding.expires_at_unix_ms,
        now,
    ) {
        let code = match error {
            PacketEvidenceTransportError::ReplayedSession => "session_replayed",
            PacketEvidenceTransportError::SessionCapacity => "session_capacity_exhausted",
            _ => "session_invalid",
        };
        channel
            .lock()
            .await
            .send(&host_failed(&request.binding.session_id, case_id, code))
            .await?;
        return Ok(());
    }

    let begin_channel = channel.clone();
    let begin_session = request.binding.session_id.clone();
    let begin_case = case_id.to_owned();
    let test_channel = channel.clone();
    let test_session = request.binding.session_id.clone();
    let test_case = case_id.to_owned();
    let finish_channel = channel.clone();
    let finish_session = request.binding.session_id.clone();
    let finish_case = case_id.to_owned();
    let stages = PacketEvidenceStages::new(
        move |ready| async move {
            let mut locked = begin_channel.lock().await;
            locked
                .send(&host_baseline(&begin_session, &begin_case, &ready))
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &begin_session,
                &begin_case,
                CAPTURE_STARTED_SEQUENCE,
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-start-failed-v5",
            )
        },
        move |ready| async move {
            let mut locked = test_channel.lock().await;
            locked
                .send(&host_test(&test_session, &test_case, &ready))
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &test_session,
                &test_case,
                TEST_SUBMITTED_SEQUENCE,
                "cfw-packet-collector-test-submitted-v5",
                "cfw-packet-collector-test-submit-failed-v5",
            )
        },
        move |terminal| async move {
            let mut locked = finish_channel.lock().await;
            match terminal {
                PacketEvidenceCaptureTerminal::Restored(ready) => locked
                    .send(&host_restored(&finish_session, &finish_case, &ready))
                    .await
                    .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?,
                PacketEvidenceCaptureTerminal::Aborted(aborted) => locked
                    .send(&host_aborted(&finish_session, &finish_case, &aborted))
                    .await
                    .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?,
            }
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &finish_session,
                &finish_case,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-completed-v5",
                "cfw-packet-collector-capture-complete-failed-v5",
            )
        },
    );
    let transaction = execute(case, stages).await;
    let final_response = match transaction {
        Ok(outcome) => HostFinalResponse::Completed(host_completed(
            &request.binding.session_id,
            case_id,
            outcome,
        )),
        Err(error) => HostFinalResponse::Failed(host_failed(
            &request.binding.session_id,
            case_id,
            transaction_failure_code(&error),
        )),
    };
    channel.lock().await.send(&final_response).await
}

async fn serve_control_connection(
    app: &AppHandle,
    stream: tokio::net::UnixStream,
    replay: &mut SessionReplayGuard,
    ticket_store: &LauncherTicketStore,
) -> Result<(), PacketEvidenceTransportError> {
    crate::legacy::require_canonical_handoff_candidate()
        .map_err(|_| PacketEvidenceTransportError::InvalidCandidate)?;
    let peer = validate_connected_unix_stream(stream.as_raw_fd())?;
    if peer.pid == std::process::id() {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_same_executable_peer(peer)?;
    validate_signed_peer(peer)?;
    let engine = app.state::<ManagedEngine>();
    let retirement = app.state::<LegacyRetirementGate>();
    run_app_protocol(
        AsyncPacketEvidenceChannel::new(stream),
        peer,
        replay,
        ticket_store,
        std::process::id(),
        |case, stages| engine.run_packet_evidence_staged_transaction(&retirement, case, stages),
    )
    .await
}

async fn serve_control_endpoint(
    app: AppHandle,
    listener: tokio::net::UnixListener,
    guard: ControlSocketGuard,
    ticket_store: LauncherTicketStore,
) {
    let _guard = guard;
    let mut replay = SessionReplayGuard::default();
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                eprintln!("physical Packet evidence control listener failed");
                return;
            }
        };
        if let Err(error) = serve_control_connection(&app, stream, &mut replay, &ticket_store).await
        {
            eprintln!("physical Packet evidence control connection failed: {error}");
        }
    }
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

fn exact_tunnel(snapshot: &WireSnapshot, ipv6_enabled: bool) -> bool {
    snapshot.desired_mode == EngineMode::Tunnel
        && snapshot.generation > 0
        && snapshot
            .config_digest
            .as_deref()
            .is_some_and(canonical_session_id)
        && snapshot.ipv6_enabled == ipv6_enabled
        && snapshot.owner == Some(EngineOwner::PacketTunnelSystemExtension)
        && snapshot.phase == "tunnel_active"
        && snapshot.ready
}

fn exact_off(snapshot: &WireSnapshot) -> bool {
    snapshot.desired_mode == EngineMode::Off
        && snapshot.generation > 0
        && snapshot.config_digest.is_none()
        && !snapshot.ipv6_enabled
        && snapshot.owner.is_none()
        && snapshot.phase == "off"
        && !snapshot.ready
}

fn validate_host_baseline(
    observed: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-baseline-observed-v5"
        || observed.sequence != BASELINE_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.baseline_observation_sequence == 0
        || !exact_tunnel(&observed.baseline, true)
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_host_test(
    observed: &HostTestObserved,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let (_, case) = parse_case(case_id)?;
    let exact_case_state = match case {
        ReleasePacketEvidenceCase::StopCleanup => exact_off(&observed.test),
        ReleasePacketEvidenceCase::Ipv6DisabledAbsence => exact_tunnel(&observed.test, false),
        _ => exact_tunnel(&observed.test, true),
    };
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-test-observed-v5"
        || observed.sequence != TEST_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.test_observation_sequence == 0
        || observed.test.generation <= baseline.baseline.generation
        || observed.test.config_digest == baseline.baseline.config_digest
        || !exact_case_state
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_host_restored(
    restored: &HostBaselineRestored,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let test_identity_matches = match (test, restored.test.as_ref()) {
        (Some(test), Some(restored_test)) => {
            restored_test == &test.test
                && restored.test_observation_sequence == Some(test.test_observation_sequence)
                && test.test.generation < restored.restore.generation
        }
        (None, None) => {
            restored.test_observation_sequence.is_none()
                && baseline.baseline.generation <= restored.restore.generation
        }
        _ => false,
    };
    if restored.schema_version != PROTOCOL_VERSION
        || restored.document != "cfw-packet-host-baseline-restored-v5"
        || restored.sequence != RESTORED_SEQUENCE
        || restored.session_id != session_id
        || restored.case_id != case_id
        || restored.baseline != baseline.baseline
        || restored.baseline_observation_sequence != baseline.baseline_observation_sequence
        || restored.restore_observation_sequence == 0
        || !exact_tunnel(&restored.restore, true)
        || restored.restore.config_digest != baseline.baseline.config_digest
        || !test_identity_matches
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_host_aborted(
    aborted: &HostCaptureAborted,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if aborted.schema_version != PROTOCOL_VERSION
        || aborted.document != "cfw-packet-host-capture-aborted-v5"
        || aborted.sequence != RESTORED_SEQUENCE
        || aborted.session_id != session_id
        || aborted.case_id != case_id
        || aborted.baseline != baseline.baseline
        || aborted.baseline_observation_sequence != baseline.baseline_observation_sequence
        || !matches!(
            aborted.code.as_str(),
            "test_apply_failed"
                | "test_snapshot_invalid"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_host_failed(
    failed: &HostFailed,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if failed.schema_version != PROTOCOL_VERSION
        || failed.document != "cfw-packet-host-failed-v5"
        || failed.sequence != RESULT_SEQUENCE
        || failed.session_id != session_id
        || failed.case_id != case_id
        || !matches!(
            failed.code.as_str(),
            "maintenance_busy"
                | "legacy_retirement_blocked"
                | "tunnel_unavailable"
                | "baseline_unavailable"
                | "baseline_mismatch"
                | "projection_failed"
                | "test_apply_failed"
                | "test_snapshot_invalid"
                | "capture_command_failed"
                | "capture_evidence_rejected"
                | "capture_archive_failed"
                | "capture_cancelled"
                | "capture_control_failed"
                | "capture_timeout"
                | "capture_panicked"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
                | "completion_closed"
                | "session_replayed"
                | "session_capacity_exhausted"
                | "session_invalid"
                | "launcher_ticket_replayed"
                | "launcher_ticket_capacity_exhausted"
                | "launcher_ticket_invalid"
                | "launcher_ticket_store_unavailable"
                | "app_control_unavailable"
                | "app_identity_invalid"
                | "app_control_invalid"
                | "app_control_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_host_completed(
    completed: &HostCompleted,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    restored: &HostBaselineRestored,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if completed.schema_version != PROTOCOL_VERSION
        || completed.document != "cfw-packet-host-completed-v5"
        || completed.sequence != RESULT_SEQUENCE
        || completed.session_id != session_id
        || completed.case_id != case_id
        || completed.candidate_observation_sequence == 0
        || completed.candidate_observation_sequence != completed.test_observation_sequence
        || completed.baseline != baseline.baseline
        || completed.baseline_observation_sequence != baseline.baseline_observation_sequence
        || completed.test != test.test
        || completed.test_observation_sequence != test.test_observation_sequence
        || completed.restore != restored.restore
        || completed.restore_observation_sequence != restored.restore_observation_sequence
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

fn cancellation(
    session_id: &str,
    case_id: &str,
    sequence: u32,
    document: &str,
) -> CollectorStageResponse {
    CollectorStageResponse::Failed(CollectorStageFailed {
        case_id: case_id.to_owned(),
        code: "cancelled".to_owned(),
        document: document.to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence,
        session_id: session_id.to_owned(),
    })
}

fn receive_and_validate_final(
    app: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    restored: Option<&HostBaselineRestored>,
    session_id: &str,
    case_id: &str,
) -> Result<HostFinalResponse, PacketEvidenceTransportError> {
    let response: HostFinalResponse = app.receive()?;
    match &response {
        HostFinalResponse::Completed(completed) => {
            let (Some(test), Some(restored)) = (test, restored) else {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            };
            validate_host_completed(completed, baseline, test, restored, session_id, case_id)?;
            Ok(response)
        }
        HostFinalResponse::Failed(failed) => {
            validate_host_failed(failed, session_id, case_id)?;
            Ok(response)
        }
    }
}

fn proxy_failure_code(error: &PacketEvidenceTransportError) -> &'static str {
    match error {
        PacketEvidenceTransportError::EndpointUnavailable
        | PacketEvidenceTransportError::EndpointUnsafe
        | PacketEvidenceTransportError::EndpointActive
        | PacketEvidenceTransportError::EndpointCleanupFailed => "app_control_unavailable",
        PacketEvidenceTransportError::InvalidPeer
        | PacketEvidenceTransportError::InvalidPeerExecutable
        | PacketEvidenceTransportError::InvalidPeerCodeIdentity
        | PacketEvidenceTransportError::InvalidCandidate => "app_identity_invalid",
        PacketEvidenceTransportError::InvalidFrame
        | PacketEvidenceTransportError::InvalidResponse
        | PacketEvidenceTransportError::FrameBound
        | PacketEvidenceTransportError::AncillaryData
        | PacketEvidenceTransportError::AncillaryCleanup
        | PacketEvidenceTransportError::InvalidSession
        | PacketEvidenceTransportError::ReplayedSession
        | PacketEvidenceTransportError::SessionCapacity
        | PacketEvidenceTransportError::LauncherTicketReplayed
        | PacketEvidenceTransportError::LauncherTicketCapacity
        | PacketEvidenceTransportError::InvalidCase => "app_control_invalid",
        PacketEvidenceTransportError::InvalidDescriptor
        | PacketEvidenceTransportError::TruncatedFrame
        | PacketEvidenceTransportError::WriteFailed
        | PacketEvidenceTransportError::LauncherTicketUnsafe
        | PacketEvidenceTransportError::LauncherTicketCommitUncertain => "app_control_failed",
    }
}

fn relay_aborted_finalization(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    aborted: HostCaptureAborted,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    validate_host_aborted(&aborted, baseline, session_id, case_id)?;
    if let Err(error) = collector.send(&aborted) {
        // The collector may have timed out its prior stage while keeping the
        // channel open, or it may have already exited. Either way, the Host
        // finish callback is still waiting for one terminal frame. Unblock
        // that callback before returning the collector-side failure so the
        // actor-owned restore/final result can reach a terminal state.
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(error);
    }
    let final_capture: CollectorStageResponse = match collector.receive() {
        Ok(response) => response,
        Err(error) => {
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final =
                receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
            return Err(error);
        }
    };
    let cleanup_result = stage_result(
        &final_capture,
        session_id,
        case_id,
        CAPTURE_COMPLETED_SEQUENCE,
        "cfw-packet-collector-capture-completed-v5",
        "cfw-packet-collector-capture-complete-failed-v5",
    );
    if cleanup_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    app.send(&final_capture)?;
    let final_response =
        receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
    let HostFinalResponse::Failed(failed) = &final_response else {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    };
    let expected_code = match cleanup_result {
        Ok(()) => aborted.code.as_str(),
        Err(error) => capture_failure_code(error),
    };
    if failed.code != expected_code {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    collector.send(&final_response)
}

fn handle_collector_test_submit_error(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    session_id: &str,
    case_id: &str,
    original: PacketEvidenceTransportError,
) -> Result<(), PacketEvidenceTransportError> {
    let restored_response: HostRestoreResponse = app.receive()?;
    match restored_response {
        HostRestoreResponse::Failed(failed) => {
            validate_host_failed(&failed, session_id, case_id)?;
            collector.send(&failed)
        }
        HostRestoreResponse::Aborted(aborted) => {
            // A collector read timeout does not prove that the collector
            // process exited. Relay the Host abort and give it the same
            // terminal cleanup opportunity as the normal response path.
            relay_aborted_finalization(app, collector, baseline, aborted, session_id, case_id)
        }
        HostRestoreResponse::Restored(restored) => {
            validate_host_restored(&restored, baseline, Some(test), session_id, case_id)?;
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final = receive_and_validate_final(
                app,
                baseline,
                Some(test),
                Some(&restored),
                session_id,
                case_id,
            )?;
            Err(original)
        }
    }
}

fn proxy_authenticated_transaction(
    collector: &mut PacketEvidenceChannel,
    hello: &CollectorHello,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let mut app = PacketEvidenceChannel::connect(&control_socket_path()?)?;
    if app.peer.pid == std::process::id() {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_same_executable_peer(app.peer)?;
    validate_signed_peer(app.peer)?;
    let proxy = process_bsd_info(
        libc::pid_t::try_from(std::process::id())
            .map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
    )?;
    let binding = LauncherBinding {
        case_id: case_id.to_owned(),
        collector_audit_token: encode_identity(&collector.peer.audit_token),
        collector_pid: collector.peer.pid,
        collector_start_time_unix_us: collector.peer.start_time_unix_us,
        collector_uid: collector.peer.uid,
        expires_at_unix_ms: hello.expires_at_unix_ms,
        issued_at_unix_ms: hello.issued_at_unix_ms,
        proxy_pid: std::process::id(),
        proxy_start_time_unix_us: process_start_time_unix_us(&proxy)?,
        proxy_uid: unsafe { libc::geteuid() },
        session_id: hello.session_id.clone(),
    };
    app.send(&AppTicketRequest {
        binding: binding.clone(),
        document: "cfw-packet-app-ticket-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
    })?;
    let ticket_response: HostTicketResponse = app.receive()?;
    let ticket = match ticket_response {
        HostTicketResponse::Issued(ticket) => ticket,
        HostTicketResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            return collector.send(&failed);
        }
    };
    validate_ticket_issued(&ticket, &binding)?;
    app.send(&AppRequest {
        binding,
        document: "cfw-packet-app-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: REQUEST_SEQUENCE,
        ticket_id: ticket.ticket_id,
    })?;
    app.set_transaction_timeout()?;
    collector.set_transaction_timeout()?;

    let first: HostBaselineResponse = app.receive()?;
    match first {
        HostBaselineResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            collector.send(&failed)
        }
        HostBaselineResponse::Observed(baseline) => {
            validate_host_baseline(&baseline, &hello.session_id, case_id)?;
            collector.send(&baseline)?;
            let capture_started: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_STARTED_SEQUENCE,
                        "cfw-packet-collector-capture-start-failed-v5",
                    ))?;
                    let terminal: HostTestResponse = app.receive()?;
                    let restored = match terminal {
                        HostTestResponse::Restored(restored) => {
                            validate_host_restored(
                                &restored,
                                &baseline,
                                None,
                                &hello.session_id,
                                case_id,
                            )?;
                            Some(restored)
                        }
                        HostTestResponse::Aborted(aborted) => {
                            validate_host_aborted(&aborted, &baseline, &hello.session_id, case_id)?;
                            None
                        }
                        HostTestResponse::Failed(failed) => {
                            validate_host_failed(&failed, &hello.session_id, case_id)?;
                            return Err(error);
                        }
                        HostTestResponse::Observed(_) => {
                            return Err(PacketEvidenceTransportError::InvalidResponse);
                        }
                    };
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        restored.as_ref(),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let capture_start_result = stage_result(
                &capture_started,
                &hello.session_id,
                case_id,
                CAPTURE_STARTED_SEQUENCE,
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-start-failed-v5",
            );
            // The actor-owning Host must see every exact bounded stage frame,
            // including one whose semantics are invalid. Begin may already
            // have produced a collector side effect, so only the Host can
            // restore and drive the take-once terminal cleanup.
            app.send(&capture_started)?;

            let test_response: HostTestResponse = app.receive()?;
            let test = match test_response {
                HostTestResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostTestResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostTestResponse::Restored(restored) => {
                    validate_host_restored(&restored, &baseline, None, &hello.session_id, case_id)?;
                    collector.send(&restored)?;
                    let final_capture: CollectorStageResponse = collector.receive()?;
                    let final_result = stage_result(
                        &final_capture,
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-completed-v5",
                        "cfw-packet-collector-capture-complete-failed-v5",
                    );
                    if final_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                        app.send(&cancellation(
                            &hello.session_id,
                            case_id,
                            CAPTURE_COMPLETED_SEQUENCE,
                            "cfw-packet-collector-capture-complete-failed-v5",
                        ))?;
                        let _final = receive_and_validate_final(
                            &mut app,
                            &baseline,
                            None,
                            Some(&restored),
                            &hello.session_id,
                            case_id,
                        )?;
                        return Err(PacketEvidenceTransportError::InvalidFrame);
                    }
                    app.send(&final_capture)?;
                    let final_response = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    let expected_failure = match final_result {
                        Err(error) => Some(capture_failure_code(error)),
                        Ok(()) => capture_start_result.err().map(capture_failure_code),
                    };
                    if let Some(expected_failure) = expected_failure
                        && !matches!(
                            &final_response,
                            HostFinalResponse::Failed(failed) if failed.code == expected_failure
                        )
                    {
                        return Err(PacketEvidenceTransportError::InvalidResponse);
                    }
                    return collector.send(&final_response);
                }
                HostTestResponse::Observed(test) => test,
            };
            validate_host_test(&test, &baseline, &hello.session_id, case_id)?;
            collector.send(&test)?;
            let test_submitted: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        TEST_SUBMITTED_SEQUENCE,
                        "cfw-packet-collector-test-submit-failed-v5",
                    ))?;
                    return handle_collector_test_submit_error(
                        &mut app,
                        collector,
                        &baseline,
                        &test,
                        &hello.session_id,
                        case_id,
                        error,
                    );
                }
            };
            let test_submit_result = stage_result(
                &test_submitted,
                &hello.session_id,
                case_id,
                TEST_SUBMITTED_SEQUENCE,
                "cfw-packet-collector-test-submitted-v5",
                "cfw-packet-collector-test-submit-failed-v5",
            );
            // Forward an exact, bounded frame even when its stage semantics are
            // invalid. The actor-owning Host independently maps it to a typed
            // control-channel failure, restores the baseline, and invokes the
            // one terminal collector cleanup. Returning here would strand a
            // capture that was already acknowledged as started.
            app.send(&test_submitted)?;

            let restored_response: HostRestoreResponse = app.receive()?;
            let restored = match restored_response {
                HostRestoreResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostRestoreResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostRestoreResponse::Restored(restored) => restored,
            };
            validate_host_restored(
                &restored,
                &baseline,
                Some(&test),
                &hello.session_id,
                case_id,
            )?;
            collector.send(&restored)?;
            let final_capture: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        Some(&test),
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let final_capture_result = stage_result(
                &final_capture,
                &hello.session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-completed-v5",
                "cfw-packet-collector-capture-complete-failed-v5",
            );
            if final_capture_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                app.send(&cancellation(
                    &hello.session_id,
                    case_id,
                    CAPTURE_COMPLETED_SEQUENCE,
                    "cfw-packet-collector-capture-complete-failed-v5",
                ))?;
                let _final = receive_and_validate_final(
                    &mut app,
                    &baseline,
                    Some(&test),
                    Some(&restored),
                    &hello.session_id,
                    case_id,
                )?;
                return Err(PacketEvidenceTransportError::InvalidFrame);
            }
            app.send(&final_capture)?;
            let final_response = receive_and_validate_final(
                &mut app,
                &baseline,
                Some(&test),
                Some(&restored),
                &hello.session_id,
                case_id,
            )?;
            let expected_failure = match final_capture_result {
                Err(error) => Some(capture_failure_code(error)),
                Ok(()) => test_submit_result.err().map(capture_failure_code),
            };
            if let Some(expected_failure) = expected_failure
                && !matches!(
                    &final_response,
                    HostFinalResponse::Failed(failed) if failed.code == expected_failure
                )
            {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            }
            collector.send(&final_response)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;

    use cfw_engine_api::{
        EngineCommandContext, EngineMode, EngineOwner, EngineSnapshot, EngineState, RuntimeIdentity,
    };
    use tempfile::tempdir;

    fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).expect("length");
        let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut body).expect("body");
        body
    }

    fn write_body(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .expect("length");
        stream.write_all(body).expect("body");
    }

    fn session(now: u64) -> CollectorHello {
        CollectorHello {
            collector_pid: std::process::id(),
            collector_uid: unsafe { libc::geteuid() },
            document: "cfw-packet-collector-hello-v5".to_owned(),
            expires_at_unix_ms: now + SESSION_LIFETIME_MS,
            issued_at_unix_ms: now,
            schema_version: PROTOCOL_VERSION,
            session_id: "a".repeat(64),
        }
    }

    fn snapshot_receipt(generation: u64, digest: char) -> PacketEvidenceSnapshotReceipt {
        let config_digest = digest.to_string().repeat(64);
        PacketEvidenceSnapshotReceipt::from_exact(
            &EngineSnapshot {
                desired_mode: EngineMode::Tunnel,
                state: EngineState::TunnelActive {
                    runtime: RuntimeIdentity {
                        owner: EngineOwner::PacketTunnelSystemExtension,
                        context: EngineCommandContext {
                            installation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                            config_epoch: 1,
                            generation,
                        },
                        config_digest: config_digest.clone(),
                        ready: true,
                    },
                },
                generation,
                config_digest: Some(config_digest),
            },
            true,
        )
        .expect("exact receipt")
    }

    fn ticket_store(root: &Path) -> LauncherTicketStore {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("private ticket root");
        LauncherTicketStore::open(root).expect("ticket store")
    }

    fn app_ticket_request(now: u64, peer: PeerIdentity, session_id: &str) -> AppTicketRequest {
        let collector_pid = unsafe { libc::getppid() };
        let collector = process_bsd_info(collector_pid).expect("live collector parent");
        let binding = LauncherBinding {
            case_id: "dns-a-primary".to_owned(),
            collector_audit_token: "a".repeat(64),
            collector_pid: u32::try_from(collector_pid).expect("collector pid"),
            collector_start_time_unix_us: process_start_time_unix_us(&collector)
                .expect("collector start"),
            collector_uid: collector.pbi_uid,
            expires_at_unix_ms: now + SESSION_LIFETIME_MS,
            issued_at_unix_ms: now,
            proxy_pid: peer.pid,
            proxy_start_time_unix_us: peer.start_time_unix_us,
            proxy_uid: peer.uid,
            session_id: session_id.to_owned(),
        };
        AppTicketRequest {
            binding,
            document: "cfw-packet-app-ticket-request-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: TICKET_SEQUENCE,
        }
    }

    async fn send_ticketed_app_request(
        collector: &mut AsyncPacketEvidenceChannel,
        request: &AppTicketRequest,
    ) {
        collector.send(request).await.expect("ticket request");
        let issued: HostTicketIssued = collector.receive().await.expect("ticket issued");
        validate_ticket_issued(&issued, &request.binding).expect("exact ticket");
        collector
            .send(&AppRequest {
                binding: request.binding.clone(),
                document: "cfw-packet-app-request-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: REQUEST_SEQUENCE,
                ticket_id: issued.ticket_id,
            })
            .await
            .expect("ticket consumption request");
    }

    fn async_pair() -> (
        AsyncPacketEvidenceChannel,
        AsyncPacketEvidenceChannel,
        PeerIdentity,
    ) {
        let (app, collector) = UnixStream::pair().expect("pair");
        let peer = validate_connected_unix_stream(app.as_raw_fd()).expect("peer");
        app.set_nonblocking(true).expect("app nonblocking");
        collector
            .set_nonblocking(true)
            .expect("collector nonblocking");
        (
            AsyncPacketEvidenceChannel::new(
                tokio::net::UnixStream::from_std(app).expect("async app"),
            ),
            AsyncPacketEvidenceChannel::new(
                tokio::net::UnixStream::from_std(collector).expect("async collector"),
            ),
            peer,
        )
    }

    #[tokio::test]
    async fn app_protocol_happy_path_returns_only_the_closed_receipt() {
        let now = now_unix_ms().expect("time");
        let session_id = "c".repeat(64);
        let (app, mut collector, peer) = async_pair();
        let request = app_ticket_request(now, peer, &session_id);
        let ticket_root = tempdir().expect("ticket root");
        let ticket_store = ticket_store(ticket_root.path());
        let mut replay = SessionReplayGuard::default();
        let app_side = run_app_protocol(
            app,
            peer,
            &mut replay,
            &ticket_store,
            u32::MAX,
            |case, stages| async move {
                let PacketEvidenceStages {
                    begin_capture,
                    exercise_test,
                    finish_capture,
                } = stages;
                let baseline = snapshot_receipt(7, 'a');
                let test = snapshot_receipt(8, 'b');
                begin_capture(PacketEvidenceBaselineReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                })
                .await?;
                exercise_test(PacketEvidenceTestReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                    test: test.clone(),
                    test_observation_sequence: 11,
                })
                .await?;
                let restore = snapshot_receipt(9, 'a');
                finish_capture(PacketEvidenceCaptureTerminal::Restored(
                    PacketEvidenceCaptureFinalizing {
                        case,
                        baseline: baseline.clone(),
                        baseline_observation_sequence: 10,
                        test: Some(test.clone()),
                        test_observation_sequence: Some(11),
                        restore: restore.clone(),
                        restore_observation_sequence: 12,
                    },
                ))
                .await?;
                Ok(PacketEvidenceTransactionOutcome {
                    baseline,
                    baseline_observation_sequence: 10,
                    test,
                    test_observation_sequence: 11,
                    restore,
                    restore_observation_sequence: 12,
                    candidate_observation_sequence: 11,
                })
            },
        );
        let collector_side = async {
            send_ticketed_app_request(&mut collector, &request).await;
            let baseline: HostBaselineObserved =
                tokio::time::timeout(Duration::from_secs(2), collector.receive())
                    .await
                    .expect("baseline timeout")
                    .expect("baseline");
            validate_host_baseline(&baseline, &session_id, "dns-a-primary")
                .expect("exact baseline");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-started-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_STARTED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("capture started");
            let test: HostTestObserved = collector.receive().await.expect("test");
            validate_host_test(&test, &baseline, &session_id, "dns-a-primary").expect("exact test");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-test-submitted-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: TEST_SUBMITTED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("test submitted");
            let restored: HostBaselineRestored = collector.receive().await.expect("restore");
            validate_host_restored(
                &restored,
                &baseline,
                Some(&test),
                &session_id,
                "dns-a-primary",
            )
            .expect("exact restore");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_COMPLETED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("capture complete");
            let completed: HostFinalResponse =
                tokio::time::timeout(Duration::from_secs(2), collector.receive())
                    .await
                    .expect("completed timeout")
                    .expect("completed");
            let HostFinalResponse::Completed(completed) = completed else {
                panic!("transaction unexpectedly failed");
            };
            validate_host_completed(
                &completed,
                &baseline,
                &test,
                &restored,
                &session_id,
                "dns-a-primary",
            )
            .expect("exact completion");
            assert_eq!(completed.candidate_observation_sequence, 11);
        };
        let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(app_side, collector_side)
        })
        .await
        .expect("complete protocol timeout");
        app_result.expect("app protocol");
    }

    #[tokio::test]
    async fn duplicate_request_in_capture_slot_is_typed_and_cannot_skip_restore() {
        let now = now_unix_ms().expect("time");
        let session_id = "d".repeat(64);
        let (app, mut collector, peer) = async_pair();
        let request = app_ticket_request(now, peer, &session_id);
        let duplicate = CollectorRequest {
            case_id: request.binding.case_id.clone(),
            document: "cfw-packet-collector-request-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: REQUEST_SEQUENCE,
            session_id: session_id.clone(),
        };
        let ticket_root = tempdir().expect("ticket root");
        let ticket_store = ticket_store(ticket_root.path());
        let mut replay = SessionReplayGuard::default();
        let app_side = run_app_protocol(
            app,
            peer,
            &mut replay,
            &ticket_store,
            u32::MAX,
            |case, stages| async move {
                let PacketEvidenceStages {
                    begin_capture,
                    finish_capture,
                    ..
                } = stages;
                let baseline = snapshot_receipt(7, 'a');
                let failure = begin_capture(PacketEvidenceBaselineReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                })
                .await
                .expect_err("duplicate frame was not rejected");
                assert_eq!(failure, PacketEvidenceCaptureFailure::ControlChannelFailed);
                finish_capture(PacketEvidenceCaptureTerminal::Restored(
                    PacketEvidenceCaptureFinalizing {
                        case,
                        baseline: baseline.clone(),
                        baseline_observation_sequence: 10,
                        test: None,
                        test_observation_sequence: None,
                        restore: baseline,
                        restore_observation_sequence: 11,
                    },
                ))
                .await?;
                Err(PacketEvidenceTransactionError::Capture(failure))
            },
        );
        let collector_side = async {
            send_ticketed_app_request(&mut collector, &request).await;
            let baseline: HostBaselineObserved =
                tokio::time::timeout(Duration::from_secs(2), collector.receive())
                    .await
                    .expect("baseline timeout")
                    .expect("baseline");
            collector.send(&duplicate).await.expect("duplicate");
            let restored: HostBaselineRestored = collector.receive().await.expect("restore");
            validate_host_restored(&restored, &baseline, None, &session_id, "dns-a-primary")
                .expect("exact ambiguous-begin restore");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_COMPLETED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("terminal cleanup");
            let failed: HostFinalResponse =
                tokio::time::timeout(Duration::from_secs(2), collector.receive())
                    .await
                    .expect("failure timeout")
                    .expect("failed");
            let HostFinalResponse::Failed(failed) = failed else {
                panic!("duplicate frame unexpectedly succeeded");
            };
            assert_eq!(failed.code, "capture_control_failed");
        };
        let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(app_side, collector_side)
        })
        .await
        .expect("duplicate protocol timeout");
        app_result.expect("typed final failure");
    }

    #[tokio::test]
    async fn semantic_test_stage_failure_restores_and_reaches_terminal_cleanup() {
        let now = now_unix_ms().expect("time");
        let session_id = "f".repeat(64);
        let (app, mut collector, peer) = async_pair();
        let request = app_ticket_request(now, peer, &session_id);
        let ticket_root = tempdir().expect("ticket root");
        let ticket_store = ticket_store(ticket_root.path());
        let mut replay = SessionReplayGuard::default();
        let app_side = run_app_protocol(
            app,
            peer,
            &mut replay,
            &ticket_store,
            u32::MAX,
            |case, stages| async move {
                let PacketEvidenceStages {
                    begin_capture,
                    exercise_test,
                    finish_capture,
                } = stages;
                let baseline = snapshot_receipt(7, 'a');
                let test = snapshot_receipt(8, 'b');
                begin_capture(PacketEvidenceBaselineReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                })
                .await?;
                let failure = exercise_test(PacketEvidenceTestReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                    test: test.clone(),
                    test_observation_sequence: 11,
                })
                .await
                .expect_err("semantically invalid stage response");
                assert_eq!(failure, PacketEvidenceCaptureFailure::ControlChannelFailed);
                let restore = snapshot_receipt(9, 'a');
                finish_capture(PacketEvidenceCaptureTerminal::Restored(
                    PacketEvidenceCaptureFinalizing {
                        case,
                        baseline,
                        baseline_observation_sequence: 10,
                        test: Some(test),
                        test_observation_sequence: Some(11),
                        restore,
                        restore_observation_sequence: 12,
                    },
                ))
                .await?;
                Err(PacketEvidenceTransactionError::Capture(failure))
            },
        );
        let collector_side = async {
            send_ticketed_app_request(&mut collector, &request).await;
            let _baseline: HostBaselineObserved = collector.receive().await.expect("baseline");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-started-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_STARTED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("capture started");
            let _test: HostTestObserved = collector.receive().await.expect("test");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-started-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: TEST_SUBMITTED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("semantic test-stage failure");
            let _restored: HostBaselineRestored =
                collector.receive().await.expect("restored baseline");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_COMPLETED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("terminal cleanup");
            let final_response: HostFinalResponse = collector.receive().await.expect("final");
            let HostFinalResponse::Failed(failed) = final_response else {
                panic!("invalid test-stage response unexpectedly succeeded");
            };
            assert_eq!(failed.code, "capture_control_failed");
        };
        let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(app_side, collector_side)
        })
        .await
        .expect("semantic failure protocol hard timeout");
        app_result.expect("typed semantic failure");
    }

    #[tokio::test]
    async fn aborted_engine_path_requires_collector_terminal_cleanup_before_failure() {
        let now = now_unix_ms().expect("time");
        let session_id = "e".repeat(64);
        let (app, mut collector, peer) = async_pair();
        let request = app_ticket_request(now, peer, &session_id);
        let ticket_root = tempdir().expect("ticket root");
        let ticket_store = ticket_store(ticket_root.path());
        let mut replay = SessionReplayGuard::default();
        let app_side = run_app_protocol(
            app,
            peer,
            &mut replay,
            &ticket_store,
            u32::MAX,
            |case, stages| async move {
                let PacketEvidenceStages {
                    begin_capture,
                    finish_capture,
                    ..
                } = stages;
                let baseline = snapshot_receipt(7, 'a');
                begin_capture(PacketEvidenceBaselineReady {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                })
                .await?;
                finish_capture(PacketEvidenceCaptureTerminal::Aborted(
                    PacketEvidenceCaptureAborted {
                        case,
                        baseline,
                        baseline_observation_sequence: 10,
                        reason: PacketEvidenceAbortReason::ObservationFailed,
                    },
                ))
                .await?;
                Err(PacketEvidenceTransactionError::Observation(
                    "injected observation failure".to_owned(),
                ))
            },
        );
        let collector_side = async {
            send_ticketed_app_request(&mut collector, &request).await;
            let baseline: HostBaselineObserved = collector.receive().await.expect("baseline");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-started-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_STARTED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("capture started");
            let aborted: HostCaptureAborted = collector.receive().await.expect("abort");
            validate_host_aborted(&aborted, &baseline, &session_id, "dns-a-primary")
                .expect("exact abort");
            collector
                .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                    case_id: "dns-a-primary".to_owned(),
                    document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                    schema_version: PROTOCOL_VERSION,
                    sequence: CAPTURE_COMPLETED_SEQUENCE,
                    session_id: session_id.clone(),
                }))
                .await
                .expect("terminal cleanup");
            let final_response: HostFinalResponse = collector.receive().await.expect("final");
            let HostFinalResponse::Failed(failed) = final_response else {
                panic!("aborted transaction unexpectedly completed");
            };
            assert_eq!(failed.code, "observation_failed");
        };
        let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(app_side, collector_side)
        })
        .await
        .expect("aborted protocol hard timeout");
        app_result.expect("typed aborted protocol");
    }

    #[test]
    fn collector_test_submit_error_relays_host_abort_and_drains_finalization() {
        let session_id = "g".repeat(64);
        let case_id = "dns-a-primary";
        let baseline_receipt = snapshot_receipt(7, 'a');
        let test_receipt = snapshot_receipt(8, 'b');
        let baseline = HostBaselineObserved {
            baseline: wire_snapshot(&baseline_receipt),
            baseline_observation_sequence: 10,
            case_id: case_id.to_owned(),
            document: "cfw-packet-host-baseline-observed-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: BASELINE_SEQUENCE,
            session_id: session_id.clone(),
        };
        let test = HostTestObserved {
            case_id: case_id.to_owned(),
            document: "cfw-packet-host-test-observed-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: TEST_SEQUENCE,
            session_id: session_id.clone(),
            test: wire_snapshot(&test_receipt),
            test_observation_sequence: 11,
        };
        let aborted = HostCaptureAborted {
            baseline: baseline.baseline.clone(),
            baseline_observation_sequence: baseline.baseline_observation_sequence,
            case_id: case_id.to_owned(),
            code: "restore_unproven_quarantined".to_owned(),
            document: "cfw-packet-host-capture-aborted-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: RESTORED_SEQUENCE,
            session_id: session_id.clone(),
        };
        let final_response =
            HostFinalResponse::Failed(host_failed(&session_id, case_id, &aborted.code));
        let terminal_cleanup = CollectorStageResponse::Complete(CollectorStageComplete {
            case_id: case_id.to_owned(),
            document: "cfw-packet-collector-capture-completed-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: CAPTURE_COMPLETED_SEQUENCE,
            session_id: session_id.clone(),
        });
        let (app_proxy, app_host) = UnixStream::pair().expect("app pair");
        let (collector_proxy, collector_peer) = UnixStream::pair().expect("collector pair");
        let mut app = PacketEvidenceChannel::from_fd(app_proxy.into_raw_fd()).expect("app");
        let mut collector =
            PacketEvidenceChannel::from_fd(collector_proxy.into_raw_fd()).expect("collector");
        let mut host = PacketEvidenceChannel::from_fd(app_host.into_raw_fd()).expect("host");
        let mut collector_peer =
            PacketEvidenceChannel::from_fd(collector_peer.into_raw_fd()).expect("peer");

        std::thread::scope(|scope| {
            let host_aborted = aborted.clone();
            let host_final = final_response.clone();
            let host_case_id = case_id.to_owned();
            let host_session_id = session_id.clone();
            let host_thread = scope.spawn(move || {
                host.send(&host_aborted).expect("host abort");
                let received: CollectorStageResponse = host.receive().expect("host cleanup");
                let CollectorStageResponse::Complete(received) = received else {
                    panic!("host did not receive terminal cleanup");
                };
                assert_eq!(received.case_id, host_case_id);
                assert_eq!(
                    received.document,
                    "cfw-packet-collector-capture-completed-v5"
                );
                assert_eq!(received.schema_version, PROTOCOL_VERSION);
                assert_eq!(received.sequence, CAPTURE_COMPLETED_SEQUENCE);
                assert_eq!(received.session_id, host_session_id);
                host.send(&host_final).expect("host final");
            });

            let peer_baseline = baseline.clone();
            let peer_cleanup = terminal_cleanup.clone();
            let peer_session_id = session_id.clone();
            let peer_case_id = case_id.to_owned();
            let peer_thread = scope.spawn(move || {
                let received: HostCaptureAborted =
                    collector_peer.receive().expect("collector abort");
                validate_host_aborted(&received, &peer_baseline, &peer_session_id, &peer_case_id)
                    .expect("exact relayed abort");
                assert_eq!(received.code, "restore_unproven_quarantined");
                collector_peer
                    .send(&peer_cleanup)
                    .expect("collector cleanup");
                let received_final: HostFinalResponse =
                    collector_peer.receive().expect("collector final");
                let HostFinalResponse::Failed(received_final) = received_final else {
                    panic!("collector did not receive typed final failure");
                };
                assert_eq!(received_final.code, "restore_unproven_quarantined");
            });

            handle_collector_test_submit_error(
                &mut app,
                &mut collector,
                &baseline,
                &test,
                &session_id,
                case_id,
                PacketEvidenceTransportError::TruncatedFrame,
            )
            .expect("aborted response was relayed after collector read failure");

            host_thread.join().expect("host thread");
            peer_thread.join().expect("collector thread");
        });
    }

    #[tokio::test]
    async fn async_readiness_wait_yields_to_the_outer_deadline() {
        let (mut app, _collector, _peer) = async_pair();
        let result =
            tokio::time::timeout(Duration::from_millis(25), app.receive::<CollectorRequest>())
                .await;
        assert!(result.is_err(), "idle read must yield to Tokio's timer");
    }

    #[tokio::test]
    async fn async_truncated_body_reaches_eof_without_blocking() {
        let (app, mut collector) = UnixStream::pair().expect("pair");
        app.set_nonblocking(true).expect("app nonblocking");
        collector
            .write_all(&10_u32.to_be_bytes())
            .expect("declared length");
        collector.write_all(b"{}").expect("partial body");
        collector
            .shutdown(std::net::Shutdown::Write)
            .expect("collector shutdown");
        let mut app = AsyncPacketEvidenceChannel::new(
            tokio::net::UnixStream::from_std(app).expect("async app"),
        );
        let result =
            tokio::time::timeout(Duration::from_secs(1), app.receive::<CollectorRequest>())
                .await
                .expect("EOF timeout");
        assert!(matches!(
            result,
            Err(PacketEvidenceTransportError::TruncatedFrame)
        ));
    }

    #[test]
    fn exact_collector_identity_session_and_case_are_closed() {
        let now = 1_700_000_000_000;
        let peer = PeerIdentity {
            audit_token: [0; 32],
            pid: std::process::id(),
            start_time_unix_us: 1,
            uid: unsafe { libc::geteuid() },
        };
        let hello = session(now);
        validate_collector_hello(&hello, peer, now).expect("exact hello");
        let request = CollectorRequest {
            case_id: "dns-aaaa-secondary".to_owned(),
            document: "cfw-packet-collector-request-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: REQUEST_SEQUENCE,
            session_id: hello.session_id.clone(),
        };
        assert_eq!(
            validate_collector_request(&request, &hello)
                .expect("fixed case")
                .1,
            ReleasePacketEvidenceCase::DnsAaaaSecondary
        );

        let mut wrong_pid = session(now);
        wrong_pid.collector_pid = peer.pid.saturating_add(1);
        assert!(matches!(
            validate_collector_hello(&wrong_pid, peer, now),
            Err(PacketEvidenceTransportError::InvalidPeer)
        ));
        let expired = session(now);
        assert!(matches!(
            validate_collector_hello(&expired, peer, now + SESSION_LIFETIME_MS + 1),
            Err(PacketEvidenceTransportError::InvalidSession)
        ));
        let mut unknown = request;
        unknown.case_id = "dns-caller-address".to_owned();
        assert!(matches!(
            validate_collector_request(&unknown, &hello),
            Err(PacketEvidenceTransportError::InvalidCase)
        ));
    }

    #[test]
    fn unbound_audit_token_cannot_satisfy_the_release_host_requirement() {
        let peer = PeerIdentity {
            audit_token: [0; 32],
            pid: std::process::id(),
            start_time_unix_us: 1,
            uid: unsafe { libc::geteuid() },
        };
        assert!(matches!(
            validate_signed_peer(peer),
            Err(PacketEvidenceTransportError::InvalidPeerCodeIdentity)
        ));
    }

    #[test]
    fn duplicate_sessions_remain_rejected_until_expiry() {
        let now = 1_700_000_000_000;
        let mut replay = SessionReplayGuard::default();
        replay
            .admit("a".repeat(64).as_str(), now + SESSION_LIFETIME_MS, now)
            .expect("first admission");
        assert!(matches!(
            replay.admit("a".repeat(64).as_str(), now + SESSION_LIFETIME_MS, now),
            Err(PacketEvidenceTransportError::ReplayedSession)
        ));
        replay
            .admit(
                "a".repeat(64).as_str(),
                now + (2 * SESSION_LIFETIME_MS),
                now + SESSION_LIFETIME_MS + 1,
            )
            .expect("expired session removed");
    }

    #[test]
    fn durable_launcher_ticket_rejects_replay_after_store_restart() {
        let now = 1_700_000_000_000;
        let session_id = "7".repeat(64);
        let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
        let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
        let binding = app_ticket_request(now, peer, &session_id).binding;
        let root = tempdir().expect("ticket root");
        {
            let store = ticket_store(root.path());
            store
                .consume(&binding, &"8".repeat(64), now)
                .expect("first durable consumption");
        }
        let restarted = LauncherTicketStore::open(root.path()).expect("restarted ticket store");
        assert!(matches!(
            restarted.consume(&binding, &"9".repeat(64), now + 1),
            Err(PacketEvidenceTransportError::LauncherTicketReplayed)
        ));
        let records = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
            .expect("ticket records")
            .collect::<Result<Vec<_>, _>>()
            .expect("ticket entries");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].file_name(),
            OsString::from(format!("consumed-{session_id}.json"))
        );
    }

    #[test]
    fn zero_byte_pending_ticket_is_swept_without_poisoning_store() {
        let now = 1_700_000_000_000;
        let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
        let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
        let root = tempdir().expect("ticket root");
        let store = ticket_store(root.path());
        let pending_id = "a".repeat(64);
        let pending_name = launcher_ticket_pending_filename(&pending_id).expect("pending name");
        let descriptor = unsafe {
            libc::openat(
                store.directory.as_raw_fd(),
                pending_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        assert_ne!(descriptor, -1, "create interrupted pending ticket");
        drop(unsafe { File::from_raw_fd(descriptor) });

        let binding = app_ticket_request(now, peer, &"b".repeat(64)).binding;
        store
            .consume(&binding, &"c".repeat(64), now)
            .expect("pending sweep followed by durable consumption");
        let names = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
            .expect("ticket records")
            .map(|entry| entry.expect("ticket entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![OsString::from(format!("consumed-{}.json", "b".repeat(64)))]
        );
    }

    #[test]
    fn expired_launcher_ticket_is_durably_swept_before_session_reuse() {
        let now = 1_700_000_000_000;
        let later = now + SESSION_LIFETIME_MS + SESSION_CLOCK_SKEW_MS + 1;
        let session_id = "d".repeat(64);
        let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
        let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
        let root = tempdir().expect("ticket root");
        let store = ticket_store(root.path());
        let first = app_ticket_request(now, peer, &session_id).binding;
        store
            .consume(&first, &"e".repeat(64), now)
            .expect("first durable ticket");
        let renewed = app_ticket_request(later, peer, &session_id).binding;
        store
            .consume(&renewed, &"f".repeat(64), later)
            .expect("expired tombstone swept before renewed session");
        let name = format!("consumed-{session_id}.json");
        let _lock = store.lock().expect("ticket read lock");
        let record = store
            .read_record_locked(&name)
            .expect("renewed durable ticket");
        assert_eq!(record.binding.issued_at_unix_ms, later);
        assert_eq!(record.ticket_id, "f".repeat(64));
    }

    #[test]
    fn noncanonical_unknown_and_oversized_frames_fail_closed() {
        for (body, expected) in [
            (
                br#"{ "case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
            (
                br#"{"case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","extra":true,"schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
        ] {
            let (host, mut collector) = UnixStream::pair().expect("pair");
            collector
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("collector timeout");
            write_body(&mut collector, body);
            let mut channel =
                PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
            let result: Result<CollectorRequest, _> = channel.receive();
            assert!(matches!(
                result,
                Err(PacketEvidenceTransportError::InvalidFrame)
            ));
            assert_eq!(expected, "invalid");
        }

        let (host, mut collector) = UnixStream::pair().expect("pair");
        collector
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .expect("oversized length");
        let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
        let result: Result<CollectorRequest, _> = channel.receive();
        assert!(matches!(
            result,
            Err(PacketEvidenceTransportError::FrameBound)
        ));
    }

    #[test]
    fn ancillary_descriptors_are_closed_and_rejected() {
        let (host, collector) = UnixStream::pair().expect("pair");
        let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
        let descriptor = fs::File::open("/dev/null").expect("sentinel");
        let payload = [descriptor.as_raw_fd()];
        let mut message = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let bytes = b"\0\0\0\x02{}";
        let mut iovec = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let mut control = [0_usize; 8];
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
            *libc::CMSG_DATA(header).cast::<RawFd>() = payload[0];
            assert_eq!(
                libc::sendmsg(collector.as_raw_fd(), &message, 0),
                bytes.len() as isize
            );
        }
        let result: Result<CollectorRequest, _> = channel.receive();
        assert!(matches!(
            result,
            Err(PacketEvidenceTransportError::AncillaryData)
        ));
    }

    #[test]
    fn host_frames_are_canonical_and_do_not_expose_error_text() {
        let (host, mut collector) = UnixStream::pair().expect("pair");
        let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
        channel
            .send(&host_failed(
                &"a".repeat(64),
                "dns-a-primary",
                "baseline_mismatch",
            ))
            .expect("failure");
        let body = read_frame(&mut collector);
        assert_eq!(
            body,
            br#"{"case_id":"dns-a-primary","code":"baseline_mismatch","document":"cfw-packet-host-failed-v5","schema_version":5,"sequence":8,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
        );
    }

    #[test]
    fn endpoint_guard_unlinks_only_the_exact_bound_socket_inode() {
        let root = tempdir().expect("root");
        let path = root.path().join("control.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        let guard = ControlSocketGuard {
            identity: SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            path: path.clone(),
        };
        drop(listener);
        fs::remove_file(&path).expect("remove original");
        let replacement = UnixListener::bind(&path).expect("replacement");
        drop(guard);
        assert!(path.exists(), "a replacement inode must never be unlinked");
        drop(replacement);
    }

    #[test]
    fn endpoint_guard_unlinks_its_own_socket_on_clean_shutdown() {
        let root = tempdir().expect("root");
        let path = root.path().join("control.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        let guard = ControlSocketGuard {
            identity: SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            path: path.clone(),
        };
        drop(listener);
        drop(guard);
        assert!(!path.exists(), "the exact endpoint inode must be unlinked");
    }

    #[test]
    fn synchronous_setup_registers_control_listener_inside_tauri_runtime() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "the regression requires a setup-equivalent thread without a Tokio reactor"
        );
        let root = tempdir().expect("root");
        let path = root.path().join("control.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let listener = register_control_endpoint(listener)
            .expect("Tauri runtime registration outside a current reactor");
        let client = UnixStream::connect(&path).expect("queued client");
        let accepted = tauri::async_runtime::block_on(async {
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("bounded accept")
                .expect("accepted client")
        });

        drop(accepted);
        drop(client);
    }

    #[test]
    fn endpoint_cleanup_failure_remains_typed_for_the_next_startup() {
        let root = tempdir().expect("root");
        let path = root.path().join("control.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        let stale = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        let result = remove_stale_control_socket_with(&path, stale, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected exact-inode unlink failure",
            ))
        });

        assert!(matches!(
            result,
            Err(PacketEvidenceTransportError::EndpointCleanupFailed)
        ));
        assert!(
            path.exists(),
            "failed cleanup must retain the exact inode for startup diagnosis"
        );
        drop(listener);
        fs::remove_file(path).expect("remove test socket");
    }
}
