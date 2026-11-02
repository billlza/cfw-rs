//! Session identity, its time window, stage parsing and replay protection.

use super::*;

pub(super) fn now_unix_ms() -> Result<u64, PacketEvidenceTransportError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PacketEvidenceTransportError::InvalidSession)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| PacketEvidenceTransportError::InvalidSession)
}

pub(super) fn canonical_session_id(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(super) fn encode_identity(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn random_launcher_ticket_id() -> String {
    let mut bytes = [0_u8; 32];
    // SAFETY: `bytes` is live writable storage of the exact length passed to
    // macOS' cryptographic `arc4random_buf`; that API has no partial-success
    // state or caller-controlled source.
    unsafe {
        libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len());
    }
    encode_identity(&bytes)
}

pub(super) fn validate_session_window(
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

pub(super) fn parse_case(
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

pub(super) fn validate_collector_hello(
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

pub(super) fn validate_collector_request(
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

pub(super) fn validate_stage_response(
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

pub(super) fn stage_result(
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
pub(super) struct SessionReplayGuard {
    expirations: BTreeMap<String, u64>,
}

impl SessionReplayGuard {
    pub(super) fn admit(
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
