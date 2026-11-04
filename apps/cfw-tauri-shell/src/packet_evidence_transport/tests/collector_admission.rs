//! The collector's admission: its exact identity, session and case, a peer
//! without a bound code identity, and a session replayed before it expires.

use super::*;

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
