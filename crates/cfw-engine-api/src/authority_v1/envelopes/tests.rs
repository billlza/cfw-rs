use super::*;
use crate::authority_v1::test_support::{
    off_snapshot, operation, ready_attestation, stop_directive, stopped_attestation, uuid,
};

fn bind(operation: OperationContext) -> Command {
    Command::BindProxyOwner(BindProxyOwnerRequest {
        operation,
        lease_id: uuid(3),
        capability: OwnerCapability::new(&[9; CAPABILITY_BYTES]).unwrap(),
    })
}

fn redeem(operation: OperationContext) -> Command {
    Command::RedeemTunnelTicket(RedeemTunnelTicketRequest {
        operation,
        lease_id: uuid(3),
        ticket: StartTicket::new(&[7; TICKET_BYTES]).unwrap(),
    })
}

#[test]
fn only_handshake_and_snapshot_are_read_only() {
    assert!(
        Command::Handshake(HandshakeRequest {
            version: ProtocolVersion::v1()
        })
        .is_read_only()
    );
    assert!(Command::Snapshot(SnapshotRequest {}).is_read_only());
    let proxy = operation(AuthorityMode::SystemProxy);
    for command in [
        bind(proxy.clone()),
        redeem(operation(AuthorityMode::Tunnel)),
        Command::AttestReady(ready_attestation(AuthorityMode::SystemProxy)),
        Command::AttestStopped(stopped_attestation()),
        Command::BeginStop(BeginStopRequest {
            expected_revision: proxy.authority_revision,
            lease_id: uuid(3),
            operation: proxy.clone(),
        }),
        Command::CancelPrepared(CancelPreparedRequest {
            expected_revision: proxy.authority_revision,
            operation: proxy,
        }),
    ] {
        assert!(!command.is_read_only());
    }
}

#[test]
fn owner_credentials_are_accepted_only_in_their_own_mode() {
    for mode in [AuthorityMode::LocalProxy, AuthorityMode::SystemProxy] {
        assert!(RequestEnvelope::new(uuid(5), 0, bind(operation(mode))).is_ok());
        assert!(matches!(
            RequestEnvelope::new(uuid(5), 0, redeem(operation(mode))),
            Err(CodecError::BoundViolation)
        ));
    }
    assert!(RequestEnvelope::new(uuid(5), 0, redeem(operation(AuthorityMode::Tunnel))).is_ok());
    assert!(matches!(
        RequestEnvelope::new(uuid(5), 0, bind(operation(AuthorityMode::Tunnel))),
        Err(CodecError::BoundViolation)
    ));

    let mut stale_proxy = operation(AuthorityMode::SystemProxy);
    stale_proxy.authority_revision = 0;
    let mut stale_tunnel = operation(AuthorityMode::Tunnel);
    stale_tunnel.root.epoch = 0;
    assert!(matches!(
        RequestEnvelope::new(uuid(5), 0, bind(stale_proxy)),
        Err(CodecError::BoundViolation)
    ));
    assert!(matches!(
        RequestEnvelope::new(uuid(5), 0, redeem(stale_tunnel)),
        Err(CodecError::BoundViolation)
    ));
}

#[test]
fn request_envelopes_carry_v1_and_refuse_unsupported_features() {
    let envelope = RequestEnvelope::new(uuid(5), 0, Command::Snapshot(SnapshotRequest {})).unwrap();
    assert_eq!(
        (
            envelope.major,
            envelope.minor,
            envelope.required_feature_bits,
            envelope.request_id
        ),
        (MAJOR, MINOR, 0, uuid(5))
    );
    assert!(matches!(
        RequestEnvelope::new(uuid(5), 0b10, Command::Snapshot(SnapshotRequest {})),
        Err(CodecError::UnsupportedRequiredFeatures(0b10))
    ));
}

#[test]
fn events_validate_their_payload() {
    assert_eq!(AuthorityEvent::Snapshot(off_snapshot()).validate(), Ok(()));
    assert_eq!(AuthorityEvent::Stop(stop_directive()).validate(), Ok(()));
    assert_eq!(AuthorityEvent::Revoke(stop_directive()).validate(), Ok(()));

    let mut expired = stop_directive();
    expired.deadline_monotonic_ms = 0;
    assert_eq!(
        AuthorityEvent::Revoke(expired.clone()).validate(),
        Err(CodecError::BoundViolation)
    );
    assert_eq!(
        AuthorityEvent::Stop(expired).validate(),
        Err(CodecError::BoundViolation)
    );
    let mut unrevised = off_snapshot();
    unrevised.revision = 0;
    assert_eq!(
        AuthorityEvent::Snapshot(unrevised).validate(),
        Err(CodecError::BoundViolation)
    );
}

#[test]
fn response_envelopes_carry_v1_and_a_valid_result() {
    let acknowledgement = AuthorityAcknowledgement {
        operation_id: uuid(2),
        revision: 1,
    };
    let envelope = ResponseEnvelope::new(uuid(5), Some(uuid(2)), acknowledgement);
    assert_eq!((envelope.major, envelope.minor), (MAJOR, MINOR));
    assert_eq!(envelope.operation_id, Some(uuid(2)));
    assert_eq!(envelope.validate(), Ok(()));

    let mut newer_major = envelope.clone();
    newer_major.major = 2;
    assert_eq!(newer_major.validate(), Err(CodecError::UnsupportedMajor(2)));
    let mut newer_minor = envelope.clone();
    newer_minor.minor = 2;
    assert_eq!(newer_minor.validate(), Err(CodecError::UnsupportedMinor(2)));
    let mut unrevised = envelope;
    unrevised.result.revision = 0;
    assert_eq!(unrevised.validate(), Err(CodecError::BoundViolation));
}
