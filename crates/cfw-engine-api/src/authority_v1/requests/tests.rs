use super::*;
use crate::authority_v1::test_support::{
    configuration, digest, lease_view, operation, rejects, stop_directive, tunnel_options, uuid,
};

#[test]
fn handshake_responses_must_equal_the_v1_limits() {
    rejects(
        &HandshakeResponse::v1(),
        &[
            |response| response.command_timeout_ms += 1,
            |response| response.maximum_configuration_bytes -= 1,
            |response| response.maximum_credential_slots -= 1,
            |response| response.maximum_individual_secret_bytes -= 1,
            |response| response.maximum_mutating_transactions += 1,
            |response| response.maximum_queued_events_per_peer -= 1,
            |response| response.maximum_read_only_requests -= 1,
            |response| response.maximum_total_secret_bytes -= 1,
            |response| response.preparation_lifetime_ms -= 1,
            |response| response.stop_attestation_timeout_ms -= 1,
        ],
    );
    let mut newer = HandshakeResponse::v1();
    newer.version.minor = 2;
    assert_eq!(newer.validate(), Err(CodecError::UnsupportedMinor(2)));
}

#[test]
fn prepare_start_binds_the_configuration_to_its_operation() {
    for mode in [AuthorityMode::SystemProxy, AuthorityMode::Tunnel] {
        let operation = operation(mode);
        let request = PrepareStartRequest {
            configuration: configuration(&operation),
            expected_revision: operation.authority_revision,
            operation,
        };
        rejects(
            &request,
            &[
                |request| request.expected_revision += 1,
                |request| {
                    request.configuration.tunnel_options =
                        match request.configuration.tunnel_options {
                            Some(_) => None,
                            None => Some(tunnel_options()),
                        }
                },
                |request| request.configuration.config_sha256 = digest('c'),
                |request| request.configuration.identity_sha256 = digest('c'),
                |request| request.configuration.byte_count = 0,
                |request| request.operation.root.epoch = 0,
            ],
        );
    }
}

#[test]
fn stop_and_cancel_requests_never_fall_behind_the_operation_revision() {
    let operation = operation(AuthorityMode::SystemProxy);
    let begin = BeginStopRequest {
        expected_revision: operation.authority_revision,
        lease_id: uuid(3),
        operation: operation.clone(),
    };
    rejects(
        &begin,
        &[
            |request| request.expected_revision -= 1,
            |request| request.operation.authority_revision = 0,
        ],
    );
    let cancel = CancelPreparedRequest {
        expected_revision: operation.authority_revision + 1,
        operation,
    };
    rejects(
        &cancel,
        &[
            |request| request.expected_revision = request.operation.authority_revision - 1,
            |request| request.operation.config_sha256.clear(),
        ],
    );
    rejects(
        &stop_directive(),
        &[
            |directive| directive.deadline_monotonic_ms = 0,
            |directive| directive.revision -= 1,
            |directive| directive.operation.identity_sha256.clear(),
        ],
    );
}

#[test]
fn acknowledgements_carry_a_revision() {
    let acknowledgement = AuthorityAcknowledgement {
        operation_id: uuid(2),
        revision: 1,
    };
    rejects(
        &acknowledgement,
        &[|acknowledgement| acknowledgement.revision = 0],
    );
}

fn prepared(mode: AuthorityMode) -> PreparedStart {
    let tunnel = mode == AuthorityMode::Tunnel;
    PreparedStart {
        operation: operation(mode),
        lease_id: uuid(3),
        ticket: tunnel.then(|| StartTicket::new(&[7; TICKET_BYTES]).unwrap()),
        owner_capability: (!tunnel).then(|| OwnerCapability::new(&[9; CAPABILITY_BYTES]).unwrap()),
        expires_monotonic_ms: 40,
        preference_descriptor_sha256: digest('f'),
    }
}

#[test]
fn prepared_starts_hand_out_exactly_the_credential_their_mode_redeems() {
    for mode in [
        AuthorityMode::LocalProxy,
        AuthorityMode::SystemProxy,
        AuthorityMode::Tunnel,
    ] {
        assert_eq!(prepared(mode).validate(), Ok(()));
        let changes: [fn(&mut PreparedStart); 5] = [
            |start| {
                start.ticket = match start.ticket {
                    Some(_) => None,
                    None => Some(StartTicket::new(&[7; TICKET_BYTES]).unwrap()),
                }
            },
            |start| {
                start.owner_capability = match start.owner_capability {
                    Some(_) => None,
                    None => Some(OwnerCapability::new(&[9; CAPABILITY_BYTES]).unwrap()),
                }
            },
            |start| start.expires_monotonic_ms = 0,
            |start| start.preference_descriptor_sha256 = digest('G'),
            |start| start.operation.authority_revision = 0,
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut start = prepared(mode);
            change(&mut start);
            assert_eq!(
                start.validate(),
                Err(CodecError::BoundViolation),
                "{mode:?} change {index}"
            );
        }
    }
}

fn redeemed() -> RedeemedTunnelStart {
    let operation = operation(AuthorityMode::Tunnel);
    RedeemedTunnelStart {
        lease: lease_view(operation.clone()),
        operation,
        configuration: SensitiveBytes::new(b"{}", MAX_CONFIGURATION_BYTES as usize).unwrap(),
        secrets: SecretMaterial::new(Vec::new()).unwrap(),
    }
}

#[test]
fn redeemed_tunnel_starts_belong_to_their_lease_operation() {
    assert_eq!(redeemed().validate(), Ok(()));
    let changes: [fn(&mut RedeemedTunnelStart); 4] = [
        |start| {
            start.operation.mode = AuthorityMode::SystemProxy;
            start.lease.operation.mode = AuthorityMode::SystemProxy;
        },
        |start| start.lease.operation.operation_id = uuid(9),
        |start| start.lease.expiry_monotonic_ms = 0,
        |start| start.operation.root.epoch = 0,
    ];
    for (index, change) in changes.iter().enumerate() {
        let mut start = redeemed();
        change(&mut start);
        assert_eq!(
            start.validate(),
            Err(CodecError::BoundViolation),
            "change {index}"
        );
    }
}
