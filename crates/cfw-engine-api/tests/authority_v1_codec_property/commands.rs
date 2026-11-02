//! Request envelopes for every command kind, built from the choices of a case.

use cfw_engine_api::authority_v1::*;

use crate::generators::{
    CaseChoices, configuration_of, digest_from, mode_for, operation_of, packet_pump_limits,
    uuid_from,
};

/// Builds the valid command selected by `choices`. Every produced command
/// satisfies its `WireValidate` contract.
pub(crate) fn build_command(choices: &CaseChoices) -> Command {
    let mode = mode_for(choices);
    let operation = operation_of(choices, mode);
    let lease_id = uuid_from(choices.entropy, 5);
    match choices.command_index {
        0 => Command::Handshake(HandshakeRequest {
            version: ProtocolVersion::v1(),
        }),
        1 => {
            let configuration = configuration_of(choices, &operation);
            Command::PrepareStart(PrepareStartRequest {
                configuration,
                expected_revision: operation.authority_revision,
                operation,
            })
        }
        2 => Command::BindProxyOwner(BindProxyOwnerRequest {
            operation,
            lease_id,
            capability: OwnerCapability::new(&[0x5a; CAPABILITY_BYTES]).expect("capability"),
        }),
        3 => Command::RedeemTunnelTicket(RedeemTunnelTicketRequest {
            operation,
            lease_id,
            ticket: StartTicket::new(&[0x5a; TICKET_BYTES]).expect("ticket"),
        }),
        4 => {
            let (owner_role, packet_pump_limits) = match mode {
                AuthorityMode::Tunnel => (AuthorityRole::Provider, Some(packet_pump_limits())),
                AuthorityMode::LocalProxy | AuthorityMode::SystemProxy => {
                    (AuthorityRole::ProxyAgent, None)
                }
            };
            Command::AttestReady(ReadyAttestation {
                lease_id,
                monotonic_timestamp_ms: choices.ready_ts,
                operation,
                owner_role,
                packet_pump_limits,
                ready_flags: if mode == AuthorityMode::LocalProxy {
                    0b011
                } else {
                    0b111
                },
                runtime_digest: digest_from(choices.entropy, 6),
            })
        }
        5 => Command::BeginStop(BeginStopRequest {
            expected_revision: choices.revision + choices.revision_delta,
            lease_id,
            operation,
        }),
        6 => Command::AttestStopped(StoppedAttestation {
            lease_id,
            libbox_stopped: true,
            monotonic_timestamp_ms: choices.stopped_ts,
            operation,
            os_restored: true,
            transport_closed: true,
        }),
        7 => Command::CancelPrepared(CancelPreparedRequest {
            expected_revision: choices.revision + choices.revision_delta,
            operation,
        }),
        _ => Command::Snapshot(SnapshotRequest {}),
    }
}

pub(crate) fn command_kind(choices: &CaseChoices) -> &'static str {
    match choices.command_index {
        0 => "handshake",
        1 => "prepare_start",
        2 => "bind_proxy_owner",
        3 => "redeem_tunnel_ticket",
        4 => "attest_ready",
        5 => "begin_stop",
        6 => "attest_stopped",
        7 => "cancel_prepared",
        _ => "snapshot",
    }
}
