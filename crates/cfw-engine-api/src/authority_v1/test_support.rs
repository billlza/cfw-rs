//! Valid Authority v1 values that tests change one field at a time.

use super::*;
use crate::{CredentialKind, CredentialTarget, DirectIpv4HostRoutes};

pub(super) fn digest(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

pub(super) fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

pub(super) fn operation(mode: AuthorityMode) -> OperationContext {
    OperationContext {
        authority_revision: 3,
        config_sha256: digest('a'),
        identity_sha256: digest('b'),
        mode,
        operation_id: uuid(2),
        owner_uid: 501,
        root: RootContext {
            epoch: 1,
            generation: 1,
            installation_id: uuid(1),
        },
    }
}

pub(super) fn credential_ref(value: u128, kind: CredentialKind) -> CredentialRef {
    CredentialRef::new(uuid(value).hyphenated().to_string(), kind)
        .expect("canonical credential reference")
}

/// `count` slots with distinct references and JSON pointers.
pub(super) fn credential_slots(count: usize) -> Vec<CredentialSlot> {
    (0..count)
        .map(|index| {
            let target = if index % 2 == 0 {
                CredentialTarget::Socks5Username
            } else {
                CredentialTarget::Socks5Password
            };
            let reference = credential_ref(100 + index as u128, target.credential_kind());
            CredentialSlot::new(reference, target, index / 2).expect("valid credential slot")
        })
        .collect()
}

pub(super) fn tunnel_options() -> TunnelNetworkOptions {
    TunnelNetworkOptions {
        ipv6_enabled: true,
        bypass_private_networks: false,
        direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
        mtu: 1_400,
        system_proxy_port: None,
    }
}

pub(super) fn configuration(operation: &OperationContext) -> ConfigurationDescriptor {
    ConfigurationDescriptor {
        byte_count: 1_024,
        config_sha256: operation.config_sha256.clone(),
        credential_audience: CredentialAudience::new(
            operation.root.installation_id.hyphenated().to_string(),
            operation.identity_sha256.clone(),
        )
        .expect("canonical credential audience"),
        credential_slots: credential_slots(2),
        identity_sha256: operation.identity_sha256.clone(),
        tunnel_options: (operation.mode == AuthorityMode::Tunnel).then(tunnel_options),
    }
}

pub(super) fn lease_view(operation: OperationContext) -> LeaseView {
    LeaseView {
        expiry_monotonic_ms: 20,
        lease_id: uuid(3),
        operation,
        state: LeaseState::Active,
    }
}

pub(super) fn replay_cursor() -> ReplayCursor {
    ReplayCursor {
        accepted_epoch: 1,
        accepted_generation: 1,
        installation_id: uuid(1),
        previous_record_sha256: digest('c'),
        revision: 3,
        schema_version: 1,
    }
}

pub(super) fn packet_pump_limits() -> PacketPumpLimits {
    PacketPumpLimits {
        maximum_packet_bytes: 1_400,
        maximum_queued_bytes: 1_048_576,
        maximum_queued_packets: 512,
        maximum_read_batch: 32,
    }
}

pub(super) fn ready_attestation(mode: AuthorityMode) -> ReadyAttestation {
    let tunnel = mode == AuthorityMode::Tunnel;
    ReadyAttestation {
        lease_id: uuid(3),
        monotonic_timestamp_ms: 7,
        operation: operation(mode),
        owner_role: if tunnel {
            AuthorityRole::Provider
        } else {
            AuthorityRole::ProxyAgent
        },
        packet_pump_limits: tunnel.then(packet_pump_limits),
        ready_flags: if mode == AuthorityMode::LocalProxy {
            0b011
        } else {
            0b111
        },
        runtime_digest: digest('d'),
    }
}

pub(super) fn stopped_attestation() -> StoppedAttestation {
    StoppedAttestation {
        lease_id: uuid(3),
        libbox_stopped: true,
        monotonic_timestamp_ms: 9,
        operation: operation(AuthorityMode::SystemProxy),
        os_restored: true,
        transport_closed: true,
    }
}

pub(super) fn stop_directive() -> StopDirective {
    StopDirective {
        deadline_monotonic_ms: 30,
        lease_id: uuid(3),
        operation: operation(AuthorityMode::SystemProxy),
        revision: 3,
    }
}

pub(super) fn off_snapshot() -> AuthoritySnapshot {
    AuthoritySnapshot {
        console_uid: None,
        last_failure: None,
        lease_view: None,
        protocol_version: ProtocolVersion::v1(),
        replay_cursor: None,
        revision: 1,
        state: AuthorityState::Off,
    }
}

/// Asserts that `valid` validates and that each change makes it a bound violation.
#[track_caller]
pub(super) fn rejects<T: Clone + WireValidate>(valid: &T, changes: &[fn(&mut T)]) {
    assert_eq!(valid.validate(), Ok(()));
    for (index, change) in changes.iter().enumerate() {
        let mut value = valid.clone();
        change(&mut value);
        assert_eq!(
            value.validate(),
            Err(CodecError::BoundViolation),
            "change {index}"
        );
    }
}
