use super::*;
use crate::authority_v1::test_support::{
    configuration, credential_slots, digest, lease_view, operation, packet_pump_limits,
    ready_attestation, rejects, replay_cursor, stopped_attestation, tunnel_options, uuid,
};

#[test]
fn global_leases_need_an_issue_time_a_later_expiry_and_a_nonce_digest() {
    let lease = GlobalLease {
        expiry_monotonic_ms: 20,
        issued_monotonic_ms: 10,
        lease_id: uuid(3),
        operation: operation(AuthorityMode::Tunnel),
        owner_connection_nonce_sha256: digest('e'),
        state: LeaseState::Bound,
    };
    rejects(
        &lease,
        &[
            |lease| lease.issued_monotonic_ms = 0,
            |lease| lease.expiry_monotonic_ms = lease.issued_monotonic_ms,
            |lease| lease.owner_connection_nonce_sha256 = digest('E'),
            |lease| lease.operation.authority_revision = 0,
        ],
    );
}

#[test]
fn replay_cursors_need_schema_one_live_counters_and_a_record_digest() {
    rejects(
        &replay_cursor(),
        &[
            |cursor| cursor.schema_version = 2,
            |cursor| cursor.accepted_epoch = 0,
            |cursor| cursor.accepted_generation = 0,
            |cursor| cursor.revision = 0,
            |cursor| cursor.previous_record_sha256 = digest('z'),
        ],
    );
}

#[test]
fn configurations_bound_their_size_slots_digests_and_tunnel_mtu() {
    let proxy = configuration(&operation(AuthorityMode::SystemProxy));
    rejects(
        &proxy,
        &[
            |descriptor| descriptor.byte_count = 0,
            |descriptor| descriptor.byte_count = MAX_CONFIGURATION_BYTES + 1,
            |descriptor| descriptor.config_sha256 = digest('X'),
            |descriptor| descriptor.identity_sha256.clear(),
            |descriptor| descriptor.credential_slots = credential_slots(MAX_CREDENTIAL_SLOTS + 1),
            |descriptor| {
                let first = descriptor.credential_slots[0].clone();
                descriptor.credential_slots.push(first);
            },
        ],
    );
    let mut largest = proxy.clone();
    largest.byte_count = MAX_CONFIGURATION_BYTES;
    largest.credential_slots = credential_slots(MAX_CREDENTIAL_SLOTS);
    assert_eq!(largest.validate(), Ok(()));

    let tunnel = configuration(&operation(AuthorityMode::Tunnel));
    rejects(
        &tunnel,
        &[
            |descriptor| descriptor.tunnel_options.as_mut().unwrap().mtu = 1_279,
            |descriptor| descriptor.tunnel_options.as_mut().unwrap().mtu = 1_501,
        ],
    );
    for mtu in [1_280, 1_500] {
        let mut edge = tunnel.clone();
        edge.tunnel_options = Some(TunnelNetworkOptions {
            mtu,
            ..tunnel_options()
        });
        assert_eq!(edge.validate(), Ok(()));
    }
}

#[test]
fn lease_views_need_an_expiry_and_a_valid_operation() {
    rejects(
        &lease_view(operation(AuthorityMode::SystemProxy)),
        &[
            |lease| lease.expiry_monotonic_ms = 0,
            |lease| lease.operation.root.epoch = 0,
        ],
    );
}

#[test]
fn failure_codes_are_short_lowercase_kebab_words() {
    let failure = FailureSummary {
        code: "dns-timeout-2".into(),
    };
    rejects(
        &failure,
        &[
            |failure| failure.code.clear(),
            |failure| failure.code = "a".repeat(65),
            |failure| failure.code = "DNS".into(),
            |failure| failure.code = "dns_timeout".into(),
        ],
    );
    let longest = FailureSummary {
        code: "a".repeat(64),
    };
    assert_eq!(longest.validate(), Ok(()));
}

#[test]
fn snapshots_bound_their_revision_parts_and_quarantined_lease() {
    let active = AuthoritySnapshot {
        console_uid: Some(501),
        last_failure: None,
        lease_view: Some(lease_view(operation(AuthorityMode::SystemProxy))),
        protocol_version: ProtocolVersion::v1(),
        replay_cursor: Some(replay_cursor()),
        revision: 3,
        state: AuthorityState::Active,
    };
    rejects(
        &active,
        &[
            |snapshot| snapshot.revision = 0,
            |snapshot| snapshot.replay_cursor.as_mut().unwrap().revision = 4,
            |snapshot| snapshot.state = AuthorityState::Quarantined,
            |snapshot| snapshot.last_failure = Some(FailureSummary { code: "Bad".into() }),
            |snapshot| snapshot.lease_view.as_mut().unwrap().expiry_monotonic_ms = 0,
            |snapshot| snapshot.replay_cursor.as_mut().unwrap().schema_version = 0,
            |snapshot| snapshot.protocol_version.max_message_bytes = 0,
        ],
    );
    let mut revoked = active.clone();
    revoked.state = AuthorityState::Quarantined;
    revoked.lease_view.as_mut().unwrap().state = LeaseState::Revoked;
    revoked.last_failure = Some(FailureSummary {
        code: "lease-revoked".into(),
    });
    assert_eq!(revoked.validate(), Ok(()));
}

#[test]
fn packet_pump_limits_stay_within_their_ranges() {
    rejects(
        &packet_pump_limits(),
        &[
            |limits| limits.maximum_queued_packets = 0,
            |limits| limits.maximum_queued_packets = 1_025,
            |limits| limits.maximum_queued_bytes = 0,
            |limits| limits.maximum_queued_bytes = 4 * 1_048_576 + 1,
            |limits| limits.maximum_packet_bytes = 1_279,
            |limits| limits.maximum_packet_bytes = 1_501,
            |limits| limits.maximum_read_batch = 0,
            |limits| limits.maximum_read_batch = 65,
        ],
    );
    let widest = PacketPumpLimits {
        maximum_packet_bytes: 1_500,
        maximum_queued_bytes: 4 * 1_048_576,
        maximum_queued_packets: 1_024,
        maximum_read_batch: 64,
    };
    let narrowest = PacketPumpLimits {
        maximum_packet_bytes: 1_280,
        maximum_queued_bytes: 1,
        maximum_queued_packets: 1,
        maximum_read_batch: 1,
    };
    assert_eq!(widest.validate(), Ok(()));
    assert_eq!(narrowest.validate(), Ok(()));
}

#[test]
fn ready_attestations_match_role_limits_and_flags_to_the_mode() {
    for mode in [
        AuthorityMode::LocalProxy,
        AuthorityMode::SystemProxy,
        AuthorityMode::Tunnel,
    ] {
        rejects(
            &ready_attestation(mode),
            &[
                |ready| ready.monotonic_timestamp_ms = 0,
                |ready| ready.runtime_digest = digest('q'),
                |ready| ready.ready_flags ^= 0b100,
                |ready| ready.owner_role = AuthorityRole::Host,
                |ready| {
                    ready.packet_pump_limits = match ready.packet_pump_limits {
                        Some(_) => None,
                        None => Some(packet_pump_limits()),
                    }
                },
                |ready| ready.operation.authority_revision = 0,
            ],
        );
    }
    let mut invalid_limits = ready_attestation(AuthorityMode::Tunnel);
    invalid_limits
        .packet_pump_limits
        .as_mut()
        .unwrap()
        .maximum_read_batch = 0;
    assert_eq!(invalid_limits.validate(), Err(CodecError::BoundViolation));
}

#[test]
fn stopped_attestations_confirm_every_teardown_step() {
    rejects(
        &stopped_attestation(),
        &[
            |stopped| stopped.libbox_stopped = false,
            |stopped| stopped.transport_closed = false,
            |stopped| stopped.os_restored = false,
            |stopped| stopped.monotonic_timestamp_ms = 0,
            |stopped| stopped.operation.root.generation = 0,
        ],
    );
}

#[test]
fn tunnel_preferences_bound_their_digest_and_description() {
    let values = TunnelPreferenceValues {
        descriptor_sha256: Some(digest('f')),
        is_enabled: true,
        localized_description: Some("Clash for Mac".into()),
    };
    rejects(
        &values,
        &[
            |values| values.descriptor_sha256 = Some(digest('F')),
            |values| values.localized_description = Some("x".repeat(MAX_DESCRIPTION_BYTES + 1)),
            |values| values.localized_description = Some("line\nbreak".into()),
        ],
    );
    let longest = TunnelPreferenceValues {
        localized_description: Some("x".repeat(MAX_DESCRIPTION_BYTES)),
        ..values.clone()
    };
    assert_eq!(longest.validate(), Ok(()));
    let unset = TunnelPreferenceValues {
        descriptor_sha256: None,
        is_enabled: false,
        localized_description: None,
    };
    assert_eq!(unset.validate(), Ok(()));
}

#[test]
fn preference_receipts_keep_prior_values_exactly_when_the_manager_existed() {
    let created = PreferenceMutationReceipt {
        created_manager: true,
        operation_id: uuid(2),
        prior_values: None,
        written_descriptor_sha256: digest('f'),
    };
    rejects(
        &created,
        &[
            |receipt| receipt.created_manager = false,
            |receipt| receipt.written_descriptor_sha256.clear(),
        ],
    );
    let updated = PreferenceMutationReceipt {
        created_manager: false,
        prior_values: Some(TunnelPreferenceValues {
            descriptor_sha256: Some(digest('e')),
            is_enabled: true,
            localized_description: None,
        }),
        ..created
    };
    rejects(
        &updated,
        &[
            |receipt| receipt.created_manager = true,
            |receipt| {
                receipt.prior_values.as_mut().unwrap().descriptor_sha256 = Some("short".into())
            },
        ],
    );
}
