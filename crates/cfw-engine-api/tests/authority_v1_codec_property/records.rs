//! Standalone canonical models other than request envelopes.

use cfw_engine_api::authority_v1::*;

use crate::generators::{CaseChoices, digest_from, operation_of, uuid_from};

pub(crate) fn replay_cursor_of(choices: &CaseChoices) -> ReplayCursor {
    ReplayCursor {
        accepted_epoch: choices.epoch,
        accepted_generation: choices.generation,
        installation_id: uuid_from(choices.entropy, 7),
        previous_record_sha256: digest_from(choices.entropy, 8),
        revision: choices.revision,
        schema_version: 1,
    }
}

pub(crate) fn snapshot_of(choices: &CaseChoices) -> AuthoritySnapshot {
    AuthoritySnapshot {
        console_uid: None,
        last_failure: None,
        lease_view: None,
        protocol_version: ProtocolVersion::v1(),
        replay_cursor: Some(replay_cursor_of(choices)),
        revision: choices.revision + choices.revision_delta,
        state: AuthorityState::Off,
    }
}

pub(crate) fn global_lease_of(choices: &CaseChoices) -> GlobalLease {
    let mode = if choices.mode_is_tunnel {
        AuthorityMode::Tunnel
    } else {
        AuthorityMode::SystemProxy
    };
    GlobalLease {
        expiry_monotonic_ms: choices.ready_ts + 1,
        issued_monotonic_ms: choices.ready_ts,
        lease_id: uuid_from(choices.entropy, 9),
        operation: operation_of(choices, mode),
        owner_connection_nonce_sha256: digest_from(choices.entropy, 10),
        state: LeaseState::Active,
    }
}

pub(crate) fn preference_receipt_of(choices: &CaseChoices) -> PreferenceMutationReceipt {
    PreferenceMutationReceipt {
        created_manager: true,
        operation_id: uuid_from(choices.entropy, 11),
        prior_values: None,
        written_descriptor_sha256: digest_from(choices.entropy, 12),
    }
}
