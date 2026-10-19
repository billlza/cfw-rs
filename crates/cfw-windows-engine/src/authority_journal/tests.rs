use super::*;
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext};
use uuid::Uuid;

fn installation() -> Uuid {
    Uuid::from_u128(0x12345678_9012_3456_7890_123456789abc)
}
fn owner() -> RecordedOwner {
    serde_json::from_value(serde_json::json!({"sid":[1,5,0,0,0,0,0,5,21,0,0,0,123,0,0,0,200,1,0,0,21,3,0,0,233,3,0,0],"authentication_id":0x1234_5678_90ab_cdefu64,"session_id":2})).unwrap()
}
fn operation() -> JournalOperation {
    JournalOperation::new(
        Uuid::from_u128(2),
        AuthorityMode::SystemProxy,
        [9; 32],
        [8; 32],
        Uuid::from_u128(3),
        owner(),
    )
    .unwrap()
}
fn root() -> RootContext {
    RootContext {
        installation_id: installation(),
        epoch: 1,
        generation: 1,
    }
}
fn prepared() -> AuthorityCommittedState {
    AuthorityCommittedState::new(
        root(),
        3,
        JournalTransition::Prepare,
        AuthorityState::Preparing,
        Some(operation()),
    )
    .unwrap()
}
fn image() -> (Vec<u8>, JournalCursor, usize) {
    let first = encode_record(
        &AuthorityCommittedState::enrollment(installation()),
        1,
        [0; 32],
    )
    .unwrap();
    let reserved = AuthorityCommittedState::enrollment(installation())
        .reserve_next_generation()
        .unwrap();
    let second = encode_record(&reserved, 2, first.digest).unwrap();
    let third = encode_record(&prepared(), 3, second.digest).unwrap();
    let first_length = first.bytes.len();
    let mut bytes = first.bytes;
    bytes.extend(second.bytes);
    bytes.extend(third.bytes);
    let cursor = JournalCursor::new(1, 3, bytes.len() as u64, third.digest, 3).unwrap();
    (bytes, cursor, first_length)
}

#[test]
fn replay_retains_full_owner_identity_but_only_returns_reconciliation() {
    let (bytes, cursor, _) = image();
    let decoded = decode_journal(&bytes).unwrap();
    decoded.verify_cursor(&cursor).unwrap();
    let value = decoded.state();
    assert_eq!(value, &prepared());
    assert_eq!(value.restart_action().unwrap(), RecoveryAction::StopOwner);
    assert_eq!(
        value.operation().unwrap().owner().sid_bytes(),
        owner().sid_bytes()
    );
    assert_eq!(
        value.operation().unwrap().owner().authentication_id(),
        0x1234_5678_90ab_cdef
    );
    assert_eq!(value.operation().unwrap().owner().session_id(), 2);
    assert!(!format!("{:?}", value.operation().unwrap().owner()).contains("1234"));
}

#[test]
fn persisted_off_and_active_do_not_restore_authorization() {
    let genesis = AuthorityCommittedState::enrollment(installation());
    assert_eq!(genesis.restart_action().unwrap(), RecoveryAction::VerifyOff);
    let active = AuthorityCommittedState::new(
        root(),
        4,
        JournalTransition::Ready,
        AuthorityState::Active,
        Some(operation()),
    )
    .unwrap();
    assert_eq!(
        active.restart_action().unwrap(),
        RecoveryAction::ReattestOwner
    );
    let quarantine = AuthorityCommittedState::new(
        root(),
        5,
        JournalTransition::ReconcileOff,
        AuthorityState::Quarantined,
        None,
    )
    .unwrap();
    assert_eq!(
        quarantine.restart_action().unwrap(),
        RecoveryAction::StopOwner
    );
    assert_eq!(
        quarantine.checkpoint().unwrap().restart_action().unwrap(),
        RecoveryAction::StopOwner
    );
    let invalid = AuthorityCommittedState::new(
        root(),
        5,
        JournalTransition::RevokeForTimeout,
        AuthorityState::Quarantined,
        None,
    )
    .unwrap();
    assert_eq!(
        invalid.restart_action(),
        Err(JournalValidationError::InvalidState)
    );
}

#[test]
fn every_single_byte_change_and_truncation_is_rejected_against_the_anchor() {
    let (bytes, cursor, _) = image();
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            decode_journal(&changed)
                .and_then(|v| v.verify_cursor(&cursor))
                .is_err(),
            "changed byte {index}"
        );
        assert!(
            decode_journal(&bytes[..index])
                .and_then(|v| v.verify_cursor(&cursor))
                .is_err(),
            "truncated at {index}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_journal(&trailing).is_err());
}

#[test]
fn a_self_consistent_old_head_still_fails_the_independent_anchor() {
    let (bytes, cursor, first_length) = image();
    let old = decode_journal(&bytes[..first_length]).unwrap();
    old.verify_cursor(&old.cursor(1).unwrap()).unwrap();
    assert_eq!(
        old.verify_cursor(&cursor),
        Err(JournalValidationError::Integrity)
    );
}

#[test]
fn complete_frames_cannot_reorder_state_or_change_installations() {
    let genesis = AuthorityCommittedState::enrollment(installation());
    let first = encode_record(&genesis, 1, [0; 32]).unwrap();
    let reserved = genesis.reserve_next_generation().unwrap();
    let second = encode_record(&reserved, 2, first.digest).unwrap();
    prepared().validate_successor(&reserved).unwrap();
    for (candidate_root, revision) in [
        (root(), 2),
        (root(), 4),
        (
            RootContext {
                installation_id: Uuid::from_u128(99),
                ..root()
            },
            3,
        ),
    ] {
        let state = AuthorityCommittedState::new(
            candidate_root,
            revision,
            JournalTransition::Prepare,
            AuthorityState::Preparing,
            Some(operation()),
        )
        .unwrap();
        let third = encode_record(&state, 3, second.digest).unwrap();
        let mut bytes = first.bytes.clone();
        bytes.extend(&second.bytes);
        bytes.extend(third.bytes);
        assert_eq!(
            decode_journal(&bytes),
            Err(JournalValidationError::Sequence)
        );
    }
    let p = prepared();
    let illegal = AuthorityCommittedState::new(
        RootContext {
            generation: 2,
            ..root()
        },
        4,
        JournalTransition::BindOwner,
        AuthorityState::Starting,
        Some(operation()),
    )
    .unwrap();
    assert_eq!(
        illegal.validate_successor(&p),
        Err(JournalValidationError::Sequence)
    );
}

#[test]
fn canonical_payload_has_no_unknown_duplicate_secret_or_partial_owner_fields() {
    let state = prepared();
    let original = state.encode().unwrap();
    let mut spaced = original.clone();
    spaced.push(b' ');
    assert!(AuthorityCommittedState::decode(&spaced).is_err());
    let text = String::from_utf8(original.clone()).unwrap();
    let duplicate = text.replacen("{", "{\"schema_version\":1,", 1);
    assert!(AuthorityCommittedState::decode(duplicate.as_bytes()).is_err());
    for field in [
        "ticket",
        "capability",
        "configuration",
        "credential",
        "endpoint",
        "secret",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value[field] = serde_json::json!("must-not-persist");
        assert!(AuthorityCommittedState::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for field in ["sid", "authentication_id", "session_id"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["operation"]["owner"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<AuthorityCommittedState>(value).is_err());
    }
    assert_eq!(AuthorityCommittedState::decode(&original).unwrap(), state);
}

#[test]
fn invalid_sid_and_logon_claims_fail_before_a_commit_is_usable() {
    let mut value = serde_json::to_value(owner()).unwrap();
    for bad in [
        serde_json::json!([]),
        serde_json::json!([1, 1, 0, 0, 0, 0, 0, 5]),
        serde_json::json!([2, 0, 0, 0, 0, 0, 0, 5]),
        serde_json::json!([1, 16, 0, 0, 0, 0, 0, 5]),
    ] {
        value["sid"] = bad;
        let claim = serde_json::from_value(value.clone()).unwrap();
        assert!(
            JournalOperation::new(
                Uuid::from_u128(2),
                AuthorityMode::SystemProxy,
                [9; 32],
                [8; 32],
                Uuid::from_u128(3),
                claim
            )
            .is_err()
        );
    }
    for (field, bad) in [
        ("authentication_id", 0),
        ("authentication_id", u64::MAX),
        ("session_id", 0),
        ("session_id", u64::from(u32::MAX)),
    ] {
        let mut v = serde_json::to_value(owner()).unwrap();
        v[field] = serde_json::json!(bad);
        let claim = serde_json::from_value(v).unwrap();
        assert!(
            JournalOperation::new(
                Uuid::from_u128(2),
                AuthorityMode::SystemProxy,
                [9; 32],
                [8; 32],
                Uuid::from_u128(3),
                claim
            )
            .is_err()
        );
    }
}

#[test]
fn pending_cursor_requires_exact_append_or_checkpoint_progress() {
    let (_, committed, _) = image();
    let next = JournalCursor::new(1, 4, committed.committed_length() + 100, [8; 32], 4).unwrap();
    let anchor =
        JournalAnchor::new(installation(), Some(committed.clone()), Some(next.clone())).unwrap();
    assert_eq!(
        JournalAnchor::decode(&anchor.encode().unwrap()).unwrap(),
        anchor
    );
    for bad in [
        JournalCursor::new(1, 5, next.committed_length(), [8; 32], 4).unwrap(),
        JournalCursor::new(1, 4, committed.committed_length(), [8; 32], 4).unwrap(),
        JournalCursor::new(1, 4, next.committed_length(), [8; 32], 5).unwrap(),
        JournalCursor::new(3, 1, 200, [8; 32], 3).unwrap(),
        JournalCursor::new(2, 1, 200, [8; 32], 4).unwrap(),
    ] {
        assert_eq!(
            JournalAnchor::new(installation(), Some(committed.clone()), Some(bad)),
            Err(JournalValidationError::Anchor)
        );
    }
    let checkpoint = JournalCursor::new(2, 1, 200, [8; 32], 3).unwrap();
    JournalAnchor::new(installation(), Some(committed), Some(checkpoint)).unwrap();
    assert!(JournalAnchor::new(installation(), None, Some(next)).is_err());
}

#[test]
fn state_fields_and_capacity_remain_closed_at_the_boundary() {
    assert!(
        AuthorityCommittedState::new(
            root(),
            2,
            JournalTransition::GlobalOff,
            AuthorityState::Off,
            Some(operation())
        )
        .is_err()
    );
    assert!(
        AuthorityCommittedState::new(
            root(),
            2,
            JournalTransition::Prepare,
            AuthorityState::Preparing,
            None
        )
        .is_err()
    );
    assert!(JournalCursor::new(1, MAX_RECORDS + 1, 100, [1; 32], 2).is_err());
    assert!(JournalCursor::new(1, 1, MAX_JOURNAL_BYTES as u64 + 1, [1; 32], 2).is_err());
    assert!(AuthorityCommittedState::decode(&vec![b' '; MAX_RECORD_PAYLOAD + 1]).is_err());
    assert!(JournalAnchor::decode(&vec![b' '; MAX_ANCHOR_BYTES + 1]).is_err());
    let checkpoint = prepared().checkpoint().unwrap();
    let record = encode_record(&checkpoint, 1, [0; 32]).unwrap();
    assert_eq!(decode_journal(&record.bytes).unwrap().state(), &checkpoint);
}

#[test]
fn allocation_and_checkpoint_retain_unused_generations_without_a_runtime_grant() {
    let initial = AuthorityCommittedState::enrollment(installation());
    let first = initial.reserve_next_generation().unwrap();
    let second = first.reserve_next_generation().unwrap();
    assert_eq!(second.root().generation, 0);
    assert_eq!(second.allocated_generation(), 2);
    assert_eq!(second.state(), AuthorityState::Off);
    assert!(second.operation().is_none());
    let checkpoint = second.checkpoint().unwrap();
    let frame = encode_record(&checkpoint, 1, [0; 32]).unwrap();
    let recovered = decode_journal(&frame.bytes).unwrap();
    assert_eq!(recovered.state().allocated_generation(), 2);
    assert_eq!(
        recovered.state().restart_action().unwrap(),
        RecoveryAction::VerifyOff
    );
    assert_eq!(
        recovered
            .state()
            .reserve_next_generation()
            .unwrap()
            .allocated_generation(),
        3
    );
}

#[test]
fn allocation_schema_never_infers_a_missing_counter_or_accepts_counter_rollback() {
    let state = AuthorityCommittedState::enrollment(installation())
        .reserve_next_generation()
        .unwrap();
    let original = serde_json::to_value(&state).unwrap();
    for schema in [0, 1, 2, 3, 4, 5, 7] {
        let mut value = original.clone();
        value["schema_version"] = serde_json::json!(schema);
        let changed: AuthorityCommittedState = serde_json::from_value(value).unwrap();
        assert_eq!(
            AuthorityCommittedState::decode(&serde_json::to_vec(&changed).unwrap()),
            Err(JournalValidationError::UnsupportedSchema)
        );
    }
    let mut missing = original.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("allocated_generation");
    assert!(AuthorityCommittedState::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    let next = state.reserve_next_generation().unwrap();
    for generation in [0, 1, 3] {
        let mut value = serde_json::to_value(&next).unwrap();
        value["allocated_generation"] = serde_json::json!(generation);
        let changed: AuthorityCommittedState = serde_json::from_value(value).unwrap();
        assert!(changed.validate_successor(&state).is_err());
    }
    let prepared = prepared();
    assert!(prepared.reserve_next_generation().is_err());
    let mut consumed = serde_json::to_value(&prepared).unwrap();
    consumed["allocated_generation"] = serde_json::json!(0);
    let changed: AuthorityCommittedState = serde_json::from_value(consumed).unwrap();
    assert_eq!(
        AuthorityCommittedState::decode(&serde_json::to_vec(&changed).unwrap()),
        Err(JournalValidationError::InvalidState)
    );
}

#[test]
fn both_configuration_digests_survive_encoding_and_checkpoint_recovery() {
    let original = prepared();
    let decoded = AuthorityCommittedState::decode(&original.encode().unwrap()).unwrap();
    assert_eq!(decoded.operation().unwrap().config_sha256(), &[9; 32]);
    assert_eq!(decoded.operation().unwrap().identity_sha256(), &[8; 32]);
    let checkpoint = decoded.checkpoint().unwrap();
    let record = encode_record(&checkpoint, 1, [0; 32]).unwrap();
    assert_eq!(
        decode_journal(&record.bytes).unwrap().state().operation(),
        original.operation()
    );
    let mut missing = serde_json::to_value(original).unwrap();
    missing["operation"]
        .as_object_mut()
        .unwrap()
        .remove("identity_sha256");
    assert!(serde_json::from_value::<AuthorityCommittedState>(missing).is_err());
}

#[test]
fn an_operation_cannot_change_identity_between_preparation_and_cleanup() {
    let original = prepared();
    let operation = original.operation().unwrap();
    let valid = original
        .transition_to(
            4,
            JournalTransition::BindOwner,
            AuthorityState::Starting,
            Some(operation.clone()),
        )
        .unwrap();
    assert_eq!(valid.operation(), Some(operation));
    for field in ["config_sha256", "identity_sha256"] {
        let mut changed = serde_json::to_value(operation).unwrap();
        changed[field][0] = serde_json::json!(99);
        let changed: JournalOperation = serde_json::from_value(changed).unwrap();
        assert_eq!(
            original.transition_to(
                4,
                JournalTransition::BindOwner,
                AuthorityState::Starting,
                Some(changed)
            ),
            Err(JournalValidationError::Sequence)
        );
    }
    assert!(
        original
            .transition_to(
                4,
                JournalTransition::ReconcileOff,
                AuthorityState::Quarantined,
                None
            )
            .is_err()
    );
    for (operation_id, lease_id) in [
        (Uuid::nil(), Uuid::from_u128(3)),
        (Uuid::from_u128(2), Uuid::nil()),
    ] {
        assert!(
            JournalOperation::new(
                operation_id,
                AuthorityMode::SystemProxy,
                [9; 32],
                [8; 32],
                lease_id,
                owner()
            )
            .is_err()
        );
    }
}
