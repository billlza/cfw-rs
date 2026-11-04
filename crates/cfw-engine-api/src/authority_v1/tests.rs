use super::codec::parse_canonical;
use super::*;
use std::fs;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/authority-v1")
        .join(name);
    fs::read(path).expect("canonical fixture must exist")
}

#[test]
fn fixed_cross_language_fixtures_decode_and_reencode() {
    verify_canonical_fixture::<HandshakeRequest>(&fixture("handshake.json")).unwrap();
    verify_canonical_fixture::<PrepareStartRequest>(&fixture("prepare-start.json")).unwrap();
    verify_canonical_fixture::<GlobalLease>(&fixture("global-lease.json")).unwrap();
    verify_canonical_fixture::<ReplayCursor>(&fixture("replay-cursor.json")).unwrap();
    verify_canonical_fixture::<AuthoritySnapshot>(&fixture("snapshot.json")).unwrap();
    verify_canonical_fixture::<ReadyAttestation>(&fixture("ready-attestation.json")).unwrap();
    verify_canonical_fixture::<StoppedAttestation>(&fixture("stopped-attestation.json")).unwrap();
    verify_canonical_fixture::<PreferenceMutationReceipt>(&fixture(
        "preference-mutation-receipt.json",
    ))
    .unwrap();
    verify_canonical_fixture::<ResponseEnvelope<HandshakeResponse>>(&fixture(
        "handshake-response-envelope.json",
    ))
    .unwrap();
    decode_request(&fixture("handshake-request-envelope.json")).unwrap();
}

#[test]
fn recovery_snapshots_round_trip_without_authorizing_an_owner() {
    for name in [
        "snapshot-unenrolled.json",
        "snapshot-recovering-without-cursor.json",
        "snapshot-quarantined-without-cursor.json",
        "snapshot-quarantined-lease.json",
    ] {
        verify_canonical_fixture::<AuthoritySnapshot>(&fixture(name)).unwrap();
    }
    let active: AuthoritySnapshot = serde_json::from_slice(&fixture("snapshot.json")).unwrap();
    for state in [
        AuthorityState::Preparing,
        AuthorityState::Starting,
        AuthorityState::Active,
        AuthorityState::Stopping,
    ] {
        let mut invalid = active.clone();
        invalid.state = state;
        invalid.replay_cursor = None;
        assert_eq!(invalid.validate(), Err(CodecError::BoundViolation));
    }
    for state in [
        AuthorityState::Off,
        AuthorityState::Recovering,
        AuthorityState::Quarantined,
    ] {
        let mut invalid = active.clone();
        invalid.state = state;
        assert_eq!(invalid.validate(), Err(CodecError::BoundViolation));
    }
    let mut revoked: AuthoritySnapshot =
        serde_json::from_slice(&fixture("snapshot-quarantined-lease.json")).unwrap();
    revoked.replay_cursor = None;
    assert_eq!(revoked.validate(), Err(CodecError::BoundViolation));
}

#[test]
fn protocol_limits_are_exact() {
    assert_eq!(MAX_ENVELOPE_BYTES, 1_048_576);
    assert_eq!(MAX_CONFIGURATION_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_TOTAL_SECRET_BYTES, 256 * 1_024);
    assert_eq!(MAX_CREDENTIAL_SLOTS, 2048);
    assert_eq!(MAX_INDIVIDUAL_SECRET_BYTES, 16 * 1_024);
    assert_eq!(MAX_READ_ONLY_REQUESTS, 64);
    assert_eq!(MAX_MUTATING_TRANSACTIONS, 1);
    assert_eq!(MAX_QUEUED_EVENTS_PER_PEER, 32);
    assert_eq!(PREPARATION_LIFETIME_MS, 10_000);
    assert_eq!(COMMAND_TIMEOUT_MS, 5_000);
    assert_eq!(STOP_ATTESTATION_TIMEOUT_MS, 5_000);
}

#[test]
fn strict_decoder_rejects_noncanonical_and_incompatible_envelopes() {
    let canonical = fixture("handshake-request-envelope.json");
    let with_space = [canonical.as_slice(), b" "].concat();
    assert!(matches!(
        decode_request(&with_space),
        Err(CodecError::Noncanonical)
    ));

    let duplicate = canonical.to_vec();
    let duplicate =
        String::from_utf8(duplicate)
            .unwrap()
            .replacen("\"major\":1", "\"major\":1,\"major\":1", 1);
    assert!(matches!(
        decode_request(duplicate.as_bytes()),
        Err(CodecError::Noncanonical)
    ));

    let unknown = String::from_utf8(canonical.clone()).unwrap().replacen(
        "\"major\":1",
        "\"extra\":0,\"major\":1",
        1,
    );
    assert!(matches!(
        decode_request(unknown.as_bytes()),
        Err(CodecError::Noncanonical)
    ));

    let major =
        String::from_utf8(canonical.clone())
            .unwrap()
            .replacen("\"major\":1", "\"major\":2", 1);
    assert!(matches!(
        decode_request(major.as_bytes()),
        Err(CodecError::UnsupportedMajor(2))
    ));

    let feature = String::from_utf8(canonical).unwrap().replacen(
        "\"required_feature_bits\":0",
        "\"required_feature_bits\":1",
        1,
    );
    assert!(matches!(
        decode_request(feature.as_bytes()),
        Err(CodecError::UnsupportedRequiredFeatures(1))
    ));
}

#[test]
fn strict_decoder_rejects_depth_type_and_size_bounds() {
    let mut deep = String::from("{\"x\":");
    deep.push_str(&"[".repeat(32));
    deep.push('0');
    deep.push_str(&"]".repeat(32));
    deep.push('}');
    assert_eq!(
        parse_canonical(deep.as_bytes()),
        Err(CodecError::BoundViolation)
    );
    assert_eq!(
        parse_canonical(b"{\"x\":1.0}"),
        Err(CodecError::InvalidType)
    );
    assert!(matches!(
        parse_canonical(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
        Err(CodecError::MessageTooLarge { .. })
    ));
}

#[test]
fn authority_diagnostic_redacts_full_digest_and_has_only_bounded_metadata() {
    let digest = "ab".repeat(32);
    let diagnostic = AuthorityDiagnostic::new(BackendErrorKind::GlobalLeaseConflict)
        .with_operation(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            7,
        )
        .with_role(AuthorityRole::Host)
        .with_digest(&digest)
        .unwrap()
        .to_string();
    assert!(diagnostic.contains("code=global_lease_conflict"));
    assert!(diagnostic.contains("generation=7"));
    assert!(diagnostic.contains("role=host"));
    assert!(diagnostic.contains("digest_prefix=abababababab"));
    assert!(!diagnostic.contains(&digest));
    assert!(!diagnostic.contains("secret"));
}

#[test]
fn secret_material_enforces_slot_and_byte_bounds() {
    assert!(StartTicket::new(&[7; TICKET_BYTES]).is_ok());
    assert!(StartTicket::new(&[7; TICKET_BYTES - 1]).is_err());
    assert!(
        SensitiveBytes::new(
            &vec![0; MAX_INDIVIDUAL_SECRET_BYTES],
            MAX_INDIVIDUAL_SECRET_BYTES
        )
        .is_ok()
    );
    assert!(
        SensitiveBytes::new(
            &vec![0; MAX_INDIVIDUAL_SECRET_BYTES + 1],
            MAX_INDIVIDUAL_SECRET_BYTES
        )
        .is_err()
    );
}

#[test]
fn codec_rejections_render_one_message_without_detail() {
    for error in [
        CodecError::Malformed,
        CodecError::UnsupportedMajor(7),
        CodecError::MessageTooLarge {
            actual: 9,
            maximum: 1,
        },
    ] {
        assert_eq!(error.to_string(), "authority-v1 codec rejection");
    }
}
