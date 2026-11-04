use super::*;
use crate::authority_v1::test_support::{configuration, digest, off_snapshot, operation, uuid};

fn encoded(command: Command) -> String {
    let envelope = RequestEnvelope::new(uuid(5), 0, command).unwrap();
    String::from_utf8(encode_request(&envelope).unwrap()).unwrap()
}

#[test]
fn a_command_is_exactly_one_kind_and_payload_object() {
    let canonical = encoded(Command::Snapshot(SnapshotRequest {}));
    assert!(decode_request(canonical.as_bytes()).is_ok());
    let cases = [
        (
            canonical.replacen(r#""kind":"snapshot""#, r#""extra":0,"kind":"snapshot""#, 1),
            CodecError::Malformed,
        ),
        (
            canonical.replacen(r#"{"kind":"snapshot","payload":{}}"#, "[]", 1),
            CodecError::InvalidType,
        ),
        (
            canonical.replacen(r#""kind":"snapshot""#, r#""kind":7"#, 1),
            CodecError::InvalidType,
        ),
        (
            canonical.replacen(r#""kind":"snapshot""#, r#""kind":"reboot""#, 1),
            CodecError::UnknownCommand,
        ),
        (
            canonical.replacen(r#""major":1"#, r#""major":70000"#, 1),
            CodecError::InvalidType,
        ),
        (
            canonical.replacen(r#""minor":1"#, r#""minor":2"#, 1),
            CodecError::UnsupportedMinor(2),
        ),
    ];
    for (data, expected) in cases {
        assert!(
            matches!(decode_request(data.as_bytes()), Err(error) if error == expected),
            "{data}"
        );
    }
}

#[test]
fn an_explicit_null_is_not_the_canonical_omission() {
    let operation = operation(AuthorityMode::SystemProxy);
    let canonical = encoded(Command::PrepareStart(PrepareStartRequest {
        configuration: configuration(&operation),
        expected_revision: operation.authority_revision,
        operation,
    }));
    assert!(decode_request(canonical.as_bytes()).is_ok());
    let last_field = format!(r#""identity_sha256":"{}"}}"#, digest('b'));
    let explicit_null = canonical.replacen(
        &last_field,
        &format!(
            r#""identity_sha256":"{}","tunnel_options":null}}"#,
            digest('b')
        ),
        1,
    );
    assert_ne!(explicit_null, canonical);
    assert!(matches!(
        decode_request(explicit_null.as_bytes()),
        Err(CodecError::Noncanonical)
    ));

    let snapshot = encode_canonical(&off_snapshot()).unwrap();
    assert_eq!(
        decode_canonical::<AuthoritySnapshot>(&snapshot),
        Ok(off_snapshot())
    );
    let null_console =
        String::from_utf8(snapshot)
            .unwrap()
            .replacen('{', r#"{"console_uid":null,"#, 1);
    assert_eq!(
        decode_canonical::<AuthoritySnapshot>(null_console.as_bytes()),
        Err(CodecError::Noncanonical)
    );
}

#[test]
fn only_a_json_object_is_a_document() {
    for data in [&b"[]"[..], b"1", b"\"x\"", b"null"] {
        assert_eq!(parse_canonical(data), Err(CodecError::InvalidType));
    }
    for data in [&b""[..], b"{"] {
        assert_eq!(parse_canonical(data), Err(CodecError::Malformed));
    }
}

#[test]
fn an_encoding_beyond_the_envelope_bound_is_refused() {
    let oversized = json!({ "x": "a".repeat(MAX_ENVELOPE_BYTES) });
    assert!(matches!(
        canonical_bytes(&oversized),
        Err(CodecError::MessageTooLarge {
            maximum: MAX_ENVELOPE_BYTES,
            ..
        })
    ));
}

#[test]
fn owner_credentials_decode_only_for_their_mode_and_exact_length() {
    let bind = encoded(Command::BindProxyOwner(BindProxyOwnerRequest {
        operation: operation(AuthorityMode::SystemProxy),
        lease_id: uuid(3),
        capability: OwnerCapability::new(&[9; CAPABILITY_BYTES]).unwrap(),
    }));
    let redeem = encoded(Command::RedeemTunnelTicket(RedeemTunnelTicketRequest {
        operation: operation(AuthorityMode::Tunnel),
        lease_id: uuid(3),
        ticket: StartTicket::new(&[7; TICKET_BYTES]).unwrap(),
    }));
    assert!(decode_request(bind.as_bytes()).is_ok());
    assert!(decode_request(redeem.as_bytes()).is_ok());
    let ticket = format!("[{}]", vec!["7"; TICKET_BYTES].join(","));

    let cases = [
        (
            bind.replacen(r#""mode":"system_proxy""#, r#""mode":"tunnel""#, 1),
            CodecError::BoundViolation,
        ),
        (bind.replacen("[9,", "[", 1), CodecError::BoundViolation),
        (bind.replacen("[9,", "[256,", 1), CodecError::InvalidType),
        (
            bind.replacen(r#""lease_id""#, r#""lease""#, 1),
            CodecError::Malformed,
        ),
        (
            redeem.replacen(r#""mode":"tunnel""#, r#""mode":"local_proxy""#, 1),
            CodecError::BoundViolation,
        ),
        (redeem.replacen("[7,", "[", 1), CodecError::BoundViolation),
        (
            redeem.replacen(&ticket, r#""ticket""#, 1),
            CodecError::InvalidType,
        ),
    ];
    for (data, expected) in cases {
        assert!(
            matches!(decode_request(data.as_bytes()), Err(error) if error == expected),
            "{data}"
        );
    }
}

#[test]
fn credential_bytes_are_read_only_after_the_mode_and_length_checks() {
    // Each payload below is wrong twice: a credential byte is out of range
    // (InvalidType once read) and an earlier check fails first, so the
    // secret bytes are never decoded for a payload the mode or length refuses.
    let bind = encoded(Command::BindProxyOwner(BindProxyOwnerRequest {
        operation: operation(AuthorityMode::SystemProxy),
        lease_id: uuid(3),
        capability: OwnerCapability::new(&[9; CAPABILITY_BYTES]).unwrap(),
    }))
    .replacen("[9,", "[256,", 1);
    let redeem = encoded(Command::RedeemTunnelTicket(RedeemTunnelTicketRequest {
        operation: operation(AuthorityMode::Tunnel),
        lease_id: uuid(3),
        ticket: StartTicket::new(&[7; TICKET_BYTES]).unwrap(),
    }))
    .replacen("[7,", "[256,", 1);
    let cases = [
        bind.replacen(r#""mode":"system_proxy""#, r#""mode":"tunnel""#, 1),
        bind.replacen("[256,9,", "[256,", 1),
        redeem.replacen(r#""mode":"tunnel""#, r#""mode":"system_proxy""#, 1),
        redeem.replacen("[256,7,", "[256,", 1),
    ];
    for data in cases {
        assert!(
            matches!(
                decode_request(data.as_bytes()),
                Err(CodecError::BoundViolation)
            ),
            "{data}"
        );
    }
}
