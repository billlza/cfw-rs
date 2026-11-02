//! Credential audiences, bindings, slot sets, and secrets at the vault edge.

use serde_json::json;
use uuid::Uuid;

use crate::{
    CredentialAudience, CredentialBinding, CredentialKind, CredentialRef, CredentialSecret,
    CredentialSlot, CredentialSlotError, CredentialTarget, InvalidCredentialAudience,
    InvalidCredentialSecret, MAX_CREDENTIAL_SLOTS, MAX_OUTBOUNDS, validate_credential_slots,
};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn digest() -> String {
    "a".repeat(64)
}

fn reference(id: u128, kind: CredentialKind) -> CredentialRef {
    CredentialRef::new(Uuid::from_u128(id).hyphenated().to_string(), kind)
        .expect("canonical credential reference")
}

fn slot(id: u128, target: CredentialTarget, index: usize) -> CredentialSlot {
    CredentialSlot::new(reference(id, target.credential_kind()), target, index)
        .expect("valid credential slot")
}

#[test]
fn audiences_bind_a_canonical_profile_id_to_a_lowercase_digest() {
    let audience = CredentialAudience::new(PROFILE_ID, digest()).unwrap();
    assert_eq!(audience.profile_id(), PROFILE_ID);
    assert_eq!(audience.profile_digest(), digest());
    for (id, profile_digest) in [
        (PROFILE_ID.to_uppercase(), digest()),
        ("not-a-uuid".to_owned(), digest()),
        (PROFILE_ID.to_owned(), "A".repeat(64)),
        (PROFILE_ID.to_owned(), "a".repeat(63)),
    ] {
        assert_eq!(
            CredentialAudience::new(id.clone(), profile_digest),
            Err(InvalidCredentialAudience),
            "{id}"
        );
    }

    let decoded: CredentialAudience =
        serde_json::from_value(json!({"profile_id": PROFILE_ID, "profile_digest": digest()}))
            .unwrap();
    assert_eq!(decoded, audience);
    let invalid = serde_json::from_value::<CredentialAudience>(
        json!({"profile_id": PROFILE_ID, "profile_digest": "short"}),
    )
    .expect_err("a short digest");
    assert!(
        invalid
            .to_string()
            .contains("credential audience requires a canonical profile UUID"),
        "{invalid}"
    );
    assert!(
        serde_json::from_value::<CredentialAudience>(
            json!({"profile_id": PROFILE_ID, "profile_digest": digest(), "extra": 1})
        )
        .is_err()
    );
}

#[test]
fn bindings_pair_one_audience_with_one_reference() {
    let audience = CredentialAudience::new(PROFILE_ID, digest()).unwrap();
    let reference = reference(1, CredentialKind::TrojanPassword);
    let binding = CredentialBinding::new(audience.clone(), reference.clone());
    assert_eq!(binding.audience(), &audience);
    assert_eq!(binding.reference(), &reference);
}

#[test]
fn slots_match_their_target_kind_and_outbound_range() {
    assert_eq!(
        CredentialTarget::HttpProxyUsername.credential_kind(),
        CredentialKind::HttpProxyUsername
    );
    assert_eq!(
        CredentialTarget::HttpProxyPassword.credential_kind(),
        CredentialKind::HttpProxyPassword
    );
    let username = reference(1, CredentialKind::Socks5Username);
    assert_eq!(
        CredentialSlot::new(
            username.clone(),
            CredentialTarget::Socks5Username,
            MAX_OUTBOUNDS
        ),
        Err(CredentialSlotError::OutboundIndexOutOfRange)
    );
    assert_eq!(
        CredentialSlot::new(username, CredentialTarget::Socks5Password, 0),
        Err(CredentialSlotError::KindMismatch)
    );
    let last = slot(2, CredentialTarget::HttpProxyPassword, MAX_OUTBOUNDS - 1);
    assert_eq!(
        last.json_pointer(),
        format!("/outbounds/{}/password", MAX_OUTBOUNDS - 1)
    );
}

#[test]
fn slot_sets_are_bounded_unique_consistent_and_point_at_empty_placeholders() {
    let template = json!({"outbounds":[{"username":"","password":""},{"username":""}]});
    let username = slot(1, CredentialTarget::Socks5Username, 0);
    let password = slot(2, CredentialTarget::Socks5Password, 0);
    assert_eq!(
        validate_credential_slots(&template, &[username.clone(), password.clone()]),
        Ok(())
    );
    assert_eq!(
        validate_credential_slots(&template, &[username.clone(), username.clone()]),
        Err(CredentialSlotError::DuplicatePointer)
    );
    let same_id_other_kind = CredentialSlot::new(
        reference(1, CredentialKind::Socks5Password),
        CredentialTarget::Socks5Password,
        0,
    )
    .unwrap();
    assert_eq!(
        validate_credential_slots(&template, &[username.clone(), same_id_other_kind]),
        Err(CredentialSlotError::ConflictingReferenceKind)
    );
    for template in [
        json!({"outbounds":[{"username":"filled"}]}),
        json!({"outbounds":[{"username":null}]}),
        json!({"outbounds":[{}]}),
    ] {
        assert_eq!(
            validate_credential_slots(&template, std::slice::from_ref(&username)),
            Err(CredentialSlotError::NonEmptyPlaceholder),
            "{template}"
        );
    }
    let too_many = (0..=MAX_CREDENTIAL_SLOTS)
        .map(|index| slot(index as u128 + 10, CredentialTarget::Socks5Username, 0))
        .collect::<Vec<_>>();
    assert_eq!(
        validate_credential_slots(&template, &too_many),
        Err(CredentialSlotError::TooManySlots)
    );
}

#[test]
fn secrets_are_bounded_printable_and_shaped_for_their_kind() {
    for invalid in [
        String::new(),
        "line\nbreak".to_owned(),
        "s".repeat(16 * 1024 + 1),
    ] {
        assert_eq!(
            CredentialSecret::new(&invalid).map(|_| ()),
            Err(InvalidCredentialSecret)
        );
    }
    let secret = CredentialSecret::new("user").unwrap();
    assert_eq!(secret.expose_to_vault(), "user");
    assert_eq!(format!("{secret:?}"), "CredentialSecret([REDACTED])");

    let fits = |value: &str, kind| {
        CredentialSecret::new(value)
            .unwrap()
            .validate_for_kind(kind)
            .is_ok()
    };
    assert!(fits(&"u".repeat(1024), CredentialKind::HttpProxyUsername));
    assert!(!fits(&"u".repeat(1025), CredentialKind::HttpProxyUsername));
    assert!(!fits("user:name", CredentialKind::HttpProxyUsername));
    assert!(fits(&"p".repeat(4096), CredentialKind::HttpProxyPassword));
    assert!(!fits(&"p".repeat(4097), CredentialKind::HttpProxyPassword));
    assert!(fits(&"s".repeat(255), CredentialKind::Socks5Password));
    assert!(!fits(&"s".repeat(256), CredentialKind::Socks5Username));
    assert!(fits(PROFILE_ID, CredentialKind::VlessUuid));
    assert!(!fits(&PROFILE_ID.to_uppercase(), CredentialKind::TuicUuid));
    assert!(!fits("not-a-uuid", CredentialKind::VmessUuid));
}
