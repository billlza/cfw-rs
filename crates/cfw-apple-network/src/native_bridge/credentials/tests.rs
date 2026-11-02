use cfw_engine_api::{
    CredentialKind, CredentialProvision, CredentialSecret, ValidatedSingBoxProfile,
};

use super::*;

#[test]
fn identity_rejection_is_not_storage_corruption() {
    let rejected = map_vault_error(NativeBridgeError::new(
        NativeBridgeErrorCode::IdentityRejected,
        "native bridge response contains a non-canonical identity",
    ));
    assert_eq!(rejected, CredentialVaultError::IdentityRejected);
    assert!(
        rejected
            .to_string()
            .contains("operation result is unconfirmed")
    );
}

#[test]
fn dedicated_corruption_code_preserves_storage_failure() {
    let wire: cfw_engine_api::BackendErrorKind =
        serde_json::from_str(r#""credential_vault_corrupt""#).expect("typed corruption code");
    assert_eq!(
        wire,
        cfw_engine_api::BackendErrorKind::CredentialVaultCorrupt
    );
    assert_eq!(
        wire.retry_directive(),
        cfw_engine_api::RetryDirective::Never
    );
    let bridge = NativeBridgeErrorCode::from(wire);
    assert_eq!(cfw_engine_api::BackendErrorKind::from(bridge), wire);
    assert_eq!(
        map_vault_error(NativeBridgeError::new(bridge, "ignored untrusted detail")),
        CredentialVaultError::Corrupt
    );
    for message in [
        "Credential vault data is corrupt.",
        "private secret must not escape",
    ] {
        assert_eq!(
            map_vault_error(NativeBridgeError::new(
                NativeBridgeErrorCode::IdentityRejected,
                message,
            )),
            CredentialVaultError::IdentityRejected
        );
        assert_eq!(
            map_vault_error(NativeBridgeError::new(
                NativeBridgeErrorCode::CredentialVaultCorrupt,
                message,
            )),
            CredentialVaultError::Corrupt
        );
    }
}

#[test]
fn only_an_admitted_bridge_timeout_has_an_unknown_vault_outcome() {
    assert_eq!(
        map_vault_error(NativeBridgeError::new(
            NativeBridgeErrorCode::Timeout,
            "bounded timeout",
        )),
        CredentialVaultError::OutcomeUnknown
    );
    assert_eq!(
        map_vault_error(NativeBridgeError::new(
            NativeBridgeErrorCode::Unavailable,
            "bridge unavailable",
        )),
        CredentialVaultError::Unavailable
    );
    assert_eq!(
        map_vault_error(NativeBridgeError::new(
            NativeBridgeErrorCode::PermissionDenied,
            "denied",
        )),
        CredentialVaultError::AccessDenied
    );
    assert_eq!(
        map_vault_error(NativeBridgeError::new(
            NativeBridgeErrorCode::ResourceExhausted,
            "vault capacity",
        )),
        CredentialVaultError::CapacityExceeded
    );
}

#[test]
fn sensitive_provision_wire_is_canonical_and_keeps_secret_bindings() {
    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";
    let first = CredentialRef::new(FIRST_ID, CredentialKind::TrojanPassword)
        .expect("canonical first reference");
    let second = CredentialRef::new(SECOND_ID, CredentialKind::TrojanPassword)
        .expect("canonical second reference");
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"first","server":"first.example.com","server_port":443,"credential_ref":{{"id":"{FIRST_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"first.example.com"}}}},{{"type":"trojan","tag":"second","server":"second.example.com","server_port":443,"credential_ref":{{"id":"{SECOND_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"second.example.com"}}}}]}}"#
    ))
    .expect("typed profile");
    let request = CredentialProvisionRequest::new(
        PROFILE_ID,
        &profile,
        vec![
            CredentialProvision::new(
                &second,
                CredentialSecret::new("second-dummy-secret").expect("second secret"),
            ),
            CredentialProvision::new(
                &first,
                CredentialSecret::new("first-dummy-secret").expect("first secret"),
            ),
        ],
    )
    .expect("canonical request");
    let wire = serde_json::to_value(sensitive_provision_envelope(
        uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("request UUID"),
        &request,
    ))
    .expect("sensitive wire");
    let entries = wire
        .pointer("/command/payload/request/entries")
        .and_then(serde_json::Value::as_array)
        .expect("wire entries");

    assert_eq!(entries[0]["reference"]["id"], FIRST_ID);
    assert_eq!(entries[0]["secret"], "first-dummy-secret");
    assert_eq!(entries[1]["reference"]["id"], SECOND_ID);
    assert_eq!(entries[1]["secret"], "second-dummy-secret");
}
