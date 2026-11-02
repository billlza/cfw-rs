use cfw_singbox_config::CredentialKind;

use super::*;
use crate::test_support::{CREDENTIAL_ID, PROFILE_ID};

#[test]
fn credential_provisioning_request_is_bounded_unique_and_redacted() {
    let reference = CredentialRef::new(CREDENTIAL_ID, CredentialKind::TrojanPassword)
        .expect("canonical reference");
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{CREDENTIAL_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .expect("typed profile");
    let secret = CredentialSecret::new("never-print-this-secret").expect("bounded secret");
    let request = CredentialProvisionRequest::new(
        PROFILE_ID,
        &profile,
        vec![CredentialProvision::new(&reference, secret)],
    )
    .expect("provision request");
    let debug = format!("{request:?}");
    assert!(!debug.contains("never-print-this-secret"));
    assert_eq!(request.profile_id(), PROFILE_ID);

    let first = CredentialSecret::new("first").expect("first secret");
    let second = CredentialSecret::new("second").expect("second secret");
    assert!(matches!(
        CredentialProvisionRequest::new(
            PROFILE_ID,
            &profile,
            vec![
                CredentialProvision::new(&reference, first),
                CredentialProvision::new(&reference, second),
            ],
        ),
        Err(CredentialProvisionRequestError::DuplicateReference)
    ));

    let existing_only = CredentialProvisionRequest::new(PROFILE_ID, &profile, Vec::new())
        .expect("the vault validates omitted references atomically");
    assert_eq!(
        existing_only.required_references(),
        std::slice::from_ref(&reference)
    );
    assert!(existing_only.entries().is_empty());
    assert!(matches!(
        CredentialProvisionRequest::new(
            PROFILE_ID,
            &ValidatedSingBoxProfile::direct(),
            vec![CredentialProvision::new(
                &reference,
                CredentialSecret::new("unexpected").expect("bounded secret"),
            )],
        ),
        Err(CredentialProvisionRequestError::UnexpectedReference)
    ));
}

#[test]
fn credential_provisioning_rejects_invalid_tuic_uuid_before_vault_io() {
    const TUIC_UUID_REFERENCE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const TUIC_PASSWORD_REFERENCE_ID: &str = "22222222-2222-4222-8222-222222222222";
    let uuid_reference = CredentialRef::new(TUIC_UUID_REFERENCE_ID, CredentialKind::TuicUuid)
        .expect("canonical TUIC UUID reference");
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_REFERENCE_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_REFERENCE_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}}}}]}}"#
    ))
    .expect("typed TUIC profile");

    let invalid = CredentialSecret::new("not-a-uuid").expect("bounded invalid UUID");
    assert!(matches!(
        CredentialProvisionRequest::new(
            PROFILE_ID,
            &profile,
            vec![CredentialProvision::new(&uuid_reference, invalid)],
        ),
        Err(CredentialProvisionRequestError::InvalidSecret)
    ));

    let valid = CredentialSecret::new("33333333-3333-4333-8333-333333333333")
        .expect("bounded canonical UUID");
    CredentialProvisionRequest::new(
        PROFILE_ID,
        &profile,
        vec![CredentialProvision::new(&uuid_reference, valid)],
    )
    .expect("canonical TUIC UUID request");
}

#[test]
fn credential_provisioning_request_canonicalizes_entry_order() {
    const FIRST_CREDENTIAL_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SECOND_CREDENTIAL_ID: &str = "22222222-2222-4222-8222-222222222222";
    let first_reference = CredentialRef::new(FIRST_CREDENTIAL_ID, CredentialKind::TrojanPassword)
        .expect("canonical first reference");
    let second_reference = CredentialRef::new(SECOND_CREDENTIAL_ID, CredentialKind::TrojanPassword)
        .expect("canonical second reference");
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"first","server":"first.example.com","server_port":443,"credential_ref":{{"id":"{FIRST_CREDENTIAL_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"first.example.com"}}}},{{"type":"trojan","tag":"second","server":"second.example.com","server_port":443,"credential_ref":{{"id":"{SECOND_CREDENTIAL_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"second.example.com"}}}}]}}"#
    ))
    .expect("typed multi-credential profile");
    let request = CredentialProvisionRequest::new(
        PROFILE_ID,
        &profile,
        vec![
            CredentialProvision::new(
                &second_reference,
                CredentialSecret::new("second-secret").expect("bounded second secret"),
            ),
            CredentialProvision::new(
                &first_reference,
                CredentialSecret::new("first-secret").expect("bounded first secret"),
            ),
        ],
    )
    .expect("canonical provision request");

    assert_eq!(
        request
            .entries()
            .iter()
            .map(|entry| entry.reference().id())
            .collect::<Vec<_>>(),
        vec![FIRST_CREDENTIAL_ID, SECOND_CREDENTIAL_ID]
    );
    assert_eq!(
        request.required_references(),
        &[first_reference.clone(), second_reference.clone()]
    );
    assert_eq!(
        request.entries()[0].secret().expose_to_vault(),
        "first-secret"
    );
    assert_eq!(
        request.entries()[1].secret().expose_to_vault(),
        "second-secret"
    );
}
