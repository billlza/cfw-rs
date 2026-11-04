use super::*;
use crate::test_support::{
    CREDENTIAL_ID, PROFILE_ID, audience, trojan_profile, trojan_reference, uuid,
};

/// The Trojan node of `trojan_profile` plus a direct node, which changes the
/// profile digest but not the credential-bearing transport.
fn with_direct_node() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{CREDENTIAL_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}},{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .expect("typed profile")
}

#[test]
fn an_unchanged_credential_node_rebinds_to_the_new_profile_digest() {
    let previous = trojan_profile(CREDENTIAL_ID, 443);
    let candidate = with_direct_node();
    let request = CredentialRebindRequest::new(
        PROFILE_ID,
        &previous,
        &candidate,
        &EngineSettings::default(),
    )
    .expect("rebind");
    assert_eq!(
        request.previous_audience(),
        &CredentialAudience::new(PROFILE_ID, previous.digest()).expect("previous audience")
    );
    assert_eq!(
        request.audience(),
        &CredentialAudience::new(PROFILE_ID, candidate.digest()).expect("audience")
    );
    assert_eq!(
        request
            .slots()
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<Vec<_>>(),
        [trojan_reference(CREDENTIAL_ID)]
    );
}

#[test]
fn a_changed_credential_node_is_never_rebound() {
    let previous = trojan_profile(CREDENTIAL_ID, 443);
    let moved = trojan_profile(CREDENTIAL_ID, 8_443);
    let error =
        CredentialRebindRequest::new(PROFILE_ID, &previous, &moved, &EngineSettings::default())
            .expect_err("the transport changed");
    assert!(
        error.contains("credential-bearing nodes changed"),
        "{error}"
    );
    let error = CredentialRebindRequest::for_retained_credentials(
        PROFILE_ID,
        &previous,
        &moved,
        &EngineSettings::default(),
    )
    .expect_err("an existing credential on a changed transport");
    assert!(
        error.contains("cannot be reused by a changed transport"),
        "{error}"
    );
}

#[test]
fn retained_credentials_rebind_only_the_unchanged_nodes() {
    let previous = trojan_profile(CREDENTIAL_ID, 443);
    let retained = CredentialRebindRequest::for_retained_credentials(
        PROFILE_ID,
        &previous,
        &with_direct_node(),
        &EngineSettings::default(),
    )
    .expect("rebind")
    .expect("one retained credential");
    assert_eq!(retained.slots().len(), 1);
    assert_eq!(
        retained.slots()[0].reference(),
        &trojan_reference(CREDENTIAL_ID)
    );

    let fresh = trojan_profile(&uuid(7), 443);
    assert_eq!(
        CredentialRebindRequest::for_retained_credentials(
            PROFILE_ID,
            &previous,
            &fresh,
            &EngineSettings::default(),
        ),
        Ok(None)
    );
}

#[test]
fn a_rebind_decodes_only_within_one_profile_with_unique_slots() {
    let previous = trojan_profile(CREDENTIAL_ID, 443);
    let request = CredentialRebindRequest::new(
        PROFILE_ID,
        &previous,
        &with_direct_node(),
        &EngineSettings::default(),
    )
    .expect("rebind");
    let wire = serde_json::to_value(&request).expect("encode");
    assert_eq!(
        serde_json::from_value::<CredentialRebindRequest>(wire.clone()).expect("decode"),
        request
    );

    let mut other_profile = wire.clone();
    other_profile["audience"] = serde_json::to_value(audience(&uuid(9))).expect("audience");
    let mut repeated_slot = wire.clone();
    let slot = repeated_slot["slots"][0].clone();
    repeated_slot["slots"]
        .as_array_mut()
        .expect("slots")
        .push(slot);
    let mut unknown_field = wire;
    unknown_field["extra"] = serde_json::Value::Bool(true);
    for rejected in [other_profile, repeated_slot, unknown_field] {
        assert!(serde_json::from_value::<CredentialRebindRequest>(rejected).is_err());
    }
}

#[test]
fn a_rebind_needs_a_canonical_profile_id() {
    let previous = trojan_profile(CREDENTIAL_ID, 443);
    let candidate = with_direct_node();
    let settings = EngineSettings::default();
    let id = PROFILE_ID.to_uppercase();
    for error in [
        CredentialRebindRequest::new(&id, &previous, &candidate, &settings)
            .expect_err("an uppercase profile id"),
        CredentialRebindRequest::for_retained_credentials(&id, &previous, &candidate, &settings)
            .expect_err("an uppercase profile id"),
    ] {
        assert!(error.contains("canonical profile UUID"), "{error}");
    }
}
