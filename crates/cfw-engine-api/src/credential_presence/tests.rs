use super::*;
use crate::test_support::{CREDENTIAL_ID, PROFILE_ID, trojan_profile, trojan_reference};

#[test]
fn a_presence_query_names_every_reference_of_the_exact_profile() {
    let profile = trojan_profile(CREDENTIAL_ID, 443);
    let request = CredentialPresenceRequest::new(PROFILE_ID, &profile).expect("query");
    assert_eq!(request.profile_id(), PROFILE_ID);
    assert_eq!(
        request.audience(),
        &CredentialAudience::new(PROFILE_ID, profile.digest()).expect("audience")
    );
    assert_eq!(request.references(), &[trojan_reference(CREDENTIAL_ID)]);

    let wire = CredentialPresenceWireRequest::from(request.clone());
    assert_eq!(&wire.audience, request.audience());
    assert_eq!(wire.references, request.references());
}

#[test]
fn a_presence_query_needs_a_canonical_profile_id() {
    let profile = trojan_profile(CREDENTIAL_ID, 443);
    assert_eq!(
        CredentialPresenceRequest::new(PROFILE_ID.to_uppercase(), &profile),
        Err(CredentialProvisionRequestError::InvalidAudience)
    );
}
