use cfw_engine_api::{
    BackendErrorKind, CredentialGarbageCollectionPreview, CredentialGarbageCollectionReceipt,
    CredentialKind, CredentialPresence, CredentialProvision, CredentialRebindRequest,
    CredentialSecret, CredentialVaultReceipt, NativeRequestEnvelope, NativeResponseEnvelope,
    ValidatedSingBoxProfile,
};

use super::*;
use crate::native_bridge::fake_native::{
    admitted_requests, answer_fake_native, failure_for, fake_bridge, ffi_test_serialization,
    result_for,
};
use crate::test_support::CODE_KIND_PAIRS;

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";
const REBIND_REQUEST: &[u8] =
    include_bytes!("../../../../../contracts/native-bridge-v10/credential-rebind-request.json");
const GC_PREVIEW_REQUEST: &[u8] =
    include_bytes!("../../../../../contracts/native-bridge-v10/gc-preview-request.json");
const GC_PREVIEW_RESPONSE: &[u8] =
    include_bytes!("../../../../../contracts/native-bridge-v10/gc-preview-response.json");

/// A profile with two Trojan password references.
fn trojan_profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"first","server":"first.example.com","server_port":443,"credential_ref":{{"id":"{FIRST_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"first.example.com"}}}},{{"type":"trojan","tag":"second","server":"second.example.com","server_port":443,"credential_ref":{{"id":"{SECOND_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"second.example.com"}}}}]}}"#
    ))
    .expect("typed profile")
}

/// The two Trojan password references of `trojan_profile`.
fn trojan_references() -> (CredentialRef, CredentialRef) {
    (
        CredentialRef::new(FIRST_ID, CredentialKind::TrojanPassword)
            .expect("canonical first reference"),
        CredentialRef::new(SECOND_ID, CredentialKind::TrojanPassword)
            .expect("canonical second reference"),
    )
}

/// Secrets for both references of `profile`, in the reverse of their order.
fn provision_request<'a>(
    profile: &'a ValidatedSingBoxProfile,
    (first, second): &'a (CredentialRef, CredentialRef),
) -> CredentialProvisionRequest<'a> {
    CredentialProvisionRequest::new(
        PROFILE_ID,
        profile,
        vec![
            CredentialProvision::new(
                second,
                CredentialSecret::new("second-dummy-secret").expect("second secret"),
            ),
            CredentialProvision::new(
                first,
                CredentialSecret::new("first-dummy-secret").expect("first secret"),
            ),
        ],
    )
    .expect("canonical request")
}

/// The command of a cross-language contract request.
fn contract_command(bytes: &[u8]) -> NativeBridgeCommand {
    serde_json::from_slice::<NativeRequestEnvelope>(bytes)
        .expect("contract request")
        .command
}

fn rebind_request() -> CredentialRebindRequest {
    match contract_command(REBIND_REQUEST) {
        NativeBridgeCommand::RebindProfileCredentials { request } => request,
        other => panic!("unexpected contract command {other:?}"),
    }
}

fn gc_request() -> CredentialGarbageCollectionRequest {
    match contract_command(GC_PREVIEW_REQUEST) {
        NativeBridgeCommand::PreviewCredentialGarbageCollection { request } => request,
        other => panic!("unexpected contract command {other:?}"),
    }
}

fn gc_preview() -> CredentialGarbageCollectionPreview {
    match serde_json::from_slice::<NativeResponseEnvelope>(GC_PREVIEW_RESPONSE)
        .expect("contract response")
        .result
    {
        Some(NativeBridgeResult::CredentialGarbageCollectionPreview(preview)) => preview,
        other => panic!("unexpected contract result {other:?}"),
    }
}

/// Answers every request with `result`.
fn answer(result: NativeBridgeResult) {
    answer_fake_native(move |request| result_for(request, result.clone()));
}

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
    let profile = trojan_profile();
    let references = trojan_references();
    let request = provision_request(&profile, &references);
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

#[tokio::test]
async fn each_vault_operation_returns_its_own_result() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();

    let rebind = rebind_request();
    let rebound = CredentialVaultReceipt {
        profile_id: rebind.audience().profile_id().to_owned(),
        profile_digest: rebind.audience().profile_digest().to_owned(),
    };
    answer(NativeBridgeResult::CredentialReceipt(rebound.clone()));
    assert_eq!(
        bridge.rebind_profile_credentials(rebind.clone()).await,
        Ok(rebound)
    );
    assert_eq!(
        admitted_requests()[0].body["command"],
        serde_json::to_value(NativeBridgeCommand::RebindProfileCredentials { request: rebind })
            .expect("rebind wire")
    );

    let profile = trojan_profile();
    let references = trojan_references();
    let provisioned = CredentialVaultReceipt {
        profile_id: PROFILE_ID.to_owned(),
        profile_digest: profile.digest().to_owned(),
    };
    answer(NativeBridgeResult::CredentialReceipt(provisioned.clone()));
    assert_eq!(
        bridge
            .provision_profile_credentials(provision_request(&profile, &references))
            .await,
        Ok(provisioned)
    );
    let sent = &admitted_requests()[0].body;
    assert_eq!(sent["command"]["opcode"], "provision_credentials");
    assert_eq!(
        sent.pointer("/command/payload/request/entries/0/secret"),
        Some(&serde_json::json!("first-dummy-secret"))
    );

    let presence = profile
        .credential_references()
        .into_iter()
        .map(|reference| CredentialPresence {
            reference,
            present: true,
        })
        .collect::<Vec<_>>();
    answer(NativeBridgeResult::CredentialPresence(presence.clone()));
    assert_eq!(
        bridge
            .query_profile_credentials(
                CredentialPresenceRequest::new(PROFILE_ID, &profile).expect("presence request")
            )
            .await,
        Ok(presence)
    );

    let preview = gc_preview();
    answer(NativeBridgeResult::CredentialGarbageCollectionPreview(
        preview.clone(),
    ));
    assert_eq!(
        bridge
            .preview_credential_garbage_collection(gc_request())
            .await,
        Ok(preview.clone())
    );

    let collected = CredentialGarbageCollectionReceipt {
        vault_revision: preview.vault_revision.clone(),
        deleted_count: preview.orphan_count,
    };
    answer(NativeBridgeResult::CredentialGarbageCollectionReceipt(
        collected.clone(),
    ));
    assert_eq!(
        bridge
            .commit_credential_garbage_collection(
                CredentialGarbageCollectionCommitRequest::new(gc_request(), &preview)
                    .expect("commit request")
            )
            .await,
        Ok(collected)
    );
}

#[tokio::test]
async fn each_vault_operation_refuses_a_result_it_did_not_ask_for() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();
    let profile = trojan_profile();
    let references = trojan_references();
    let preview = gc_preview();
    let rebind = rebind_request();

    // A rebinding receipt for another profile is not a receipt for this one.
    answer(NativeBridgeResult::CredentialReceipt(
        CredentialVaultReceipt {
            profile_id: "abcdefab-cdef-4abc-8def-abcdefabcdef".to_owned(),
            profile_digest: rebind.audience().profile_digest().to_owned(),
        },
    ));
    assert_eq!(
        bridge.rebind_profile_credentials(rebind.clone()).await,
        Err(CredentialVaultError::IdentityRejected)
    );

    answer(NativeBridgeResult::Acknowledged);
    assert_eq!(
        bridge.rebind_profile_credentials(rebind).await,
        Err(CredentialVaultError::IdentityRejected)
    );
    assert_eq!(
        bridge
            .provision_profile_credentials(provision_request(&profile, &references))
            .await,
        Err(CredentialVaultError::Internal)
    );
    assert_eq!(
        bridge
            .query_profile_credentials(
                CredentialPresenceRequest::new(PROFILE_ID, &profile).expect("presence request")
            )
            .await,
        Err(CredentialVaultError::Internal)
    );
    assert_eq!(
        bridge
            .preview_credential_garbage_collection(gc_request())
            .await,
        Err(CredentialVaultError::Internal)
    );
    assert_eq!(
        bridge
            .commit_credential_garbage_collection(
                CredentialGarbageCollectionCommitRequest::new(gc_request(), &preview)
                    .expect("commit request")
            )
            .await,
        Err(CredentialVaultError::Internal)
    );
}

#[tokio::test]
async fn a_native_vault_failure_is_reported_as_its_vault_error() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();
    let profile = trojan_profile();
    let references = trojan_references();
    let preview = gc_preview();
    answer_fake_native(|request| failure_for(request, BackendErrorKind::CredentialConflict));
    let conflict = Err(CredentialVaultError::ImmutableConflict);
    assert_eq!(
        bridge.rebind_profile_credentials(rebind_request()).await,
        conflict
    );
    assert_eq!(
        bridge
            .provision_profile_credentials(provision_request(&profile, &references))
            .await,
        conflict
    );
    assert_eq!(
        bridge
            .query_profile_credentials(
                CredentialPresenceRequest::new(PROFILE_ID, &profile).expect("presence request")
            )
            .await
            .map(|_| ()),
        Err(CredentialVaultError::ImmutableConflict)
    );
    assert_eq!(
        bridge
            .preview_credential_garbage_collection(gc_request())
            .await
            .map(|_| ()),
        Err(CredentialVaultError::ImmutableConflict)
    );
    assert_eq!(
        bridge
            .commit_credential_garbage_collection(
                CredentialGarbageCollectionCommitRequest::new(gc_request(), &preview)
                    .expect("commit request")
            )
            .await
            .map(|_| ()),
        Err(CredentialVaultError::ImmutableConflict)
    );
}

#[test]
fn every_native_code_maps_to_one_vault_error() {
    use NativeBridgeErrorCode as Code;
    let dedicated = [
        (Code::Timeout, CredentialVaultError::OutcomeUnknown),
        (Code::PermissionDenied, CredentialVaultError::AccessDenied),
        (
            Code::CredentialConflict,
            CredentialVaultError::ImmutableConflict,
        ),
        (
            Code::CredentialVaultMissing,
            CredentialVaultError::MissingVault,
        ),
        (Code::CredentialVaultCorrupt, CredentialVaultError::Corrupt),
        (
            Code::CredentialMigrationRequired,
            CredentialVaultError::MigrationRequired,
        ),
        (
            Code::CredentialGcConflict,
            CredentialVaultError::ConcurrentModification,
        ),
        (
            Code::ResourceExhausted,
            CredentialVaultError::CapacityExceeded,
        ),
        (
            Code::ConfigurationRejected,
            CredentialVaultError::InvalidMaterial,
        ),
        (
            Code::IdentityRejected,
            CredentialVaultError::IdentityRejected,
        ),
    ];
    // Failures of the native services rather than of the vault itself.
    let unavailable = [
        Code::Busy,
        Code::JournalCapacityExhausted,
        Code::ApprovalDenied,
        Code::CredentialsUnavailable,
        Code::ProxyAgentApprovalRequired,
        Code::GlobalAuthorityUnavailable,
        Code::GlobalAuthorityRegistrationRequired,
        Code::GlobalAuthorityApprovalRequired,
        Code::GlobalAuthorityIdentityRejected,
        Code::GlobalAuthorityProtocolMismatch,
        Code::GlobalAuthorityRecovering,
        Code::GlobalAuthorityTimeout,
        Code::GlobalAuthorityInterrupted,
        Code::GlobalLeaseConflict,
        Code::ReplayRejected,
        Code::StaleOperation,
        Code::TicketExpired,
        Code::TicketAlreadyRedeemed,
        Code::TicketInvalid,
        Code::CompensationConflict,
        Code::CleanupUnproven,
        Code::Quarantined,
        Code::OwnerUnresponsive,
        Code::Unavailable,
    ];
    for &(code, _) in CODE_KIND_PAIRS {
        let expected = dedicated
            .iter()
            .find(|(dedicated, _)| *dedicated == code)
            .map(|(_, error)| *error)
            .unwrap_or(if unavailable.contains(&code) {
                CredentialVaultError::Unavailable
            } else {
                CredentialVaultError::Internal
            });
        assert_eq!(
            map_vault_error(NativeBridgeError::new(code, "untrusted detail")),
            expected,
            "{code:?}"
        );
    }
}

#[test]
fn a_provisioning_entry_never_prints_its_secret() {
    let profile = trojan_profile();
    let references = trojan_references();
    let envelope = sensitive_provision_envelope(
        uuid::Uuid::new_v4(),
        &provision_request(&profile, &references),
    );
    let SensitiveCommand::ProvisionCredentials { request } = &envelope.command;
    let printed = format!("{:?}", request.entries);
    assert!(
        printed.contains(FIRST_ID) && printed.contains(SECOND_ID),
        "{printed}"
    );
    assert!(printed.contains("[REDACTED]"), "{printed}");
    assert!(
        !printed.contains("first-dummy-secret") && !printed.contains("second-dummy-secret"),
        "{printed}"
    );
}
