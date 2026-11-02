use cfw_engine_api::{
    BackendErrorKind, CredentialAudience, CredentialGarbageCollectionReceipt, CredentialKind,
    CredentialPresence, CredentialRef, CutoverPreflightAttestation, ENGINE_PROTOCOL_VERSION,
    EngineCommandContext, NativeServiceMaintenanceAction, NativeServiceMaintenanceResult,
    NativeServiceRegistrationStatus, ProfileProbeFailure, ProfileProxyDelay, TunnelApprovalWait,
};

use super::*;

const REQUEST: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn request_id() -> uuid::Uuid {
    uuid::Uuid::parse_str(REQUEST).expect("request UUID")
}

/// The wire form of a response to the request.
fn envelope(
    result: Option<NativeBridgeResult>,
    failure: Option<NativeBridgeFailure>,
) -> serde_json::Value {
    serde_json::to_value(NativeResponseEnvelope {
        schema_version: ENGINE_PROTOCOL_VERSION,
        request_id: Some(request_id()),
        result,
        failure,
    })
    .expect("response wire")
}

fn parsed(envelope: serde_json::Value) -> Result<NativeBridgeResult, NativeBridgeError> {
    parse_response(
        request_id(),
        &serde_json::to_vec(&envelope).expect("response bytes"),
    )
}

/// What the bridge makes of a success response carrying `result`.
fn answered(result: NativeBridgeResult) -> Result<NativeBridgeResult, NativeBridgeError> {
    parsed(envelope(Some(result), None))
}

fn non_canonical() -> Result<NativeBridgeResult, NativeBridgeError> {
    Err(NativeBridgeError::new(
        NativeBridgeErrorCode::IdentityRejected,
        "native bridge response contains a non-canonical identity",
    ))
}

fn incomplete_runtime() -> Result<NativeBridgeResult, NativeBridgeError> {
    Err(NativeBridgeError::new(
        NativeBridgeErrorCode::IdentityRejected,
        "native runtime attestation is incomplete or non-canonical",
    ))
}

fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
        config_epoch: 4,
        generation: 9,
    }
}

fn runtime(owner: EngineOwner) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: context(),
        config_digest: "a".repeat(64),
        ready: true,
    }
}

fn failure() -> NativeBridgeFailure {
    NativeBridgeFailure {
        code: BackendErrorKind::Busy,
        message: "native detail".to_owned(),
    }
}

#[test]
fn unknown_wire_failure_maps_to_stable_internal_non_retryable_error() {
    let request_id =
        uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request UUID");
    let response = format!(
        "{{\"schema_version\":{},\"request_id\":\"{request_id}\",\"result\":null,\"failure\":{{\"code\":\"future_authority_code\",\"message\":\"/private/path secret identity\"}}}}",
        cfw_engine_api::ENGINE_PROTOCOL_VERSION
    );
    let error = parse_response(request_id, response.as_bytes()).expect_err("unknown code");
    assert_eq!(error.code, NativeBridgeErrorCode::Internal);
    assert_eq!(error.message, BackendErrorKind::Internal.stable_message());
    assert!(!error.message.contains("private"));
    assert!(!error.message.contains("secret"));
    let kind = BackendErrorKind::from(error.code);
    assert!(!kind.allows_automatic_retry(true));
}

#[test]
fn startup_failure_stages_keep_their_codes_without_exposing_native_text() {
    for kind in [
        BackendErrorKind::SystemExtensionValidationFailed,
        BackendErrorKind::SystemProxyConfigurationFailed,
        BackendErrorKind::SystemProxyRuntimeFailed,
        BackendErrorKind::EngineStartTimedOut,
        BackendErrorKind::SystemProxyPreferencesFailed,
        BackendErrorKind::SystemProxyJournalFailed,
        BackendErrorKind::SystemProxyAuthorityFailed,
    ] {
        let error = map_wire_failure(NativeBridgeFailure {
            code: kind,
            message: "private native credential".into(),
        });
        assert_eq!(BackendErrorKind::from(error.code), kind);
        assert_eq!(error.message, kind.stable_message());
        assert!(!error.message.contains("credential"));
        assert!(!kind.allows_automatic_retry(false));
    }
}

#[test]
fn global_authority_failure_preserves_code_and_discards_wire_text() {
    let error = map_wire_failure(NativeBridgeFailure {
        code: BackendErrorKind::GlobalAuthorityUnavailable,
        message: "/Users/alice/private/secret localized diagnostic".into(),
    });
    assert_eq!(
        error.code,
        NativeBridgeErrorCode::GlobalAuthorityUnavailable
    );
    assert_eq!(
        error.message,
        BackendErrorKind::GlobalAuthorityUnavailable.stable_message()
    );
    assert!(!error.message.contains("alice"));
    assert!(!error.message.contains("secret"));
}

#[test]
fn vault_failure_preserves_typed_corruption_and_discards_wire_text() {
    let request_id =
        uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").expect("request UUID");
    for (code, expected) in [
        (
            "credential_vault_corrupt",
            NativeBridgeErrorCode::CredentialVaultCorrupt,
        ),
        ("identity_rejected", NativeBridgeErrorCode::IdentityRejected),
        (
            "engine_start_timed_out",
            NativeBridgeErrorCode::EngineStartTimedOut,
        ),
    ] {
        let response = serde_json::json!({
            "schema_version": cfw_engine_api::ENGINE_PROTOCOL_VERSION,
            "request_id": request_id,
            "failure": {"code": code, "message": "/private/secret localized diagnostic"},
        });
        let error = parse_response(
            request_id,
            &serde_json::to_vec(&response).expect("failure response"),
        )
        .expect_err("typed native failure");
        assert_eq!(error.code, expected);
        assert_eq!(
            error.message,
            BackendErrorKind::from(expected).stable_message()
        );
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("secret"));
    }
}

#[test]
fn cross_language_preview_response_is_validated() {
    let request_id =
        uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request UUID");
    let result = parse_response(
        request_id,
        include_bytes!("../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
    )
    .expect("cross-language response");
    let NativeBridgeResult::CredentialGarbageCollectionPreview(preview) = result else {
        panic!("unexpected response kind");
    };
    assert_eq!(preview.orphan_count, 1);
}

#[test]
fn cross_language_credential_receipt_is_validated() {
    let request_id =
        uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").expect("request UUID");
    let result = parse_response(
        request_id,
        include_bytes!(
            "../../../../../contracts/native-bridge-v10/credential-receipt-response.json"
        ),
    )
    .expect("Swift producer credential receipt");
    let NativeBridgeResult::CredentialReceipt(receipt) = result else {
        panic!("unexpected response kind");
    };
    assert_eq!(receipt.profile_id, "abcdefab-cdef-4abc-8def-abcdefabcdef");
    assert_eq!(receipt.profile_digest, "ab".repeat(32));
}

#[test]
fn credential_receipt_rejects_noncanonical_profile_identity() {
    let request_id =
        uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").expect("request UUID");
    let mut response: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../contracts/native-bridge-v10/credential-receipt-response.json"
    ))
    .expect("shared receipt fixture");
    for profile_id in [
        "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
        "abcdefabcdef4abc8defabcdefabcdef",
        "not-a-profile-uuid",
    ] {
        response["result"]["value"]["profile_id"] = profile_id.into();
        let error = parse_response(
            request_id,
            &serde_json::to_vec(&response).expect("mutated response"),
        )
        .expect_err("noncanonical receipt must fail");
        assert_eq!(error.code, NativeBridgeErrorCode::IdentityRejected);
    }
}

#[test]
fn response_identity_mismatch_fails_closed() {
    let expected =
        uuid::Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("request UUID");
    let error = parse_response(
        expected,
        include_bytes!("../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
    )
    .expect_err("mismatched response must fail");
    assert_eq!(error.code, NativeBridgeErrorCode::IdentityRejected);
}

#[tokio::test]
async fn callback_keeps_dynamic_bridge_state_alive_after_future_cancellation() {
    let bridge = Arc::new(BridgeState::Unavailable("test".into()));
    let weak = Arc::downgrade(&bridge);
    let (sender, receiver) = oneshot::channel();
    let callback = Box::new(CallbackState {
        sender: Some(sender),
        _bridge: Arc::clone(&bridge),
    });
    let context = Box::into_raw(callback).cast::<c_void>();
    drop(bridge);
    assert!(weak.upgrade().is_some());
    let bytes = b"{}";
    // SAFETY: context is one live CallbackState allocation and bytes stay
    // readable for the callback duration.
    unsafe {
        bridge_completion(context, bytes.as_ptr(), bytes.len() as isize);
    }
    assert_eq!(
        receiver.await.expect("callback result").expect("bytes"),
        bytes
    );
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn callback_rejects_negative_response_length_without_reading_memory() {
    let bridge = Arc::new(BridgeState::Unavailable("test".into()));
    let (sender, receiver) = oneshot::channel();
    let callback = Box::new(CallbackState {
        sender: Some(sender),
        _bridge: bridge,
    });
    let context = Box::into_raw(callback).cast::<c_void>();

    // SAFETY: context is one live CallbackState allocation. A negative
    // length must be rejected before the null byte pointer is inspected.
    unsafe {
        bridge_completion(context, std::ptr::null(), -1);
    }

    let error = receiver
        .await
        .expect("callback result")
        .expect_err("negative length must fail closed");
    assert_eq!(error.code, NativeBridgeErrorCode::Internal);
}

#[test]
fn a_response_of_another_shape_version_or_request_is_refused() {
    assert_eq!(
        parse_response(request_id(), b"not json"),
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge returned a malformed response"
        ))
    );
    for version in [ENGINE_PROTOCOL_VERSION - 1, ENGINE_PROTOCOL_VERSION + 1] {
        let mut other_version = envelope(Some(NativeBridgeResult::Acknowledged), None);
        other_version["schema_version"] = serde_json::json!(version);
        assert_eq!(
            parsed(other_version),
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::IdentityRejected,
                "native bridge response schema does not match Rust"
            )),
            "{version}"
        );
    }
    for shape in [
        envelope(Some(NativeBridgeResult::Acknowledged), Some(failure())),
        envelope(None, None),
    ] {
        assert_eq!(
            parsed(shape),
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Internal,
                "native bridge response has an invalid result/failure shape"
            ))
        );
    }

    let other_request = serde_json::json!("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    let mut failed_elsewhere = envelope(None, Some(failure()));
    failed_elsewhere["request_id"] = other_request.clone();
    assert_eq!(
        parsed(failed_elsewhere),
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native bridge failure response has a mismatched request identity"
        ))
    );
    // A failure the bridge raised before it read the request id is reported.
    let mut failed_unidentified = envelope(None, Some(failure()));
    failed_unidentified["request_id"] = serde_json::Value::Null;
    assert_eq!(
        parsed(failed_unidentified),
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Busy,
            BackendErrorKind::Busy.stable_message()
        ))
    );
    for request in [other_request, serde_json::Value::Null] {
        let mut answered_elsewhere = envelope(Some(NativeBridgeResult::Acknowledged), None);
        answered_elsewhere["request_id"] = request;
        assert_eq!(
            parsed(answered_elsewhere),
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::IdentityRejected,
                "native bridge success response has a mismatched request identity"
            ))
        );
    }
}

#[test]
fn profile_delays_are_bounded_named_and_either_measured_or_failed() {
    let delay = |name: &str, delay: Option<u32>, error_kind: Option<ProfileProbeFailure>| {
        ProfileProxyDelay {
            name: name.to_owned(),
            delay,
            error_kind,
        }
    };
    let accepted = vec![
        delay("Tokyo", Some(1), None),
        delay("Osaka", None, Some(ProfileProbeFailure::NotFound)),
    ];
    assert_eq!(
        answered(NativeBridgeResult::ProfileDelays(accepted.clone())),
        Ok(NativeBridgeResult::ProfileDelays(accepted))
    );
    assert!(
        answered(NativeBridgeResult::ProfileDelays(vec![
            delay(
                "Tokyo",
                Some(1),
                None
            );
            32
        ]))
        .is_ok()
    );
    for refused in [
        vec![delay("Tokyo", Some(1), None); 33],
        vec![delay("", Some(1), None)],
        vec![delay(&"n".repeat(513), Some(1), None)],
        vec![delay("Tokyo", Some(0), None)],
        vec![delay("Tokyo", Some(1), Some(ProfileProbeFailure::Timeout))],
        vec![delay("Tokyo", None, None)],
    ] {
        assert_eq!(
            answered(NativeBridgeResult::ProfileDelays(refused)),
            non_canonical()
        );
    }
    assert!(
        answered(NativeBridgeResult::ProfileDelays(vec![delay(
            &"n".repeat(512),
            Some(1),
            None
        )]))
        .is_ok()
    );
}

#[test]
fn a_runtime_must_be_ready_attested_and_owned_by_its_mode() {
    for (status, owner) in [
        (
            NativeEngineStatus::LocalProxy {
                runtime: runtime(EngineOwner::ProxyAgent),
            },
            EngineOwner::ProxyAgent,
        ),
        (
            NativeEngineStatus::SystemProxy {
                runtime: runtime(EngineOwner::ProxyAgent),
            },
            EngineOwner::ProxyAgent,
        ),
        (
            NativeEngineStatus::Tunnel {
                runtime: runtime(EngineOwner::PacketTunnelSystemExtension),
            },
            EngineOwner::PacketTunnelSystemExtension,
        ),
    ] {
        assert_eq!(
            answered(NativeBridgeResult::Status(status.clone())),
            Ok(NativeBridgeResult::Status(status)),
            "{owner:?}"
        );
    }
    for misowned in [
        NativeEngineStatus::SystemProxy {
            runtime: runtime(EngineOwner::PacketTunnelSystemExtension),
        },
        NativeEngineStatus::Tunnel {
            runtime: runtime(EngineOwner::ProxyAgent),
        },
    ] {
        assert_eq!(
            answered(NativeBridgeResult::Status(misowned)),
            incomplete_runtime()
        );
    }

    let attested = runtime(EngineOwner::PacketTunnelSystemExtension);
    assert!(answered(NativeBridgeResult::Runtime(attested.clone())).is_ok());
    let broken: [fn(&mut RuntimeIdentity); 6] = [
        |runtime| runtime.context.installation_id = "60FB4B30-53DA-47CA-A933-E98268CE5703".into(),
        |runtime| runtime.context.config_epoch = 0,
        |runtime| runtime.context.generation = 0,
        |runtime| runtime.config_digest = "A".repeat(64),
        |runtime| runtime.config_digest = "a".repeat(63),
        |runtime| runtime.ready = false,
    ];
    for break_it in broken {
        let mut runtime = attested.clone();
        break_it(&mut runtime);
        assert_eq!(
            answered(NativeBridgeResult::Runtime(runtime)),
            incomplete_runtime()
        );
    }
}

#[test]
fn vault_and_service_results_are_bounded_and_canonical() {
    let reference = CredentialRef::new(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::TrojanPassword,
    )
    .expect("credential reference");
    let presence = CredentialPresence {
        reference,
        present: true,
    };
    assert!(
        answered(NativeBridgeResult::CredentialPresence(vec![
            presence.clone();
            MAX_CREDENTIAL_SLOTS
        ]))
        .is_ok()
    );
    assert_eq!(
        answered(NativeBridgeResult::CredentialPresence(vec![
            presence;
            MAX_CREDENTIAL_SLOTS
                + 1
        ])),
        non_canonical()
    );

    let mut preview = match parse_response(
        request_id(),
        include_bytes!("../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
    ) {
        Ok(NativeBridgeResult::CredentialGarbageCollectionPreview(preview)) => preview,
        other => panic!("unexpected contract result {other:?}"),
    };
    preview.vault_revision = "not-a-revision".into();
    assert_eq!(
        answered(NativeBridgeResult::CredentialGarbageCollectionPreview(
            preview
        )),
        non_canonical()
    );
    for (vault_revision, accepted) in [
        ("cccccccc-cccc-4ccc-8ccc-cccccccccccc", true),
        ("CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", false),
    ] {
        let receipt = NativeBridgeResult::CredentialGarbageCollectionReceipt(
            CredentialGarbageCollectionReceipt {
                vault_revision: vault_revision.into(),
                deleted_count: 1,
            },
        );
        assert_eq!(answered(receipt).is_ok(), accepted, "{vault_revision}");
    }

    let status = NativeServiceMaintenanceResult {
        action: NativeServiceMaintenanceAction::Status,
        engine_status: None,
        global_authority: NativeServiceRegistrationStatus::Enabled,
        off_proof_profile: None,
        proxy_agent: NativeServiceRegistrationStatus::Enabled,
    };
    assert!(answered(NativeBridgeResult::ServiceMaintenance(status.clone())).is_ok());
    let unproven_off = NativeServiceMaintenanceResult {
        action: NativeServiceMaintenanceAction::ProveOff,
        ..status
    };
    assert_eq!(
        answered(NativeBridgeResult::ServiceMaintenance(unproven_off)),
        non_canonical()
    );
    assert!(
        answered(NativeBridgeResult::TunnelApproval(
            TunnelApprovalWait::StillAwaiting
        ))
        .is_ok()
    );
}

#[test]
fn a_cutover_awaiting_approval_names_a_real_target_and_context() {
    let awaiting = |target: EngineMode, context: EngineCommandContext, digest: String| {
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::AwaitingApproval {
            target,
            context,
            system_proxy_config_digest: digest.clone(),
            tunnel_config_digest: digest,
            credential_audience: CredentialAudience::new(REQUEST, "c".repeat(64))
                .expect("audience"),
        })
    };
    assert!(answered(awaiting(EngineMode::Tunnel, context(), "a".repeat(64))).is_ok());
    let mut uppercase = context();
    uppercase.installation_id = uppercase.installation_id.to_uppercase();
    let mut first_epoch = context();
    first_epoch.config_epoch = 0;
    let mut first_generation = context();
    first_generation.generation = 0;
    for refused in [
        awaiting(EngineMode::Off, context(), "a".repeat(64)),
        awaiting(EngineMode::Tunnel, uppercase, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, first_epoch, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, first_generation, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, context(), "not-a-digest".into()),
    ] {
        assert_eq!(answered(refused), non_canonical());
    }
}

#[tokio::test]
async fn the_callback_refuses_an_empty_oversized_or_missing_response_without_reading_it() {
    let bytes = b"{}";
    for (pointer, length, message) in [
        (
            bytes.as_ptr(),
            0,
            "native bridge returned an empty response",
        ),
        (
            bytes.as_ptr(),
            MAXIMUM_RESPONSE_BYTES as isize + 1,
            "native bridge response exceeds the fixed bound",
        ),
        (
            std::ptr::null(),
            bytes.len() as isize,
            "native bridge returned a null response pointer",
        ),
    ] {
        let (sender, receiver) = oneshot::channel();
        let context = Box::into_raw(Box::new(CallbackState {
            sender: Some(sender),
            _bridge: Arc::new(BridgeState::Unavailable("test".into())),
        }))
        .cast::<c_void>();
        // SAFETY: context is one live CallbackState allocation; the length is
        // checked before any byte is read.
        unsafe {
            bridge_completion(context, pointer, length);
        }
        assert_eq!(
            receiver.await.expect("callback result"),
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Internal,
                message
            ))
        );
    }
}

#[test]
fn a_callback_without_its_context_is_ignored() {
    let bytes = b"{}";
    // SAFETY: a null context is the one input the callback must ignore.
    unsafe {
        bridge_completion(std::ptr::null_mut(), bytes.as_ptr(), bytes.len() as isize);
    }
}

#[test]
fn a_ready_cutover_carries_an_attestation_that_is_still_valid() {
    let ready = |valid_for_millis: u32| {
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::Ready {
            attestation: CutoverPreflightAttestation {
                attestation_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(),
                target: EngineMode::Tunnel,
                context: context(),
                system_proxy_config_digest: "a".repeat(64),
                tunnel_config_digest: "b".repeat(64),
                credential_audience: CredentialAudience::new(REQUEST, "c".repeat(64))
                    .expect("audience"),
                credential_references: Vec::new(),
                valid_for_millis,
            },
        })
    };
    assert!(answered(ready(1_000)).is_ok());
    assert_eq!(answered(ready(0)), non_canonical());
}
