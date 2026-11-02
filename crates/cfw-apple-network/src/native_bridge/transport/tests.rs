use cfw_engine_api::BackendErrorKind;

use super::*;

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
