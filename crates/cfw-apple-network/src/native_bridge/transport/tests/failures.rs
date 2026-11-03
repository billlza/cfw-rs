//! Native failures that cross the bridge: each keeps its stable code and typed
//! detail, and none carries the native text.

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
