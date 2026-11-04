//! Responses checked against their request: the preview and credential
//! receipts across languages, a non-canonical profile identity, and a response
//! of another identity, shape, version or request.

use super::*;

#[test]
fn cross_language_preview_response_is_validated() {
    let request_id =
        uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request UUID");
    let result = parse_response(
        request_id,
        include_bytes!("../../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
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
            "../../../../../../contracts/native-bridge-v10/credential-receipt-response.json"
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
        "../../../../../../contracts/native-bridge-v10/credential-receipt-response.json"
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
        include_bytes!("../../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
    )
    .expect_err("mismatched response must fail");
    assert_eq!(error.code, NativeBridgeErrorCode::IdentityRejected);
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
