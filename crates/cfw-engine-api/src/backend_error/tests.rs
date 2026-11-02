use std::collections::BTreeSet;

use super::*;

#[derive(Deserialize)]
struct AuthorityErrorContract {
    errors: Vec<AuthorityErrorFixture>,
}

#[derive(Deserialize)]
struct AuthorityErrorFixture {
    code: String,
    retry: String,
    message: String,
}

#[test]
fn authority_error_fixture_is_unique_complete_and_stable() {
    let contract: AuthorityErrorContract = serde_json::from_str(include_str!(
        "../../../../fixtures/authority-v1/error-contract.json"
    ))
    .expect("authority error fixture");
    assert_eq!(
        contract.errors.len(),
        BackendErrorKind::AUTHORITY_KINDS.len()
    );

    let mut codes = BTreeSet::new();
    for entry in contract.errors {
        assert!(codes.insert(entry.code.clone()), "duplicate Authority code");
        let kind: BackendErrorKind = serde_json::from_str(&format!("\"{}\"", entry.code))
            .expect("known Authority wire code");
        assert!(BackendErrorKind::AUTHORITY_KINDS.contains(&kind));
        assert_eq!(
            serde_json::to_value(kind).expect("wire code"),
            serde_json::Value::String(entry.code)
        );
        assert_eq!(kind.stable_message(), entry.message);
        assert_eq!(
            serde_json::to_value(kind.retry_directive()).expect("retry directive"),
            serde_json::Value::String(entry.retry)
        );
        assert!(!kind.allows_automatic_retry(false));
        assert_eq!(
            kind.allows_automatic_retry(true),
            kind.retry_directive() == RetryDirective::IdempotentReadOnly
        );
    }
}

#[test]
fn unknown_wire_error_is_internal_and_never_retryable() {
    let unknown: BackendErrorKind =
        serde_json::from_str("\"future_authority_code\"").expect("safe unknown mapping");
    assert_eq!(unknown, BackendErrorKind::Internal);
    assert_eq!(unknown.retry_directive(), RetryDirective::Never);
    assert!(!unknown.allows_automatic_retry(true));
}

#[test]
fn endpoint_conflicts_are_not_part_of_the_generic_retry_policy() {
    for kind in [
        BackendErrorKind::MixedEndpointInUse,
        BackendErrorKind::ControllerEndpointInUse,
    ] {
        assert_eq!(kind.retry_directive(), RetryDirective::Never);
        assert!(!kind.allows_automatic_retry(true));
    }
}

#[test]
fn engine_start_timeout_is_a_typed_cause_that_is_never_retried_automatically() {
    let kind = BackendErrorKind::EngineStartTimedOut;
    assert_eq!(
        serde_json::to_value(kind).expect("wire code"),
        serde_json::Value::String("engine_start_timed_out".into())
    );
    assert_eq!(
        serde_json::from_str::<BackendErrorKind>("\"engine_start_timed_out\"")
            .expect("known wire code"),
        kind
    );
    assert_eq!(kind.retry_directive(), RetryDirective::Never);
    assert!(!kind.allows_automatic_retry(true));
    assert!(!kind.allows_read_only_recheck());
    // The same text as the Swift NativeBridgeErrorCode.engineStartTimedOut.
    assert_eq!(
        kind.stable_message(),
        "The engine did not finish starting in time and was stopped, usually because \
             rule datasets were still downloading. Datasets that finished are kept for the \
             next start."
    );
}

#[test]
fn proxy_agent_approval_has_a_typed_registration_retry_contract() {
    let kind = BackendErrorKind::ProxyAgentApprovalRequired;
    assert_eq!(
        serde_json::to_value(kind).expect("wire code"),
        serde_json::Value::String("proxy_agent_approval_required".into())
    );
    assert_eq!(
        kind.retry_directive(),
        RetryDirective::RegistrationStatusChange
    );
    assert!(!kind.allows_automatic_retry(true));
    assert_eq!(
        kind.stable_message(),
        "ProxyAgent approval is required in System Settings."
    );
}
