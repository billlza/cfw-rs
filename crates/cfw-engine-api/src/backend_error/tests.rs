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

/// Every kind with the directive the native boundary documents for it. The
/// Authority kinds also come from the shared error fixture above.
const RETRY_DIRECTIVES: [(BackendErrorKind, RetryDirective); 49] = [
    (
        BackendErrorKind::Busy,
        RetryDirective::FreshSnapshotAfterOff,
    ),
    (
        BackendErrorKind::ResourceExhausted,
        RetryDirective::IdempotentReadOnly,
    ),
    (
        BackendErrorKind::JournalCapacityExhausted,
        RetryDirective::MaintenanceRequired,
    ),
    (BackendErrorKind::PermissionDenied, RetryDirective::Never),
    (BackendErrorKind::ApprovalDenied, RetryDirective::Never),
    (
        BackendErrorKind::ConfigurationRejected,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SystemExtensionValidationFailed,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SystemProxyConfigurationFailed,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SystemProxyRuntimeFailed,
        RetryDirective::Never,
    ),
    (BackendErrorKind::EngineStartTimedOut, RetryDirective::Never),
    (
        BackendErrorKind::SystemProxyPreferencesFailed,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SystemProxyJournalFailed,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SystemProxyAuthorityFailed,
        RetryDirective::Never,
    ),
    (BackendErrorKind::ExistingSystemProxy, RetryDirective::Never),
    (
        BackendErrorKind::CredentialsUnavailable,
        RetryDirective::Never,
    ),
    (BackendErrorKind::CredentialConflict, RetryDirective::Never),
    (
        BackendErrorKind::CredentialVaultMissing,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::CredentialVaultCorrupt,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::CredentialMigrationRequired,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::CredentialGcConflict,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::ProxyAgentApprovalRequired,
        RetryDirective::RegistrationStatusChange,
    ),
    (
        BackendErrorKind::GlobalAuthorityUnavailable,
        RetryDirective::RegistrationStatusChange,
    ),
    (
        BackendErrorKind::GlobalAuthorityRegistrationRequired,
        RetryDirective::RegistrationStatusChange,
    ),
    (
        BackendErrorKind::GlobalAuthorityApprovalRequired,
        RetryDirective::RegistrationStatusChange,
    ),
    (
        BackendErrorKind::GlobalAuthorityIdentityRejected,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::GlobalAuthorityProtocolMismatch,
        RetryDirective::CompatibleSoftwareUpdate,
    ),
    (
        BackendErrorKind::GlobalAuthorityRecovering,
        RetryDirective::ExplicitReconciliation,
    ),
    (
        BackendErrorKind::GlobalAuthorityTimeout,
        RetryDirective::IdempotentReadOnly,
    ),
    (
        BackendErrorKind::GlobalAuthorityInterrupted,
        RetryDirective::IdempotentReadOnly,
    ),
    (
        BackendErrorKind::GlobalLeaseConflict,
        RetryDirective::FreshSnapshotAfterOff,
    ),
    (
        BackendErrorKind::ReplayRejected,
        RetryDirective::FreshContext,
    ),
    (
        BackendErrorKind::StaleOperation,
        RetryDirective::FreshContext,
    ),
    (
        BackendErrorKind::TicketExpired,
        RetryDirective::FreshGenerationAfterOff,
    ),
    (
        BackendErrorKind::TicketAlreadyRedeemed,
        RetryDirective::FreshGenerationAfterOff,
    ),
    (BackendErrorKind::TicketInvalid, RetryDirective::Never),
    (
        BackendErrorKind::CompensationConflict,
        RetryDirective::ExplicitReconciliation,
    ),
    (
        BackendErrorKind::CleanupUnproven,
        RetryDirective::ExplicitReconciliation,
    ),
    (
        BackendErrorKind::Quarantined,
        RetryDirective::ExplicitReconciliation,
    ),
    (BackendErrorKind::InvalidMessage, RetryDirective::Never),
    (
        BackendErrorKind::SecretBoundsExceeded,
        RetryDirective::Never,
    ),
    (
        BackendErrorKind::SecretLifecycleViolation,
        RetryDirective::ExplicitReconciliation,
    ),
    (
        BackendErrorKind::JournalCorrupt,
        RetryDirective::ExplicitReconciliation,
    ),
    (
        BackendErrorKind::OwnerUnresponsive,
        RetryDirective::IdempotentReadOnly,
    ),
    (BackendErrorKind::IdentityRejected, RetryDirective::Never),
    (
        BackendErrorKind::Timeout,
        RetryDirective::IdempotentReadOnly,
    ),
    (
        BackendErrorKind::Unavailable,
        RetryDirective::IdempotentReadOnly,
    ),
    (BackendErrorKind::MixedEndpointInUse, RetryDirective::Never),
    (
        BackendErrorKind::ControllerEndpointInUse,
        RetryDirective::Never,
    ),
    (BackendErrorKind::Internal, RetryDirective::Never),
];

#[test]
fn every_kind_has_one_wire_code_one_retry_directive_and_its_own_message() {
    let mut codes = BTreeSet::new();
    let mut messages = BTreeSet::new();
    for (kind, directive) in RETRY_DIRECTIVES {
        let code = serde_json::to_value(kind).expect("wire code");
        assert!(
            codes.insert(code.to_string()),
            "{kind:?} shares a wire code"
        );
        assert_eq!(
            serde_json::from_value::<BackendErrorKind>(code).expect("decode"),
            kind
        );
        assert_eq!(kind.retry_directive(), directive, "{kind:?}");
        let message = kind.stable_message();
        assert!(message.ends_with('.'), "{kind:?}: {message}");
        assert!(messages.insert(message), "{kind:?} shares its message");
        assert_eq!(
            kind.allows_automatic_retry(true),
            directive == RetryDirective::IdempotentReadOnly
        );
        assert_eq!(
            kind.allows_read_only_recheck(),
            directive == RetryDirective::IdempotentReadOnly || kind == BackendErrorKind::Busy,
            "{kind:?}"
        );
    }
}

#[test]
fn a_backend_error_displays_its_kind_and_message() {
    let error = BackendError::new(BackendErrorKind::Timeout, "status query timed out");
    assert_eq!(error.kind, BackendErrorKind::Timeout);
    assert_eq!(error.to_string(), "Timeout: status query timed out");
    let wire = serde_json::to_value(&error).expect("error");
    assert_eq!(
        wire,
        serde_json::json!({"kind": "timeout", "message": "status query timed out"})
    );
}
