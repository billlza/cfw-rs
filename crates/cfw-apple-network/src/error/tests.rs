use cfw_engine_api::BackendErrorKind;

use super::*;

#[test]
fn authority_error_mapping_is_one_to_one() {
    for kind in BackendErrorKind::AUTHORITY_KINDS {
        let bridge = NativeBridgeErrorCode::from(kind);
        assert_eq!(BackendErrorKind::from(bridge), kind);
    }
}

#[test]
fn proxy_agent_approval_mapping_is_one_to_one() {
    let kind = BackendErrorKind::ProxyAgentApprovalRequired;
    let bridge = NativeBridgeErrorCode::from(kind);
    assert_eq!(bridge, NativeBridgeErrorCode::ProxyAgentApprovalRequired);
    assert_eq!(BackendErrorKind::from(bridge), kind);
}

/// Pairs every code with the backend kind of the same name. Each of the two
/// matches stops compiling when its enum gains a variant the list lacks.
macro_rules! code_kind_pairs {
    ($($name:ident),+ $(,)?) => {
        const CODE_KIND_PAIRS: &[(NativeBridgeErrorCode, BackendErrorKind)] =
            &[$((NativeBridgeErrorCode::$name, BackendErrorKind::$name)),+];

        fn listed_code(code: NativeBridgeErrorCode) {
            match code {
                $(NativeBridgeErrorCode::$name)|+ => {}
            }
        }

        fn listed_kind(kind: BackendErrorKind) {
            match kind {
                $(BackendErrorKind::$name)|+ => {}
            }
        }
    };
}

code_kind_pairs![
    Busy,
    ResourceExhausted,
    JournalCapacityExhausted,
    PermissionDenied,
    ApprovalDenied,
    ConfigurationRejected,
    SystemExtensionValidationFailed,
    SystemProxyConfigurationFailed,
    SystemProxyRuntimeFailed,
    EngineStartTimedOut,
    SystemProxyPreferencesFailed,
    SystemProxyJournalFailed,
    SystemProxyAuthorityFailed,
    ExistingSystemProxy,
    CredentialsUnavailable,
    CredentialConflict,
    CredentialVaultMissing,
    CredentialVaultCorrupt,
    CredentialMigrationRequired,
    CredentialGcConflict,
    ProxyAgentApprovalRequired,
    GlobalAuthorityUnavailable,
    GlobalAuthorityRegistrationRequired,
    GlobalAuthorityApprovalRequired,
    GlobalAuthorityIdentityRejected,
    GlobalAuthorityProtocolMismatch,
    GlobalAuthorityRecovering,
    GlobalAuthorityTimeout,
    GlobalAuthorityInterrupted,
    GlobalLeaseConflict,
    ReplayRejected,
    StaleOperation,
    TicketExpired,
    TicketAlreadyRedeemed,
    TicketInvalid,
    CompensationConflict,
    CleanupUnproven,
    Quarantined,
    InvalidMessage,
    SecretBoundsExceeded,
    SecretLifecycleViolation,
    JournalCorrupt,
    OwnerUnresponsive,
    IdentityRejected,
    Timeout,
    Unavailable,
    MixedEndpointInUse,
    ControllerEndpointInUse,
    Internal,
];

#[test]
fn every_code_maps_to_the_backend_kind_of_the_same_name_and_back() {
    for &(code, kind) in CODE_KIND_PAIRS {
        listed_code(code);
        listed_kind(kind);
        assert_eq!(BackendErrorKind::from(code), kind);
        assert_eq!(NativeBridgeErrorCode::from(kind), code);
    }
}
