//! Native bridge failures and their one-to-one mapping to backend error kinds.

use cfw_engine_api::BackendErrorKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBridgeErrorCode {
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
}

impl From<NativeBridgeErrorCode> for BackendErrorKind {
    fn from(code: NativeBridgeErrorCode) -> Self {
        match code {
            NativeBridgeErrorCode::Busy => Self::Busy,
            NativeBridgeErrorCode::ResourceExhausted => Self::ResourceExhausted,
            NativeBridgeErrorCode::JournalCapacityExhausted => Self::JournalCapacityExhausted,
            NativeBridgeErrorCode::PermissionDenied => Self::PermissionDenied,
            NativeBridgeErrorCode::ApprovalDenied => Self::ApprovalDenied,
            NativeBridgeErrorCode::ConfigurationRejected => Self::ConfigurationRejected,
            NativeBridgeErrorCode::SystemExtensionValidationFailed => {
                Self::SystemExtensionValidationFailed
            }
            NativeBridgeErrorCode::SystemProxyConfigurationFailed => {
                Self::SystemProxyConfigurationFailed
            }
            NativeBridgeErrorCode::SystemProxyRuntimeFailed => Self::SystemProxyRuntimeFailed,
            NativeBridgeErrorCode::EngineStartTimedOut => Self::EngineStartTimedOut,
            NativeBridgeErrorCode::SystemProxyPreferencesFailed => {
                Self::SystemProxyPreferencesFailed
            }
            NativeBridgeErrorCode::SystemProxyJournalFailed => Self::SystemProxyJournalFailed,
            NativeBridgeErrorCode::SystemProxyAuthorityFailed => Self::SystemProxyAuthorityFailed,
            NativeBridgeErrorCode::ExistingSystemProxy => Self::ExistingSystemProxy,
            NativeBridgeErrorCode::CredentialsUnavailable => Self::CredentialsUnavailable,
            NativeBridgeErrorCode::CredentialConflict => Self::CredentialConflict,
            NativeBridgeErrorCode::CredentialVaultMissing => Self::CredentialVaultMissing,
            NativeBridgeErrorCode::CredentialVaultCorrupt => Self::CredentialVaultCorrupt,
            NativeBridgeErrorCode::CredentialMigrationRequired => Self::CredentialMigrationRequired,
            NativeBridgeErrorCode::CredentialGcConflict => Self::CredentialGcConflict,
            NativeBridgeErrorCode::ProxyAgentApprovalRequired => Self::ProxyAgentApprovalRequired,
            NativeBridgeErrorCode::GlobalAuthorityUnavailable => Self::GlobalAuthorityUnavailable,
            NativeBridgeErrorCode::GlobalAuthorityRegistrationRequired => {
                Self::GlobalAuthorityRegistrationRequired
            }
            NativeBridgeErrorCode::GlobalAuthorityApprovalRequired => {
                Self::GlobalAuthorityApprovalRequired
            }
            NativeBridgeErrorCode::GlobalAuthorityIdentityRejected => {
                Self::GlobalAuthorityIdentityRejected
            }
            NativeBridgeErrorCode::GlobalAuthorityProtocolMismatch => {
                Self::GlobalAuthorityProtocolMismatch
            }
            NativeBridgeErrorCode::GlobalAuthorityRecovering => Self::GlobalAuthorityRecovering,
            NativeBridgeErrorCode::GlobalAuthorityTimeout => Self::GlobalAuthorityTimeout,
            NativeBridgeErrorCode::GlobalAuthorityInterrupted => Self::GlobalAuthorityInterrupted,
            NativeBridgeErrorCode::GlobalLeaseConflict => Self::GlobalLeaseConflict,
            NativeBridgeErrorCode::ReplayRejected => Self::ReplayRejected,
            NativeBridgeErrorCode::StaleOperation => Self::StaleOperation,
            NativeBridgeErrorCode::TicketExpired => Self::TicketExpired,
            NativeBridgeErrorCode::TicketAlreadyRedeemed => Self::TicketAlreadyRedeemed,
            NativeBridgeErrorCode::TicketInvalid => Self::TicketInvalid,
            NativeBridgeErrorCode::CompensationConflict => Self::CompensationConflict,
            NativeBridgeErrorCode::CleanupUnproven => Self::CleanupUnproven,
            NativeBridgeErrorCode::Quarantined => Self::Quarantined,
            NativeBridgeErrorCode::InvalidMessage => Self::InvalidMessage,
            NativeBridgeErrorCode::SecretBoundsExceeded => Self::SecretBoundsExceeded,
            NativeBridgeErrorCode::SecretLifecycleViolation => Self::SecretLifecycleViolation,
            NativeBridgeErrorCode::JournalCorrupt => Self::JournalCorrupt,
            NativeBridgeErrorCode::OwnerUnresponsive => Self::OwnerUnresponsive,
            NativeBridgeErrorCode::IdentityRejected => Self::IdentityRejected,
            NativeBridgeErrorCode::Timeout => Self::Timeout,
            NativeBridgeErrorCode::Unavailable => Self::Unavailable,
            NativeBridgeErrorCode::MixedEndpointInUse => Self::MixedEndpointInUse,
            NativeBridgeErrorCode::ControllerEndpointInUse => Self::ControllerEndpointInUse,
            NativeBridgeErrorCode::Internal => Self::Internal,
        }
    }
}

impl From<BackendErrorKind> for NativeBridgeErrorCode {
    fn from(kind: BackendErrorKind) -> Self {
        match kind {
            BackendErrorKind::Busy => Self::Busy,
            BackendErrorKind::ResourceExhausted => Self::ResourceExhausted,
            BackendErrorKind::JournalCapacityExhausted => Self::JournalCapacityExhausted,
            BackendErrorKind::PermissionDenied => Self::PermissionDenied,
            BackendErrorKind::ApprovalDenied => Self::ApprovalDenied,
            BackendErrorKind::ConfigurationRejected => Self::ConfigurationRejected,
            BackendErrorKind::SystemExtensionValidationFailed => {
                Self::SystemExtensionValidationFailed
            }
            BackendErrorKind::SystemProxyConfigurationFailed => {
                Self::SystemProxyConfigurationFailed
            }
            BackendErrorKind::SystemProxyRuntimeFailed => Self::SystemProxyRuntimeFailed,
            BackendErrorKind::EngineStartTimedOut => Self::EngineStartTimedOut,
            BackendErrorKind::SystemProxyPreferencesFailed => Self::SystemProxyPreferencesFailed,
            BackendErrorKind::SystemProxyJournalFailed => Self::SystemProxyJournalFailed,
            BackendErrorKind::SystemProxyAuthorityFailed => Self::SystemProxyAuthorityFailed,
            BackendErrorKind::ExistingSystemProxy => Self::ExistingSystemProxy,
            BackendErrorKind::CredentialsUnavailable => Self::CredentialsUnavailable,
            BackendErrorKind::CredentialConflict => Self::CredentialConflict,
            BackendErrorKind::CredentialVaultMissing => Self::CredentialVaultMissing,
            BackendErrorKind::CredentialVaultCorrupt => Self::CredentialVaultCorrupt,
            BackendErrorKind::CredentialMigrationRequired => Self::CredentialMigrationRequired,
            BackendErrorKind::CredentialGcConflict => Self::CredentialGcConflict,
            BackendErrorKind::ProxyAgentApprovalRequired => Self::ProxyAgentApprovalRequired,
            BackendErrorKind::GlobalAuthorityUnavailable => Self::GlobalAuthorityUnavailable,
            BackendErrorKind::GlobalAuthorityRegistrationRequired => {
                Self::GlobalAuthorityRegistrationRequired
            }
            BackendErrorKind::GlobalAuthorityApprovalRequired => {
                Self::GlobalAuthorityApprovalRequired
            }
            BackendErrorKind::GlobalAuthorityIdentityRejected => {
                Self::GlobalAuthorityIdentityRejected
            }
            BackendErrorKind::GlobalAuthorityProtocolMismatch => {
                Self::GlobalAuthorityProtocolMismatch
            }
            BackendErrorKind::GlobalAuthorityRecovering => Self::GlobalAuthorityRecovering,
            BackendErrorKind::GlobalAuthorityTimeout => Self::GlobalAuthorityTimeout,
            BackendErrorKind::GlobalAuthorityInterrupted => Self::GlobalAuthorityInterrupted,
            BackendErrorKind::GlobalLeaseConflict => Self::GlobalLeaseConflict,
            BackendErrorKind::ReplayRejected => Self::ReplayRejected,
            BackendErrorKind::StaleOperation => Self::StaleOperation,
            BackendErrorKind::TicketExpired => Self::TicketExpired,
            BackendErrorKind::TicketAlreadyRedeemed => Self::TicketAlreadyRedeemed,
            BackendErrorKind::TicketInvalid => Self::TicketInvalid,
            BackendErrorKind::CompensationConflict => Self::CompensationConflict,
            BackendErrorKind::CleanupUnproven => Self::CleanupUnproven,
            BackendErrorKind::Quarantined => Self::Quarantined,
            BackendErrorKind::InvalidMessage => Self::InvalidMessage,
            BackendErrorKind::SecretBoundsExceeded => Self::SecretBoundsExceeded,
            BackendErrorKind::SecretLifecycleViolation => Self::SecretLifecycleViolation,
            BackendErrorKind::JournalCorrupt => Self::JournalCorrupt,
            BackendErrorKind::OwnerUnresponsive => Self::OwnerUnresponsive,
            BackendErrorKind::IdentityRejected => Self::IdentityRejected,
            BackendErrorKind::Timeout => Self::Timeout,
            BackendErrorKind::Unavailable => Self::Unavailable,
            BackendErrorKind::MixedEndpointInUse => Self::MixedEndpointInUse,
            BackendErrorKind::ControllerEndpointInUse => Self::ControllerEndpointInUse,
            BackendErrorKind::Internal => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBridgeError {
    pub code: NativeBridgeErrorCode,
    pub message: String,
}

impl NativeBridgeError {
    pub fn new(code: NativeBridgeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests;
