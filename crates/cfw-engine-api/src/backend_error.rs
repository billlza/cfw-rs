//! Typed native failures, their retry directives and stable messages.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendErrorKind {
    Busy,
    ResourceExhausted,
    JournalCapacityExhausted,
    PermissionDenied,
    ApprovalDenied,
    ConfigurationRejected,
    SystemExtensionValidationFailed,
    SystemProxyConfigurationFailed,
    SystemProxyRuntimeFailed,
    /// An engine owner interrupted a libbox start that ran past its deadline,
    /// usually because rule datasets were still downloading. The owner proved
    /// Stopped first, so nothing is left to reconcile.
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
    #[serde(other)]
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDirective {
    Never,
    IdempotentReadOnly,
    RegistrationStatusChange,
    CompatibleSoftwareUpdate,
    FreshSnapshotAfterOff,
    FreshContext,
    FreshGenerationAfterOff,
    ExplicitReconciliation,
    MaintenanceRequired,
}

impl BackendErrorKind {
    pub const AUTHORITY_KINDS: [Self; 25] = [
        Self::GlobalAuthorityUnavailable,
        Self::GlobalAuthorityRegistrationRequired,
        Self::GlobalAuthorityApprovalRequired,
        Self::GlobalAuthorityIdentityRejected,
        Self::GlobalAuthorityProtocolMismatch,
        Self::GlobalAuthorityRecovering,
        Self::GlobalAuthorityTimeout,
        Self::GlobalAuthorityInterrupted,
        Self::Busy,
        Self::ResourceExhausted,
        Self::JournalCapacityExhausted,
        Self::GlobalLeaseConflict,
        Self::ReplayRejected,
        Self::StaleOperation,
        Self::TicketExpired,
        Self::TicketAlreadyRedeemed,
        Self::TicketInvalid,
        Self::SecretBoundsExceeded,
        Self::SecretLifecycleViolation,
        Self::CompensationConflict,
        Self::CleanupUnproven,
        Self::Quarantined,
        Self::InvalidMessage,
        Self::JournalCorrupt,
        Self::OwnerUnresponsive,
    ];

    pub const fn retry_directive(self) -> RetryDirective {
        match self {
            Self::ResourceExhausted
            | Self::OwnerUnresponsive
            | Self::GlobalAuthorityTimeout
            | Self::GlobalAuthorityInterrupted
            | Self::Timeout
            | Self::Unavailable => RetryDirective::IdempotentReadOnly,
            Self::JournalCapacityExhausted => RetryDirective::MaintenanceRequired,
            Self::CredentialMigrationRequired => RetryDirective::Never,
            Self::ProxyAgentApprovalRequired
            | Self::GlobalAuthorityUnavailable
            | Self::GlobalAuthorityRegistrationRequired
            | Self::GlobalAuthorityApprovalRequired => RetryDirective::RegistrationStatusChange,
            Self::GlobalAuthorityProtocolMismatch => RetryDirective::CompatibleSoftwareUpdate,
            Self::Busy | Self::GlobalLeaseConflict => RetryDirective::FreshSnapshotAfterOff,
            Self::ReplayRejected | Self::StaleOperation => RetryDirective::FreshContext,
            Self::TicketExpired | Self::TicketAlreadyRedeemed => {
                RetryDirective::FreshGenerationAfterOff
            }
            Self::GlobalAuthorityRecovering
            | Self::SecretLifecycleViolation
            | Self::CompensationConflict
            | Self::CleanupUnproven
            | Self::Quarantined
            | Self::JournalCorrupt => RetryDirective::ExplicitReconciliation,
            Self::PermissionDenied
            | Self::ApprovalDenied
            | Self::ConfigurationRejected
            | Self::SystemExtensionValidationFailed
            | Self::SystemProxyConfigurationFailed
            | Self::SystemProxyRuntimeFailed
            | Self::EngineStartTimedOut
            | Self::SystemProxyPreferencesFailed
            | Self::SystemProxyJournalFailed
            | Self::SystemProxyAuthorityFailed
            | Self::ExistingSystemProxy
            | Self::CredentialsUnavailable
            | Self::CredentialConflict
            | Self::CredentialVaultMissing
            | Self::CredentialVaultCorrupt
            | Self::CredentialGcConflict
            | Self::GlobalAuthorityIdentityRejected
            | Self::TicketInvalid
            | Self::InvalidMessage
            | Self::SecretBoundsExceeded
            | Self::MixedEndpointInUse
            | Self::ControllerEndpointInUse
            | Self::IdentityRejected
            | Self::Internal => RetryDirective::Never,
        }
    }

    pub const fn allows_automatic_retry(self, is_idempotent_read_only: bool) -> bool {
        is_idempotent_read_only
            && matches!(self.retry_directive(), RetryDirective::IdempotentReadOnly)
    }

    /// Whether a failed read-only status observation may simply be repeated.
    /// Beyond the idempotent read-only kinds, `Busy` qualifies: a status read
    /// that lands while the Authority or an owner is mid-mutation observes
    /// nothing, and the same read settles once that mutation ends. Every other
    /// kind is a definitive answer and is never repeated.
    pub const fn allows_read_only_recheck(self) -> bool {
        matches!(self.retry_directive(), RetryDirective::IdempotentReadOnly)
            || matches!(self, Self::Busy)
    }

    pub const fn stable_message(self) -> &'static str {
        match self {
            Self::Busy => "Global Authority mutation is busy.",
            Self::ResourceExhausted => "Global Authority read capacity is exhausted.",
            Self::JournalCapacityExhausted => {
                "The Global Authority journal reached its fixed capacity and requires maintenance."
            }
            Self::PermissionDenied => "The native operation was denied.",
            Self::ApprovalDenied => "Required operating-system approval was denied.",
            Self::ConfigurationRejected => "The native configuration was rejected.",
            Self::SystemProxyAuthorityFailed => {
                "System Proxy ownership or readiness could not be confirmed by the network authority."
            }
            Self::SystemExtensionValidationFailed => {
                "macOS rejected the Packet Tunnel extension configuration or signature. Install a corrected application build."
            }
            Self::SystemProxyConfigurationFailed => {
                "System Proxy could not resolve or validate the selected configuration."
            }
            Self::SystemProxyRuntimeFailed => {
                "The System Proxy runtime could not be created or started."
            }
            Self::EngineStartTimedOut => {
                "The engine did not finish starting in time and was stopped, usually because rule \
                 datasets were still downloading. Datasets that finished are kept for the next start."
            }
            Self::SystemProxyPreferencesFailed => {
                "System Proxy could not read, apply, or verify macOS network preferences."
            }
            Self::SystemProxyJournalFailed => {
                "System Proxy could not save its network recovery record."
            }
            Self::ExistingSystemProxy => {
                "Another system proxy is enabled. Turn it off in its app or System Settings before enabling Clash for Mac. Existing proxy settings were not changed."
            }
            Self::CredentialsUnavailable => "Required credentials are unavailable.",
            Self::CredentialConflict => "Credential material conflicts with an immutable entry.",
            Self::CredentialVaultMissing => "The credential vault is unavailable.",
            Self::CredentialVaultCorrupt => "The credential vault data is corrupt.",
            Self::CredentialMigrationRequired => {
                "The credential vault uses an unsupported schema and must be cleared and reprovisioned."
            }
            Self::CredentialGcConflict => "Credential cleanup requires a fresh preview.",
            Self::ProxyAgentApprovalRequired => {
                "ProxyAgent approval is required in System Settings."
            }
            Self::GlobalAuthorityUnavailable => "Global Authority is unavailable.",
            Self::GlobalAuthorityRegistrationRequired => {
                "Global Authority registration is required."
            }
            Self::GlobalAuthorityApprovalRequired => "Global Authority approval is required.",
            Self::GlobalAuthorityIdentityRejected => "Global Authority peer identity was rejected.",
            Self::GlobalAuthorityProtocolMismatch => "Global Authority protocol is incompatible.",
            Self::GlobalAuthorityRecovering => {
                "Global Authority is recovering; starts are disabled."
            }
            Self::GlobalAuthorityTimeout => "The Authority operation timed out.",
            Self::GlobalAuthorityInterrupted => "The Authority connection was interrupted.",
            Self::GlobalLeaseConflict => "A conflicting Global Authority lease exists.",
            Self::ReplayRejected => "Authority replay protection rejected the context.",
            Self::StaleOperation => "Authority operation context is stale.",
            Self::TicketExpired => "The Authority start ticket expired.",
            Self::TicketAlreadyRedeemed => "The Authority start ticket was already redeemed.",
            Self::TicketInvalid => "The Authority start ticket is invalid.",
            Self::CompensationConflict => "Tunnel preference compensation conflicted.",
            Self::CleanupUnproven => "Global cleanup could not be proven.",
            Self::Quarantined => "Global Authority is quarantined pending reconciliation.",
            Self::InvalidMessage => "The Authority message is invalid.",
            Self::SecretBoundsExceeded => "Authority secret material exceeds a fixed bound.",
            Self::SecretLifecycleViolation => "Authority secret lifecycle verification failed.",
            Self::JournalCorrupt => "The Authority journal is corrupt.",
            Self::OwnerUnresponsive => "The Authority engine owner is unresponsive.",
            Self::IdentityRejected => "The native peer identity was rejected.",
            Self::Timeout => "The native operation timed out.",
            Self::Unavailable => "The native operation is unavailable.",
            Self::MixedEndpointInUse => "The mixed listener endpoint is already in use.",
            Self::ControllerEndpointInUse => "The controller endpoint is already in use.",
            Self::Internal => "The native bridge failed at a stable internal boundary.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{kind:?}: {message}")]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests;
