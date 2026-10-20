use super::*;
use crate::{
    ServiceTransportError,
    authority::wire::{Rejection, WireError},
    credential_lifecycle::CredentialLifecycleError,
    user_agent::{launch_channel::LaunchChannelError, launcher::LaunchError},
};

pub(super) fn desktop_error(error: DesktopError) -> BackendError {
    fail(desktop_kind(&error), error.to_string())
}
pub(super) fn host_error(error: HostError) -> BackendError {
    let kind = match &error {
        HostError::Executable(error) => engine_kind(error),
        HostError::Desktop(error) => desktop_kind(error),
        HostError::Credentials(error) => credential_kind(error),
        HostError::Lineage(crate::LineageError::Authority(error)) => wire_kind(error),
        HostError::Lineage(crate::LineageError::Conflict { .. }) => Kind::StaleOperation,
        HostError::Lineage(_)
        | HostError::Manifest
        | HostError::InstallationSecurity
        | HostError::Peer(_)
        | HostError::Launcher(_) => Kind::IdentityRejected,
        HostError::Transport(error) => transport_kind(error),
        HostError::Cleanup { .. } => Kind::CleanupUnproven,
        _ => Kind::GlobalAuthorityUnavailable,
    };
    fail(kind, error.to_string())
}
fn desktop_kind(error: &DesktopError) -> Kind {
    match error {
        DesktopError::Configuration(error) => engine_kind(error),
        DesktopError::Credentials(error) => credential_kind(error),
        DesktopError::Authority(error) => wire_kind(error),
        DesktopError::Transport(error) => transport_kind(error),
        DesktopError::Launch(error) => match error {
            LaunchError::Transport(error) => transport_kind(error),
            LaunchError::Handoff(error) => channel_kind(error),
            LaunchError::Deadline => Kind::Timeout,
            LaunchError::Cancelled => Kind::GlobalAuthorityInterrupted,
            LaunchError::Exit(_) | LaunchError::State => Kind::OwnerUnresponsive,
            LaunchError::Io(_) => Kind::Unavailable,
            LaunchError::WorkerPanicked => Kind::Internal,
            LaunchError::Peer(_)
            | LaunchError::Console(_)
            | LaunchError::Identity
            | LaunchError::Invocation => Kind::IdentityRejected,
        },
        DesktopError::Proxy(error) => match error {
            crate::ProxyError::ExistingProxy => Kind::ExistingSystemProxy,
            crate::ProxyError::PolicyDenied | crate::ProxyError::UnsafeUser => {
                Kind::PermissionDenied
            }
            crate::ProxyError::InvalidJournal | crate::ProxyError::InvalidRestorationRecord => {
                Kind::SystemProxyJournalFailed
            }
            crate::ProxyError::SettingsChanged | crate::ProxyError::OwnershipConflict => {
                Kind::CompensationConflict
            }
            _ => Kind::CleanupUnproven,
        },
        DesktopError::Observation(error) => desktop_kind(error),
        DesktopError::Cleanup { .. } | DesktopError::CleanupScope(_) => Kind::CleanupUnproven,
        DesktopError::Context => Kind::IdentityRejected,
        DesktopError::Response | DesktopError::Handoff(_) => Kind::InvalidMessage,
        DesktopError::ReadyReceiver => Kind::GlobalAuthorityInterrupted,
        DesktopError::State(_) => Kind::OwnerUnresponsive,
    }
}
fn channel_kind(error: &LaunchChannelError) -> Kind {
    match error {
        LaunchChannelError::Transport(error) => transport_kind(error),
        LaunchChannelError::Peer(_) | LaunchChannelError::Identity => Kind::IdentityRejected,
        LaunchChannelError::Io(_) => Kind::OwnerUnresponsive,
        LaunchChannelError::Frame(_)
        | LaunchChannelError::Acknowledgement
        | LaunchChannelError::Observation => Kind::InvalidMessage,
    }
}
fn engine_kind(error: &crate::Error) -> Kind {
    match error {
        crate::Error::Configuration(_) | crate::Error::Rejected(_) => Kind::ConfigurationRejected,
        crate::Error::Protocol(_) => Kind::InvalidMessage,
        crate::Error::Timeout => Kind::Timeout,
        crate::Error::Cancelled => Kind::GlobalAuthorityInterrupted,
        crate::Error::Exited => Kind::OwnerUnresponsive,
        crate::Error::ExecutableIdentity => Kind::IdentityRejected,
        crate::Error::Cleanup
        | crate::Error::CleanupFailed { .. }
        | crate::Error::ProxyRestoration(_) => Kind::CleanupUnproven,
        crate::Error::Io(_) | crate::Error::Operation { .. } | crate::Error::Storage(_) => {
            Kind::Unavailable
        }
    }
}
fn credential_kind(error: &CredentialLifecycleError) -> Kind {
    use cfw_engine_api::CredentialVaultError as Vault;
    match error {
        CredentialLifecycleError::Vault(error) => match error {
            Vault::Corrupt => Kind::CredentialVaultCorrupt,
            Vault::MissingVault => Kind::CredentialVaultMissing,
            Vault::MigrationRequired => Kind::CredentialMigrationRequired,
            Vault::IdentityRejected => Kind::IdentityRejected,
            Vault::AccessDenied => Kind::PermissionDenied,
            Vault::ImmutableConflict => Kind::CredentialConflict,
            Vault::ConcurrentModification => Kind::CredentialGcConflict,
            Vault::CapacityExceeded => Kind::ResourceExhausted,
            Vault::InvalidMaterial => Kind::ConfigurationRejected,
            Vault::Internal => Kind::Internal,
            Vault::OutcomeUnknown | Vault::Unavailable => Kind::CredentialsUnavailable,
        },
        CredentialLifecycleError::Record | CredentialLifecycleError::ProtectedVaultMissing => {
            Kind::CredentialVaultCorrupt
        }
        CredentialLifecycleError::Schema => Kind::CredentialMigrationRequired,
        CredentialLifecycleError::Identity => Kind::IdentityRejected,
        CredentialLifecycleError::Deadline => Kind::Timeout,
        CredentialLifecycleError::CancelledBeforeAdmission => Kind::GlobalAuthorityInterrupted,
        CredentialLifecycleError::Authority(error) => wire_kind(error),
        CredentialLifecycleError::Cleanup { .. } => Kind::CleanupUnproven,
        CredentialLifecycleError::Unavailable | CredentialLifecycleError::Storage(_) => {
            Kind::CredentialsUnavailable
        }
    }
}
fn transport_kind(error: &ServiceTransportError) -> Kind {
    match error {
        ServiceTransportError::Deadline => Kind::GlobalAuthorityTimeout,
        ServiceTransportError::Cancelled => Kind::GlobalAuthorityInterrupted,
        ServiceTransportError::Capacity => Kind::ResourceExhausted,
        ServiceTransportError::Client(_) | ServiceTransportError::ClientIdentity => {
            Kind::IdentityRejected
        }
        ServiceTransportError::MessageLength | ServiceTransportError::RequestOrder => {
            Kind::GlobalAuthorityProtocolMismatch
        }
        ServiceTransportError::Cleanup { .. } => Kind::CleanupUnproven,
        ServiceTransportError::Io(_) | ServiceTransportError::Closed => {
            Kind::GlobalAuthorityUnavailable
        }
        ServiceTransportError::Endpoint(error) => match error {
            crate::ServicePeerError::Native { .. }
            | crate::ServicePeerError::NotRunning { .. }
            | crate::ServicePeerError::Exited
            | crate::ServicePeerError::ConnectionClosed => Kind::GlobalAuthorityUnavailable,
            _ => Kind::GlobalAuthorityIdentityRejected,
        },
    }
}
fn wire_kind(error: &WireError) -> Kind {
    match error {
        WireError::Rejected(rejected) => match rejected {
            Rejection::Recovering => Kind::GlobalAuthorityRecovering,
            Rejection::Quarantined => Kind::Quarantined,
            Rejection::LeaseConflict => Kind::GlobalLeaseConflict,
            Rejection::Stale => Kind::StaleOperation,
            Rejection::Identity => Kind::IdentityRejected,
            Rejection::Invalid => Kind::InvalidMessage,
            Rejection::Replay => Kind::ReplayRejected,
            Rejection::GenerationExhausted => Kind::ResourceExhausted,
            Rejection::Ticket => Kind::TicketInvalid,
            Rejection::Expired => Kind::TicketExpired,
            Rejection::CleanupUnproven => Kind::CleanupUnproven,
            Rejection::Publication => Kind::GlobalAuthorityRecovering,
            Rejection::Observation => Kind::GlobalAuthorityRecovering,
            Rejection::Entropy => Kind::Internal,
        },
        WireError::Transport(error) => transport_kind(error),
        WireError::Identity(_) | WireError::Owner(_) | WireError::Keeper(_) => {
            Kind::IdentityRejected
        }
        WireError::Version => Kind::GlobalAuthorityProtocolMismatch,
        WireError::Correlation | WireError::Length | WireError::Malformed => Kind::InvalidMessage,
    }
}
