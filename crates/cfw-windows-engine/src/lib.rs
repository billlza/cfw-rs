//! Owned Windows data-plane child, below the application/privileged authority.
//!
//! A stopped child is not evidence of globally restored proxy/TUN state. This
//! layer admits local/SystemProxy data planes and separately journals current-
//! user WinINet settings. The installed backend requires independent Authority
//! cleanup before returning `NativeEngineStatus::Off`.

#[cfg(windows)]
pub mod backend;

#[cfg(any(windows, test))]
pub mod authority;
#[cfg(any(windows, test))]
pub mod authority_journal;
#[cfg(any(windows, test))]
mod configuration;
#[cfg(any(windows, test))]
mod connection_binding;
#[cfg(any(windows, test))]
pub mod credential_lifecycle;
#[cfg(any(windows, test))]
mod protocol;
#[cfg(any(windows, test))]
pub mod runtime_host;
#[cfg(any(windows, test))]
pub mod user_agent;
#[cfg(any(windows, test))]
pub use configuration::{CheckedStartConfiguration, PreparedConfig, ResolvedProjection};

#[cfg(windows)]
mod lineage;
#[cfg(windows)]
mod peer;
#[cfg(windows)]
pub use peer::{
    LiveConsoleSession, NativePeerIdentity, NativePeerProcess, NativeUserSession,
    PeerIdentityError, ServiceAuthorizationError, ServicePeerAuthorization,
    UserAgentLeaseRequirement, authorize_service_request,
};
#[cfg(windows)]
mod service_peer;
#[cfg(windows)]
pub use service_peer::{
    LocalServicePipe, ServiceClientRole, ServicePeerError, WindowsServicePeer,
    configure_service_process_observation,
};
#[cfg(windows)]
mod service_transport;
#[cfg(windows)]
pub use service_transport::{
    AuthenticatedServiceRequest, LocalServiceConnection, LocalServiceListener, ServiceChannel,
    ServicePayload, ServiceTransportError,
};
#[cfg(windows)]
mod listeners;
#[cfg(windows)]
pub use lineage::{LineageError, WindowsEngineGenerationStore};
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod process_handles;
#[cfg(all(windows, feature = "native-service-validation"))]
pub use process_handles::ProcessHandleList;
#[cfg(windows)]
mod system_proxy;
#[cfg(windows)]
pub use process::{
    CheckedConfiguration, EngineProcess, RunningChild, StoppedChild, VerifiedExecutable,
};
#[cfg(windows)]
pub use system_proxy::{
    ProxyError, ProxyOwnershipObservation, ProxyRestorationObservation, ProxySettings,
    ProxySettingsReceipt, ProxySettingsRestored, WindowsSystemProxy,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Windows engine configuration: {0}")]
    Configuration(&'static str),
    #[error("Windows engine control protocol: {0}")]
    Protocol(&'static str),
    #[error("Windows engine rejected operation: {0}")]
    Rejected(&'static str),
    #[error("Windows engine I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows engine {operation}: {source}")]
    Operation {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[cfg(windows)]
    #[error("Windows engine private runtime directory: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[cfg(windows)]
    #[error("Windows engine cannot stop before proxy restoration: {0}")]
    ProxyRestoration(Box<ProxyError>),
    #[error("Windows engine operation exceeded its deadline")]
    Timeout,
    #[error("Windows engine operation was cancelled before completion")]
    Cancelled,
    #[error("Windows engine process exited unexpectedly")]
    Exited,
    #[error("Windows engine emergency cleanup could not be verified")]
    Cleanup,
    #[error("Windows engine operation failed ({operation}); cleanup also failed ({cleanup})")]
    CleanupFailed {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
    #[error("Windows engine executable does not match the installation identity")]
    ExecutableIdentity,
}
