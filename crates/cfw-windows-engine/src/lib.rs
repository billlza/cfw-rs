//! Owned Windows data-plane child, below the application/privileged authority.
//!
//! A stopped child is not evidence of globally restored proxy/TUN state. This
//! layer currently admits local-proxy projections only. It does not implement
//! `EngineBackend` or manufacture `NativeEngineStatus::Off`.

#[cfg(any(windows, test))]
mod configuration;
#[cfg(any(windows, test))]
mod protocol;
#[cfg(any(windows, test))]
pub use configuration::PreparedConfig;

#[cfg(windows)]
mod listeners;
#[cfg(windows)]
mod process;
#[cfg(windows)]
pub use process::{EngineProcess, RunningChild, StoppedChild, VerifiedExecutable};

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
    #[error("Windows engine operation exceeded its deadline")]
    Timeout,
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
