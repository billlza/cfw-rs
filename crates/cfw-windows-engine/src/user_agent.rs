//! Current-user runtime ownership under an authenticated Windows Authority
//! lease. Per-instance cleanup never certifies that the whole machine is Off.
mod plan;
pub use plan::UserAgentPlan;
#[cfg(windows)]
mod control;
#[cfg(windows)]
mod runtime;
#[cfg(windows)]
pub use runtime::{
    LocalCleanupObservation, ReadyObservation, StopReason, UserAgentRuntime, UserAgentSession,
};

#[derive(Debug, thiserror::Error)]
pub enum UserAgentError {
    #[error("Windows user-agent configuration does not match its exact lease")]
    ConfigurationMismatch,
    #[error("Windows user-agent cannot own the requested platform mode")]
    Mode,
    #[error("Windows user-agent control protocol: {0}")]
    Wire(#[from] crate::authority::wire::WireError),
    #[error("Windows user-agent authority worker: {0}")]
    Control(std::sync::Arc<ControlError>),
    #[error("Windows user-agent native child: {0}")]
    Engine(#[from] crate::Error),
    #[cfg(windows)]
    #[error("Windows user-agent proxy ownership: {0}")]
    Proxy(#[from] crate::ProxyError),
    #[error("Windows user-agent lifecycle deadline expired; completion is not established")]
    Deadline,
    #[error("Windows user-agent operation was cancelled or revoked")]
    Cancelled,
    #[error("Windows user-agent lifecycle state does not permit this operation")]
    State,
    #[error("Windows user-agent control worker ended without its required receipt")]
    WorkerEnded,
    #[error("Windows user-agent synchronization is poisoned")]
    Poisoned,
    #[error("Windows user-agent worker I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows user-agent operation failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
pub type Result<T> = std::result::Result<T, UserAgentError>;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("authority channel: {0}")]
    Wire(#[from] crate::authority::wire::WireError),
    #[error("authority command exceeded its deadline; delivery may be uncertain")]
    Deadline,
    #[error("authority control was cancelled")]
    Cancelled,
    #[error("authority command receiver disconnected")]
    Disconnected,
    #[error("authority command queue is full")]
    Busy,
    #[error("authority returned an unrelated response")]
    Response,
    #[error("authority control worker synchronization is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests;
