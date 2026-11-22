//! Why a Desktop operation failed.
use crate::{
    ServiceTransportError,
    authority::wire::WireError,
    credential_lifecycle::CredentialLifecycleError,
    user_agent::{StartRefusal, handoff::HandoffError, launcher::LaunchError},
};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("Windows Desktop configuration: {0}")]
    Configuration(#[from] crate::Error),
    #[error("Windows Desktop credential lifecycle: {0}")]
    Credentials(#[from] CredentialLifecycleError),
    #[error("Windows Desktop authority: {0}")]
    Authority(#[from] WireError),
    #[error("Windows Desktop transport: {0}")]
    Transport(#[from] ServiceTransportError),
    #[error("Windows Desktop handoff: {0}")]
    Handoff(#[from] HandoffError),
    #[error("Windows Desktop launcher: {0}")]
    Launch(#[from] LaunchError),
    #[error("Windows Desktop proxy restoration: {0}")]
    Proxy(#[from] crate::ProxyError),
    #[error("Windows Desktop cleanup scope: {0}")]
    CleanupScope(#[from] crate::authority::AuthorityError),
    #[error("Windows Desktop operation state: {0}")]
    State(&'static str),
    #[error("Windows Desktop authority context changed")]
    Context,
    #[error("Windows Desktop authority returned an unrelated response")]
    Response,
    #[error("Windows Desktop readiness receiver is unavailable")]
    ReadyReceiver,
    #[error("Windows Desktop status request: {0}")]
    Observation(Arc<Self>),
    /// The Agent ended the run after its engine refused the start, and
    /// cleaned up first; global Off is still to be proven by the caller.
    #[error("Windows Desktop start: {0}")]
    StartRefused(StartRefusal),
    #[error("Windows Desktop operation failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
pub type Result<T> = std::result::Result<T, DesktopError>;

impl DesktopError {
    /// The refusal an Agent reported by its exit code, as a stop that revoked
    /// the lease first observed it.
    pub(super) fn reported_refusal(&self) -> Option<StartRefusal> {
        match self {
            Self::Launch(LaunchError::Exit(code)) => StartRefusal::of_exit_code(*code),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_observed_refusal_exit_is_a_reported_refusal() {
        for (code, refusal) in [
            (0xCF30, StartRefusal::Engine),
            (0xCF31, StartRefusal::MixedEndpoint),
            (0xCF32, StartRefusal::ControllerEndpoint),
        ] {
            assert_eq!(
                DesktopError::Launch(LaunchError::Exit(code)).reported_refusal(),
                Some(refusal)
            );
        }
        for error in [
            DesktopError::Launch(LaunchError::Exit(1)),
            // The C runtime's abort().
            DesktopError::Launch(LaunchError::Exit(3)),
            DesktopError::Launch(LaunchError::Deadline),
            // A stop whose revocation failed too did not see the run end.
            DesktopError::Cleanup {
                operation: Box::new(DesktopError::Context),
                cleanup: Box::new(DesktopError::Launch(LaunchError::Exit(0xCF30))),
            },
        ] {
            assert_eq!(error.reported_refusal(), None, "{error}");
        }
    }
}
