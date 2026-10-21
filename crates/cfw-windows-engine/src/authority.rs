//! Serialized Windows lifecycle policy. Only the native controller may publish
//! grants, after committing their candidate state and revalidating the caller.
#[cfg(windows)]
mod client;
#[cfg(windows)]
mod dispatch;
mod machine;
#[cfg(windows)]
mod native;
mod recovery;
#[cfg(windows)]
mod runtime_job;
mod secret;
mod types;
pub mod wire;
#[cfg(windows)]
pub use client::AuthorityChannel;
#[cfg(windows)]
pub use dispatch::{AuthorizedReply, DispatchError};
#[cfg(windows)]
pub use native::ObservedRecordedOff;
#[cfg(windows)]
pub use native::ProxyRecoveryObservation;
#[cfg(windows)]
pub use native::VerifiedLocalCleanup;
#[cfg(windows)]
pub use native::VerifiedOffAdmission;
#[cfg(windows)]
pub use native::WindowsAuthority;
pub use recovery::{ProxyRecoveryContext, ProxyRecoveryPurpose, ProxyRecoveryTarget};
#[cfg(windows)]
pub(crate) use runtime_job::RuntimeKeeper;
#[cfg(all(windows, feature = "native-service-validation"))]
pub use runtime_job::{
    JobKeeperProbe, runtime_job_name_for_validation, validate_runtime_job_failures_for_validation,
    validate_runtime_keeper_adoption,
};
#[cfg(windows)]
pub use runtime_job::{RuntimeJobError, RuntimeProcessObservation, RuntimeProcessState};
pub use types::{
    AuthorityLineage, AuthoritySnapshot, CleanupEvidence, LeaseContext, OperationContext,
    PrepareRequest, PreparedTicket, ReadyReport, RecordedRuntimeScope, RuntimeStartAuthorization,
    StoppedReport,
};

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("Windows authority is recovering and cannot authorize an operation")]
    Recovering,
    #[error("Windows authority is quarantined until cleanup is proved")]
    Quarantined,
    #[error("Windows authority already holds an exclusive lease")]
    LeaseConflict,
    #[error("Windows authority operation or revision is stale")]
    Stale,
    #[error("Windows authority caller, connection, or runtime role does not own this operation")]
    Identity,
    #[error("Windows authority input is invalid")]
    Invalid,
    #[error("Windows authority rejected an installation or generation replay")]
    Replay,
    #[error("Windows authority generation is exhausted")]
    GenerationExhausted,
    #[error("Windows authority preparation ticket is invalid or already consumed")]
    Ticket,
    #[error("Windows authority preparation expired")]
    Expired,
    #[error("Windows authority cleanup is not proved")]
    CleanupUnproven,
    #[error("Windows authority journal state: {0}")]
    JournalValidation(#[from] crate::authority_journal::JournalValidationError),
    #[cfg(windows)]
    #[error("Windows authority publication or recovery failed: {0}")]
    Journal(#[from] crate::authority_journal::JournalStoreError),
    #[cfg(windows)]
    #[error("Windows authority peer admission: {0}")]
    Peer(#[from] crate::ServiceAuthorizationError),
    #[cfg(windows)]
    #[error("Windows authority owner observation: {0}")]
    Process(#[from] crate::PeerIdentityError),
    #[cfg(windows)]
    #[error("Windows authority runtime observation: {0}")]
    RuntimeJob(#[from] RuntimeJobError),
    #[cfg(windows)]
    #[error("Windows authority listener observation: {0}")]
    RuntimeEndpoints(#[source] crate::Error),
    #[cfg(windows)]
    #[error("Windows authority system entropy failed with status {0:#x}")]
    Entropy(i32),
}
pub type Result<T> = std::result::Result<T, AuthorityError>;

#[cfg(test)]
mod tests;
