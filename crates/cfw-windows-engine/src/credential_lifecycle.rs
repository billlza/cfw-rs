//! Persisted credential bindings for the single Authority runtime. Native
//! lifecycle admission, not a frontend-supplied list, chooses GC protection.
#[cfg(windows)]
mod native;
mod record;
#[cfg(windows)]
pub use native::WindowsCredentialLifecycle;

#[derive(Debug, thiserror::Error)]
pub enum CredentialLifecycleError {
    #[error("Windows runtime credential record is malformed or noncanonical")]
    Record,
    #[error("Windows runtime credential record requires explicit migration")]
    Schema,
    #[error("Windows runtime credential bindings do not match Authority state")]
    Identity,
    #[error("Windows runtime credential state is unavailable for maintenance")]
    Unavailable,
    #[error("Windows credential vault is missing while runtime bindings remain protected")]
    ProtectedVaultMissing,
    #[error("Windows runtime credential operation exceeded its admission deadline")]
    Deadline,
    #[cfg(windows)]
    #[error("Windows runtime credential storage: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[cfg(windows)]
    #[error("Windows runtime credential Authority: {0}")]
    Authority(#[from] crate::authority::wire::WireError),
    #[cfg(windows)]
    #[error("Windows runtime credential vault: {0}")]
    Vault(#[from] cfw_engine_api::CredentialVaultError),
    #[error(
        "Windows runtime credential operation failed ({operation}); lock release failed ({cleanup})"
    )]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
type Result<T> = std::result::Result<T, CredentialLifecycleError>;

#[cfg(test)]
mod tests;
