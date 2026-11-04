//! The native credential vault boundary and its errors.

use std::pin::Pin;

use thiserror::Error;

use crate::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionReceipt, CredentialGarbageCollectionRequest, CredentialPresence,
    CredentialPresenceRequest, CredentialProvisionRequest, CredentialRebindRequest,
    CredentialVaultReceipt,
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialVaultError {
    #[error("credential vault outcome is unknown; completion could not be confirmed")]
    OutcomeUnknown,
    #[error("credential vault is unavailable")]
    Unavailable,
    #[error("credential vault access was denied")]
    AccessDenied,
    #[error("credential vault capacity is exhausted")]
    CapacityExceeded,
    #[error("credential UUID already exists with different immutable material")]
    ImmutableConflict,
    #[error("credential vault rejected invalid material")]
    InvalidMaterial,
    #[error("credential vault data is corrupt")]
    Corrupt,
    #[error(
        "credential vault identity or response was rejected; the operation result is unconfirmed"
    )]
    IdentityRejected,
    #[error("credential vault does not exist")]
    MissingVault,
    #[error("credential vault schema requires explicit migration")]
    MigrationRequired,
    #[error("credential vault changed after maintenance preview")]
    ConcurrentModification,
    #[error("credential vault failed internally")]
    Internal,
}

pub type CredentialVaultFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CredentialVaultReceipt, CredentialVaultError>> + Send + 'a>>;
pub type CredentialPresenceFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Vec<CredentialPresence>, CredentialVaultError>> + Send + 'a>,
>;
pub type CredentialGarbageCollectionPreviewFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<CredentialGarbageCollectionPreview, CredentialVaultError>>
            + Send
            + 'a,
    >,
>;
pub type CredentialGarbageCollectionCommitFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<CredentialGarbageCollectionReceipt, CredentialVaultError>>
            + Send
            + 'a,
    >,
>;

/// Native boundary for atomically provisioning one immutable credential set.
/// There is intentionally no overwrite operation and no default or in-memory
/// production fallback.
pub trait CredentialVaultProvisioner: Send + Sync + 'static {
    fn rebind_profile_credentials(
        &self,
        _request: CredentialRebindRequest,
    ) -> CredentialVaultFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Unavailable) })
    }
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a>;

    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_>;

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_>;

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_>;
}

impl<T: CredentialVaultProvisioner + ?Sized> CredentialVaultProvisioner for std::sync::Arc<T> {
    fn rebind_profile_credentials(
        &self,
        request: CredentialRebindRequest,
    ) -> CredentialVaultFuture<'_> {
        (**self).rebind_profile_credentials(request)
    }

    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        (**self).provision_profile_credentials(request)
    }

    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        (**self).query_profile_credentials(request)
    }

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        (**self).preview_credential_garbage_collection(request)
    }

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        (**self).commit_credential_garbage_collection(request)
    }
}

#[cfg(test)]
mod tests;
