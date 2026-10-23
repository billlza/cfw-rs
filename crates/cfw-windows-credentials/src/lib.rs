//! Current-user Windows credential persistence. This is the storage boundary;
//! it does not authorize UI callers, impersonate users, or observe an engine.
//! Runtime-aware garbage collection must be owned by the Windows coordinator.
#![cfg(windows)]

mod document;
mod dpapi;
mod owned;
pub use owned::OwnedCredentialProvision;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionReceipt, CredentialGarbageCollectionRequest, CredentialPresence,
    CredentialPresenceRequest, CredentialProvisionRequest, CredentialRebindRequest,
    CredentialVaultError as Error, CredentialVaultReceipt,
};
use cfw_singbox_config::{CredentialAudience, CredentialBinding, CredentialRef};
use cfw_windows_storage::{PrivateDirectory, ReadPolicy, Snapshot};
use uuid::Uuid;

use document::Document;
pub use document::ResolvedCredentials;
use dpapi::MAX_CIPHERTEXT_BYTES;

const VAULT_FILE: &str = "credentials-v1.dpapi";

/// Synchronous OS persistence. Call from a native blocking worker; never from
/// the UI thread or by blocking an asynchronous executor. Transactions retain
/// the cross-process lock through decrypt, validation, encrypt, rename and flush.
#[derive(Debug, Clone)]
pub struct WindowsCredentialStore {
    directory: PathBuf,
}

impl WindowsCredentialStore {
    /// The path must be a dedicated absolute private directory. Every operation
    /// reopens and validates it under the process user; no handles or plaintext
    /// are retained between operations.
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_owned(),
        }
    }

    pub fn provision(
        &self,
        request: CredentialProvisionRequest<'_>,
    ) -> Result<CredentialVaultReceipt, Error> {
        let supplied: Vec<_> = request
            .entries()
            .iter()
            .map(|entry| (entry.reference(), entry.secret().expose_to_vault()))
            .collect();
        self.provision_parts(request.audience(), request.required_references(), &supplied)
    }

    pub fn provision_owned(
        &self,
        request: OwnedCredentialProvision,
    ) -> Result<CredentialVaultReceipt, Error> {
        let supplied: Vec<_> = request
            .entries
            .iter()
            .map(|(reference, secret)| (reference, secret.as_str()))
            .collect();
        self.provision_parts(&request.audience, &request.references, &supplied)
    }

    fn provision_parts(
        &self,
        audience: &CredentialAudience,
        references: &[CredentialRef],
        supplied: &[(&CredentialRef, &str)],
    ) -> Result<CredentialVaultReceipt, Error> {
        self.mutate(false, |document| {
            let changed = document.provision(audience, references, supplied)?;
            Ok((changed, receipt(audience)))
        })
    }

    pub fn presence(
        &self,
        request: &CredentialPresenceRequest,
    ) -> Result<Vec<CredentialPresence>, Error> {
        self.read()?
            .unwrap_or_else(Document::empty)
            .presence(request.audience(), request.references())
    }

    /// This operation requires the engine to have already authenticated and
    /// admitted the exact profile audience. It is never a frontend command.
    pub fn resolve_for_engine(
        &self,
        audience: &CredentialAudience,
        references: &[CredentialRef],
    ) -> Result<ResolvedCredentials, Error> {
        self.read()?
            .unwrap_or_else(Document::empty)
            .resolve(audience, references)
    }

    pub fn rebind(
        &self,
        request: &CredentialRebindRequest,
    ) -> Result<CredentialVaultReceipt, Error> {
        let references: Vec<_> = request
            .slots()
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.mutate(false, |document| {
            let material = document.resolve(request.previous_audience(), &references)?;
            let supplied: Vec<_> = material.expose_to_engine().collect();
            let changed = document.provision(request.audience(), &references, &supplied)?;
            Ok((changed, receipt(request.audience())))
        })
    }

    /// The owner must hold its engine lifecycle mutation guard while observing
    /// runtime bindings and calling this method. Include active, pending and
    /// persisted recovery configurations, including older profile digests. An
    /// observation failure must be returned, never substituted with an empty
    /// slice. The same contract applies again at commit.
    pub fn preview_garbage_collection(
        &self,
        request: &CredentialGarbageCollectionRequest,
        runtime_bindings: &[CredentialBinding],
    ) -> Result<CredentialGarbageCollectionPreview, Error> {
        validate_catalog(request)?;
        let document = self.read()?.ok_or(Error::MissingVault)?;
        let orphan_bindings = document.orphans(request.catalog(), runtime_bindings)?;
        Ok(CredentialGarbageCollectionPreview {
            snapshot_digest: request.snapshot_digest().to_owned(),
            vault_revision: document.revision.to_string(),
            orphan_count: u32::try_from(orphan_bindings.len())
                .map_err(|_| Error::CapacityExceeded)?,
            orphan_bindings,
        })
    }

    pub fn commit_garbage_collection(
        &self,
        request: &CredentialGarbageCollectionCommitRequest,
        runtime_bindings: &[CredentialBinding],
    ) -> Result<CredentialGarbageCollectionReceipt, Error> {
        let catalog = CredentialGarbageCollectionRequest::new(
            request.snapshot_digest(),
            request.catalog().to_vec(),
        )
        .map_err(|_| Error::InvalidMaterial)?;
        let preview = CredentialGarbageCollectionPreview {
            snapshot_digest: request.snapshot_digest().to_owned(),
            vault_revision: request.expected_vault_revision().to_owned(),
            orphan_bindings: request.expected_orphan_bindings().to_vec(),
            orphan_count: u32::try_from(request.expected_orphan_bindings().len())
                .map_err(|_| Error::InvalidMaterial)?,
        };
        let canonical = CredentialGarbageCollectionCommitRequest::new(catalog, &preview)
            .map_err(|_| Error::InvalidMaterial)?;
        if &canonical != request {
            return Err(Error::InvalidMaterial);
        }
        self.mutate(true, |document| {
            if document.revision.to_string() != request.expected_vault_revision() {
                return Err(Error::ConcurrentModification);
            }
            let actual = document.orphans(request.catalog(), runtime_bindings)?;
            if actual != request.expected_orphan_bindings() {
                return Err(Error::ConcurrentModification);
            }
            let changed = !actual.is_empty();
            let deleted_count = u32::try_from(actual.len()).map_err(|_| Error::CapacityExceeded)?;
            if changed {
                document.remove(&actual);
                document.revision = Uuid::new_v4();
            }
            Ok((
                changed,
                CredentialGarbageCollectionReceipt {
                    vault_revision: document.revision.to_string(),
                    deleted_count,
                },
            ))
        })
    }

    fn read(&self) -> Result<Option<Document>, Error> {
        dpapi::require_process_identity()?;
        let Some(directory) =
            PrivateDirectory::open_existing(&self.directory).map_err(storage_error)?
        else {
            return Ok(None);
        };
        let transaction = directory.read().map_err(storage_error)?;
        decode(
            transaction
                .read(VAULT_FILE, MAX_CIPHERTEXT_BYTES, ReadPolicy::Private)
                .map_err(storage_error)?,
        )
    }

    fn mutate<T>(
        &self,
        require_existing: bool,
        operation: impl FnOnce(&mut Document) -> Result<(bool, T), Error>,
    ) -> Result<T, Error> {
        dpapi::require_process_identity()?;
        let directory = PrivateDirectory::open_or_create(&self.directory).map_err(storage_error)?;
        let mut transaction = directory.write().map_err(storage_error)?;
        let previous = decode(
            transaction
                .read(VAULT_FILE, MAX_CIPHERTEXT_BYTES, ReadPolicy::Private)
                .map_err(storage_error)?,
        )?;
        if require_existing && previous.is_none() {
            return Err(Error::MissingVault);
        }
        let mut document = previous.unwrap_or_else(Document::empty);
        let previous_revision = document.revision;
        let (changed, result) = operation(&mut document)?;
        if changed {
            if document.revision == previous_revision {
                document.revision = Uuid::new_v4();
            }
            let plaintext = document.encode()?;
            let ciphertext = dpapi::protect(&plaintext)?;
            transaction
                .replace(VAULT_FILE, &ciphertext, MAX_CIPHERTEXT_BYTES)
                .map_err(storage_error)?;
        }
        Ok(result)
    }
}

// These shared maintenance DTOs also implement Deserialize, so the storage
// boundary cannot assume that their checked constructors were used.
fn validate_catalog(request: &CredentialGarbageCollectionRequest) -> Result<(), Error> {
    let canonical = CredentialGarbageCollectionRequest::new(
        request.snapshot_digest(),
        request.catalog().to_vec(),
    )
    .map_err(|_| Error::InvalidMaterial)?;
    if &canonical == request {
        Ok(())
    } else {
        Err(Error::InvalidMaterial)
    }
}

fn receipt(audience: &CredentialAudience) -> CredentialVaultReceipt {
    CredentialVaultReceipt {
        profile_id: audience.profile_id().to_owned(),
        profile_digest: audience.profile_digest().to_owned(),
    }
}

fn decode(snapshot: Option<Snapshot>) -> Result<Option<Document>, Error> {
    snapshot
        .map(|snapshot| Document::decode(&dpapi::unprotect(&snapshot.bytes)?))
        .transpose()
}

fn storage_error(error: cfw_windows_storage::Error) -> Error {
    use cfw_windows_storage::Error as Storage;
    match error {
        Storage::CommitUncertain(_) => Error::OutcomeUnknown,
        Storage::Busy | Storage::MutexBusy => Error::ConcurrentModification,
        Storage::UnsafeDirectory
        | Storage::UnsafeFile
        | Storage::InvalidSecurityDescriptor
        | Storage::UnsafeMutex
        | Storage::ImpersonatedIdentity => Error::AccessDenied,
        Storage::TooLarge { .. } | Storage::InvalidDirectoryListing => Error::Corrupt,
        Storage::TooManyEntries { .. } => Error::CapacityExceeded,
        Storage::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Error::AccessDenied
        }
        Storage::Io(_) | Storage::Enumeration { .. } => Error::Unavailable,
        // CleanupFailed is emitted before publication; it does not conceal a
        // commit. Preserve publication uncertainty if that contract ever grows.
        Storage::CleanupFailed { operation, .. } => storage_error(*operation),
        Storage::InvalidName
        | Storage::InvalidLimit
        | Storage::IncompleteStream
        | Storage::UnexpectedDirectory
        | Storage::InvalidMutexParameters => Error::Internal,
    }
}

#[cfg(test)]
mod tests;
