//! Bounded async application adapter. Dropping a future cancels work before
//! vault admission, including while waiting for the native lifecycle mutex.
//! After admission, native I/O finishes under its guard; abandoning the future
//! does not assert rollback. Blocking tasks cannot safely be force-stopped.
use super::{CredentialLifecycleError as Error, Result, WindowsCredentialLifecycle};
use cfw_engine_api::{
    CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionCommitRequest,
    CredentialGarbageCollectionPreviewFuture, CredentialGarbageCollectionRequest,
    CredentialPresenceFuture, CredentialPresenceRequest, CredentialProvisionRequest,
    CredentialRebindRequest, CredentialVaultError as VaultError, CredentialVaultFuture,
    CredentialVaultProvisioner,
};
use cfw_windows_credentials::OwnedCredentialProvision;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::AbortHandle,
};

pub(super) const MAX_OPERATIONS: usize = 4;
const ADMISSION_LIMIT: Duration = Duration::from_secs(15);
const COMPLETION_LIMIT: Duration = Duration::from_secs(30);
const QUEUED: u8 = 0;
const CANCELLED: u8 = 1;
const ADMITTED: u8 = 2;

struct Admission {
    state: AtomicU8,
    deadline: Instant,
}
impl Admission {
    fn new(deadline: Instant) -> Self {
        Self {
            state: AtomicU8::new(QUEUED),
            deadline,
        }
    }
    fn check(&self) -> Result<()> {
        if self.state.load(Ordering::Acquire) == CANCELLED {
            return Err(Error::CancelledBeforeAdmission);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn begin(&self) -> Result<()> {
        self.check()?;
        self.state
            .compare_exchange(QUEUED, ADMITTED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| {
                if state == CANCELLED {
                    Error::CancelledBeforeAdmission
                } else {
                    Error::Identity
                }
            })
    }
    fn admitted(&self) -> bool {
        self.state.load(Ordering::Acquire) == ADMITTED
    }
    fn cancel(&self) {
        let _ = self
            .state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
    }
    fn timeout_error(&self) -> VaultError {
        // Cancellation and vault admission race through one CAS. A successful
        // cancellation cannot later become an admitted write.
        self.cancel();
        if self.admitted() {
            VaultError::OutcomeUnknown
        } else {
            VaultError::Unavailable
        }
    }
}
struct CancelOnDrop {
    admission: Arc<Admission>,
    worker: AbortHandle,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.admission.cancel();
        // May retire queued work; the admission CAS also handles an already
        // running worker that is still waiting on the native lifecycle mutex.
        self.worker.abort();
    }
}
struct Worker {
    runtime: Handle,
    permit: OwnedSemaphorePermit,
    admission: Arc<Admission>,
    completion_deadline: Instant,
}
impl Worker {
    fn reserve(capacity: &Arc<Semaphore>) -> std::result::Result<Self, VaultError> {
        let runtime = Handle::try_current().map_err(|_| VaultError::Unavailable)?;
        // A thread pool does not inherit the caller's impersonation token.
        // Reject that context here rather than silently switching identities.
        cfw_windows_storage::require_process_identity()
            .map_err(|error| map_error(Error::Storage(error), false))?;
        let permit = Arc::clone(capacity)
            .try_acquire_owned()
            .map_err(|_| VaultError::ConcurrentModification)?;
        Ok(Self {
            runtime,
            permit,
            admission: Arc::new(Admission::new(Instant::now() + ADMISSION_LIMIT)),
            completion_deadline: Instant::now() + COMPLETION_LIMIT,
        })
    }
    async fn run<T: Send + 'static>(
        self,
        operation: impl FnOnce(&Admission) -> Result<T> + Send + 'static,
    ) -> std::result::Result<T, VaultError> {
        // Like the Mac bridge, the application executor must enable Tokio time.
        // Construct its watchdog before spawning any native operation.
        let watchdog =
            tokio::time::sleep_until(tokio::time::Instant::from_std(self.completion_deadline));
        tokio::pin!(watchdog);
        let admission = Arc::clone(&self.admission);
        let mut worker = self.runtime.spawn_blocking(move || {
            // Capacity is held by the real worker until its buffers and native
            // operation retire, even when the caller abandons its future.
            let _permit = self.permit;
            admission.check()?;
            operation(&admission)
        });
        let _cancel = CancelOnDrop {
            admission: Arc::clone(&self.admission),
            worker: worker.abort_handle(),
        };
        tokio::select! {
            biased;
            _ = &mut watchdog => Err(self.admission.timeout_error()),
            result = &mut worker => match result {
                Ok(result) => result.map_err(|error| map_error(error, self.admission.admitted())),
                Err(_) if self.admission.admitted() => Err(VaultError::OutcomeUnknown),
                Err(_) => Err(VaultError::Internal),
            },
        }
    }
}

impl CredentialVaultProvisioner for WindowsCredentialLifecycle {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        Box::pin(async move {
            // Reject queue pressure before copying borrowed secrets.
            let worker = Worker::reserve(&self.workers)?;
            let owned = OwnedCredentialProvision::capture(&request)?;
            let owner = self.clone();
            worker
                .run(move |admission| owner.provision_owned_admitted(owned, || admission.begin()))
                .await
        })
    }
    fn rebind_profile_credentials(
        &self,
        request: CredentialRebindRequest,
    ) -> CredentialVaultFuture<'_> {
        Box::pin(async move {
            let worker = Worker::reserve(&self.workers)?;
            let owner = self.clone();
            worker
                .run(move |admission| owner.rebind_admitted(&request, || admission.begin()))
                .await
        })
    }
    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async move {
            let worker = Worker::reserve(&self.workers)?;
            let owner = self.clone();
            worker
                .run(move |admission| owner.presence_admitted(&request, || admission.begin()))
                .await
        })
    }
    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        Box::pin(async move {
            let worker = Worker::reserve(&self.workers)?;
            let owner = self.clone();
            worker
                .run(move |admission| owner.preview_admitted(&request, || admission.begin()))
                .await
        })
    }
    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        Box::pin(async move {
            let worker = Worker::reserve(&self.workers)?;
            let owner = self.clone();
            worker
                .run(move |admission| owner.commit_admitted(&request, || admission.begin()))
                .await
        })
    }
}

fn map_error(error: Error, admitted: bool) -> VaultError {
    use cfw_windows_storage::Error as Storage;
    match error {
        Error::Vault(error) => error,
        // These wrapper failures can occur after the vault returned success.
        Error::Storage(_) | Error::Cleanup { .. } if admitted => VaultError::OutcomeUnknown,
        Error::Cleanup { operation, .. } => map_error(*operation, false),
        Error::Record | Error::ProtectedVaultMissing => VaultError::Corrupt,
        Error::Schema => VaultError::MigrationRequired,
        Error::Identity => VaultError::IdentityRejected,
        Error::Unavailable | Error::Deadline | Error::CancelledBeforeAdmission => {
            VaultError::Unavailable
        }
        Error::Authority(error) => {
            use crate::authority::wire::{Rejection, WireError};
            match error {
                WireError::Transport(_)
                | WireError::Rejected(
                    Rejection::Recovering
                    | Rejection::Quarantined
                    | Rejection::CleanupUnproven
                    | Rejection::Publication
                    | Rejection::Observation
                    | Rejection::Expired,
                ) => VaultError::Unavailable,
                WireError::Rejected(Rejection::Stale | Rejection::LeaseConflict) => {
                    VaultError::ConcurrentModification
                }
                _ => VaultError::IdentityRejected,
            }
        }
        Error::Storage(error) => match error {
            Storage::CommitUncertain(_) => VaultError::OutcomeUnknown,
            Storage::Busy | Storage::MutexBusy => VaultError::ConcurrentModification,
            Storage::UnsafeDirectory
            | Storage::UnsafeFile
            | Storage::InvalidSecurityDescriptor
            | Storage::UnsafeMutex
            | Storage::ImpersonatedIdentity => VaultError::AccessDenied,
            Storage::TooLarge { .. } | Storage::InvalidDirectoryListing => VaultError::Corrupt,
            Storage::TooManyEntries { .. } => VaultError::CapacityExceeded,
            Storage::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                VaultError::AccessDenied
            }
            Storage::Io(_) | Storage::Enumeration { .. } => VaultError::Unavailable,
            Storage::CleanupFailed { operation, .. } => {
                map_error(Error::Storage(*operation), false)
            }
            Storage::InvalidName
            | Storage::InvalidLimit
            | Storage::IncompleteStream
            | Storage::UnexpectedDirectory
            | Storage::InvalidMutexParameters => VaultError::Internal,
        },
    }
}

#[cfg(test)]
mod tests;
