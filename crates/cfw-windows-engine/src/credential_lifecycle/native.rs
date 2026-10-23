use super::{
    CredentialLifecycleError as Error, Result,
    record::{self, MAX_BYTES, Record},
};
use crate::{
    CheckedStartConfiguration, ServiceClientRole, VerifiedExecutable,
    authority::{
        AuthorityChannel, PrepareRequest,
        wire::{Command, PreparedGrant, Request, Response},
    },
};
use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionReceipt, CredentialGarbageCollectionRequest, CredentialPresence,
    CredentialPresenceRequest, CredentialProvisionRequest, CredentialRebindRequest,
    CredentialVaultReceipt, authority_v1::AuthorityState,
};
use cfw_windows_credentials::{OwnedCredentialProvision, WindowsCredentialStore};
use cfw_windows_storage::{PrivateDirectory, PrivateUserMutex, ReadPolicy};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const RECORD: &str = "runtime-bindings-v1.json";
const LOCK_WAIT: Duration = Duration::from_secs(3);
const REQUEST_WAIT: Duration = Duration::from_secs(5);

/// Trusted installation inputs, never frontend-selected service or paths. Every
/// current-user start and vault mutation shares one cross-session native mutex.
/// Run these synchronous operations on the native lifecycle/blocking worker.
/// The UserAgent must derive the same vault path from its installation inputs.
#[derive(Clone)]
pub struct WindowsCredentialLifecycle {
    service: String,
    image: Arc<VerifiedExecutable>,
    directory: PathBuf,
    pub(super) workers: Arc<tokio::sync::Semaphore>,
}
impl WindowsCredentialLifecycle {
    pub fn new(
        service: String,
        image: Arc<VerifiedExecutable>,
        directory: impl AsRef<Path>,
    ) -> Self {
        Self {
            service,
            image,
            directory: directory.as_ref().to_owned(),
            workers: Arc::new(tokio::sync::Semaphore::new(
                super::asynchronous::MAX_OPERATIONS,
            )),
        }
    }
    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn vault(&self) -> WindowsCredentialStore {
        WindowsCredentialStore::new(self.directory.join("vault"))
    }

    /// The installed Desktop has authenticated its current installation and
    /// validated this candidate's complete audience/digest before calling.
    /// A check consumes a private material snapshot, not a runtime binding;
    /// it never writes a protected-runtime record or reserves a generation.
    pub(crate) fn resolve_candidate_material(
        &self,
        request: &CheckedStartConfiguration,
        deadline: Instant,
    ) -> Result<cfw_windows_credentials::ResolvedCredentials> {
        self.locked(deadline, || {
            Ok(self.vault().resolve_for_engine(
                request.credential_audience(),
                &request.credential_references(),
            )?)
        })
    }

    /// One immutable, audience-bound snapshot for a transient profile probe.
    /// No runtime binding or generation is created; all resolved bytes remain
    /// in the private native worker and are erased when that snapshot retires.
    pub(crate) fn resolve_probe_material(
        &self,
        request: &crate::CheckedProbeConfiguration,
        deadline: Instant,
    ) -> Result<cfw_windows_credentials::ResolvedCredentials> {
        self.locked(deadline, || {
            Ok(self.vault().resolve_for_engine(
                request.credential_audience(),
                &request.credential_references(),
            )?)
        })
    }

    pub fn provision(
        &self,
        request: CredentialProvisionRequest<'_>,
    ) -> Result<CredentialVaultReceipt> {
        self.locked(Instant::now() + LOCK_WAIT, || {
            Ok(self.vault().provision(request)?)
        })
    }
    pub fn presence(&self, request: &CredentialPresenceRequest) -> Result<Vec<CredentialPresence>> {
        self.presence_admitted(request, || Ok(()))
    }
    pub(super) fn provision_owned_admitted(
        &self,
        request: OwnedCredentialProvision,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<CredentialVaultReceipt> {
        self.locked(Instant::now() + LOCK_WAIT, || {
            admit()?;
            Ok(self.vault().provision_owned(request)?)
        })
    }
    pub(super) fn presence_admitted(
        &self,
        request: &CredentialPresenceRequest,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<Vec<CredentialPresence>> {
        admit()?;
        Ok(self.vault().presence(request)?)
    }
    pub fn rebind(&self, request: &CredentialRebindRequest) -> Result<CredentialVaultReceipt> {
        self.rebind_admitted(request, || Ok(()))
    }
    pub(super) fn rebind_admitted(
        &self,
        request: &CredentialRebindRequest,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<CredentialVaultReceipt> {
        self.locked(Instant::now() + LOCK_WAIT, || {
            admit()?;
            Ok(self.vault().rebind(request)?)
        })
    }
    pub fn preview_garbage_collection(
        &self,
        request: &CredentialGarbageCollectionRequest,
    ) -> Result<CredentialGarbageCollectionPreview> {
        self.preview_admitted(request, || Ok(()))
    }
    pub(super) fn preview_admitted(
        &self,
        request: &CredentialGarbageCollectionRequest,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<CredentialGarbageCollectionPreview> {
        self.locked(Instant::now() + LOCK_WAIT, || {
            let bindings = self.protected_bindings()?;
            admit()?;
            vault_result(
                self.vault().preview_garbage_collection(request, &bindings),
                &bindings,
            )
        })
    }
    pub fn commit_garbage_collection(
        &self,
        request: &CredentialGarbageCollectionCommitRequest,
    ) -> Result<CredentialGarbageCollectionReceipt> {
        self.commit_admitted(request, || Ok(()))
    }
    pub(super) fn commit_admitted(
        &self,
        request: &CredentialGarbageCollectionCommitRequest,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<CredentialGarbageCollectionReceipt> {
        self.locked(Instant::now() + LOCK_WAIT, || {
            // Re-observe inside the guard. The store checks both vault revision
            // and the exact orphan set from the user's confirmed preview.
            let bindings = self.protected_bindings()?;
            admit()?;
            vault_result(
                self.vault().commit_garbage_collection(request, &bindings),
                &bindings,
            )
        })
    }
    fn connect(&self) -> Result<AuthorityChannel> {
        Ok(AuthorityChannel::connect(
            &self.service,
            ServiceClientRole::Desktop,
            Arc::clone(&self.image),
        )?)
    }
    fn protected_bindings(&self) -> Result<Vec<cfw_singbox_config::CredentialBinding>> {
        let Response::RuntimeScope(scope) = send(
            &mut self.connect()?,
            Command::ReadRuntimeScope,
            Instant::now() + REQUEST_WAIT,
        )?
        else {
            return Err(Error::Identity);
        };
        let record = self.read_record()?;
        record::protected(scope.snapshot(), scope.operation(), record.as_ref())
    }
    fn read_record(&self) -> Result<Option<Record>> {
        let Some(directory) = PrivateDirectory::open_existing(&self.directory)? else {
            return Ok(None);
        };
        let read = directory.read()?;
        read.read(RECORD, MAX_BYTES, ReadPolicy::Private)?
            .map(|snapshot| Record::decode(&snapshot.bytes))
            .transpose()
    }
    fn write_record(&self, value: &Record) -> Result<()> {
        let bytes = value.encode()?;
        let directory = PrivateDirectory::open_or_create(&self.directory)?;
        let mut transaction = directory.write()?;
        if let Some(previous) = transaction.read(RECORD, MAX_BYTES, ReadPolicy::Private)? {
            Record::decode(&previous.bytes)?;
        }
        transaction.replace(RECORD, &bytes, MAX_BYTES)?;
        Ok(())
    }
    pub(crate) fn prepare(
        &self,
        request: CheckedStartConfiguration,
        deadline: Instant,
    ) -> Result<(AuthorityChannel, PreparedGrant, CheckedStartConfiguration)> {
        // A Tunnel run binds its credentials like a proxy run; the combined
        // mode's user proxy settings are not owned on Windows.
        if request.mode() == cfw_singbox_config::ProjectionMode::TunnelSystemProxy {
            return Err(Error::Unavailable);
        }
        self.locked(deadline, || {
            let mut authority = self.connect()?;
            let Response::Observed(before) = send(&mut authority, Command::Observe, deadline)?
            else {
                return Err(Error::Identity);
            };
            if before.state != AuthorityState::Off {
                return Err(Error::Unavailable);
            }
            let record = Record::new(&request, uuid::Uuid::new_v4())?;
            // A complete binding is durable before the service can admit this
            // configuration. An uncertain write or Prepare leaves the record;
            // future GC must correlate actual committed/recovery state.
            self.write_record(&record)?;
            let input = PrepareRequest {
                root: record.root().clone(),
                operation_id: record.operation_id(),
                mode: record.mode(),
                config_sha256: record.content_digest()?,
                identity_sha256: record.identity_digest()?,
                expected_revision: before.revision.ok_or(Error::Identity)?,
            };
            let Response::Prepared(grant) =
                send(&mut authority, Command::Prepare(input), deadline)?
            else {
                return Err(Error::Identity);
            };
            Ok((authority, grant, request))
        })
    }
    fn locked<T>(&self, deadline: Instant, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        cfw_windows_storage::require_process_identity()?;
        let wait = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(Error::Deadline)?
            .min(LOCK_WAIT);
        let lock = PrivateUserMutex::acquire("runtime-credentials-v1", wait)?;
        // Durable record and service state are always reloaded, including after
        // an abandoned owner; mutex acquisition itself certifies no recovery.
        let outcome = if Instant::now() >= deadline {
            Err(Error::Deadline)
        } else {
            operation()
        };
        let release = lock.release().map_err(Error::from);
        match (outcome, release) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(Error::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
}
fn send(channel: &mut AuthorityChannel, command: Command, deadline: Instant) -> Result<Response> {
    Ok(channel.request(
        Request::new(command)?,
        deadline.min(Instant::now() + REQUEST_WAIT),
    )?)
}
fn vault_result<T>(
    result: std::result::Result<T, cfw_engine_api::CredentialVaultError>,
    bindings: &[cfw_singbox_config::CredentialBinding],
) -> Result<T> {
    match result {
        Err(cfw_engine_api::CredentialVaultError::MissingVault) if !bindings.is_empty() => {
            Err(Error::ProtectedVaultMissing)
        }
        other => other.map_err(Error::from),
    }
}
