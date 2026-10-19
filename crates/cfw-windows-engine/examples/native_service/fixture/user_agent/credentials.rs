use super::*;
use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionRequest,
    CredentialPresenceRequest, CredentialProvision, CredentialProvisionRequest, CredentialSecret,
    CredentialVaultError,
};
use cfw_windows_engine::credential_lifecycle::{
    CredentialLifecycleError, WindowsCredentialLifecycle,
};
use cfw_windows_storage::{PrivateDirectory, PrivateUserMutex, ReadPolicy};

pub(super) const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const RECORD: &str = "runtime-bindings-v1.json";
const MAX_RECORD: usize = 2 * 1024 * 1024;
pub(super) fn outbound() -> serde_json::Value {
    serde_json::json!({"type":"trojan","tag":"gc-protected","server":"unused.example.com","server_port":443,"credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"unused.example.com"}})
}
pub(super) struct Fixture {
    active: CredentialPresenceRequest,
    inactive: CredentialPresenceRequest,
    before_start: CredentialGarbageCollectionCommitRequest,
}
impl Fixture {
    pub(super) fn new(
        lifecycle: &WindowsCredentialLifecycle,
        active: &ValidatedSingBoxProfile,
    ) -> Result<Self> {
        let mut other = outbound();
        other["server"] = "older.example.com".into();
        let other = ValidatedSingBoxProfile::parse(
            &serde_json::to_string(&serde_json::json!({"outbounds":[other]}))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        for profile in [active, &other] {
            let references = profile.credential_references();
            if references.len() != 1 {
                return Err("credential runtime fixture expected one reference".into());
            }
            let request = CredentialProvisionRequest::new(
                PROFILE,
                profile,
                vec![CredentialProvision::new(
                    &references[0],
                    CredentialSecret::new("fixture-runtime-secret").map_err(|e| e.to_string())?,
                )],
            )
            .map_err(|e| e.to_string())?;
            lifecycle.provision(request).map_err(|e| e.to_string())?;
        }
        let empty = catalog()?;
        let preview = lifecycle
            .preview_garbage_collection(&empty)
            .map_err(|e| e.to_string())?;
        if preview.orphan_count != 2 {
            return Err("Off GC did not observe two distinct profile-digest bindings".into());
        }
        Ok(Self {
            active: CredentialPresenceRequest::new(PROFILE, active).map_err(|e| e.to_string())?,
            inactive: CredentialPresenceRequest::new(PROFILE, &other).map_err(|e| e.to_string())?,
            before_start: CredentialGarbageCollectionCommitRequest::new(empty, &preview)
                .map_err(|e| e.to_string())?,
        })
    }
    pub(super) fn while_active(
        &self,
        lifecycle: &WindowsCredentialLifecycle,
        state_directory: &Path,
        image: Arc<VerifiedExecutable>,
    ) -> Result<()> {
        match lifecycle.commit_garbage_collection(&self.before_start) {
            Err(CredentialLifecycleError::Vault(CredentialVaultError::ConcurrentModification)) => {}
            Err(error) => return Err(format!("active GC conflict mismatch: {error}")),
            Ok(_) => return Err("pre-start GC preview deleted running credentials".into()),
        }
        self.require_presence(lifecycle, true, true)?;
        // A fresh object must reload persisted bindings, not inherit an in-memory list.
        let reopened = WindowsCredentialLifecycle::new(
            lifecycle.service().into(),
            Arc::clone(&image),
            state_directory,
        );
        let request = catalog()?;
        let preview = reopened
            .preview_garbage_collection(&request)
            .map_err(|e| e.to_string())?;
        if preview.orphan_count != 1
            || preview.orphan_bindings[0].audience() != self.inactive.audience()
        {
            return Err("active GC did not preserve the exact running audience".into());
        }
        let unavailable = WindowsCredentialLifecycle::new(
            format!("{}-missing", lifecycle.service()),
            image,
            state_directory,
        );
        if !matches!(
            unavailable.preview_garbage_collection(&request),
            Err(CredentialLifecycleError::Authority(_))
        ) {
            return Err("missing Authority became an empty GC scope".into());
        }
        self.require_presence(&reopened, true, true)?;
        record_faults(&reopened, state_directory, &request)?;
        let receipt = reopened
            .commit_garbage_collection(
                &CredentialGarbageCollectionCommitRequest::new(request, &preview)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        if receipt.deleted_count != 1 {
            return Err("active GC did not delete only the unused binding".into());
        }
        self.require_presence(&reopened, true, false)
    }
    pub(super) fn after_stop(&self, lifecycle: &WindowsCredentialLifecycle) -> Result<()> {
        let request = catalog()?;
        let preview = lifecycle
            .preview_garbage_collection(&request)
            .map_err(|e| e.to_string())?;
        if preview.orphan_count != 1
            || preview.orphan_bindings[0].audience() != self.active.audience()
        {
            return Err("stopped scope retained or changed the last credential binding".into());
        }
        let result = lifecycle
            .commit_garbage_collection(
                &CredentialGarbageCollectionCommitRequest::new(request, &preview)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        if result.deleted_count != 1 {
            return Err("Off GC did not collect the retired binding".into());
        }
        self.require_presence(lifecycle, false, false)
    }
    fn require_presence(
        &self,
        lifecycle: &WindowsCredentialLifecycle,
        active: bool,
        inactive: bool,
    ) -> Result<()> {
        for (request, expected) in [(&self.active, active), (&self.inactive, inactive)] {
            let observed = lifecycle.presence(request).map_err(|e| e.to_string())?;
            if observed.len() != 1
                || observed[0].reference != request.references()[0]
                || observed[0].present != expected
            {
                return Err("runtime credential presence mismatch".into());
            }
        }
        Ok(())
    }
}
fn catalog() -> Result<CredentialGarbageCollectionRequest> {
    CredentialGarbageCollectionRequest::new("a".repeat(64), vec![]).map_err(|e| e.to_string())
}
fn record_faults(
    lifecycle: &WindowsCredentialLifecycle,
    path: &Path,
    request: &CredentialGarbageCollectionRequest,
) -> Result<()> {
    for fault in 0..3 {
        let directory_path = if fault == 2 {
            path.join("vault")
        } else {
            path.to_owned()
        };
        let filename = if fault == 2 {
            "credentials-v1.dpapi"
        } else {
            RECORD
        };
        let directory = PrivateDirectory::open_existing(&directory_path)
            .map_err(|e| e.to_string())?
            .ok_or("missing runtime credential directory")?;
        let original = directory
            .read()
            .map_err(|e| e.to_string())?
            .read(filename, MAX_RECORD, ReadPolicy::Private)
            .map_err(|e| e.to_string())?
            .ok_or("missing runtime credential record")?
            .bytes;
        let lock = PrivateUserMutex::acquire("runtime-credentials-v1", Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
        {
            let mut transaction = directory.write().map_err(|e| e.to_string())?;
            if fault != 0 {
                transaction.remove(filename, MAX_RECORD, ReadPolicy::Private)
            } else {
                transaction.replace(filename, b"{}", MAX_RECORD)
            }
            .map_err(|e| e.to_string())?;
        }
        lock.release().map_err(|e| e.to_string())?;
        let outcome = lifecycle.preview_garbage_collection(request);
        // Restore before asserting the rejection, even if the negative check fails.
        let lock = PrivateUserMutex::acquire("runtime-credentials-v1", Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
        let restored = directory
            .write()
            .map_err(|e| e.to_string())?
            .replace(filename, &original, MAX_RECORD)
            .map_err(|e| e.to_string());
        let release = lock.release().map_err(|e| e.to_string());
        match (restored, release) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Err(restore), Err(release)) => {
                return Err(format!(
                    "restore runtime credential fault: {restore}; unlock: {release}"
                ));
            }
        }
        match (fault, outcome) {
            (1, Err(CredentialLifecycleError::Unavailable))
            | (0, Err(CredentialLifecycleError::Record))
            | (2, Err(CredentialLifecycleError::ProtectedVaultMissing)) => {}
            (_, Err(error)) => return Err(format!("runtime binding fault rejection: {error}")),
            (_, Ok(_)) => return Err("incomplete runtime binding became an empty GC scope".into()),
        }
    }
    Ok(())
}
