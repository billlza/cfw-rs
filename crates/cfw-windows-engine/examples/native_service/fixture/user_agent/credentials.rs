use super::*;
use cfw_engine_api::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionRequest,
    CredentialPresenceRequest, CredentialProvision, CredentialProvisionRequest,
    CredentialRebindRequest, CredentialSecret, CredentialVaultError, CredentialVaultProvisioner,
};
use cfw_windows_engine::credential_lifecycle::WindowsCredentialLifecycle;
use cfw_windows_storage::{PrivateDirectory, PrivateUserMutex, ReadPolicy};

pub(super) const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const RECORD: &str = "runtime-bindings-v1.json";
const MAX_RECORD: usize = 2 * 1024 * 1024;
pub(super) fn outbound() -> serde_json::Value {
    serde_json::json!({"type":"trojan","tag":"gc-protected","server":"unused.example.com","server_port":443,"credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"unused.example.com"}})
}
pub(super) struct Fixture {
    runtime: tokio::runtime::Runtime,
    active: CredentialPresenceRequest,
    inactive: CredentialPresenceRequest,
    before_start: CredentialGarbageCollectionCommitRequest,
}
impl Fixture {
    pub(super) fn new(
        lifecycle: &WindowsCredentialLifecycle,
        active: &ValidatedSingBoxProfile,
    ) -> Result<Self> {
        let runtime = runtime()?;
        let mut other: serde_json::Value =
            serde_json::from_str(active.as_json()).map_err(|e| e.to_string())?;
        other["route"] = serde_json::json!({"final":"direct","rules":[{"type":"domain","value":"unused.internal.example","outbound":"direct"}]});
        let other =
            ValidatedSingBoxProfile::parse(&other.to_string()).map_err(|e| e.to_string())?;
        let references = active.credential_references();
        if references.len() != 1 {
            return Err("credential runtime fixture expected one reference".into());
        }
        let request = CredentialProvisionRequest::new(
            PROFILE,
            active,
            vec![CredentialProvision::new(
                &references[0],
                CredentialSecret::new("fixture-runtime-secret").map_err(|e| e.to_string())?,
            )],
        )
        .map_err(|e| e.to_string())?;
        runtime
            .block_on(lifecycle.provision_profile_credentials(request))
            .map_err(|e| e.to_string())?;
        let rebind =
            CredentialRebindRequest::new(PROFILE, active, &other, &EngineSettings::default())?;
        let receipt = runtime
            .block_on(lifecycle.rebind_profile_credentials(rebind))
            .map_err(|e| e.to_string())?;
        if receipt.profile_id != PROFILE || receipt.profile_digest != other.digest() {
            return Err("async rebind returned a different audience".into());
        }
        let empty = catalog()?;
        let preview = runtime
            .block_on(lifecycle.preview_credential_garbage_collection(empty.clone()))
            .map_err(|e| e.to_string())?;
        if preview.orphan_count != 2 {
            return Err("Off GC did not observe two distinct profile-digest bindings".into());
        }
        Ok(Self {
            runtime,
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
        match self
            .runtime
            .block_on(lifecycle.commit_credential_garbage_collection(self.before_start.clone()))
        {
            Err(CredentialVaultError::ConcurrentModification) => {}
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
        let preview = self
            .runtime
            .block_on(reopened.preview_credential_garbage_collection(request.clone()))
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
            self.runtime
                .block_on(unavailable.preview_credential_garbage_collection(request.clone())),
            Err(CredentialVaultError::Unavailable)
        ) {
            return Err("missing Authority became an empty GC scope".into());
        }
        self.require_presence(&reopened, true, true)?;
        record_faults(&reopened, state_directory, &request, &self.runtime)?;
        let receipt = self
            .runtime
            .block_on(
                reopened.commit_credential_garbage_collection(
                    CredentialGarbageCollectionCommitRequest::new(request, &preview)
                        .map_err(|e| e.to_string())?,
                ),
            )
            .map_err(|e| e.to_string())?;
        if receipt.deleted_count != 1 {
            return Err("active GC did not delete only the unused binding".into());
        }
        self.require_presence(&reopened, true, false)
    }
    pub(super) fn after_stop(&self, lifecycle: &WindowsCredentialLifecycle) -> Result<()> {
        let request = catalog()?;
        let preview = self
            .runtime
            .block_on(lifecycle.preview_credential_garbage_collection(request.clone()))
            .map_err(|e| e.to_string())?;
        if preview.orphan_count != 1
            || preview.orphan_bindings[0].audience() != self.active.audience()
        {
            return Err("stopped scope retained or changed the last credential binding".into());
        }
        let result = self
            .runtime
            .block_on(
                lifecycle.commit_credential_garbage_collection(
                    CredentialGarbageCollectionCommitRequest::new(request, &preview)
                        .map_err(|e| e.to_string())?,
                ),
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
            let observed = self
                .runtime
                .block_on(lifecycle.query_profile_credentials(request.clone()))
                .map_err(|e| e.to_string())?;
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
    runtime: &tokio::runtime::Runtime,
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
        let outcome =
            runtime.block_on(lifecycle.preview_credential_garbage_collection(request.clone()));
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
            (1, Err(CredentialVaultError::Unavailable))
            | (0, Err(CredentialVaultError::Corrupt))
            | (2, Err(CredentialVaultError::Corrupt)) => {}
            (_, Err(error)) => return Err(format!("runtime binding fault rejection: {error}")),
            (_, Ok(_)) => return Err("incomplete runtime binding became an empty GC scope".into()),
        }
    }
    Ok(())
}
