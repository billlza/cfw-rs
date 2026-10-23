//! Native Desktop wiring shared by the application backend and installed
//! lifecycle validation. No caller supplies a service name, executable or
//! private storage path. These synchronous operations belong on a worker.
use super::*;
use crate::{
    CheckedConfiguration, CheckedStartConfiguration, EngineProcess, ServiceClientRole,
    WindowsEngineGenerationStore,
    authority::{
        AuthorityChannel, AuthoritySnapshot,
        wire::{Command, Request, Response},
    },
    credential_lifecycle::WindowsCredentialLifecycle,
    user_agent::{UserRuntimeStorage, desktop::DesktopUserAgent},
};
use cfw_engine_api::EngineStartRequest;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub struct InstalledDesktop {
    installation: InstalledRuntime,
    paths: UserPaths,
    // Held without write/delete sharing for the entire desktop lifetime. The
    // service image below has a different role and cannot admit this process.
    desktop_image: crate::VerifiedExecutable,
    image: Arc<crate::VerifiedExecutable>,
    credentials: WindowsCredentialLifecycle,
    generations: WindowsEngineGenerationStore,
    storage: UserRuntimeStorage,
}
impl InstalledDesktop {
    pub fn open() -> Result<Self> {
        let installation = InstalledRuntime::open()?;
        let desktop_image = installation.desktop()?;
        crate::NativePeerProcess::open(std::process::id())?.verify_executable(&desktop_image)?;
        let paths = installation.user_paths()?;
        let image = Arc::new(installation.runtime()?);
        let credentials = WindowsCredentialLifecycle::new(
            SERVICE_NAME.into(),
            Arc::clone(&image),
            &paths.credentials,
        );
        let generations =
            WindowsEngineGenerationStore::new(SERVICE_NAME.into(), Arc::clone(&image));
        let storage = UserRuntimeStorage::open(&paths.runtime)?;
        Ok(Self {
            installation,
            paths,
            desktop_image,
            image,
            credentials,
            generations,
            storage,
        })
    }
    pub fn credentials(&self) -> &WindowsCredentialLifecycle {
        &self.credentials
    }
    pub fn generations(&self) -> &WindowsEngineGenerationStore {
        &self.generations
    }
    pub fn storage(&self) -> &UserRuntimeStorage {
        &self.storage
    }
    pub fn paths(&self) -> &UserPaths {
        &self.paths
    }
    fn require_current_process(&self) -> Result<()> {
        // Re-observe the live process and exact file identity on every call.
        // Rehashing an immutable, already retained image on every status poll
        // adds file-size-dependent work to a two-second observation boundary.
        crate::NativePeerProcess::open(std::process::id())?
            .verify_executable(&self.desktop_image)?;
        Ok(())
    }

    #[cfg(feature = "native-service-validation")]
    pub fn desktop_identity_timing_for_validation(&self) -> Result<serde_json::Value> {
        let mut samples = Vec::with_capacity(3);
        for _ in 0..3 {
            let start = Instant::now();
            self.installation.require_desktop_process()?;
            let fresh_micros = start.elapsed().as_micros();
            let start = Instant::now();
            self.require_current_process()?;
            let retained_micros = start.elapsed().as_micros();
            samples.push(
                serde_json::json!({"fresh_hash_and_identity_micros":fresh_micros,
                "retained_file_identity_micros":retained_micros}),
            );
        }
        Ok(
            serde_json::json!({"image_bytes":std::fs::metadata(self.desktop_image.path())?.len(),
            "fresh_and_retained_identity_checks_passed":true,"samples":samples,
            "status_timeout_changed":false,"release_accepted":false}),
        )
    }
    /// Read-only authorization before a shared application mode transition.
    /// An owned proxy may be restored; a foreign proxy or changed journal is
    /// never taken over. Activation still rechecks policy under its own lock.
    pub(crate) fn authorize_system_proxy(&self, restoration_only: bool) -> Result<()> {
        self.require_current_process()?;
        crate::user_agent::launcher::medium_process()?;
        self.storage.proxy().authorize(restoration_only)?;
        Ok(())
    }
    pub(crate) fn test_profile_delays(
        &self,
        request: cfw_engine_api::ProfileDelayTestRequest,
        cancellation: Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
    ) -> Result<Vec<cfw_engine_api::ProfileProxyDelay>> {
        let candidate = crate::CheckedProbeConfiguration::new(request)?;
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        remaining(deadline)?;
        self.require_current_process()?;
        crate::user_agent::launcher::medium_process()?;
        let lock = cfw_windows_storage::PrivateUserMutex::acquire(
            "profile-probe-v1",
            remaining(deadline)?.min(Duration::from_secs(3)),
        )?;
        let result = (|| -> Result<Vec<cfw_engine_api::ProfileProxyDelay>> {
            if cancellation.load(std::sync::atomic::Ordering::Acquire) {
                return Err(crate::Error::Cancelled.into());
            }
            remaining(deadline)?;
            let material = self
                .credentials
                .resolve_probe_material(&candidate, deadline)?;
            let resolved = candidate.resolve(material.expose_to_engine())?;
            drop(material);
            let worker = EngineProcess::spawn_cancellable(
                self.installation.engine()?,
                &self.paths.runtime.join("probe-engine-v1"),
                remaining(deadline)?,
                Some(cancellation),
            )?;
            Ok(worker.probe_until(&resolved, deadline)?)
        })();
        let released = lock.release().map_err(HostError::from);
        match (result, released) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(HostError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
    pub(crate) fn observe_authority(&self, deadline: Instant) -> Result<AuthoritySnapshot> {
        self.require_current_process()?;
        let mut channel = AuthorityChannel::connect(
            SERVICE_NAME,
            ServiceClientRole::Desktop,
            Arc::clone(&self.image),
        )
        .map_err(crate::LineageError::from)?;
        match channel
            .request(
                Request::new(Command::Observe).map_err(crate::LineageError::from)?,
                deadline.min(Instant::now() + Duration::from_secs(5)),
            )
            .map_err(crate::LineageError::from)?
        {
            Response::Observed(snapshot) => Ok(snapshot),
            _ => Err(HostError::State("Authority omitted its status observation")),
        }
    }

    pub fn prepare_proxy(
        &self,
        request: EngineStartRequest,
        deadline: Instant,
    ) -> Result<DesktopUserAgent> {
        let request = CheckedStartConfiguration::new(request)?;
        self.prepare_checked_run(request, deadline)
    }
    pub(crate) fn prepare_checked_run(
        &self,
        request: CheckedStartConfiguration,
        deadline: Instant,
    ) -> Result<DesktopUserAgent> {
        self.require_current_process()?;
        Ok(DesktopUserAgent::prepare_checked(
            &self.credentials,
            Arc::clone(&self.image),
            request,
            deadline,
        )?)
    }

    /// Native parser/constructor/Close validation, including Tunnel candidates.
    /// No Prepare/Bind/Ready command, generation reservation, engine start or
    /// WinINet mutation occurs here. Resolved material is never returned to UI.
    /// Success includes worker exit, empty Job and retired control I/O.
    pub fn check_configuration(
        &self,
        request: EngineStartRequest,
        deadline: Instant,
    ) -> Result<CheckedConfiguration> {
        let candidate = CheckedStartConfiguration::new(request)?;
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        remaining(deadline)?;
        self.require_current_process()?;
        crate::user_agent::launcher::medium_process()?;
        let lineage = self.generations.load_lineage_until(deadline)?;
        if candidate.context().installation_id != lineage.session.installation_id
            || candidate.context().config_epoch != lineage.session.config_epoch
        {
            return Err(HostError::State(
                "candidate belongs to another installation or epoch",
            ));
        }
        // One fixed check directory per user. The kernel mutex bounds native
        // concurrency across Desktop processes without extending runtime leases.
        let lock = cfw_windows_storage::PrivateUserMutex::acquire(
            "configuration-check-v1",
            remaining(deadline)?.min(Duration::from_secs(3)),
        )?;
        let result = (|| -> Result<CheckedConfiguration> {
            remaining(deadline)?;
            let material = self
                .credentials
                .resolve_candidate_material(&candidate, deadline)?;
            let resolved = candidate.resolve(material.expose_to_engine())?;
            drop(material);
            let executable = self.installation.engine()?;
            let worker = EngineProcess::spawn(
                executable,
                &self.paths.runtime.join("check-engine-v1"),
                remaining(deadline)?,
            )?;
            // An expired deadline after launch still performs explicit child
            // retirement and preserves cleanup failure alongside the timeout.
            Ok(worker.check_until(&resolved, deadline)?)
        })();
        let released = lock.release().map_err(HostError::from);
        match (result, released) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(HostError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .map(|left| left.min(Duration::from_secs(15)))
        .ok_or_else(|| crate::Error::Timeout.into())
}
