//! Disposable SCM crash/restart with a real SystemProxy owner. Fixture files
//! coordinate the test; only authenticated native channels authorize the runtime.
use super::*;
use cfw_windows_engine::{
    authority::{AuthorityChannel, AuthorityError, WindowsAuthority, wire::Response},
    credential_lifecycle::WindowsCredentialLifecycle,
    user_agent::{
        desktop::{DesktopError, DesktopUserAgent},
        launcher::{LaunchError, UserAgentInvocation, ValidationAgent},
    },
};
mod desktop;
mod recovery;
pub(crate) use desktop::run as desktop;

fn publish(root: &Path, name: &str, value: &serde_json::Value) -> Result<()> {
    let target = root.join(name);
    let partial = target.with_extension("part");
    write_report(&partial, value)?;
    std::fs::hard_link(&partial, &target).map_err(|e| e.to_string())?;
    std::fs::remove_file(partial).map_err(|e| e.to_string())
}
fn read(root: &Path, name: &str) -> Result<serde_json::Value> {
    let file = std::fs::File::open(root.join(name)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("restart fixture receipt exceeded bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

pub(crate) struct Service {
    authority: Option<WindowsAuthority>,
    root: PathBuf,
    path: PathBuf,
    scope: String,
    recovered: bool,
    proxy_observations: usize,
    cleanup_publications: usize,
}
impl Service {
    pub(crate) fn open(name: &str) -> Result<Self> {
        let root = authority_journal::root()?;
        let scope = format!("{name}-restart");
        let path = root.join("restart-authority");
        let mut authority = WindowsAuthority::open(&path, &scope).map_err(|e| e.to_string())?;
        let target = authority
            .recovery_target()
            .ok_or("missing restart metadata")?;
        let recovered = target.root().generation != 0;
        if recovered {
            if authority.snapshot().state != AuthorityState::Recovering
                || authority.lease_owner().is_some()
                || target.state() != AuthorityState::Active
            {
                return Err(
                    "restarted Authority restored execution or lost Active metadata".into(),
                );
            }
            let processes = match authority.observe_runtime_processes() {
                Ok(observed) => authority_wire::process_report("restart", &observed),
                Err(AuthorityError::RuntimeJob(
                    cfw_windows_engine::authority::RuntimeJobError::Unavailable,
                )) => serde_json::json!({"state":"unavailable","processes_retired":false}),
                Err(error) => return Err(error.to_string()),
            };
            // The Agent may already have cleaned up before SCM starts the new
            // process. A missing name remains unknown, never a count of zero.
            publish(
                &root,
                "runtime-restart-recovered.json",
                &serde_json::json!({
                    "service_pid":std::process::id(), "snapshot":authority.snapshot(),
                    "metadata":authority.recovery_target(), "lease_restored":false,
                    "processes":processes,
                }),
            )?;
        } else {
            if target.root().epoch != 0 || target.revision() != 1 || target.operation().is_some() {
                return Err("restart fixture initial journal was not fresh enrollment".into());
            }
            // Fresh disposable fixture enrollment only. A reopened runtime must
            // never take this branch or receive injected global-Off evidence.
            authority
                .reconcile_off(CleanupEvidence::for_validation(1, None, true))
                .map_err(|e| e.to_string())?;
        }
        Ok(Self {
            authority: Some(authority),
            root,
            path,
            scope,
            recovered,
            proxy_observations: 0,
            cleanup_publications: 0,
        })
    }
    pub(crate) fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
    ) -> Result<(AuthorizedReply, bool)> {
        let command = Request::decode(request.body()).map_err(|e| e.to_string())?;
        let ready = matches!(command.command(), Command::Ready(_));
        let observe_retired =
            self.recovered && matches!(command.command(), Command::ReadRuntimeScope);
        let expected_recovery_rejection =
            self.recovered && matches!(command.command(), Command::ReserveGeneration(_));
        drop(command);
        let authority = self
            .authority
            .as_mut()
            .ok_or("restart authority already closed")?;
        let reply = authority
            .handle(connection, request, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?;
        if let Some(observed) = reply.proxy_recovery_observation() {
            if !self.recovered || authority.lease_owner().is_some() {
                return Err("recovery observation was repeated or granted execution".into());
            }
            match observed.context().purpose() {
                cfw_windows_engine::authority::ProxyRecoveryPurpose::Observe => {
                    if self.proxy_observations != 0
                        || authority.snapshot().state != AuthorityState::Recovering
                    {
                        return Err("observation alone changed recovery policy".into());
                    }
                    self.proxy_observations += 1;
                    publish(
                        &self.root,
                        "runtime-restart-proxy-recovery.json",
                        &serde_json::json!({
                            "context":observed.context(),
                            "processes":authority_wire::process_report("proxy_recovery", observed.processes()),
                            "recorded_process_id":observed.recorded_process_id(),
                            "recorded_process_creation_time":observed.recorded_process_creation_time(),
                            "snapshot":authority.snapshot(), "lease_restored":false,
                        }),
                    )?;
                }
                cfw_windows_engine::authority::ProxyRecoveryPurpose::ReconcileOff => {
                    if self.proxy_observations != 1
                        || self.cleanup_publications != 0
                        || authority.snapshot().state != AuthorityState::Off
                        || authority.snapshot().revision
                            != observed.context().target().revision.checked_add(1)
                        || authority.recovery_target().is_none_or(|state| {
                            state.operation().is_some() || state.state() != AuthorityState::Off
                        })
                    {
                        return Err(
                            "production cleanup did not commit exact Off without a lease".into(),
                        );
                    }
                    self.cleanup_publications += 1;
                    publish(
                        &self.root,
                        "runtime-restart-cleanup.json",
                        &serde_json::json!({
                            "context":observed.context(),
                            "processes":authority_wire::process_report("cleanup", observed.processes()),
                            "snapshot":authority.snapshot(),"metadata":authority.recovery_target(),
                            "production_cleanup_evidence":true,"lease_restored":false,
                        }),
                    )?;
                }
            }
        }
        if ready && reply.rejection().is_none() {
            if self.recovered {
                return Err("restarted service authorized Ready".into());
            }
            publish(
                &self.root,
                "runtime-restart-before.json",
                &serde_json::json!({
                    "service_pid":std::process::id(), "snapshot":authority.snapshot(),
                    "metadata":authority.recovery_target(),
                }),
            )?;
        }
        if expected_recovery_rejection
            && !matches!(reply.rejection(), Some(AuthorityError::Recovering))
        {
            return Err("restarted service did not reject allocation as Recovering".into());
        }
        if observe_retired && reply.rejection().is_none() {
            // The Desktop has retained and observed the Agent and engine exits.
            // Independently wait for every member of the exact SYSTEM Job;
            // a missing Job remains an error, never an implicit zero count.
            let deadline = Instant::now() + Duration::from_secs(3);
            let observed = loop {
                let observed = authority
                    .observe_runtime_processes()
                    .map_err(|e| e.to_string())?;
                if matches!(
                    observed.state(),
                    cfw_windows_engine::authority::RuntimeProcessState::Accounting {
                        active: 0,
                        ..
                    }
                ) {
                    break observed;
                }
                if Instant::now() >= deadline {
                    return Err("restarted service could not prove whole-Job retirement".into());
                }
                thread::sleep(Duration::from_millis(10));
            };
            publish(
                &self.root,
                "runtime-restart-retired.json",
                &authority_wire::process_report("retired", &observed),
            )?;
        }
        Ok((reply, expected_recovery_rejection))
    }
    pub(crate) fn finish(&mut self) -> Result<()> {
        if !self.recovered || self.proxy_observations != 1 || self.cleanup_publications != 1 {
            return Err(
                "restart fixture did not restart and admit exactly one proxy observation".into(),
            );
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.authority.take();
        // This removes only disposable test assets after the coordinator has
        // joined the clients. A killed service cannot execute this cleanup.
        if let Err(error) = authority_journal::cleanup(&self.path, &self.scope) {
            SERVICE_EXIT.store(1, Ordering::SeqCst);
            if let Err(record) =
                record_service_failure(&format!("restart fixture cleanup: {error}"))
            {
                eprintln!("restart fixture cleanup ({error}); recording failed ({record})");
            }
        }
    }
}

pub(crate) fn exercise(
    service: &mut Installed,
    root: &Path,
    name: &str,
    digest: [u8; 32],
) -> Result<()> {
    thread::scope(|scope| {
        let image = root.join("desktop-fixture.exe");
        let worker = scope.spawn(move || restricted::run_restart_desktop(&image, name, digest));
        let crash = (|| {
            let deadline = Instant::now() + Duration::from_secs(40);
            while !root
                .join("runtime-restart-request.json")
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                if worker.is_finished() {
                    return Err("restart Desktop exited before its crash request".into());
                }
                if Instant::now() >= deadline {
                    return Err("restart Desktop did not request service crash".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            let request = read(root, "runtime-restart-request.json")?;
            let before = read(root, "runtime-restart-before.json")?;
            if request["context"]["operation"]["root"] != before["snapshot"]["root"]
                || before["snapshot"]["state"] != "active"
            {
                return Err("crash request did not match the committed Active runtime".into());
            }
            let (old, new) = crash_restart(service)?;
            let recovered = read(root, "runtime-restart-recovered.json")?;
            if before["service_pid"] != old
                || recovered["service_pid"] != new
                || before["metadata"] != recovered["metadata"]
                || recovered["snapshot"]["state"] != "recovering"
                || recovered["lease_restored"] != false
            {
                return Err(
                    "SCM restart did not retain exact operation metadata without a lease".into(),
                );
            }
            publish(
                root,
                "runtime-restart-complete.json",
                &serde_json::json!({
                    "old_service_pid":old,"new_service_pid":new,
                    "old_process_exit_observed":true,"different_process_object":true,
                    "same_durable_runtime":true,"recovery_lease_restored":false,
                }),
            )
        })();
        let client = worker
            .join()
            .map_err(|_| "restart Desktop coordinator panicked")?;
        match (crash, client) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(crash), Err(client)) => Err(format!("{crash}; restart Desktop: {client}")),
        }
    })
}
fn crash_restart(service: &mut Installed) -> Result<(u32, u32)> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("service crash requires disposable CI opt-in".into());
    }
    let status = service.query()?;
    let old = service
        .process
        .as_ref()
        .ok_or("missing retained original service process")?;
    if status.dwCurrentState != SERVICE_RUNNING
        || status.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || status.dwProcessId != unsafe { GetProcessId(old.as_raw_handle()) }
    {
        return Err("disposable service no longer matches its retained process".into());
    }
    let identity = NativePeerProcess::open(status.dwProcessId).map_err(|e| e.to_string())?;
    if !identity.identity().is_local_system() || identity.identity().session_id() != 0 {
        return Err("crash target is not the admitted SYSTEM service".into());
    }
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            status.dwProcessId,
        )
    };
    if raw.is_null() {
        return Err(error("open disposable service for crash"));
    }
    let target = unsafe { OwnedHandle::from_raw_handle(raw) };
    let current = NativePeerProcess::open(status.dwProcessId).map_err(|e| e.to_string())?;
    if current.identity() != identity.identity()
        || unsafe { WaitForSingleObject(target.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err("service crash target identity or liveness changed".into());
    }
    if unsafe { CompareObjectHandles(old.as_raw_handle(), target.as_raw_handle()) } == 0 {
        return Err("service crash target process object changed".into());
    }
    const EXIT: u32 = 0xcf01;
    if unsafe { TerminateProcess(target.as_raw_handle(), EXIT) } == 0 {
        return Err(error("crash disposable service"));
    }
    require_exit(old)?;
    let mut code = 0;
    if unsafe { GetExitCodeProcess(old.as_raw_handle(), &mut code) } == 0 {
        return Err(error("read crashed service exit code"));
    }
    if code != EXIT {
        return Err("service exit did not match the injected crash".into());
    }
    service.wait(SERVICE_STOPPED)?;
    if unsafe { StartServiceW(service.handle.0, 0, null()) } == 0 {
        return Err(error("restart disposable service"));
    }
    service.wait(SERVICE_RUNNING)?;
    let new_pid = service.query()?.dwProcessId;
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            new_pid,
        )
    };
    if raw.is_null() {
        return Err(error("retain restarted service"));
    }
    let new = unsafe { OwnedHandle::from_raw_handle(raw) };
    if unsafe { CompareObjectHandles(old.as_raw_handle(), new.as_raw_handle()) } != 0 {
        return Err("SCM reused the original process object".into());
    }
    let new_identity = NativePeerProcess::open(new_pid).map_err(|e| e.to_string())?;
    if !new_identity.identity().is_local_system() || new_identity.identity().session_id() != 0 {
        return Err("restarted service identity differs".into());
    }
    service.process = Some(new);
    Ok((status.dwProcessId, new_pid))
}
fn require_exit(handle: &OwnedHandle) -> Result<()> {
    if cfw_windows_storage::wait_until(handle, Instant::now() + LIMIT).map_err(|e| e.to_string())?
        != cfw_windows_storage::WaitOutcome::Signaled
    {
        return Err("retained restart process did not exit".into());
    }
    Ok(())
}

pub(crate) fn agent_report() -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,
        "actual_system_proxy_runtime":true,"product_operation_succeeded":false,
        "control_loss_preserved":true,"local_cleanup_observed":true,
        "durable_runtime_storage":true,"durable_proxy_restoration_record":true,"original_proxy_restored":true,"stopped_acknowledged":false})
}
pub(crate) fn desktop_report() -> serde_json::Value {
    serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,
        "actual_http_proxy_traffic":true,"product_operation_succeeded":false,
        "held_agent_and_engine_exit_observed":true,"restoration_observed_after_agent_exit":true,"original_proxy_restored":true,
        "listeners_released":true,"restart_recovering_observed":true,
        "new_execution_rejected":true,"full_service_backend_proven":false})
}
pub(crate) fn receipt(root: &Path, receipts: &Path, source: &str) -> Result<()> {
    let before = read(root, "runtime-restart-before.json")?;
    let recovered = read(root, "runtime-restart-recovered.json")?;
    let restart = read(root, "runtime-restart-complete.json")?;
    let retired = read(root, "runtime-restart-retired.json")?;
    let proxy_recovery = read(root, "runtime-restart-proxy-recovery.json")?;
    let proxy_recovery_observer = read(root, "runtime-restart-proxy-recovery-observer.json")?;
    let cleanup = read(root, "runtime-restart-cleanup.json")?;
    let cleanup_observer = read(root, "runtime-restart-cleanup-observer.json")?;
    if before["metadata"] != recovered["metadata"] {
        return Err("restart metadata changed".into());
    }
    write_report(
        &receipts.join("runtime-restart-receipt.json"),
        &serde_json::json!({
        "product_source":source,"before":before,"recovered":recovered,"restart":restart,"retired":retired,
            "proxy_recovery":proxy_recovery,"proxy_recovery_observer":proxy_recovery_observer,
            "cleanup":cleanup,"cleanup_observer":cleanup_observer,
            "desktop":desktop_report(),"agent":agent_report(),"temporary_service_removed":true,
            "global_cleanup_proven":true,"release_accepted":false,
        }),
    )
}

fn transport_loss(error: &ServiceTransportError) -> bool {
    match error {
        ServiceTransportError::Closed => true,
        ServiceTransportError::Io(error) => matches!(error.raw_os_error(), Some(109 | 232 | 233)),
        ServiceTransportError::Endpoint(
            ServicePeerError::Exited
            | ServicePeerError::NotRunning { .. }
            | ServicePeerError::WrongProcess,
        )
        | ServiceTransportError::Endpoint(ServicePeerError::ServiceIdentity(
            cfw_windows_engine::PeerIdentityError::Exited,
        )) => true,
        ServiceTransportError::Cleanup { operation, cleanup } => {
            transport_loss(operation) && transport_loss(cleanup)
        }
        _ => false,
    }
}
pub(super) fn agent_control_loss(error: &UserAgentError) -> bool {
    match error {
        UserAgentError::Control(error) => {
            matches!(&**error, ControlError::Wire(WireError::Transport(error)) if transport_loss(error))
        }
        UserAgentError::Cleanup { operation, cleanup } => {
            (agent_control_loss(operation) && agent_loss_auxiliary(cleanup))
                || (agent_control_loss(cleanup) && agent_loss_auxiliary(operation))
        }
        _ => false,
    }
}
fn agent_loss_auxiliary(error: &UserAgentError) -> bool {
    agent_control_loss(error)
        || matches!(
            error,
            UserAgentError::Cancelled
                | UserAgentError::Engine(cfw_windows_engine::Error::Cancelled)
        )
}
