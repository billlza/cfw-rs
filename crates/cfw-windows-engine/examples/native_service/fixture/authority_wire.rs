//! Actual desktop -> SYSTEM dispatcher -> restricted UserAgent protocol path.
//! Runtime readiness/stop reports and cleanup observations are synthetic here;
//! this validates native ownership, not an engine or OS-cleanup implementation.
use super::*;
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext};
use cfw_windows_engine::authority::{
    AuthorityChannel, AuthorityError, AuthorizedReply, CleanupEvidence, PrepareRequest,
    ReadyReport, RuntimeProcessObservation, RuntimeProcessState, StoppedReport, WindowsAuthority,
    wire::{
        BindRequest, Command, MAX_MESSAGE_BYTES, Rejection, Request, Response, StopRequest,
        TicketMaterial, WireError,
    },
};
use cfw_windows_engine::{AuthenticatedServiceRequest, LocalServiceConnection};
use std::io::{Read, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(super) struct Validation {
    scoped: Option<Scoped>,
    complete: bool,
}
pub(super) struct Scoped {
    pub(super) controller: Option<WindowsAuthority>,
    path: PathBuf,
    scope: String,
    requests: usize,
    cleaned: bool,
}
impl Scoped {
    pub(super) fn new() -> Result<Self> {
        cfw_windows_engine::authority::validate_runtime_job_failures_for_validation()
            .map_err(|e| e.to_string())?;
        let scope = format!("CFW-authority-wire-{}", uuid::Uuid::new_v4());
        let path = authority_journal::root()?.join(&scope);
        let mut value = Self {
            controller: None,
            path,
            scope,
            requests: 0,
            cleaned: false,
        };
        let mut controller =
            WindowsAuthority::open(&value.path, &value.scope).map_err(|e| e.to_string())?;
        assert_eq!(controller.snapshot().state, AuthorityState::Recovering);
        verify_initial_off(&mut controller, &value.scope)?;
        value.controller = Some(controller);
        Ok(value)
    }
    pub(super) fn cleanup(&mut self) -> Result<()> {
        self.cleaned = true;
        self.controller = None;
        authority_journal::cleanup(&self.path, &self.scope)
    }
    pub(super) fn verify_reopen_with_live_runtime(
        &mut self,
        minimum: u32,
    ) -> Result<RuntimeProcessObservation> {
        self.controller
            .as_mut()
            .ok_or("missing original controller")?
            .release_runtime_job_observer_for_validation()
            .map_err(|e| e.to_string())?;
        // All service handles are gone. The production transferred reference
        // (or the actual engine's inherited copy) must retain this exact name.
        let mut recovered =
            WindowsAuthority::open(&self.path, &self.scope).map_err(|e| e.to_string())?;
        assert_eq!(recovered.snapshot().state, AuthorityState::Recovering);
        let observation = require_live_runtime(&mut recovered, minimum)?;
        assert!(recovered.lease_owner().is_none());
        assert!(matches!(
            recovered.verify_recorded_off(),
            Err(AuthorityError::CleanupUnproven)
        ));
        assert_eq!(recovered.snapshot().state, AuthorityState::Recovering);
        self.controller
            .as_mut()
            .ok_or("missing original controller")?
            .restore_runtime_job_observer_for_validation()
            .map_err(|e| e.to_string())?;
        Ok(observation)
    }
}
pub(super) fn verify_initial_off(controller: &mut WindowsAuthority, name: &str) -> Result<()> {
    let admission = controller
        .verify_recorded_off()
        .map_err(|e| e.to_string())?;
    if admission.processes().state() != RuntimeProcessState::NoRuntimeRoot
        || admission.snapshot().state != AuthorityState::Off
        || admission.snapshot().revision != Some(admission.prior().revision())
        || admission.prior().operation().is_some()
        || controller.lease_owner().is_some()
    {
        return Err(
            "initial production Off admission did not preserve an unused installation".into(),
        );
    }
    let report = serde_json::json!({
        "prior":admission.prior(),"processes":process_report("startup", admission.processes()),
        "snapshot":admission.snapshot(),"production_admission":true,"lease_restored":false,
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(authority_journal::root()?.join(format!("{name}.off-admission.json")))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&report).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
impl Drop for Scoped {
    fn drop(&mut self) {
        if !self.cleaned
            && let Err(error) = self.cleanup()
        {
            SERVICE_EXIT.store(1, Ordering::SeqCst);
            if let Err(record) = record_service_failure(&format!("authority wire cleanup: {error}"))
            {
                eprintln!("authority wire cleanup failed ({error}); recording failed ({record})");
            }
        }
    }
}
impl Validation {
    pub(super) fn new() -> Self {
        Self {
            scoped: None,
            complete: false,
        }
    }
    pub(super) fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
    ) -> Result<AuthorizedReply> {
        if self.complete {
            return Err("authority wire fixture already completed".into());
        }
        if self.scoped.is_none() {
            self.scoped = Some(Scoped::new()?);
        }
        let scoped = self.scoped.as_mut().ok_or("missing wire fixture scope")?;
        let controller = scoped
            .controller
            .as_mut()
            .ok_or("missing wire fixture controller")?;
        let reply = controller
            .handle(connection, request, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?;
        let expected = [
            (AuthorityState::Off, 1, None),
            (AuthorityState::Off, 1, None),
            (AuthorityState::Off, 2, None),
            (AuthorityState::Off, 2, Some(Rejection::Stale)),
            (AuthorityState::Preparing, 3, None),
            (AuthorityState::Preparing, 3, None),
            (AuthorityState::Preparing, 3, Some(Rejection::Identity)),
            (AuthorityState::Preparing, 3, Some(Rejection::Identity)),
            (AuthorityState::Preparing, 3, Some(Rejection::Ticket)),
            (AuthorityState::Starting, 4, None),
            (AuthorityState::Starting, 4, Some(Rejection::Identity)),
            (AuthorityState::Starting, 4, None),
            (AuthorityState::Starting, 4, Some(Rejection::Identity)),
            (AuthorityState::Starting, 4, Some(Rejection::Identity)),
            (AuthorityState::Active, 5, None),
            (AuthorityState::Active, 5, None),
            (AuthorityState::Active, 5, None),
            (AuthorityState::Stopping, 6, None),
            (AuthorityState::Stopping, 6, Some(Rejection::Identity)),
            (AuthorityState::Stopping, 6, None),
            (AuthorityState::Stopping, 6, None),
            (AuthorityState::Stopping, 6, None),
        ];
        let (phase, revision, rejection) = expected
            .get(scoped.requests)
            .ok_or("unexpected wire fixture request")?;
        assert_eq!(controller.snapshot().state, *phase);
        assert_eq!(controller.snapshot().revision, Some(*revision));
        match (reply.rejection(), rejection) {
            (None, None)
            | (Some(AuthorityError::Ticket), Some(Rejection::Ticket))
            | (Some(AuthorityError::Stale), Some(Rejection::Stale))
            | (Some(AuthorityError::Identity), Some(Rejection::Identity)) => {}
            (Some(error), _) => {
                return Err(format!("unexpected native authority rejection: {error}"));
            }
            (None, Some(_)) => {
                return Err("native authority admitted a rejected fixture command".into());
            }
        }
        scoped.requests += 1;
        if scoped.requests == 10 {
            scoped.verify_reopen_with_live_runtime(1)?;
        } else if scoped.requests == 20 {
            require_live_runtime(
                scoped
                    .controller
                    .as_mut()
                    .ok_or("missing stopped controller")?,
                1,
            )?;
        }
        Ok(reply)
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        if self.complete {
            return Err("duplicate wire fixture finish".into());
        }
        let scoped = self.scoped.as_mut().ok_or("missing wire fixture scope")?;
        if scoped.requests != 22 {
            return Err("wire fixture command sequence incomplete".into());
        }
        let controller = scoped
            .controller
            .as_mut()
            .ok_or("missing wire fixture controller")?;
        assert_eq!(controller.snapshot().state, AuthorityState::Stopping);
        assert_eq!(controller.snapshot().revision, Some(6));
        let lease = controller
            .cleanup_target()
            .ok_or("stopped report erased native ownership")?
            .lease_id;
        controller
            .reconcile_off(CleanupEvidence::for_validation(6, Some(lease), true))
            .map_err(|e| e.to_string())?;
        assert_eq!(controller.snapshot().state, AuthorityState::Off);
        assert_eq!(controller.snapshot().revision, Some(7));
        scoped.cleanup()?;
        self.complete = true;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(authority_journal::root()?.join("lifecycle.wire-validation.json"))
            .map_err(|e| e.to_string())?;
        output
            .write_all(&serde_json::to_vec(&report()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())
    }
}
fn request(channel: &mut AuthorityChannel, command: Command) -> Result<Response> {
    channel
        .request(
            Request::new(command).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())
}
fn status(response: Response, state: AuthorityState, revision: u64) -> Result<()> {
    match response {
        Response::Observed(snapshot) | Response::Status(snapshot)
            if snapshot.state == state && snapshot.revision == Some(revision) =>
        {
            Ok(())
        }
        _ => Err("unexpected authority wire state/revision".into()),
    }
}
pub(super) fn run(name: &str, image: &Path, digest: [u8; 32]) -> Result<()> {
    let service_image = Arc::new(verified(image, digest)?);
    let mut channel =
        AuthorityChannel::connect(name, ServiceClientRole::Desktop, Arc::clone(&service_image))
            .map_err(|e| e.to_string())?;
    status(
        request(&mut channel, Command::Observe)?,
        AuthorityState::Off,
        1,
    )?;
    let Response::Lineage(initial) = request(&mut channel, Command::LoadLineage)? else {
        return Err("authority did not publish its installation lineage".into());
    };
    assert_eq!(initial.generation, 0);
    let Response::Lineage(allocated) =
        request(&mut channel, Command::ReserveGeneration(initial.clone()))?
    else {
        return Err("authority did not reserve the next generation".into());
    };
    assert_eq!(allocated.generation, 1);
    match channel.request(
        Request::new(Command::ReserveGeneration(initial)).map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Stale)) => {}
        Err(error) => return Err(format!("stale allocation rejection: {error}")),
        Ok(_) => return Err("stale generation allocation was accepted".into()),
    }
    let Response::Prepared(prepared) = request(
        &mut channel,
        Command::Prepare(PrepareRequest {
            root: RootContext {
                installation_id: allocated.installation_id,
                epoch: allocated.config_epoch,
                generation: allocated.generation,
            },
            operation_id: uuid::Uuid::new_v4(),
            mode: AuthorityMode::SystemProxy,
            config_sha256: [3; 32],
            identity_sha256: [4; 32],
            expected_revision: 2,
        }),
    )?
    else {
        return Err("prepare did not return a grant".into());
    };
    let context = prepared.context().clone();
    let mut observer =
        AuthorityChannel::connect(name, ServiceClientRole::Desktop, Arc::clone(&service_image))
            .map_err(|e| e.to_string())?;
    let Response::RuntimeScope(recorded) = request(&mut observer, Command::ReadRuntimeScope)?
    else {
        return Err("new Desktop connection did not receive the recorded scope".into());
    };
    assert_eq!(recorded.snapshot().state, AuthorityState::Preparing);
    assert_eq!(recorded.snapshot().revision, Some(3));
    assert_eq!(
        recorded.snapshot().root.as_ref(),
        Some(&context.operation.root)
    );
    let operation = recorded
        .operation()
        .ok_or("prepared scope omitted its operation")?;
    assert_eq!(operation.operation_id(), context.operation.operation_id);
    assert_eq!(operation.lease_id(), context.lease_id);
    assert_eq!(operation.mode(), context.operation.mode);
    assert_eq!(operation.config_sha256(), &context.operation.config_sha256);
    assert_eq!(
        operation.identity_sha256(),
        &context.operation.identity_sha256
    );
    assert_eq!(operation.owner(), &context.operation.owner);
    for command in [
        Command::OwnedLease,
        Command::BeginStop(StopRequest {
            context: context.clone(),
            expected_revision: 3,
        }),
    ] {
        match observer.request(
            Request::new(command).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        ) {
            Err(WireError::Rejected(Rejection::Identity)) => {}
            Err(error) => {
                return Err(format!(
                    "recorded scope observer control rejection: {error}"
                ));
            }
            Ok(_) => return Err("recorded scope observer acquired lease control".into()),
        }
    }
    drop(observer);
    let handoff = Request::new(Command::BindUserAgent(prepared.into_bind()))
        .map_err(|e| e.to_string())?
        .encode()
        .map_err(|e| e.to_string())?;
    restricted::run_authority(image, name, digest, handoff.as_bytes())?;
    drop(handoff);
    let Response::Lease(observed) = request(&mut channel, Command::OwnedLease)? else {
        return Err("desktop lost its exact lease view".into());
    };
    assert_eq!(observed, context);
    status(
        request(
            &mut channel,
            Command::BeginStop(StopRequest {
                context,
                expected_revision: 6,
            }),
        )?,
        AuthorityState::Stopping,
        6,
    )?;
    drop(channel);
    let mut finish = ServiceChannel::connect(name, ServiceClientRole::Desktop, service_image)
        .map_err(|e| e.to_string())?;
    if finish
        .request(b"authority-wire-finish", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"wire-ok"
    {
        return Err("wire fixture completion mismatch".into());
    }
    Ok(())
}
pub(super) fn agent(name: &str, image: &Path, digest: [u8; 32]) -> Result<()> {
    let mut bytes = Zeroizing::new(vec![0; MAX_MESSAGE_BYTES + 1]);
    let mut length = 0;
    let mut input = std::io::stdin().lock();
    while length < bytes.len() {
        let count = input
            .read(&mut bytes[length..])
            .map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length += count;
    }
    let bind = Request::decode(&bytes[..length]).map_err(|e| e.to_string())?;
    let Command::BindUserAgent(material) = bind.command() else {
        return Err("agent handoff was not a bind request".into());
    };
    let context = material.context.clone();
    let wrong = material
        .ticket
        .with_bytes(|ticket| {
            let mut bytes = Zeroizing::new([0; 32]);
            bytes.copy_from_slice(ticket);
            bytes[0] ^= 1;
            TicketMaterial::from_slice(bytes.as_ref())
        })
        .map_err(|e| e.to_string())?;
    let service_image = Arc::new(verified(image, digest)?);
    let mut channel = AuthorityChannel::connect(
        name,
        ServiceClientRole::UserAgent,
        Arc::clone(&service_image),
    )
    .map_err(|e| e.to_string())?;
    match channel.request(
        Request::new(Command::BindUserAgent(BindRequest {
            context: context.clone(),
            ticket: wrong,
        }))
        .map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Ticket)) => {}
        Err(error) => return Err(format!("wrong ticket rejection: {error}")),
        Ok(_) => return Err("wrong ticket was accepted".into()),
    }
    let Response::Bound(bound) = channel
        .unconfirmed_bind_for_validation(bind, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
    else {
        return Err("agent did not receive a runtime binding".into());
    };
    assert_eq!(bound.context(), &context);
    assert_eq!(bound.committed_revision(), 4);
    require_job_access_denied(&context.operation.root)?;
    let ready = ReadyReport {
        context: context.clone(),
        runtime_digest: context.operation.identity_sha256,
        ready_flags: 7,
        packet_pump_limits: None,
        observed_millis: 1,
    };
    match channel.request(
        Request::new(Command::Ready(ready.clone())).map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Identity)) => {}
        Err(error) => return Err(format!("unconfirmed keeper Ready rejection: {error}")),
        Ok(_) => return Err("Ready admitted before keeper confirmation".into()),
    }
    let bound = channel
        .confirm_binding_for_validation(bound, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?;
    drop((bound, bytes));
    match channel.request(
        Request::new(Command::LoadLineage).map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Identity)) => {}
        Err(error) => return Err(format!("agent lineage role rejection: {error}")),
        Ok(_) => return Err("agent acquired Desktop lineage access".into()),
    }
    match channel.request(
        Request::new(Command::ReadRuntimeScope).map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Identity)) => {}
        Err(error) => return Err(format!("agent recorded scope role rejection: {error}")),
        Ok(_) => return Err("agent acquired Desktop recorded scope access".into()),
    }
    status(
        request(&mut channel, Command::Ready(ready.clone()))?,
        AuthorityState::Active,
        5,
    )?;
    status(
        request(&mut channel, Command::Heartbeat(context.clone()))?,
        AuthorityState::Active,
        5,
    )?;
    status(
        request(&mut channel, Command::Ready(ready))?,
        AuthorityState::Active,
        5,
    )?;
    status(
        request(
            &mut channel,
            Command::Stopped(StoppedReport {
                context,
                engine_stopped: true,
                transport_closed: true,
                os_restored: true,
                observed_millis: 2,
            }),
        )?,
        AuthorityState::Stopping,
        6,
    )?;
    drop(channel);
    let mut reconnected =
        AuthorityChannel::connect(name, ServiceClientRole::UserAgent, service_image)
            .map_err(|e| e.to_string())?;
    match reconnected.request(
        Request::new(Command::OwnedLease).map_err(|e| e.to_string())?,
        Instant::now() + LIMIT,
    ) {
        Err(WireError::Rejected(Rejection::Identity)) => {}
        Err(error) => return Err(format!("new connection rejection: {error}")),
        Ok(_) => return Err("new agent connection inherited the old lease".into()),
    }
    status(
        request(&mut reconnected, Command::Observe)?,
        AuthorityState::Stopping,
        6,
    )?;
    Ok(())
}
pub(super) fn require_live_runtime(
    controller: &mut WindowsAuthority,
    minimum: u32,
) -> Result<RuntimeProcessObservation> {
    let observed = controller
        .observe_runtime_processes()
        .map_err(|e| e.to_string())?;
    let cfw_windows_engine::authority::RuntimeProcessState::Accounting { active, total } =
        observed.state()
    else {
        return Err("live runtime job was not independently observed".into());
    };
    if active < minimum || total < minimum || observed.processes_retired() {
        return Err(format!(
            "runtime job missing members: active={active}, total={total}, minimum={minimum}"
        ));
    }
    let snapshot = controller.snapshot();
    let lease = controller
        .recovery_target()
        .and_then(|s| s.operation())
        .map(|o| o.lease_id());
    assert!(matches!(
        controller.reconcile_off(CleanupEvidence::for_validation(
            snapshot.revision.ok_or("unknown job fixture revision")?,
            lease,
            true
        )),
        Err(AuthorityError::CleanupUnproven)
    ));
    assert_eq!(controller.snapshot(), snapshot);
    Ok(observed)
}
pub(super) fn process_report(
    stage: &str,
    observation: &RuntimeProcessObservation,
) -> serde_json::Value {
    let state = match observation.state() {
        RuntimeProcessState::NoRuntimeRoot => serde_json::json!({"kind":"no_runtime_root"}),
        RuntimeProcessState::DurablyRetired => serde_json::json!({"kind":"durably_retired"}),
        RuntimeProcessState::NeverAuthorized => serde_json::json!({"kind":"never_authorized"}),
        RuntimeProcessState::Accounting { active, total } => {
            serde_json::json!({"kind":"accounting","active":active,"total":total})
        }
    };
    serde_json::json!({"stage":stage,"root":observation.root(),"state":state,"processes_retired":observation.processes_retired()})
}
pub(super) fn require_job_access_denied(root: &RootContext) -> Result<()> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::ERROR_ACCESS_DENIED,
        System::{
            JobObjects::OpenJobObjectW,
            SystemServices::{JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE},
        },
    };
    let name = cfw_windows_engine::authority::runtime_job_name_for_validation(root)
        .map_err(|e| e.to_string())?;
    for access in [
        JOB_OBJECT_QUERY,
        JOB_OBJECT_ASSIGN_PROCESS,
        JOB_OBJECT_TERMINATE,
    ] {
        let raw = unsafe { OpenJobObjectW(access, 0, wide(&name).as_ptr()) };
        if !raw.is_null() {
            drop(unsafe { OwnedHandle::from_raw_handle(raw) });
            return Err(format!(
                "ordinary UserAgent obtained service job rights {access:#x}"
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
            return Err(error(
                "ordinary UserAgent job access was not explicitly denied",
            ));
        }
    }
    Ok(())
}
fn report() -> serde_json::Value {
    serde_json::json!({"success":true,"versioned_requests":22,"typed_rejections":8,"unconfirmed_keeper_ready_rejected":true,"machine_lineage_cas":true,"user_agent_lineage_role_rejected":true,"recorded_runtime_scope_validated":true,"recorded_scope_observer_control_rejected":true,"user_agent_recorded_scope_role_rejected":true,"native_runtime_owner_bound":true,"same_owner_new_connection_rejected":true,"ticket_handoff_stayed_in_memory":true,"stopped_report_did_not_publish_off":true,"live_processes_block_reconcile":true,"job_reopened_after_service_handles_closed":true,"live_member_without_job_name_rejected":true,"ordinary_agent_job_rights_denied":true,"runtime_reports_synthetic":true,"cleanup_observations_injected":true,"actual_runtime_started":false,"full_service_backend_proven":false})
}
pub(super) fn require_report(root: &Path) -> Result<()> {
    let bytes =
        std::fs::read(root.join("lifecycle.wire-validation.json")).map_err(|e| e.to_string())?;
    if bytes.len() > 8192
        || serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())?
            != report()
    {
        return Err("wire fixture report differs from the required checks".into());
    }
    Ok(())
}
