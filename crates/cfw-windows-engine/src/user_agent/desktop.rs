//! One Desktop operation on its dedicated native thread. The same authenticated
//! connection owns preparation, observation and revocation; snapshots never
//! turn local child retirement into independent machine cleanup.
use super::{
    StopReason,
    handoff::{HandoffError, UserAgentLaunch},
    launcher::{AgentExit, LaunchError, UserAgentChild, UserAgentInvocation, medium_process},
};
use crate::{
    CheckedStartConfiguration, ServiceTransportError, VerifiedExecutable,
    authority::{
        AuthorityChannel, AuthoritySnapshot, LeaseContext,
        wire::{Command, Rejection, Request, Response, RuntimeReference, StopRequest, WireError},
    },
    credential_lifecycle::{CredentialLifecycleError, WindowsCredentialLifecycle},
    service_transport::check_deadline,
};
use cfw_engine_api::{EngineStartRequest, authority_v1::AuthorityState};
use std::{
    fs::File,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    thread,
    time::{Duration, Instant},
};

const COMMAND_LIMIT: Duration = Duration::from_secs(5);
const START_LIMIT: Duration = Duration::from_secs(15);
const STOP_LIMIT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("Windows Desktop configuration: {0}")]
    Configuration(#[from] crate::Error),
    #[error("Windows Desktop credential lifecycle: {0}")]
    Credentials(#[from] CredentialLifecycleError),
    #[error("Windows Desktop authority: {0}")]
    Authority(#[from] WireError),
    #[error("Windows Desktop transport: {0}")]
    Transport(#[from] ServiceTransportError),
    #[error("Windows Desktop handoff: {0}")]
    Handoff(#[from] HandoffError),
    #[error("Windows Desktop launcher: {0}")]
    Launch(#[from] LaunchError),
    #[error("Windows Desktop proxy restoration: {0}")]
    Proxy(#[from] crate::ProxyError),
    #[error("Windows Desktop cleanup scope: {0}")]
    CleanupScope(#[from] crate::authority::AuthorityError),
    #[error("Windows Desktop operation state: {0}")]
    State(&'static str),
    #[error("Windows Desktop authority context changed")]
    Context,
    #[error("Windows Desktop authority returned an unrelated response")]
    Response,
    #[error("Windows Desktop readiness receiver is unavailable")]
    ReadyReceiver,
    #[error("Windows Desktop operation failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
pub type Result<T> = std::result::Result<T, DesktopError>;

pub struct DesktopReady {
    context: LeaseContext,
    agent_process_id: u32,
    authority: AuthoritySnapshot,
    runtime_reference: Arc<RuntimeReference>,
}
impl DesktopReady {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn agent_process_id(&self) -> u32 {
        self.agent_process_id
    }
    pub fn authority(&self) -> &AuthoritySnapshot {
        &self.authority
    }
    /// Keep this receipt or clone its reference until independent global
    /// cleanup finishes, including when the operation's worker returns an error.
    pub fn runtime_reference(&self) -> &Arc<RuntimeReference> {
        &self.runtime_reference
    }
}
/// Native process retirement plus the actual Authority observation, which may
/// still be Stopping or Recovering. This is not a global Off constructor.
pub struct DesktopStopped {
    context: LeaseContext,
    agent_exit: Option<AgentExit>,
    authority: AuthoritySnapshot,
    _runtime_reference: Option<Arc<RuntimeReference>>,
}
impl DesktopStopped {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn agent_exit(&self) -> Option<&AgentExit> {
        self.agent_exit.as_ref()
    }
    pub fn authority(&self) -> &AuthoritySnapshot {
        &self.authority
    }
}
pub struct DesktopCompleted {
    reason: StopReason,
    stopped: DesktopStopped,
}
impl DesktopCompleted {
    pub fn reason(&self) -> StopReason {
        self.reason
    }
    pub fn stopped(&self) -> &DesktopStopped {
        &self.stopped
    }
}

pub struct DesktopUserAgent {
    service: String,
    authority: Option<AuthorityChannel>,
    context: LeaseContext,
    pending: Option<UserAgentLaunch>,
    agent_image: Arc<VerifiedExecutable>,
    child: Option<UserAgentChild>,
    attempted: bool,
    last_authority: Option<AuthoritySnapshot>,
    runtime_reference: Option<Arc<RuntimeReference>>,
}
impl DesktopUserAgent {
    pub fn prepare(
        credentials: &WindowsCredentialLifecycle,
        agent_image: Arc<VerifiedExecutable>,
        request: EngineStartRequest,
        deadline: Instant,
    ) -> Result<Self> {
        check_deadline(deadline)?;
        let request = CheckedStartConfiguration::new(request)?;
        let current = medium_process()?;
        current
            .require_current_console_session()
            .map_err(LaunchError::from)?;
        let (authority, grant, request) = credentials.prepare(request, deadline)?;
        // AuthorityChannel already checked root, operation, mode, digests,
        // native owner and revision. No child exists if this validation fails;
        // closing this exact connection revokes an unbound preparation.
        let launch = UserAgentLaunch::checked(grant.into_bind(), request)?;
        Ok(Self {
            service: credentials.service().to_owned(),
            authority: Some(authority),
            context: launch.context().clone(),
            pending: Some(launch),
            agent_image,
            child: None,
            attempted: false,
            last_authority: None,
            runtime_reference: None,
        })
    }
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn last_authority_observation(&self) -> Option<&AuthoritySnapshot> {
        self.last_authority.as_ref()
    }
    pub fn agent_exit_observation(&self) -> Option<&AgentExit> {
        self.child
            .as_ref()
            .and_then(UserAgentChild::exit_observation)
    }
    #[cfg(feature = "native-service-validation")]
    pub fn rejected_launch_for_validation(&self) -> Result<UserAgentLaunch> {
        Ok(self
            .pending
            .as_ref()
            .ok_or(DesktopError::State("no pending launch"))?
            .rejected_copy_for_validation()?)
    }
    /// Run on the thread that prepared this operation. It keeps the Desktop
    /// connection alive independently of UI refresh, until stop or revocation.
    /// Errors retain this owner for explicit recovery; cleanup ignores startup
    /// cancellation and never force-kills a possibly active UserAgent.
    /// The readiness channel needs capacity for one observation; an unavailable
    /// receiver fails the operation and runs its normal scoped cleanup.
    pub fn run(
        &mut self,
        invocation: UserAgentInvocation,
        diagnostics: &File,
        stop: Arc<AtomicBool>,
        ready: SyncSender<DesktopReady>,
    ) -> Result<DesktopCompleted> {
        if self.attempted || self.pending.is_none() {
            return Err(DesktopError::State("operation already consumed"));
        }
        if invocation.service() != self.service {
            return Err(DesktopError::State("invocation names a different service"));
        }
        self.attempted = true;
        let operated = self.operate(invocation, diagnostics, stop, ready);
        let stopped = self.stop(Instant::now() + STOP_LIMIT);
        match (operated, stopped) {
            (Ok(reason), Ok(stopped)) => Ok(DesktopCompleted { reason, stopped }),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(DesktopError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
    fn operate(
        &mut self,
        invocation: UserAgentInvocation,
        diagnostics: &File,
        stop: Arc<AtomicBool>,
        ready: SyncSender<DesktopReady>,
    ) -> Result<StopReason> {
        if stop.load(Ordering::Acquire) {
            return Ok(StopReason::Requested);
        }
        let launch = self
            .pending
            .take()
            .ok_or(DesktopError::State("missing launch"))?;
        let deadline = Instant::now() + START_LIMIT;
        match UserAgentChild::launch(
            Arc::clone(&self.agent_image),
            invocation,
            launch,
            diagnostics,
            deadline,
            Arc::clone(&stop),
        ) {
            Ok(child) => self.child = Some(child),
            Err(failure) => {
                self.child = failure.owner.map(|owner| *owner);
                return Err(failure.error.into());
            }
        }
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(StopReason::Requested);
            }
            self.child
                .as_ref()
                .ok_or(DesktopError::State("missing child"))?
                .verify_live()?;
            let snapshot = self.observe_owned(deadline)?;
            match snapshot.state {
                AuthorityState::Active => {
                    let Response::RuntimeRetained(grant) =
                        self.command(Command::RetainRuntime(self.context.clone()), deadline)?
                    else {
                        return Err(DesktopError::Response);
                    };
                    let reference = Arc::new(grant.into_reference()?);
                    self.runtime_reference = Some(Arc::clone(&reference));
                    self.child
                        .as_ref()
                        .ok_or(DesktopError::State("missing child"))?
                        .verify_live()?;
                    ready
                        .try_send(DesktopReady {
                            context: self.context.clone(),
                            agent_process_id: self
                                .child
                                .as_ref()
                                .ok_or(DesktopError::State("missing child"))?
                                .process_id(),
                            authority: snapshot,
                            runtime_reference: reference,
                        })
                        .map_err(|_| DesktopError::ReadyReceiver)?;
                    break;
                }
                AuthorityState::Preparing | AuthorityState::Starting => {}
                _ => return Err(DesktopError::State("authority ended before Ready")),
            }
            check_deadline(deadline)?;
            wait_signal(&stop, Duration::from_millis(100));
        }
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(StopReason::Requested);
            }
            let snapshot = self.observe_owned(Instant::now() + COMMAND_LIMIT)?;
            match snapshot.state {
                AuthorityState::Active => self
                    .child
                    .as_ref()
                    .ok_or(DesktopError::State("missing child"))?
                    .verify_live()?,
                AuthorityState::Stopping
                | AuthorityState::Recovering
                | AuthorityState::Quarantined
                | AuthorityState::Off => return Ok(StopReason::AuthorityRevoked),
                _ => return Err(DesktopError::State("authority regressed after Ready")),
            }
            wait_signal(&stop, Duration::from_secs(1));
        }
    }
    fn observe(&mut self, deadline: Instant) -> Result<AuthoritySnapshot> {
        self.last_authority = None;
        let Response::Observed(snapshot) = self.command(Command::Observe, deadline)? else {
            return Err(DesktopError::Response);
        };
        if snapshot.root.as_ref() != Some(&self.context.operation.root) {
            return Err(DesktopError::Context);
        }
        self.last_authority = Some(snapshot.clone());
        Ok(snapshot)
    }
    fn observe_owned(&mut self, deadline: Instant) -> Result<AuthoritySnapshot> {
        let snapshot = self.observe(deadline)?;
        if matches!(
            snapshot.state,
            AuthorityState::Preparing
                | AuthorityState::Starting
                | AuthorityState::Active
                | AuthorityState::Stopping
        ) {
            let Response::Lease(context) = self.command(Command::OwnedLease, deadline)? else {
                return Err(DesktopError::Response);
            };
            if context != self.context {
                return Err(DesktopError::Context);
            }
        }
        Ok(snapshot)
    }
    fn command(&mut self, command: Command, deadline: Instant) -> Result<Response> {
        send(
            self.authority
                .as_mut()
                .ok_or(DesktopError::State("authority connection unavailable"))?,
            command,
            deadline,
        )
    }
    /// Invalid deadlines have no effect. Typed stale-revision races can be
    /// retried at most three times on this same connection/context; uncertain
    /// transport outcomes are never replayed. Partial observations stay owned.
    pub fn stop(&mut self, deadline: Instant) -> Result<DesktopStopped> {
        check_deadline(deadline)?;
        self.pending.take();
        if let Some(child) = &self.child {
            child.cancel_handoff();
        }
        let revoked = self.revoke(deadline);
        if revoked.is_err() {
            self.authority.take();
        }
        let retired = match &mut self.child {
            Some(child) => child
                .wait_for_exit(deadline)
                .map(Some)
                .map_err(DesktopError::from),
            None => Ok(None),
        };
        let agent_exit = match (revoked, retired) {
            (Ok(()), Ok(exit)) => exit,
            (Err(error), Ok(_)) | (Ok(()), Err(error)) => return Err(error),
            (Err(operation), Err(cleanup)) => {
                return Err(DesktopError::Cleanup {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                });
            }
        };
        let authority = self.observe(deadline)?;
        if !matches!(
            authority.state,
            AuthorityState::Off
                | AuthorityState::Stopping
                | AuthorityState::Recovering
                | AuthorityState::Quarantined
        ) {
            return Err(DesktopError::State(
                "authority remained executable after stop",
            ));
        }
        Ok(DesktopStopped {
            context: self.context.clone(),
            agent_exit,
            authority,
            _runtime_reference: self.runtime_reference.clone(),
        })
    }
    fn revoke(&mut self, deadline: Instant) -> Result<()> {
        retry_stale_revocation(|| self.revoke_once(deadline))
    }
    /// Finish a normally acknowledged SystemProxy stop on its original
    /// connection. Keep this owner/runtime reference through the final reply;
    /// failed or uncertain commands are never replayed here.
    pub fn reconcile_system_proxy_stop(
        &mut self,
        proxy: &crate::WindowsSystemProxy,
        deadline: Instant,
    ) -> Result<crate::authority::wire::ProxyCleanupReceipt> {
        check_deadline(deadline)?;
        if self.context.operation.mode != cfw_engine_api::authority_v1::AuthorityMode::SystemProxy
            || self.agent_exit_observation().is_none()
        {
            return Err(DesktopError::State("SystemProxy owner has not exited"));
        }
        self.last_authority = None;
        let Response::RuntimeScope(scope) = self.command(Command::ReadRuntimeScope, deadline)?
        else {
            return Err(DesktopError::Response);
        };
        let target = crate::authority::ProxyRecoveryTarget::from_stopped(&scope, &self.context)?;
        let Response::ProxyRecoveryGranted(grant) =
            self.command(Command::BeginProxyCleanup(target), deadline)?
        else {
            return Err(DesktopError::Response);
        };
        let report = grant.observe_restoration(proxy)?;
        let Response::ProxyCleanupReconciled(receipt) =
            self.command(Command::ReconcileProxyCleanup(report), deadline)?
        else {
            return Err(DesktopError::Response);
        };
        self.last_authority = Some(receipt.snapshot().clone());
        Ok(receipt)
    }
    fn revoke_once(&mut self, deadline: Instant) -> Result<Revocation> {
        let snapshot = self.observe_owned(deadline)?;
        match snapshot.state {
            AuthorityState::Off
            | AuthorityState::Stopping
            | AuthorityState::Recovering
            | AuthorityState::Quarantined => return Ok(Revocation::Done),
            AuthorityState::Preparing | AuthorityState::Starting | AuthorityState::Active => {}
        }
        let command = Command::BeginStop(StopRequest {
            context: self.context.clone(),
            expected_revision: snapshot.revision.ok_or(DesktopError::Context)?,
        });
        match self.command(command, deadline) {
            Ok(Response::Status(stopped))
                if matches!(
                    stopped.state,
                    AuthorityState::Off | AuthorityState::Stopping
                ) =>
            {
                Ok(Revocation::Done)
            }
            Ok(_) => Err(DesktopError::Response),
            // Only a typed rejection of this BeginStop permits a new attempt.
            // Observation/ownership errors above are never reclassified.
            Err(DesktopError::Authority(WireError::Rejected(Rejection::Stale))) => {
                Ok(Revocation::StaleRevision)
            }
            Err(error) => Err(error),
        }
    }
}
impl Drop for DesktopUserAgent {
    fn drop(&mut self) {
        // Close the host binding first. Native authority timers revoke closed
        // bindings; this cannot certify completed OS cleanup.
        self.authority.take();
        if let Some(child) = &self.child {
            child.cancel_handoff();
        }
    }
}
enum Revocation {
    Done,
    StaleRevision,
}
fn retry_stale_revocation(mut attempt: impl FnMut() -> Result<Revocation>) -> Result<()> {
    for _ in 0..3 {
        if matches!(attempt()?, Revocation::Done) {
            return Ok(());
        }
    }
    Err(DesktopError::State(
        "authority revision kept changing during stop",
    ))
}
fn send(authority: &mut AuthorityChannel, command: Command, deadline: Instant) -> Result<Response> {
    check_deadline(deadline)?;
    Ok(authority.request(
        Request::new(command)?,
        deadline.min(Instant::now() + COMMAND_LIMIT),
    )?)
}
fn wait_signal(stop: &AtomicBool, interval: Duration) {
    let end = Instant::now() + interval;
    while !stop.load(Ordering::Acquire) {
        let Some(left) = end
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            break;
        };
        thread::sleep(left.min(Duration::from_millis(25)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_revision_races_can_finish_within_the_attempt_budget() {
        for stale_count in 0..3 {
            let mut attempts = 0;
            retry_stale_revocation(|| {
                attempts += 1;
                Ok(if attempts <= stale_count {
                    Revocation::StaleRevision
                } else {
                    Revocation::Done
                })
            })
            .unwrap();
            assert_eq!(attempts, stale_count + 1);
        }
    }

    #[test]
    fn stop_revision_races_fail_explicitly_at_exhaustion() {
        let mut attempts = 0;
        let result = retry_stale_revocation(|| {
            attempts += 1;
            Ok(Revocation::StaleRevision)
        });
        assert!(matches!(
            result,
            Err(DesktopError::State(
                "authority revision kept changing during stop"
            ))
        ));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn stop_uncertain_delivery_and_unclassified_rejections_are_never_replayed() {
        for error in [
            DesktopError::Context,
            WireError::Correlation.into(),
            WireError::Transport(ServiceTransportError::Deadline).into(),
            WireError::Transport(ServiceTransportError::Closed).into(),
            // A Stale rejection from observation/ownership is not a rejected
            // BeginStop and must not acquire that command's retry permission.
            WireError::Rejected(Rejection::Stale).into(),
        ] {
            let expected = error.to_string();
            let mut error = Some(error);
            let mut attempts = 0;
            let result = retry_stale_revocation(|| {
                attempts += 1;
                Err(error.take().expect("uncertain operation was replayed"))
            });
            assert_eq!(result.unwrap_err().to_string(), expected);
            assert_eq!(attempts, 1);
        }
    }
}
