use super::plan::PlannedConfiguration;
use super::{Result, UserAgentError, UserAgentPlan, control::ControlSession};
use crate::{
    EngineProcess, PreparedConfig, VerifiedExecutable, WindowsSystemProxy,
    authority::{AuthoritySnapshot, LeaseContext, ReadyReport, StoppedReport, wire::BindRequest},
    process::ChildLaunchFailure,
};
use cfw_engine_api::{EngineCommandContext, authority_v1::AuthorityMode};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    thread,
    time::{Duration, Instant},
};

const NATIVE_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(100);

/// Installation-owned assets, supplied by the native launcher rather than a
/// serialized command. The executable already holds its verified file identity.
pub struct UserAgentRuntime {
    executable: VerifiedExecutable,
    directory: PathBuf,
    proxy: Option<WindowsSystemProxy>,
    #[cfg(feature = "native-service-validation")]
    release_agent_keeper: bool,
}
impl UserAgentRuntime {
    pub fn new(
        executable: VerifiedExecutable,
        directory: PathBuf,
        proxy: Option<WindowsSystemProxy>,
    ) -> Self {
        Self {
            executable,
            directory,
            proxy,
            #[cfg(feature = "native-service-validation")]
            release_agent_keeper: false,
        }
    }
    #[cfg(feature = "native-service-validation")]
    pub fn release_agent_keeper_after_spawn_for_validation(mut self) -> Self {
        self.release_agent_keeper = true;
        self
    }
}

/// A local observation plus an authenticated Ready acknowledgement. This is
/// not a constructor for a global native engine status.
pub struct ReadyObservation {
    context: LeaseContext,
    process_id: u32,
    authority: AuthoritySnapshot,
}
impl ReadyObservation {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    pub fn authority(&self) -> &AuthoritySnapshot {
        &self.authority
    }
}

/// A fresh local resource observation. It survives a failed Stopped delivery
/// without turning that delivery failure into successful global cleanup.
pub struct LocalCleanupObservation {
    context: LeaseContext,
    process_id: Option<u32>,
    observed_millis: u64,
}
impl LocalCleanupObservation {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn process_id(&self) -> Option<u32> {
        self.process_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Requested,
    AuthorityRevoked,
}

/// Runs on the UserAgent's lifecycle thread. The control worker keeps the same
/// native connection alive during engine startup; its cancellation signal also
/// interrupts engine RPC waits. An error retains this owner for explicit retry.
pub struct UserAgentSession {
    context: LeaseContext,
    binding: Option<BindRequest>,
    planned: Option<PlannedConfiguration>,
    configuration: Option<PreparedConfig>,
    service: String,
    service_image: Arc<VerifiedExecutable>,
    assets: Option<UserAgentRuntime>,
    proxy: Option<WindowsSystemProxy>,
    control: Option<ControlSession>,
    child: Option<EngineProcess>,
    keeper: Option<crate::authority::RuntimeKeeper>,
    cancel: Arc<AtomicBool>,
    attempted: bool,
    bound: bool,
    started: bool,
    cleanup: Option<LocalCleanupObservation>,
    stopped_ack: Option<AuthoritySnapshot>,
    clock: Instant,
}
impl UserAgentSession {
    pub fn new(
        plan: UserAgentPlan,
        service: String,
        service_image: Arc<VerifiedExecutable>,
        assets: UserAgentRuntime,
    ) -> Result<Self> {
        if (plan.context().operation.mode == AuthorityMode::SystemProxy) != assets.proxy.is_some() {
            return Err(UserAgentError::Mode);
        }
        let UserAgentPlan { binding, config } = plan;
        Ok(Self {
            context: binding.context.clone(),
            binding: Some(binding),
            planned: Some(config),
            configuration: None,
            service,
            service_image,
            assets: Some(assets),
            proxy: None,
            control: None,
            child: None,
            keeper: None,
            cancel: Arc::new(AtomicBool::new(false)),
            attempted: false,
            bound: false,
            started: false,
            cleanup: None,
            stopped_ack: None,
            clock: Instant::now(),
        })
    }

    /// Caller retains the session if this fails. A readiness receiver must have
    /// capacity for one item; disappearance/full capacity cancels this operation.
    pub fn run(
        &mut self,
        stop: &AtomicBool,
        ready: SyncSender<ReadyObservation>,
    ) -> Result<StopReason> {
        if self.attempted {
            return Err(UserAgentError::State);
        }
        self.attempted = true;
        let operation = self.operate(stop, ready);
        let operation = classify_revocation(operation, self.cancel.load(Ordering::Acquire), || {
            self.control().and_then(ControlSession::failure)
        });
        let cleanup = self.stop();
        // A failed restoration retains the child and recovery journal, but it
        // must not keep renewing permission as if the operation were healthy.
        let cleanup = match cleanup {
            Err(error) => match self.close_control() {
                Ok(()) => Err(error),
                Err(closing) => Err(combine(Some(error), closing)),
            },
            success => success,
        };
        match (operation, cleanup) {
            (Ok(reason), Ok(())) => Ok(reason),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(UserAgentError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
    pub fn local_cleanup(&self) -> Option<&LocalCleanupObservation> {
        self.cleanup.as_ref()
    }
    pub fn stopped_acknowledgement(&self) -> Option<&AuthoritySnapshot> {
        self.stopped_ack.as_ref()
    }

    fn control(&self) -> Result<&ControlSession> {
        self.control.as_ref().ok_or(UserAgentError::State)
    }
    fn live(&self) -> Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            self.control()?.failure()?;
            return Err(UserAgentError::Cancelled);
        }
        self.control()?.failure()
    }
    fn stamp(&self) -> Result<u64> {
        u64::try_from(self.clock.elapsed().as_millis())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(UserAgentError::State)
    }
    fn command_context(&self) -> EngineCommandContext {
        let root = &self.context.operation.root;
        EngineCommandContext {
            installation_id: root.installation_id.to_string(),
            config_epoch: root.epoch,
            generation: root.generation,
        }
    }
    fn observe(&mut self) -> Result<u32> {
        self.live()?;
        let running = self
            .child
            .as_mut()
            .ok_or(UserAgentError::State)?
            .observe_retained(NATIVE_TIMEOUT)?;
        if let Some(proxy) = &self.proxy {
            proxy.verify_owned(
                &self.command_context(),
                self.child.as_mut().ok_or(UserAgentError::State)?,
            )?;
        }
        self.live()?;
        Ok(running.process_id)
    }
    fn operate(
        &mut self,
        stop: &AtomicBool,
        ready: SyncSender<ReadyObservation>,
    ) -> Result<StopReason> {
        if stop.load(Ordering::Acquire) {
            return Ok(StopReason::Requested);
        }
        let binding = self.binding.take().ok_or(UserAgentError::State)?;
        self.control = Some(ControlSession::start(
            self.service.clone(),
            Arc::clone(&self.service_image),
            binding,
            Arc::clone(&self.cancel),
        )?);
        let grant = self
            .control
            .as_mut()
            .ok_or(UserAgentError::State)?
            .wait_bound()?;
        if grant.context() != &self.context {
            return Err(UserAgentError::ConfigurationMismatch);
        }
        let keeper = grant.into_keeper()?;
        if keeper.root() != &self.context.operation.root {
            return Err(UserAgentError::ConfigurationMismatch);
        }
        self.keeper = Some(keeper);
        self.bound = true;
        self.live()?;
        if stop.load(Ordering::Acquire) {
            return Ok(StopReason::Requested);
        }
        self.configuration = Some(
            self.planned
                .take()
                .ok_or(UserAgentError::State)?
                .prepare_after_binding()?,
        );
        self.live()?;
        let assets = self.assets.take().ok_or(UserAgentError::State)?;
        self.proxy = assets.proxy;
        match EngineProcess::spawn_retained(
            assets.executable,
            &assets.directory,
            NATIVE_TIMEOUT,
            Some(Arc::clone(&self.cancel)),
            self.keeper.as_ref(),
        ) {
            Ok(owner) => self.child = Some(owner),
            Err(ChildLaunchFailure { error, owner }) => {
                self.child = owner.map(|owner| *owner);
                return Err(error.into());
            }
        }
        #[cfg(feature = "native-service-validation")]
        if assets.release_agent_keeper {
            // Fault injection: the actual Go child must retain the only
            // non-service reference before Ready closes all service handles.
            self.keeper.take();
        }
        let child = self.child.as_mut().ok_or(UserAgentError::State)?;
        let config = self.configuration.as_ref().ok_or(UserAgentError::State)?;
        child.start_retained(config, NATIVE_TIMEOUT)?;
        self.started = true;
        if let Some(proxy) = &self.proxy {
            let context = self.command_context();
            proxy.activate(
                &context,
                self.child.as_mut().ok_or(UserAgentError::State)?,
                self.configuration.as_ref().ok_or(UserAgentError::State)?,
            )?;
        }
        // Engine control serialization has completed; retain no configuration
        // credentials in this lifecycle owner beyond successful activation.
        self.configuration.take();
        let process_id = self.observe()?;
        if stop.load(Ordering::Acquire) {
            return Ok(StopReason::Requested);
        }
        let authority = self.control()?.ready(ReadyReport {
            context: self.context.clone(),
            runtime_digest: self.context.operation.identity_sha256,
            ready_flags: if self.proxy.is_some() { 0b111 } else { 0b011 },
            packet_pump_limits: None,
            observed_millis: self.stamp()?,
        })?;
        self.live()?;
        ready
            .try_send(ReadyObservation {
                context: self.context.clone(),
                process_id,
                authority,
            })
            .map_err(|_| UserAgentError::WorkerEnded)?;
        loop {
            if self.cancel.load(Ordering::Acquire) {
                self.control()?.failure()?;
                return Ok(StopReason::AuthorityRevoked);
            }
            self.control()?.failure()?;
            if stop.load(Ordering::Acquire) {
                return Ok(StopReason::Requested);
            }
            self.observe()?;
            thread::sleep(OBSERVE_INTERVAL);
        }
    }

    /// An explicit retry is permitted after a failed restoration. No successful
    /// local cleanup claim is made until the held child/job/I/O and exact proxy
    /// settings have been reobserved. Stopped delivery failure remains an error.
    pub fn stop(&mut self) -> Result<()> {
        if !self.attempted {
            return Err(UserAgentError::State);
        }
        self.configuration.take();
        self.binding.take();
        self.planned.take();
        self.assets.take();
        let mut operation_error = None;
        let process_id = match self.child.as_mut() {
            Some(child) => {
                // A prior successful cleanup may still need a failed control
                // worker to be closed. Reobserve before reusing its receipt.
                let observed = if self.cleanup.is_some() {
                    child.observe_cleanup()?
                } else if self.started {
                    if let Err(error) = child.stop(STOP_TIMEOUT) {
                        operation_error = Some(UserAgentError::Engine(error));
                    }
                    match child.observe_cleanup() {
                        Ok(observed) => observed,
                        Err(cleanup) => return Err(combine(operation_error, cleanup.into())),
                    }
                } else {
                    child.force_cleanup()?
                };
                if observed.configuration_digest().is_some_and(|digest| {
                    digest != super::plan::hex(&self.context.operation.identity_sha256)
                }) {
                    return Err(UserAgentError::ConfigurationMismatch);
                }
                Some(observed.process_id())
            }
            None => None,
        };
        self.cleanup = Some(LocalCleanupObservation {
            context: self.context.clone(),
            process_id,
            observed_millis: self.stamp()?,
        });
        let attestation = if self.bound && self.stopped_ack.is_none() {
            let report = StoppedReport {
                context: self.context.clone(),
                engine_stopped: true,
                transport_closed: true,
                os_restored: true,
                observed_millis: self
                    .cleanup
                    .as_ref()
                    .ok_or(UserAgentError::State)?
                    .observed_millis,
            };
            self.control()?
                .stopped(report)
                .map(|ack| self.stopped_ack = Some(ack))
        } else {
            Ok(())
        };
        let closing = self.close_control();
        let result = match (attestation, closing) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(UserAgentError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        };
        match (operation_error, result) {
            (Some(error), Ok(())) => Err(error),
            (operation, Err(cleanup)) => Err(combine(operation, cleanup)),
            (None, Ok(())) => Ok(()),
        }
    }

    fn close_control(&mut self) -> Result<()> {
        match self.control.as_mut() {
            Some(control) => control.close(),
            None => Ok(()),
        }
    }
}

fn classify_revocation(
    operation: Result<StopReason>,
    cancelled: bool,
    control_health: impl FnOnce() -> Result<()>,
) -> Result<StopReason> {
    match operation {
        // Proxy ownership verification observes the engine under its journal
        // lock and wraps this same cancellation one boundary deeper. Only that
        // exact no-completion error is eligible, with a live control receipt.
        // Uncertain writes, cleanup failures and unrelated errors stay errors.
        Err(
            UserAgentError::Cancelled
            | UserAgentError::Engine(crate::Error::Cancelled)
            | UserAgentError::Proxy(crate::ProxyError::Engine(crate::Error::Cancelled)),
        ) if cancelled => control_health().map(|()| StopReason::AuthorityRevoked),
        other => other,
    }
}

fn combine(operation: Option<UserAgentError>, cleanup: UserAgentError) -> UserAgentError {
    match operation {
        Some(operation) => UserAgentError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        },
        None => cleanup,
    }
}
impl Drop for UserAgentSession {
    fn drop(&mut self) {
        if self.attempted && self.cleanup.is_none() {
            eprintln!("Windows user-agent owner dropped without a confirmed local cleanup receipt");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_admits_only_exact_cancelled_work_with_healthy_authority() {
        let proxy_cancel =
            || UserAgentError::Proxy(crate::ProxyError::Engine(crate::Error::Cancelled));
        assert_eq!(
            classify_revocation(Err(proxy_cancel()), true, || Ok(())).unwrap(),
            StopReason::AuthorityRevoked
        );
        assert!(matches!(
            classify_revocation(Err(proxy_cancel()), false, || Ok(())),
            Err(UserAgentError::Proxy(crate::ProxyError::Engine(
                crate::Error::Cancelled
            )))
        ));
        assert!(matches!(
            classify_revocation(Err(proxy_cancel()), true, || Err(
                UserAgentError::WorkerEnded
            )),
            Err(UserAgentError::WorkerEnded)
        ));
        for error in [
            UserAgentError::Engine(crate::Error::Rejected("start_failed")),
            UserAgentError::Proxy(crate::ProxyError::SettingsChanged),
            UserAgentError::Proxy(crate::ProxyError::OutcomeUnknown(Box::new(
                crate::ProxyError::Engine(crate::Error::Cancelled),
            ))),
            UserAgentError::Engine(crate::Error::CleanupFailed {
                operation: Box::new(crate::Error::Cancelled),
                cleanup: Box::new(crate::Error::Cleanup),
            }),
        ] {
            assert!(classify_revocation(Err(error), true, || Ok(())).is_err());
        }
    }
}
