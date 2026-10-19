use super::{
    AuthorityError, Result,
    machine::{Machine, TimerAction},
    secret::Ticket,
    types::*,
};
use crate::{
    LiveConsoleSession, NativePeerProcess, NativeUserSession, ServiceAuthorizationError,
    ServiceClientRole, ServicePeerAuthorization, UserAgentLeaseRequirement,
    authority_journal::{AuthorityCommittedState, WindowsAuthorityJournal},
};
use cfw_engine_api::authority_v1::AuthorityState;
use std::{
    path::Path,
    time::{Duration, Instant},
};

const ADMISSION: Duration = Duration::from_millis(cfw_engine_api::authority_v1::COMMAND_TIMEOUT_MS);

/// The service owns one instance behind its lifecycle guard. This component
/// binds native callers and persists policy; the runtime supervisor still owns
/// actual engine/proxy/TUN effects and produces independent cleanup evidence.
pub struct WindowsAuthority {
    journal: WindowsAuthorityJournal,
    machine: Machine,
    owner_session: Option<NativeUserSession>,
    host_process: Option<NativePeerProcess>,
    runtime_process: Option<NativePeerProcess>,
    cleanup_context: Option<LeaseContext>,
    #[cfg(feature = "native-service-validation")]
    next_fault: Option<crate::authority_journal::JournalFaultPoint>,
}
impl WindowsAuthority {
    pub fn open(root: &Path, scope: &str) -> Result<Self> {
        let journal = WindowsAuthorityJournal::open(root, scope)?;
        let machine = Machine::recovering(journal.recover()?)?;
        let mut authority = Self {
            journal,
            machine,
            owner_session: None,
            host_process: None,
            runtime_process: None,
            cleanup_context: None,
            #[cfg(feature = "native-service-validation")]
            next_fault: None,
        };
        if authority.machine.metadata().is_none() {
            let mut initial = authority.machine.clone();
            // SYSTEM chooses the installation once, before serving any client.
            // Enrollment preserves Recovering until independent cleanup passes.
            initial.enroll(uuid::Uuid::new_v4())?;
            authority.commit(initial)?;
        }
        Ok(authority)
    }
    pub fn snapshot(&self) -> AuthoritySnapshot {
        self.machine.snapshot()
    }
    pub fn lease_owner(&self) -> Option<&NativeUserSession> {
        self.owner_session.as_ref()
    }
    /// Available only to the trusted service supervisor, not a generic user
    /// observation command. Neither target restores a runtime authorization.
    pub fn cleanup_target(&self) -> Option<&LeaseContext> {
        self.cleanup_context.as_ref()
    }
    pub fn recovery_target(&self) -> Option<&AuthorityCommittedState> {
        self.machine.metadata()
    }
    pub fn reload_for_recovery(&mut self) -> Result<()> {
        require_service()?;
        self.suspend(false);
        let recovery = match self.journal.recover() {
            Ok(value) => value,
            Err(error) => {
                self.suspend(true);
                return Err(error.into());
            }
        };
        match Machine::recovering(recovery) {
            Ok(machine) => {
                self.machine = machine;
                Ok(())
            }
            Err(error) => {
                self.suspend(true);
                Err(error)
            }
        }
    }
    fn admit(&self, authorization: &ServicePeerAuthorization, deadline: Instant) -> Result<Peer> {
        authorization.revalidate(
            self.owner_session.as_ref(),
            UserAgentLeaseRequirement::OwnedLease,
            deadline,
        )?;
        Ok(Peer {
            owner: crate::authority_journal::RecordedOwner::from_native(authorization.owner())?,
            connection: authorization.request().binding(),
            role: match authorization.request().role() {
                ServiceClientRole::Desktop => Role::Desktop,
                ServiceClientRole::UserAgent => Role::UserAgent,
            },
        })
    }
    fn after_publication(
        &mut self,
        authorization: &ServicePeerAuthorization,
        deadline: Instant,
    ) -> Result<()> {
        if let Err(error) = authorization.revalidate(
            self.owner_session.as_ref(),
            UserAgentLeaseRequirement::OwnedLease,
            deadline,
        ) {
            self.suspend(false);
            return Err(error.into());
        }
        Ok(())
    }
    fn suspend(&mut self, uncertain: bool) {
        if let Some(context) = self.machine.context() {
            self.cleanup_context = Some(context.clone());
        }
        self.machine.enter_recovery(uncertain);
        // Retain process/owner observations for cleanup, not for issuing grants.
    }
    fn commit(&mut self, candidate: Machine) -> Result<()> {
        if candidate.metadata() != self.machine.metadata() {
            let metadata = candidate.metadata().ok_or(AuthorityError::Invalid)?;
            #[cfg(feature = "native-service-validation")]
            let publication = match self.next_fault.take() {
                Some(point) => self
                    .journal
                    .append_interrupted_for_validation(metadata, point),
                None => self.journal.append(metadata),
            };
            #[cfg(not(feature = "native-service-validation"))]
            let publication = self.journal.append(metadata);
            if let Err(error) = publication {
                self.suspend(true);
                return Err(error.into());
            }
        }
        self.machine = candidate;
        if let Some(context) = self.machine.context() {
            self.cleanup_context = Some(context.clone());
        }
        if self.machine.phase() == AuthorityState::Off {
            self.owner_session = None;
            self.host_process = None;
            self.runtime_process = None;
            self.cleanup_context = None;
        }
        Ok(())
    }
    pub fn reconcile_off(&mut self, evidence: CleanupEvidence) -> Result<AuthoritySnapshot> {
        require_service()?;
        if !self.machine.durable_known() {
            return Err(AuthorityError::Recovering);
        }
        let mut candidate = self.machine.clone();
        candidate.reconcile(&evidence)?;
        self.commit(candidate)?;
        Ok(self.snapshot())
    }
    pub fn lineage(&self, authorization: &ServicePeerAuthorization) -> Result<AuthorityLineage> {
        let peer = self.admit(authorization, Instant::now() + ADMISSION)?;
        if peer.role != Role::Desktop {
            return Err(AuthorityError::Identity);
        }
        self.machine.lineage()
    }
    pub fn reserve_generation(
        &mut self,
        authorization: &ServicePeerAuthorization,
        expected: &AuthorityLineage,
    ) -> Result<AuthorityLineage> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        self.advance_timers(Instant::now())?;
        let mut candidate = self.machine.clone();
        let allocated = candidate.reserve_generation(&peer, expected)?;
        self.commit(candidate)?;
        self.after_publication(authorization, deadline)?;
        Ok(allocated)
    }
    pub fn prepare(
        &mut self,
        authorization: &ServicePeerAuthorization,
        input: PrepareRequest,
    ) -> Result<PreparedTicket> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        if peer.role != Role::Desktop {
            return Err(AuthorityError::Identity);
        }
        input.validate()?;
        self.advance_timers(Instant::now())?;
        if input.expected_revision != self.machine.revision() {
            return Err(AuthorityError::Stale);
        }
        let ticket = Ticket::generate()?;
        let process = authorization.process().retain()?;
        let mut candidate = self.machine.clone();
        let context = candidate.prepare(
            &input,
            &peer,
            uuid::Uuid::new_v4(),
            ticket.digest(),
            Instant::now(),
        )?;
        self.commit(candidate)?;
        self.owner_session = Some(authorization.owner().clone());
        self.host_process = Some(process);
        self.after_publication(authorization, deadline)?;
        Ok(PreparedTicket { context, ticket })
    }
    pub fn bind_user_agent(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: LeaseContext,
        ticket: &[u8],
    ) -> Result<RuntimeStartAuthorization> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        if peer.role != Role::UserAgent {
            return Err(AuthorityError::Identity);
        }
        let now = Instant::now();
        self.advance_timers(now)?;
        let process = authorization.process().retain()?;
        let mut candidate = self.machine.clone();
        candidate.bind(&peer, &context, ticket, now)?;
        self.commit(candidate)?;
        self.runtime_process = Some(process);
        self.after_publication(authorization, deadline)?;
        Ok(RuntimeStartAuthorization {
            context,
            committed_revision: self.machine.revision(),
        })
    }
    pub fn ready(
        &mut self,
        authorization: &ServicePeerAuthorization,
        report: ReadyReport,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let now = Instant::now();
        self.advance_timers(now)?;
        let mut candidate = self.machine.clone();
        candidate.ready(&peer, &report, now)?;
        self.commit(candidate)?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }
    pub fn heartbeat(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let now = Instant::now();
        self.advance_timers(now)?;
        self.machine.heartbeat(&peer, context, now)?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }
    pub fn begin_stop(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
        expected_revision: u64,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let now = Instant::now();
        self.advance_timers(now)?;
        let mut candidate = self.machine.clone();
        if self.machine.phase() == AuthorityState::Preparing {
            if self.machine.context() != Some(context) {
                return Err(AuthorityError::Stale);
            }
            candidate.abort_prepared(Some(&peer), expected_revision, now)?;
            self.commit(candidate)?;
            let mut candidate = self.machine.clone();
            candidate.finish_unbound_abort()?;
            self.commit(candidate)?;
        } else {
            candidate.begin_stop(&peer, context, expected_revision, now)?;
            self.commit(candidate)?;
        }
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }
    pub fn abort_prepared(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
        expected_revision: u64,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        if self.machine.context() != Some(context) {
            return Err(AuthorityError::Stale);
        }
        let mut candidate = self.machine.clone();
        candidate.abort_prepared(Some(&peer), expected_revision, Instant::now())?;
        self.commit(candidate)?;
        let mut candidate = self.machine.clone();
        candidate.finish_unbound_abort()?;
        self.commit(candidate)?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }
    pub fn stopped(
        &mut self,
        authorization: &ServicePeerAuthorization,
        report: StoppedReport,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let now = Instant::now();
        self.advance_timers(now)?;
        let mut candidate = self.machine.clone();
        candidate.stopped(&peer, &report, now)?;
        self.commit(candidate)?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }
    pub fn owned_lease(&self, authorization: &ServicePeerAuthorization) -> Result<LeaseContext> {
        let peer = self.admit(authorization, Instant::now() + ADMISSION)?;
        self.machine.lease_for_owner(&peer)
    }
    fn advance_timers(&mut self, now: Instant) -> Result<()> {
        match self.machine.timer_action(now)? {
            TimerAction::None => Ok(()),
            TimerAction::AbortUnbound => {
                let mut candidate = self.machine.clone();
                candidate.abort_prepared(None, candidate.revision(), now)?;
                self.commit(candidate)?;
                let mut candidate = self.machine.clone();
                candidate.finish_unbound_abort()?;
                self.commit(candidate)
            }
            TimerAction::Revoke => {
                let mut candidate = self.machine.clone();
                candidate.revoke(false, now)?;
                self.commit(candidate)
            }
            TimerAction::Quarantine => {
                let mut candidate = self.machine.clone();
                candidate.quarantine_expired_stop()?;
                self.commit(candidate)
            }
        }
    }
    fn revoke_current(&mut self, console_change: bool, now: Instant) -> Result<()> {
        if self.machine.phase() == AuthorityState::Preparing {
            let mut candidate = self.machine.clone();
            candidate.abort_prepared(None, candidate.revision(), now)?;
            self.commit(candidate)?;
            let mut candidate = self.machine.clone();
            candidate.finish_unbound_abort()?;
            self.commit(candidate)
        } else {
            let mut candidate = self.machine.clone();
            candidate.revoke(console_change, now)?;
            self.commit(candidate)
        }
    }
    /// A successful poll reports policy state, never completed OS cleanup. On an
    /// observation error, revocation is attempted and the error still propagates;
    /// the supervisor must use cleanup_target/recovery_target to stop resources.
    pub fn poll(&mut self) -> Result<AuthoritySnapshot> {
        require_service()?;
        let now = Instant::now();
        self.advance_timers(now)?;
        if self.machine.context().is_none() {
            return Ok(self.snapshot());
        }
        let console = LiveConsoleSession::observe();
        match console {
            Ok(console) if self.owner_session.as_ref() == Some(console.identity()) => {}
            Ok(_) | Err(ServiceAuthorizationError::NoActiveConsole) => {
                self.revoke_current(true, now)?;
                return Ok(self.snapshot());
            }
            Err(error) => {
                self.revoke_current(false, now)?;
                return Err(error.into());
            }
        }
        let observed = (|| {
            self.host_process
                .as_ref()
                .ok_or(AuthorityError::Identity)?
                .revalidate()?;
            if self.machine.is_bound() {
                self.runtime_process
                    .as_ref()
                    .ok_or(AuthorityError::Identity)?
                    .revalidate()?;
            }
            Ok(())
        })();
        if let Err(error) = observed {
            self.revoke_current(false, now)?;
            return Err(error);
        }
        Ok(self.snapshot())
    }
    #[cfg(feature = "native-service-validation")]
    pub fn interrupt_next_publication_for_validation(
        &mut self,
        point: crate::authority_journal::JournalFaultPoint,
    ) -> Result<()> {
        if self.next_fault.is_some() {
            return Err(AuthorityError::Invalid);
        }
        self.next_fault = Some(point);
        Ok(())
    }
}
fn require_service() -> Result<()> {
    crate::service_peer::require_system_service_identity()
        .map_err(ServiceAuthorizationError::from)?;
    Ok(())
}
