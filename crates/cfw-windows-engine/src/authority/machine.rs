use super::{AuthorityError, Result, secret::TicketDigest, types::*};
use crate::authority_journal::{AuthorityCommittedState, JournalRecovery, JournalTransition};
use cfw_engine_api::authority_v1::{AuthorityState, LeaseState};
use std::time::{Duration, Instant};
use uuid::Uuid;

const PREPARATION: Duration =
    Duration::from_millis(cfw_engine_api::authority_v1::PREPARATION_LIFETIME_MS);
const HEARTBEAT: Duration = Duration::from_millis(cfw_engine_api::authority_v1::COMMAND_TIMEOUT_MS);
const STOP: Duration =
    Duration::from_millis(cfw_engine_api::authority_v1::STOP_ATTESTATION_TIMEOUT_MS);

#[derive(Clone)]
struct Lease {
    context: LeaseContext,
    state: LeaseState,
    host: Peer,
    runtime: Option<Peer>,
    ticket: Option<TicketDigest>,
    expires: Instant,
    heartbeat: Option<Instant>,
    stop_deadline: Option<Instant>,
    owner_stopped: bool,
    accepted_ready: Option<ReadyReport>,
}
#[derive(Clone)]
pub(super) struct Machine {
    phase: AuthorityState,
    revision: u64,
    durable_known: bool,
    metadata: Option<AuthorityCommittedState>,
    lease: Option<Lease>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TimerAction {
    None,
    AbortUnbound,
    Revoke,
    Quarantine,
}

impl Machine {
    pub(super) fn recovering(recovery: JournalRecovery) -> Result<Self> {
        match (&recovery.committed, &recovery.cursor) {
            (None, None)
                if recovery.action == crate::authority_journal::RecoveryAction::VerifyOff => {}
            (Some(state), Some(cursor))
                if state.revision() == cursor.state_revision()
                    && state.restart_action()? == recovery.action =>
            {
                state.encode()?;
            }
            _ => return Err(AuthorityError::Invalid),
        }
        let revision = recovery
            .committed
            .as_ref()
            .map_or(1, AuthorityCommittedState::revision);
        Ok(Self {
            phase: AuthorityState::Recovering,
            revision,
            durable_known: true,
            metadata: recovery.committed,
            lease: None,
        })
    }
    pub(super) fn snapshot(&self) -> AuthoritySnapshot {
        AuthoritySnapshot {
            state: self.phase,
            revision: self.durable_known.then_some(self.revision),
            root: if self.durable_known {
                self.metadata.as_ref().map(|s| s.root().clone())
            } else {
                None
            },
        }
    }
    pub(super) fn metadata(&self) -> Option<&AuthorityCommittedState> {
        self.metadata.as_ref()
    }
    pub(super) fn phase(&self) -> AuthorityState {
        self.phase
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }
    pub(super) fn durable_known(&self) -> bool {
        self.durable_known
    }
    pub(super) fn recorded_off_target(&self) -> Result<AuthorityCommittedState> {
        if !self.durable_known || self.phase != AuthorityState::Recovering {
            return Err(AuthorityError::Recovering);
        }
        let metadata = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        metadata.validate()?;
        if self.lease.is_some()
            || metadata.state() != AuthorityState::Off
            || metadata.operation().is_some()
        {
            return Err(AuthorityError::CleanupUnproven);
        }
        Ok(metadata.clone())
    }
    pub(super) fn context(&self) -> Option<&LeaseContext> {
        self.lease.as_ref().map(|lease| &lease.context)
    }
    pub(super) fn is_bound(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.runtime.is_some())
    }
    pub(super) fn runtime_liveness_required(&self) -> bool {
        self.lease.as_ref().is_some_and(|lease| {
            lease.runtime.is_some()
                && !(self.phase == AuthorityState::Stopping && lease.owner_stopped)
        })
    }
    pub(super) fn enter_recovery(&mut self, uncertain: bool) {
        // Keep the last known metadata for cleanup, but never expose its revision
        // as current after an uncertain write. Dropping the lease erases tickets.
        self.phase = AuthorityState::Recovering;
        self.durable_known &= !uncertain;
        self.lease = None;
    }
    fn expected_revision(&self, expected: u64) -> Result<()> {
        if !self.durable_known {
            return Err(AuthorityError::Recovering);
        }
        if expected != self.revision {
            return Err(AuthorityError::Stale);
        }
        Ok(())
    }
    fn next_revision(&self) -> Result<u64> {
        self.revision.checked_add(1).ok_or(AuthorityError::Invalid)
    }
    fn require_phase_off(&self) -> Result<()> {
        match self.phase {
            AuthorityState::Off => Ok(()),
            AuthorityState::Recovering => Err(AuthorityError::Recovering),
            AuthorityState::Quarantined => Err(AuthorityError::Quarantined),
            _ => Err(AuthorityError::LeaseConflict),
        }
    }
    pub(super) fn enroll(&mut self, installation: Uuid) -> Result<()> {
        if !matches!(self.phase, AuthorityState::Off | AuthorityState::Recovering)
            || !self.durable_known
            || self.metadata.is_some()
            || self.lease.is_some()
            || self.revision != 1
            || installation.is_nil()
        {
            return Err(AuthorityError::Replay);
        }
        self.metadata = Some(AuthorityCommittedState::enrollment(installation));
        Ok(())
    }
    pub(super) fn lineage(&self) -> Result<AuthorityLineage> {
        if !self.durable_known {
            return Err(AuthorityError::Recovering);
        }
        let state = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        Ok(AuthorityLineage {
            installation_id: state.root().installation_id,
            config_epoch: state.root().epoch.max(1),
            generation: state.allocated_generation(),
        })
    }
    pub(super) fn recorded_runtime_scope(&self) -> Result<RecordedRuntimeScope> {
        if !self.durable_known {
            return Err(AuthorityError::Recovering);
        }
        let metadata = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        Ok(RecordedRuntimeScope {
            snapshot: self.snapshot(),
            operation: metadata.operation().cloned(),
        })
    }
    pub(super) fn reserve_generation(
        &mut self,
        host: &Peer,
        expected: &AuthorityLineage,
    ) -> Result<AuthorityLineage> {
        expected.validate()?;
        host.live()?;
        if host.role != Role::Desktop {
            return Err(AuthorityError::Identity);
        }
        self.require_phase_off()?;
        if &self.lineage()? != expected {
            return Err(AuthorityError::Stale);
        }
        if expected.generation == u64::MAX {
            return Err(AuthorityError::GenerationExhausted);
        }
        let next = self
            .metadata
            .as_ref()
            .ok_or(AuthorityError::Recovering)?
            .reserve_next_generation()?;
        self.revision = next.revision();
        self.metadata = Some(next);
        self.lineage()
    }
    pub(super) fn prepare(
        &mut self,
        input: &PrepareRequest,
        host: &Peer,
        lease_id: Uuid,
        ticket: TicketDigest,
        now: Instant,
    ) -> Result<LeaseContext> {
        input.validate()?;
        host.live()?;
        self.expected_revision(input.expected_revision)?;
        self.require_phase_off()?;
        if host.role != Role::Desktop {
            return Err(AuthorityError::Identity);
        }
        if self.lease.is_some() || lease_id.is_nil() {
            return Err(AuthorityError::LeaseConflict);
        }
        let prior = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        if prior.root().installation_id != input.root.installation_id
            || input.root.epoch != prior.root().epoch.max(1)
            || input.root.generation != prior.allocated_generation()
            || (input.root.epoch, input.root.generation)
                <= (prior.root().epoch, prior.root().generation)
        {
            return Err(AuthorityError::Replay);
        }
        let revision = self.next_revision()?;
        let context = LeaseContext {
            operation: OperationContext {
                root: input.root.clone(),
                operation_id: input.operation_id,
                mode: input.mode,
                config_sha256: input.config_sha256,
                identity_sha256: input.identity_sha256,
                owner: host.owner.clone(),
                prepared_revision: revision,
            },
            lease_id,
        };
        let expires = now
            .checked_add(PREPARATION)
            .ok_or(AuthorityError::Invalid)?;
        let metadata = AuthorityCommittedState::new(
            input.root.clone(),
            revision,
            JournalTransition::Prepare,
            AuthorityState::Preparing,
            Some(context.recorded()?),
        )?;
        metadata.validate_successor(prior)?;
        self.metadata = Some(metadata);
        self.revision = revision;
        self.phase = AuthorityState::Preparing;
        self.lease = Some(Lease {
            context: context.clone(),
            state: LeaseState::Prepared,
            host: host.clone(),
            runtime: None,
            ticket: Some(ticket),
            expires,
            heartbeat: None,
            stop_deadline: None,
            owner_stopped: false,
            accepted_ready: None,
        });
        Ok(context)
    }
    fn lease_exact(&self, context: &LeaseContext) -> Result<&Lease> {
        let lease = self.lease.as_ref().ok_or(AuthorityError::Stale)?;
        if &lease.context != context {
            return Err(AuthorityError::Stale);
        }
        Ok(lease)
    }
    fn host_exact(&self, peer: &Peer, context: &LeaseContext) -> Result<()> {
        peer.live()?;
        let lease = self.lease_exact(context)?;
        if peer.role != Role::Desktop || !peer.same(&lease.host) {
            return Err(AuthorityError::Identity);
        }
        Ok(())
    }
    fn runtime_exact(&self, peer: &Peer, context: &LeaseContext) -> Result<()> {
        peer.live()?;
        let lease = self.lease_exact(context)?;
        if peer.role != expected_role(context.operation.mode)
            || lease.runtime.as_ref().is_none_or(|bound| !peer.same(bound))
        {
            return Err(AuthorityError::Identity);
        }
        Ok(())
    }
    fn transition(&mut self, kind: JournalTransition, phase: AuthorityState) -> Result<()> {
        let revision = self.next_revision()?;
        let previous = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        let operation = if phase == AuthorityState::Off {
            None
        } else if let Some(lease) = &self.lease {
            Some(lease.context.recorded()?)
        } else {
            previous.operation().cloned()
        };
        let metadata = previous.transition_to(revision, kind, phase, operation)?;
        self.metadata = Some(metadata);
        self.revision = revision;
        self.phase = phase;
        Ok(())
    }
    pub(super) fn bind(
        &mut self,
        peer: &Peer,
        context: &LeaseContext,
        ticket: &[u8],
        now: Instant,
    ) -> Result<()> {
        peer.live()?;
        let lease = self.lease_exact(context)?;
        if self.phase != AuthorityState::Preparing {
            return Err(AuthorityError::Ticket);
        }
        if now >= lease.expires {
            return Err(AuthorityError::Expired);
        }
        if peer.owner != context.operation.owner
            || peer.role != expected_role(context.operation.mode)
        {
            return Err(AuthorityError::Identity);
        }
        if lease
            .ticket
            .as_ref()
            .is_none_or(|expected| !expected.accepts(ticket))
        {
            return Err(AuthorityError::Ticket);
        }
        self.transition(JournalTransition::BindOwner, AuthorityState::Starting)?;
        let lease = self.lease.as_mut().ok_or(AuthorityError::Stale)?;
        lease.ticket = None;
        lease.runtime = Some(peer.clone());
        lease.state = LeaseState::Starting;
        lease.heartbeat = Some(now);
        Ok(())
    }
    pub(super) fn ready(&mut self, peer: &Peer, report: &ReadyReport, now: Instant) -> Result<()> {
        report.validate()?;
        self.runtime_exact(peer, &report.context)?;
        let lease = self.lease_exact(&report.context)?;
        if self.phase == AuthorityState::Active {
            if lease.state == LeaseState::Active && lease.accepted_ready.as_ref() == Some(report) {
                return Ok(());
            }
            return Err(AuthorityError::Stale);
        }
        if self.phase != AuthorityState::Starting {
            return Err(AuthorityError::Stale);
        }
        self.transition(JournalTransition::Ready, AuthorityState::Active)?;
        let lease = self.lease.as_mut().ok_or(AuthorityError::Stale)?;
        lease.state = LeaseState::Active;
        lease.accepted_ready = Some(report.clone());
        lease.heartbeat = Some(now);
        Ok(())
    }
    pub(super) fn heartbeat(
        &mut self,
        peer: &Peer,
        context: &LeaseContext,
        now: Instant,
    ) -> Result<()> {
        self.runtime_exact(peer, context)?;
        if !matches!(
            self.phase,
            AuthorityState::Starting | AuthorityState::Active | AuthorityState::Stopping
        ) {
            return Err(AuthorityError::Stale);
        }
        let lease = self.lease.as_mut().ok_or(AuthorityError::Stale)?;
        if lease.heartbeat.is_some_and(|prior| now < prior) {
            return Err(AuthorityError::Invalid);
        }
        lease.heartbeat = Some(now);
        Ok(())
    }
    pub(super) fn begin_stop(
        &mut self,
        peer: &Peer,
        context: &LeaseContext,
        expected: u64,
        now: Instant,
    ) -> Result<()> {
        self.host_exact(peer, context)?;
        if self.phase == AuthorityState::Stopping {
            if expected == self.revision
                || expected.checked_add(1) == Some(self.revision)
                    && self
                        .metadata
                        .as_ref()
                        .is_some_and(|s| s.transition() == JournalTransition::BeginStop)
            {
                return Ok(());
            }
            return Err(AuthorityError::Stale);
        }
        self.expected_revision(expected)?;
        if !matches!(
            self.phase,
            AuthorityState::Preparing | AuthorityState::Starting | AuthorityState::Active
        ) {
            return Err(AuthorityError::Stale);
        }
        self.stop(JournalTransition::BeginStop, now)
    }
    fn stop(&mut self, transition: JournalTransition, now: Instant) -> Result<()> {
        let deadline = now.checked_add(STOP).ok_or(AuthorityError::Invalid)?;
        self.transition(transition, AuthorityState::Stopping)?;
        let lease = self.lease.as_mut().ok_or(AuthorityError::Stale)?;
        lease.ticket = None;
        lease.accepted_ready = None;
        lease.owner_stopped = false;
        lease.stop_deadline = Some(deadline);
        lease.state = if matches!(
            transition,
            JournalTransition::RevokeForTimeout | JournalTransition::RevokeForConsoleChange
        ) {
            LeaseState::Revoked
        } else {
            LeaseState::Stopping
        };
        Ok(())
    }
    pub(super) fn abort_prepared(
        &mut self,
        peer: Option<&Peer>,
        expected: u64,
        now: Instant,
    ) -> Result<()> {
        self.expected_revision(expected)?;
        let context = self.context().cloned().ok_or(AuthorityError::Stale)?;
        if let Some(peer) = peer {
            self.host_exact(peer, &context)?;
        }
        if self.phase != AuthorityState::Preparing || self.is_bound() {
            return Err(AuthorityError::Stale);
        }
        self.stop(JournalTransition::AbortPrepared, now)?;
        self.lease
            .as_mut()
            .ok_or(AuthorityError::Stale)?
            .owner_stopped = true;
        Ok(())
    }
    pub(super) fn finish_unbound_abort(&mut self) -> Result<()> {
        let lease = self.lease.as_ref().ok_or(AuthorityError::Stale)?;
        if self.phase != AuthorityState::Stopping
            || !lease.owner_stopped
            || lease.runtime.is_some()
            || lease.ticket.is_some()
            || self
                .metadata
                .as_ref()
                .is_none_or(|s| s.transition() != JournalTransition::AbortPrepared)
        {
            return Err(AuthorityError::CleanupUnproven);
        }
        // No runtime authorization was issued: preparation could not mutate
        // the data plane. This proof is in-memory only and never reconstructed
        // from an AbortPrepared record after a restart.
        self.transition(JournalTransition::GlobalOff, AuthorityState::Off)?;
        self.lease = None;
        Ok(())
    }
    pub(super) fn revoke(&mut self, console_change: bool, now: Instant) -> Result<()> {
        if self.lease.is_none()
            || matches!(
                self.phase,
                AuthorityState::Stopping | AuthorityState::Quarantined
            )
        {
            return Ok(());
        }
        if !matches!(
            self.phase,
            AuthorityState::Preparing | AuthorityState::Starting | AuthorityState::Active
        ) {
            return Err(AuthorityError::Stale);
        }
        self.stop(
            if console_change {
                JournalTransition::RevokeForConsoleChange
            } else {
                JournalTransition::RevokeForTimeout
            },
            now,
        )
    }
    pub(super) fn stopped(
        &mut self,
        peer: &Peer,
        report: &StoppedReport,
        now: Instant,
    ) -> Result<()> {
        report.validate()?;
        self.runtime_exact(peer, &report.context)?;
        if !matches!(
            self.phase,
            AuthorityState::Starting | AuthorityState::Active | AuthorityState::Stopping
        ) {
            return Err(AuthorityError::Stale);
        }
        if self.lease_exact(&report.context)?.owner_stopped {
            return Ok(());
        }
        let deadline = now.checked_add(STOP).ok_or(AuthorityError::Invalid)?;
        self.transition(JournalTransition::OwnerStopped, AuthorityState::Stopping)?;
        let lease = self.lease.as_mut().ok_or(AuthorityError::Stale)?;
        lease.ticket = None;
        lease.accepted_ready = None;
        lease.state = LeaseState::Stopping;
        lease.owner_stopped = true;
        lease.stop_deadline = Some(deadline);
        Ok(())
    }
    pub(super) fn reconcile(&mut self, evidence: &CleanupEvidence) -> Result<()> {
        self.expected_revision(evidence.revision)?;
        evidence.validate_scope(self.metadata.as_ref())?;
        if !matches!(
            self.phase,
            AuthorityState::Recovering | AuthorityState::Stopping | AuthorityState::Quarantined
        ) {
            return Err(AuthorityError::CleanupUnproven);
        }
        if evidence.lease_id != metadata_lease_id(self.metadata.as_ref()) {
            return Err(AuthorityError::Stale);
        }
        let exact = evidence.exact()
            && self
                .lease
                .as_ref()
                .is_none_or(|lease| lease.ticket.is_none())
            && (self.phase != AuthorityState::Stopping
                || self.lease.as_ref().is_some_and(|lease| lease.owner_stopped));
        let phase = if exact {
            AuthorityState::Off
        } else {
            AuthorityState::Quarantined
        };
        // Before the first preparation, no runtime root/lease exists to append
        // a post-start record. The durable genesis remains Off but every restart
        // still requires a fresh cleanup proof; this does not restore permission.
        if self.metadata.as_ref().is_none_or(|s| s.root().epoch == 0) {
            if self.lease.is_some() {
                return Err(AuthorityError::Invalid);
            }
            self.phase = phase;
            return Ok(());
        }
        let kind = if self.phase == AuthorityState::Stopping && exact {
            JournalTransition::GlobalOff
        } else {
            JournalTransition::ReconcileOff
        };
        self.transition(kind, phase)?;
        if exact {
            self.lease = None;
        } else if let Some(lease) = &mut self.lease {
            lease.ticket = None;
            lease.state = LeaseState::Revoked;
            lease.accepted_ready = None;
            if evidence.endpoints_closed {
                lease.runtime = None;
            }
        }
        Ok(())
    }
    pub(super) fn quarantine_expired_stop(&mut self) -> Result<()> {
        if self.phase != AuthorityState::Stopping {
            return Err(AuthorityError::Stale);
        }
        self.transition(JournalTransition::ReconcileOff, AuthorityState::Quarantined)?;
        if let Some(lease) = &mut self.lease {
            lease.ticket = None;
            lease.state = LeaseState::Revoked;
            lease.accepted_ready = None;
        }
        Ok(())
    }
    pub(super) fn timer_action(&self, now: Instant) -> Result<TimerAction> {
        let Some(lease) = &self.lease else {
            return Ok(TimerAction::None);
        };
        if self.phase == AuthorityState::Preparing {
            return Ok(
                if now >= lease.expires || !lease.host.connection.is_open() {
                    TimerAction::AbortUnbound
                } else {
                    TimerAction::None
                },
            );
        }
        if matches!(
            self.phase,
            AuthorityState::Starting | AuthorityState::Active
        ) {
            if !lease.host.connection.is_open()
                || lease
                    .runtime
                    .as_ref()
                    .is_none_or(|peer| !peer.connection.is_open())
            {
                return Ok(TimerAction::Revoke);
            }
            let last = lease.heartbeat.ok_or(AuthorityError::Invalid)?;
            let elapsed = now
                .checked_duration_since(last)
                .ok_or(AuthorityError::Invalid)?;
            return Ok(if elapsed >= HEARTBEAT {
                TimerAction::Revoke
            } else {
                TimerAction::None
            });
        }
        if self.phase == AuthorityState::Stopping
            && !lease.owner_stopped
            && lease.stop_deadline.is_some_and(|deadline| now >= deadline)
        {
            return Ok(TimerAction::Quarantine);
        }
        Ok(TimerAction::None)
    }
    pub(super) fn lease_for_owner(&self, peer: &Peer) -> Result<LeaseContext> {
        peer.live()?;
        let lease = self.lease.as_ref().ok_or(AuthorityError::Identity)?;
        if !peer.same(&lease.host)
            && lease
                .runtime
                .as_ref()
                .is_none_or(|runtime| !peer.same(runtime))
        {
            return Err(AuthorityError::Identity);
        }
        Ok(lease.context.clone())
    }
    /// A normal stop keeps its original Desktop binding until cleanup commits.
    /// The owner's report removes execution material, but native process and
    /// operating-system observations are still required before GlobalOff.
    pub(super) fn stopped_cleanup_context(
        &self,
        peer: &Peer,
        revision: u64,
    ) -> Result<&LeaseContext> {
        self.expected_revision(revision)?;
        if self.phase != AuthorityState::Stopping {
            return Err(AuthorityError::CleanupUnproven);
        }
        let lease = self.lease.as_ref().ok_or(AuthorityError::Identity)?;
        self.host_exact(peer, &lease.context)?;
        if !lease.owner_stopped || lease.ticket.is_some() || lease.accepted_ready.is_some() {
            return Err(AuthorityError::CleanupUnproven);
        }
        Ok(&lease.context)
    }
    pub(super) fn local_stopped_cleanup_target(&self) -> Result<AuthorityCommittedState> {
        if !self.durable_known {
            return Err(AuthorityError::Recovering);
        }
        if self.phase != AuthorityState::Stopping {
            return Err(AuthorityError::CleanupUnproven);
        }
        let lease = self.lease.as_ref().ok_or(AuthorityError::CleanupUnproven)?;
        let metadata = self.metadata.as_ref().ok_or(AuthorityError::Recovering)?;
        if lease.context.operation.mode != cfw_engine_api::authority_v1::AuthorityMode::LocalProxy
            || !lease.owner_stopped
            || lease.ticket.is_some()
            || lease.accepted_ready.is_some()
            || metadata.root() != &lease.context.operation.root
            || metadata.operation() != Some(&lease.context.recorded()?)
            || metadata.revision() != self.revision
        {
            return Err(AuthorityError::CleanupUnproven);
        }
        metadata.validate()?;
        Ok(metadata.clone())
    }
}
