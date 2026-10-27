use super::super::{
    ProxyRecoveryContext, ProxyRecoveryPurpose, ProxyRecoveryTarget, RuntimeProcessObservation,
    RuntimeProcessState,
    recovery::ProxyRecoveryAdmission,
    wire::{ProxyRecoveryGrant, ProxyRecoveryReceipt, ProxyRecoveryReport, TicketMaterial},
};
use super::*;

/// The service independently observed the entire exact runtime Job at zero and
/// admitted a fresh proxy observation by the authenticated current-user image.
/// This scoped, time-bound fact does not attest other cleanup obligations. It
/// cannot be deserialized or constructed from client-provided process counts.
pub struct ProxyRecoveryObservation {
    pub(super) context: ProxyRecoveryContext,
    processes: RuntimeProcessObservation,
    recorded_process_id: u32,
    recorded_process_creation_time: u64,
    observed_at: Instant,
    pub(super) expires: Instant,
    pub(super) connection: crate::connection_binding::ConnectionBinding,
}
impl ProxyRecoveryObservation {
    pub fn context(&self) -> &ProxyRecoveryContext {
        &self.context
    }
    pub fn processes(&self) -> &RuntimeProcessObservation {
        &self.processes
    }
    pub fn recorded_process_id(&self) -> u32 {
        self.recorded_process_id
    }
    pub fn recorded_process_creation_time(&self) -> u64 {
        self.recorded_process_creation_time
    }
    pub fn observed_at(&self) -> Instant {
        self.observed_at
    }
    pub(in crate::authority) fn receipt(&self) -> Result<ProxyRecoveryReceipt> {
        let RuntimeProcessState::Accounting { active: 0, total } = self.processes.state() else {
            return Err(AuthorityError::CleanupUnproven);
        };
        Ok(ProxyRecoveryReceipt {
            context: self.context.clone(),
            retired_process_count: total,
        })
    }
}
impl WindowsAuthority {
    pub(in crate::authority) fn begin_proxy_recovery(
        &mut self,
        authorization: &ServicePeerAuthorization,
        target: ProxyRecoveryTarget,
        purpose: ProxyRecoveryPurpose,
    ) -> Result<ProxyRecoveryGrant> {
        require_service()?;
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        if self
            .proxy_recovery
            .as_ref()
            .is_some_and(|pending| pending.available(Instant::now()))
        {
            return Err(AuthorityError::LeaseConflict);
        }
        self.proxy_recovery = None;
        let ticket = Ticket::generate()?;
        let admission = ProxyRecoveryAdmission::new(
            &self.machine,
            &peer,
            target,
            purpose,
            ticket.recovery_digest(),
            Instant::now(),
        )?;
        self.retired_proxy_processes(&admission.context().target)?;
        authorization.revalidate(
            self.owner_session.as_ref(),
            UserAgentLeaseRequirement::OwnedLease,
            deadline,
        )?;
        if !admission.available(Instant::now()) {
            return Err(AuthorityError::Expired);
        }
        let grant = ProxyRecoveryGrant {
            context: admission.context().clone(),
            ticket: ticket
                .expose(TicketMaterial::from_slice)
                .map_err(|_| AuthorityError::Invalid)?,
        };
        self.proxy_recovery = Some(admission);
        Ok(grant)
    }
    pub(in crate::authority) fn confirm_proxy_recovery(
        &mut self,
        authorization: &ServicePeerAuthorization,
        report: ProxyRecoveryReport,
        purpose: ProxyRecoveryPurpose,
    ) -> Result<ProxyRecoveryObservation> {
        require_service()?;
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let pending = self.proxy_recovery.as_ref().ok_or(AuthorityError::Ticket)?;
        if !pending.belongs_to(&peer) {
            return Err(AuthorityError::Identity);
        }
        // One owning-connection attempt consumes the challenge even if native
        // observation later fails. No retry of uncertain delivery is authorized.
        let pending = self.proxy_recovery.take().ok_or(AuthorityError::Ticket)?;
        let (context, expires) = report.ticket.with_bytes(|ticket| {
            pending.consume(
                &self.machine,
                &peer,
                &report.context,
                ticket,
                Instant::now(),
            )
        })?;
        if context.purpose() != purpose {
            return Err(AuthorityError::Identity);
        }
        let processes = self.retired_proxy_processes(&context.target)?;
        authorization.revalidate(
            self.owner_session.as_ref(),
            UserAgentLeaseRequirement::OwnedLease,
            deadline.min(expires),
        )?;
        Ok(ProxyRecoveryObservation {
            context,
            processes,
            recorded_process_id: report.recorded_process_id,
            recorded_process_creation_time: report.recorded_process_creation_time,
            observed_at: Instant::now(),
            expires,
            connection: authorization.request().binding(),
        })
    }
    fn retired_proxy_processes(
        &self,
        target: &ProxyRecoveryTarget,
    ) -> Result<RuntimeProcessObservation> {
        let observed = self.observe_runtime_processes()?;
        if observed.root() != &target.root
            || !matches!(
                observed.state(),
                RuntimeProcessState::Accounting {
                    active: 0,
                    total: 1..
                }
            )
        {
            return Err(AuthorityError::CleanupUnproven);
        }
        Ok(observed)
    }
}
