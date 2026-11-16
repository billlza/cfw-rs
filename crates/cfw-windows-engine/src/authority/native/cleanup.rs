//! Production reconciliation, under the schema-6 resource contract, of a run
//! that owned this user's proxy settings. A combined run enters only with
//! SYSTEM's own native observation of its adapter and pump; a plain Tunnel
//! run never enters. No wire Boolean becomes a cleanup fact here.
use super::super::{ProcessRetirement, ProxyRecoveryObservation, ProxyRecoveryPurpose};
use super::*;
use crate::RunMode;

impl WindowsAuthority {
    pub(in crate::authority) fn reconcile_proxy_cleanup(
        &mut self,
        authorization: &ServicePeerAuthorization,
        observed: &ProxyRecoveryObservation,
    ) -> Result<AuthoritySnapshot> {
        require_service()?;
        let deadline = (Instant::now() + ADMISSION).min(observed.expires);
        let peer = self.admit(authorization, deadline)?;
        if observed.context.purpose() != ProxyRecoveryPurpose::ReconcileOff
            || observed.connection != peer.connection
            || observed.context.observer() != &peer.owner
            || peer.role != Role::Desktop
        {
            return Err(AuthorityError::Identity);
        }
        observed.context.target().matches(
            &self.machine,
            &peer,
            ProxyRecoveryPurpose::ReconcileOff,
        )?;

        // Reopen under the lifecycle guard again immediately before composing
        // cleanup evidence. A missing name alone never establishes retired
        // processes.
        let processes = self.observe_runtime_processes()?;
        let target = observed.context.target();
        let retirement = processes.run_retirement(&target.root);
        let retired = retirement.is_some();
        // Independently read both native TCP listener tables. A reused PID
        // with any listener conservatively blocks cleanup; a lookup failure is
        // not an empty result and cannot be turned into Off. A run whose logon
        // has ended is the exception: its process identifier can only name a
        // process of a later logon, whose listeners this run never owned.
        let listeners_closed = retirement == Some(ProcessRetirement::LogonEnded)
            || crate::listeners::owned(observed.recorded_process_id())
                .map_err(AuthorityError::RuntimeEndpoints)?
                .is_empty();

        // A SystemProxy run is an ordinary UserAgent/engine tree: its plan and
        // checked configuration reject a tunnel, system WireGuard interfaces
        // and extra services, and the exclusive Authority sequence required
        // the preceding root to be Off, so it owns no adapter or packet pump.
        // A combined run does. Those are SYSTEM's own, and they are observed
        // gone here, natively; nothing in this report speaks for them. Until
        // then the proof is refused and nothing is recorded: the Desktop has
        // restored the settings already and gives its proof again.
        let no_tunnel_resources = match target.operation.mode() {
            RunMode::SystemProxy => true,
            RunMode::TunnelSystemProxy => {
                retired && self.combined_tunnel_retired(target.root.installation_id)?
            }
            RunMode::LocalProxy | RunMode::Tunnel => false,
        };
        let execution_material_retired = match self.machine.phase() {
            AuthorityState::Recovering => {
                self.machine.context().is_none()
                    && !self.keeper_confirmed
                    && !self.desktop_reference_issued
                    && !self.desktop_reference_confirmed
            }
            AuthorityState::Stopping => {
                // Original binding and non-secret operation identity remain
                // until GlobalOff commits. No ticket or accepted Ready remains.
                self.machine
                    .stopped_cleanup_context(&peer, target.revision)?;
                true
            }
            _ => return Err(AuthorityError::CleanupUnproven),
        };
        let authority_cleared = execution_material_retired && self.proxy_recovery.is_none();
        // The consumed report has dropped its zeroizing ticket. Dispatch erased
        // the raw request copy. The Authority never receives profile secrets;
        // runtime-owner address spaces and their private IPC died with the run.
        let request_erased = authorization.request().body().is_empty();
        let evidence = CleanupEvidence {
            binding: CleanupBinding::Runtime(target.clone()),
            revision: target.revision,
            lease_id: Some(target.operation.lease_id()),
            proxy_listener_closed: retired && listeners_closed,
            system_proxy_restored: observed.context.purpose() == ProxyRecoveryPurpose::ReconcileOff,
            tunnel_engine_stopped: no_tunnel_resources && retired,
            packet_pump_closed: no_tunnel_resources && retired,
            managed_tunnel_off: no_tunnel_resources,
            endpoints_closed: authority_cleared && retired && listeners_closed,
            secret_buffers_cleared: authority_cleared && request_erased && retired,
        };
        evidence.validate_scope(self.machine.metadata())?;
        if !evidence.exact() {
            return Err(AuthorityError::CleanupUnproven);
        }
        authorization.revalidate(
            self.owner_session.as_ref(),
            UserAgentLeaseRequirement::OwnedLease,
            deadline,
        )?;
        let snapshot = self.reconcile_off(evidence)?;
        if target.operation.mode().owns_tunnel() {
            // Off is committed: nothing of the run's network is left to drive.
            self.tunnel = None;
            self.tunnel_recovery = None;
        }
        // Late caller/session failure remains an error, even after a committed
        // record. Unknown publication cannot issue a new lease or claim Off.
        self.after_publication(authorization, deadline)?;
        Ok(snapshot)
    }
}
