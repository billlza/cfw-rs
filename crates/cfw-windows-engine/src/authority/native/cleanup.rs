//! Production reconciliation for the schema-6 SystemProxy resource contract.
//! Tunnel modes require their own native adapter/pump observations and cannot
//! enter this constructor. No wire Boolean becomes a cleanup fact here.
use super::super::{ProxyRecoveryObservation, ProxyRecoveryPurpose, RuntimeProcessState};
use super::*;
use cfw_engine_api::authority_v1::AuthorityMode;

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
        if !self.machine.durable_known() || self.machine.phase() != AuthorityState::Recovering {
            return Err(AuthorityError::Recovering);
        }

        // Reopen under the lifecycle guard again immediately before composing
        // cleanup evidence. Missing names never establish retired processes.
        let processes = self.observe_runtime_processes()?;
        let target = observed.context.target();
        let retired = processes.root() == &target.root
            && matches!(
                processes.state(),
                RuntimeProcessState::Accounting {
                    active: 0,
                    total: 1..
                }
            );
        // Independently read both native TCP listener tables. A reused PID
        // with any listener conservatively blocks cleanup; a lookup failure is
        // not an empty result and cannot be turned into Off.
        let listeners_closed = crate::listeners::owned(observed.recorded_process_id())
            .map_err(AuthorityError::RuntimeEndpoints)?
            .is_empty();

        // This admitted mode creates only an ordinary UserAgent/engine tree.
        // UserAgentPlan and CheckedStartConfiguration reject Tunnel activation,
        // system WireGuard interfaces and extra services here. The
        // exclusive Authority sequence required the preceding root to be Off;
        // a SystemProxy root cannot own a managed TUN adapter or packet pump.
        // These facts must not be reused for Tunnel or combined-mode cleanup.
        let no_tunnel_resources = target.operation.mode() == AuthorityMode::SystemProxy;
        let authority_cleared = self.machine.context().is_none()
            && self.proxy_recovery.is_none()
            && !self.keeper_confirmed
            && !self.desktop_reference_issued
            && !self.desktop_reference_confirmed;
        // The consumed report has dropped its zeroizing ticket. Dispatch erased
        // the raw request copy. The Authority never receives profile secrets;
        // runtime-owner address spaces and their private IPC died with the Job.
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
        // Late caller/session failure remains an error, even after a committed
        // record. Unknown publication cannot issue a new lease or claim Off.
        self.after_publication(authorization, deadline)?;
        Ok(snapshot)
    }
}
