//! LocalProxy normal-stop and recovery cleanup. The schema-6 contract admits only
//! process-local sockets/pipes; no system proxy, managed interface or packet
//! pump is created. This proof is not usable for SystemProxy or Tunnel.
use super::super::{RuntimeProcessObservation, RuntimeProcessState};
use super::*;
use cfw_engine_api::authority_v1::AuthorityMode;

pub struct VerifiedLocalCleanup {
    prior: AuthorityCommittedState,
    processes: RuntimeProcessObservation,
    snapshot: AuthoritySnapshot,
}
impl VerifiedLocalCleanup {
    pub fn prior(&self) -> &AuthorityCommittedState {
        &self.prior
    }
    pub fn processes(&self) -> &RuntimeProcessObservation {
        &self.processes
    }
    pub fn snapshot(&self) -> &AuthoritySnapshot {
        &self.snapshot
    }
}
impl WindowsAuthority {
    /// Trusted supervisor entrypoint after an acknowledged LocalProxy stop.
    /// A live member or unavailable native observer fails explicitly. The
    /// acknowledgement alone never certifies termination of the entire tree.
    pub fn reconcile_local_stop(&mut self) -> Result<VerifiedLocalCleanup> {
        require_service()?;
        let target = self.machine.local_stopped_cleanup_target()?;
        self.reconcile_local_runtime(target)
    }
    /// Reconcile a known LocalProxy record after losing the execution lease.
    /// The old acknowledgement is not reconstructed. Independent whole-Job
    /// retirement and the bounded resource contract replace it for recovery;
    /// a missing Job, unknown journal, live member or another mode still fails.
    pub fn reconcile_local_recovery(&mut self) -> Result<VerifiedLocalCleanup> {
        require_service()?;
        let target = self.machine.local_recovery_target()?;
        if self.machine.context().is_some()
            || self.keeper_confirmed
            || self.desktop_reference_issued
            || self.desktop_reference_confirmed
            || self.proxy_recovery.is_some()
        {
            return Err(AuthorityError::CleanupUnproven);
        }
        self.reconcile_local_runtime(target)
    }
    fn reconcile_local_runtime(
        &mut self,
        target: AuthorityCommittedState,
    ) -> Result<VerifiedLocalCleanup> {
        let operation = target.operation().ok_or(AuthorityError::CleanupUnproven)?;
        let process_local = operation.mode() == AuthorityMode::LocalProxy;
        let processes = self.observe_runtime_processes()?;
        let retired = processes.root() == target.root()
            && matches!(
                processes.state(),
                RuntimeProcessState::Accounting {
                    active: 0,
                    total: 1..
                }
            );
        if !retired || !process_local || self.proxy_recovery.is_some() {
            return Err(AuthorityError::CleanupUnproven);
        }
        // Windows closes a terminated process's handles. The exact SYSTEM Job
        // includes the Agent and all descendants; admission disallows breakaway
        // and the pinned runtime never exports sockets outside that tree. Job
        // zero therefore retires its TCP/UDP sockets, private IPC and memory.
        // Configuration validation excludes system interfaces/extra services.
        // These process-local facts cannot substitute for per-user WinINet or
        // TUN/route/DNS restoration in another mode.
        let evidence = CleanupEvidence {
            binding: CleanupBinding::LocalRuntime(target.clone()),
            revision: target.revision(),
            lease_id: Some(operation.lease_id()),
            proxy_listener_closed: retired,
            system_proxy_restored: process_local,
            tunnel_engine_stopped: process_local && retired,
            packet_pump_closed: process_local,
            managed_tunnel_off: process_local,
            endpoints_closed: retired,
            secret_buffers_cleared: retired,
        };
        evidence.validate_scope(self.machine.metadata())?;
        let snapshot = self.reconcile_off(evidence)?;
        Ok(VerifiedLocalCleanup {
            prior: target,
            processes,
            snapshot,
        })
    }
}
