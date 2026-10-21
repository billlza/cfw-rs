//! Startup admission from an explicit, protected Off record. A retired record
//! is prior proof, never a fabricated fresh native process count or new lease.
use super::super::{RuntimeProcessObservation, RuntimeProcessState};
use super::*;
use crate::authority_journal::RecoveryAction;

/// Fresh native checking of an existing protected Off record. Constructing
/// this observation publishes no authority transition and grants no lease.
pub struct ObservedRecordedOff {
    record: AuthorityCommittedState,
    processes: RuntimeProcessObservation,
    retired: bool,
    empty_controller: bool,
}
impl ObservedRecordedOff {
    pub fn record(&self) -> &AuthorityCommittedState {
        &self.record
    }
    pub fn processes(&self) -> &RuntimeProcessObservation {
        &self.processes
    }
}

pub struct VerifiedOffAdmission {
    prior: AuthorityCommittedState,
    processes: RuntimeProcessObservation,
    snapshot: AuthoritySnapshot,
}
impl VerifiedOffAdmission {
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
    /// Observe an existing Off record after open/reload without entering Off
    /// in this controller or publishing a new revision. Recovery of an already
    /// pending journal publication still follows the normal journal contract.
    /// Active, Preparing, Stopping, Quarantined and unknown records are rejected.
    pub fn observe_recorded_off(&mut self) -> Result<ObservedRecordedOff> {
        require_service()?;
        let target = self.machine.recorded_off_target()?;
        let empty_controller = self.owner_session.is_none()
            && self.host_process.is_none()
            && self.runtime_process.is_none()
            && self.runtime_job.is_none()
            && self.cleanup_context.is_none()
            && self.proxy_recovery.is_none()
            && !self.keeper_confirmed
            && !self.desktop_reference_issued
            && !self.desktop_reference_confirmed;
        if !empty_controller {
            return Err(AuthorityError::CleanupUnproven);
        }
        self.recheck_recorded_off(&target)?;
        let processes = self.observe_runtime_processes()?;
        let retired = processes.root() == target.root()
            && match processes.state() {
                RuntimeProcessState::NoRuntimeRoot => {
                    target.root().epoch == 0 && target.root().generation == 0
                }
                RuntimeProcessState::DurablyRetired => {
                    target.root().epoch != 0 && target.root().generation != 0
                }
                RuntimeProcessState::Accounting { active: 0, .. } => {
                    target.root().epoch != 0 && target.root().generation != 0
                }
                _ => false,
            };
        if !retired {
            return Err(AuthorityError::CleanupUnproven);
        }
        self.recheck_recorded_off(&target)?;
        Ok(ObservedRecordedOff {
            record: target,
            processes,
            retired,
            empty_controller,
        })
    }

    /// Called by the trusted service supervisor before offering operations.
    /// Admission is a state transition; maintenance observations use the method
    /// above so repeated reads cannot advance the durable authority revision.
    pub fn verify_recorded_off(&mut self) -> Result<VerifiedOffAdmission> {
        let observed = self.observe_recorded_off()?;
        let target = observed.record;
        let processes = observed.processes;
        // Schema-6 Off is committed only after all owned runtime effects have
        // retired, or before any runtime has been admitted. Subsequent grants
        // must first change this protected record. External/user-owned network
        // settings are not relabelled as application-owned cleanup obligations.
        // The private observation constructor has checked an empty controller
        // and exact native retirement before any of these conditions are set.
        let proof = CleanupEvidence {
            binding: CleanupBinding::RecordedOff(target.clone()),
            revision: target.revision(),
            lease_id: None,
            proxy_listener_closed: observed.retired,
            system_proxy_restored: observed.retired,
            tunnel_engine_stopped: observed.retired,
            packet_pump_closed: observed.retired,
            managed_tunnel_off: observed.retired,
            endpoints_closed: observed.empty_controller && observed.retired,
            secret_buffers_cleared: observed.empty_controller && observed.retired,
        };
        // Re-read the anchored journal after native observation as well. The
        // normal supervisor also holds its lifecycle guard through this call.
        self.recheck_recorded_off(&target)?;
        let snapshot = self.reconcile_off(proof)?;
        Ok(VerifiedOffAdmission {
            prior: target,
            processes,
            snapshot,
        })
    }
    fn recheck_recorded_off(&mut self, expected: &AuthorityCommittedState) -> Result<()> {
        let recovered = match self.journal.recover() {
            Ok(recovered) => recovered,
            Err(error) => {
                self.suspend(true);
                return Err(error.into());
            }
        };
        if recovered.committed.as_ref() != Some(expected)
            || recovered.action != RecoveryAction::VerifyOff
        {
            self.suspend(true);
            return Err(AuthorityError::Stale);
        }
        Ok(())
    }
}
