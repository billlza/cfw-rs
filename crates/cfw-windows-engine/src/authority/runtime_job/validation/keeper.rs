//! Isolated validation of a zero-access Job handle, not a product start grant.
use super::super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Sent,
    Observed,
    Released,
}

/// The authenticated native fixture transfers one zero-access handle to its
/// bounded child. On uncertain delivery the service never closes a remote
/// handle number that the receiver might have already closed/reused. The child
/// process lifetime is the final bound. No process is assigned to this Job.
pub struct JobKeeperProbe {
    root: RootContext,
    creator: Option<OwnedHandle>,
    peer: NativePeerProcess,
    value: u64,
    phase: Phase,
}
impl JobKeeperProbe {
    pub fn new(peer: &NativePeerProcess) -> Result<Self> {
        crate::service_peer::require_system_service_identity()?;
        let peer = peer.retain()?;
        if peer.identity().is_local_system() || peer.identity().integrity_rid() != 0x2000 {
            return Err(RuntimeJobError::Security);
        }
        let root = RootContext {
            installation_id: uuid::Uuid::new_v4(),
            epoch: 1,
            generation: 1,
        };
        let creator = create(&root)?;
        let value = super::super::keeper::transfer(&creator, &peer)?;
        Ok(Self {
            root,
            creator: Some(creator),
            peer,
            value,
            phase: Phase::Sent,
        })
    }
    pub fn handle_value(&self) -> u64 {
        self.value
    }
    pub fn root(&self) -> &RootContext {
        &self.root
    }
    fn check_peer(&self, peer: &NativePeerProcess) -> Result<()> {
        crate::service_peer::require_system_service_identity()?;
        self.peer.revalidate()?;
        peer.revalidate()?;
        if peer.process_id() != self.peer.process_id() || peer.identity() != self.peer.identity() {
            return Err(RuntimeJobError::Security);
        }
        Ok(())
    }
    pub fn observe_without_creator(&mut self, peer: &NativePeerProcess) -> Result<()> {
        self.check_peer(peer)?;
        if self.phase != Phase::Sent {
            return Err(RuntimeJobError::Observation);
        }
        self.creator.take().ok_or(RuntimeJobError::Observation)?;
        if observe(&self.root)?.state()
            != (RuntimeProcessState::Accounting {
                active: 0,
                total: 0,
            })
        {
            return Err(RuntimeJobError::Observation);
        }
        self.phase = Phase::Observed;
        Ok(())
    }
    pub fn observe_release(&mut self, peer: &NativePeerProcess) -> Result<()> {
        self.check_peer(peer)?;
        if self.phase != Phase::Observed {
            return Err(RuntimeJobError::Observation);
        }
        if !matches!(observe(&self.root), Err(RuntimeJobError::Unavailable)) {
            return Err(RuntimeJobError::Observation);
        }
        self.phase = Phase::Released;
        Ok(())
    }
    pub fn released(&self) -> bool {
        self.phase == Phase::Released
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_user_cannot_create_job_keeper_probes() {
        let peer = NativePeerProcess::open(std::process::id()).unwrap();
        assert!(!peer.identity().is_local_system());
        assert!(matches!(
            JobKeeperProbe::new(&peer),
            Err(RuntimeJobError::Service(_))
        ));
    }
}
