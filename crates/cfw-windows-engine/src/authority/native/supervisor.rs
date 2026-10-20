use super::*;
use cfw_engine_api::authority_v1::AuthorityMode;

impl WindowsAuthority {
    pub(crate) fn start_service_drain(&mut self) -> Result<()> {
        require_service()?;
        self.draining = true;
        if self.machine.context().is_some() {
            self.revoke_current(false, Instant::now())?;
        }
        Ok(())
    }
    /// Called under the same guard as command publication. A failed peer/OS
    /// observation invalidates live authorization and remains a recorded error.
    /// The next tick may independently reconcile known retired LocalProxy state.
    pub(crate) fn supervise(&mut self) -> Result<AuthoritySnapshot> {
        if let Err(error) = self.poll() {
            self.suspend(false);
            return Err(error);
        }
        let state = self.snapshot();
        if state.revision.is_none() {
            return Err(AuthorityError::Recovering);
        }
        let local = self
            .machine
            .metadata()
            .and_then(|m| m.operation())
            .is_some_and(|o| o.mode() == AuthorityMode::LocalProxy);
        if local
            && matches!(
                state.state,
                AuthorityState::Stopping | AuthorityState::Recovering
            )
        {
            let processes = self.observe_runtime_processes()?;
            if matches!(
                processes.state(),
                super::super::RuntimeProcessState::Accounting {
                    active: 0,
                    total: 1..
                }
            ) {
                match state.state {
                    AuthorityState::Recovering => {
                        self.reconcile_local_recovery()?;
                    }
                    AuthorityState::Stopping => {
                        // Missing acknowledgement is a real unresolved stop.
                        // A later owner-disconnect poll moves into recovery.
                        self.reconcile_local_stop()?;
                    }
                    _ => return Err(AuthorityError::Invalid),
                }
            }
        }
        Ok(self.snapshot())
    }
}
