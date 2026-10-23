use super::*;
use cfw_engine_api::authority_v1::AuthorityMode;

impl WindowsAuthority {
    pub(crate) fn start_service_drain(&mut self) -> Result<()> {
        require_service()?;
        self.draining = true;
        if self.machine.context().is_some() {
            self.revoke_current(false, "service drain", Instant::now())?;
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
        let mode = self
            .machine
            .metadata()
            .and_then(|m| m.operation())
            .map(|o| o.mode());
        if mode == Some(AuthorityMode::Tunnel) || self.tunnel.is_some() {
            self.drive_tunnel()?;
            let reconcilable = match state.state {
                AuthorityState::Recovering => true,
                // Only an acknowledged stop keeps its binding until Off.
                AuthorityState::Stopping => self
                    .machine
                    .stopped_cleanup_target(AuthorityMode::Tunnel)
                    .is_ok(),
                _ => false,
            };
            if mode == Some(AuthorityMode::Tunnel) && reconcilable {
                self.reconcile_tunnel()?;
            }
            return Ok(self.snapshot());
        }
        let local = mode == Some(AuthorityMode::LocalProxy);
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
