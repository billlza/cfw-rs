use super::*;
use crate::RunMode;

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
        if mode.is_some_and(RunMode::owns_tunnel) || self.tunnel.is_some() {
            self.drive_tunnel()?;
            let reconcilable = match (state.state, mode) {
                (AuthorityState::Recovering, Some(_)) => true,
                // Only an acknowledged stop keeps its binding until Off.
                (AuthorityState::Stopping, Some(mode)) => {
                    self.machine.stopped_cleanup_target(mode).is_ok()
                }
                _ => false,
            };
            if reconcilable {
                match mode {
                    Some(RunMode::Tunnel) => {
                        self.reconcile_tunnel()?;
                    }
                    // SYSTEM retires its network at once. Off waits for the
                    // proof that this user's proxy settings were restored, which
                    // may be days away: a retired network is not asked about
                    // again on every tick.
                    Some(RunMode::TunnelSystemProxy) => {
                        let revision = self.machine.revision();
                        if self.tunnel_retired_at != Some(revision)
                            && self.retire_combined_tunnel()?
                        {
                            self.tunnel_retired_at = Some(revision);
                        }
                    }
                    _ => {}
                }
            }
            return Ok(self.snapshot());
        }
        let local = mode == Some(RunMode::LocalProxy);
        if local
            && matches!(
                state.state,
                AuthorityState::Stopping | AuthorityState::Recovering
            )
        {
            let processes = self.observe_runtime_processes()?;
            let retired = self
                .machine
                .metadata()
                .is_some_and(|record| processes.run_retirement(record.root()).is_some());
            if retired {
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
    /// The supervision tick itself, for a validation service that hosts this
    /// Authority in place of the product's service loop.
    #[cfg(feature = "native-service-validation")]
    pub fn supervise_for_validation(&mut self) -> Result<AuthoritySnapshot> {
        self.supervise()
    }
}
