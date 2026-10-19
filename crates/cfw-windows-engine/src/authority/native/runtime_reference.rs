use super::super::wire::RuntimeReferenceGrant;
use super::*;

impl WindowsAuthority {
    pub(in crate::authority) fn retain_runtime(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
    ) -> Result<RuntimeReferenceGrant> {
        let deadline = Instant::now() + ADMISSION;
        self.admit_reference_owner(authorization, context, deadline)?;
        if self.desktop_reference_issued {
            return Err(AuthorityError::Stale);
        }
        // One transfer per live lease. An uncertain native transfer or reply
        // cannot be retried or remotely closed by an untrusted numeric value.
        self.desktop_reference_issued = true;
        let transfer = self
            .runtime_job
            .as_ref()
            .ok_or(AuthorityError::Recovering)?
            .transfer_keeper(authorization.process());
        let keeper_handle = match transfer {
            Ok(handle) => handle,
            Err(error) => {
                self.suspend(false);
                return Err(error.into());
            }
        };
        self.after_publication(authorization, deadline)?;
        Ok(RuntimeReferenceGrant {
            context: context.clone(),
            keeper_handle,
            keeper: None,
        })
    }
    pub(in crate::authority) fn confirm_runtime_reference(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
        handle: u64,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        self.admit_reference_owner(authorization, context, deadline)?;
        if !self.desktop_reference_issued || self.desktop_reference_confirmed {
            return Err(AuthorityError::Stale);
        }
        self.runtime_job
            .as_ref()
            .ok_or(AuthorityError::Recovering)?
            .verify_keeper(authorization.process(), handle)?;
        self.after_publication(authorization, deadline)?;
        self.desktop_reference_confirmed = true;
        Ok(self.snapshot())
    }
    fn admit_reference_owner(
        &self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
        deadline: Instant,
    ) -> Result<()> {
        let peer = self.admit(authorization, deadline)?;
        if peer.role != Role::Desktop || self.machine.lease_for_owner(&peer)? != *context {
            return Err(AuthorityError::Identity);
        }
        // Transfer only after Agent Ready. Existing native validation can still
        // isolate the inherited engine keeper while handling Ready, before any
        // Desktop request acquires this extra lifetime reference.
        if self.machine.phase() != AuthorityState::Active || !self.keeper_confirmed {
            return Err(AuthorityError::Stale);
        }
        Ok(())
    }
}
