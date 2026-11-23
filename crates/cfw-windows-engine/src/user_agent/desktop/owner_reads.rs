//! This Desktop's reads of its own run on the operation's Authority connection.
use super::{DesktopError, DesktopUserAgent, Result};
use crate::{
    authority::{
        AuthoritySnapshot,
        wire::{Command, Rejection, Response, WireError},
    },
    user_agent::owner_observation::{self, OwnerReads},
};
use std::time::Instant;

impl DesktopUserAgent {
    /// Observe this owner's run and prove its lease while it holds one. A
    /// lease the Agent's own stop released between the two reads is read as
    /// the state that followed; see `owner_observation`.
    pub(super) fn observe_owned(&mut self, deadline: Instant) -> Result<AuthoritySnapshot> {
        owner_observation::observe_owned(&mut Connection {
            owner: self,
            deadline,
        })
    }
}

struct Connection<'a> {
    owner: &'a mut DesktopUserAgent,
    deadline: Instant,
}
impl OwnerReads for Connection<'_> {
    type Error = DesktopError;
    fn observe(&mut self) -> Result<AuthoritySnapshot> {
        self.owner.observe(self.deadline)
    }
    fn prove_lease(&mut self) -> Result<()> {
        let Response::Lease(context) = self.owner.command(Command::OwnedLease, self.deadline)?
        else {
            return Err(DesktopError::Response);
        };
        if context != self.owner.context {
            return Err(DesktopError::Context);
        }
        Ok(())
    }
    fn is_lease_refusal(error: &DesktopError) -> bool {
        matches!(
            error,
            DesktopError::Authority(WireError::Rejected(Rejection::Identity))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_authoritys_identity_rejection_is_a_lease_refusal() {
        assert!(Connection::is_lease_refusal(&DesktopError::Authority(
            WireError::Rejected(Rejection::Identity)
        )));
        for error in [
            DesktopError::Authority(WireError::Rejected(Rejection::Stale)),
            DesktopError::Authority(WireError::Rejected(Rejection::Quarantined)),
            DesktopError::Authority(WireError::Malformed),
            DesktopError::Context,
            DesktopError::Response,
            DesktopError::State("authority connection unavailable"),
        ] {
            assert!(!Connection::is_lease_refusal(&error), "{error}");
        }
    }
}
