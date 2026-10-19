//! Recovery observations have their own bounded connection authorization. They
//! neither resurrect a runtime lease nor constitute global cleanup evidence.
use super::{AuthorityError, Result, machine::Machine, secret::TicketDigest, types::*};
use crate::authority_journal::{JournalOperation, RecordedOwner};
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext, WireValidate};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(10);

/// Exact durable operation, including the former full logon identity and both
/// configuration hashes. This is a request selector, never execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRecoveryTarget {
    pub root: RootContext,
    pub revision: u64,
    pub operation: JournalOperation,
}
impl ProxyRecoveryTarget {
    pub fn from_recorded(scope: &RecordedRuntimeScope) -> Result<Self> {
        if scope.snapshot().state != AuthorityState::Recovering {
            return Err(AuthorityError::Recovering);
        }
        let value = Self {
            root: scope
                .snapshot()
                .root
                .clone()
                .ok_or(AuthorityError::Recovering)?,
            revision: scope
                .snapshot()
                .revision
                .ok_or(AuthorityError::Recovering)?,
            operation: scope
                .operation()
                .cloned()
                .ok_or(AuthorityError::CleanupUnproven)?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.operation.validate()?;
        if self.root.installation_id.is_nil()
            || self.root.validate().is_err()
            || self.revision < 2
            || self.operation.mode() != AuthorityMode::SystemProxy
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }
    fn matches(&self, machine: &Machine) -> Result<()> {
        self.validate()?;
        if !machine.durable_known() || machine.phase() != AuthorityState::Recovering {
            return Err(AuthorityError::Recovering);
        }
        let metadata = machine.metadata().ok_or(AuthorityError::Recovering)?;
        if self.revision != machine.revision()
            || self.revision != metadata.revision()
            || self.root != *metadata.root()
            || Some(&self.operation) != metadata.operation()
        {
            return Err(AuthorityError::Stale);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRecoveryContext {
    pub(super) target: ProxyRecoveryTarget,
    pub(super) observer: RecordedOwner,
}
impl ProxyRecoveryContext {
    pub fn target(&self) -> &ProxyRecoveryTarget {
        &self.target
    }
    pub fn observer(&self) -> &RecordedOwner {
        &self.observer
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.target.validate()?;
        self.observer.validate()?;
        // Cross-logon recovery is limited to the same account. Both full
        // identities remain distinct; no old runtime ownership is inherited.
        if self.target.operation.owner().sid_bytes() != self.observer.sid_bytes() {
            return Err(AuthorityError::Identity);
        }
        Ok(())
    }
}

pub(super) struct ProxyRecoveryAdmission {
    context: ProxyRecoveryContext,
    peer: Peer,
    expires: Instant,
    ticket: TicketDigest,
}
impl ProxyRecoveryAdmission {
    pub(super) fn new(
        machine: &Machine,
        peer: &Peer,
        target: ProxyRecoveryTarget,
        ticket: TicketDigest,
        now: Instant,
    ) -> Result<Self> {
        peer.live()?;
        if peer.role != Role::Desktop {
            return Err(AuthorityError::Identity);
        }
        target.matches(machine)?;
        let context = ProxyRecoveryContext {
            target,
            observer: peer.owner.clone(),
        };
        context.validate()?;
        Ok(Self {
            context,
            peer: peer.clone(),
            expires: now.checked_add(LIFETIME).ok_or(AuthorityError::Invalid)?,
            ticket,
        })
    }
    pub(super) fn context(&self) -> &ProxyRecoveryContext {
        &self.context
    }
    pub(super) fn available(&self, now: Instant) -> bool {
        now < self.expires && self.peer.connection.is_open()
    }
    pub(super) fn belongs_to(&self, peer: &Peer) -> bool {
        self.peer.same(peer)
    }
    /// Consumed on the owning connection's first attempt, including a bad
    /// challenge or stale scope. Another connection cannot consume this grant.
    pub(super) fn consume(
        self,
        machine: &Machine,
        peer: &Peer,
        context: &ProxyRecoveryContext,
        ticket: &[u8],
        now: Instant,
    ) -> Result<(ProxyRecoveryContext, Instant)> {
        peer.live()?;
        if !self.belongs_to(peer) {
            return Err(AuthorityError::Identity);
        }
        if now >= self.expires {
            return Err(AuthorityError::Expired);
        }
        if self.context != *context {
            return Err(AuthorityError::Stale);
        }
        self.context.target.matches(machine)?;
        if !self.ticket.accepts(ticket) {
            return Err(AuthorityError::Ticket);
        }
        Ok((self.context, self.expires))
    }
}

#[cfg(test)]
mod tests;
