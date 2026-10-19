use super::{AuthorityError, Result, secret::Ticket};
use crate::{
    authority_journal::{AuthorityCommittedState, JournalOperation, RecordedOwner},
    connection_binding::ConnectionBinding,
};
use cfw_engine_api::authority_v1::{
    AuthorityMode, AuthorityState, PacketPumpLimits, RootContext, WireValidate,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub root: RootContext,
    pub operation_id: Uuid,
    pub mode: AuthorityMode,
    pub config_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
    pub expected_revision: u64,
}
impl PrepareRequest {
    pub(super) fn validate(&self) -> Result<()> {
        if self.root.installation_id.is_nil()
            || self.operation_id.is_nil()
            || self.expected_revision == 0
            || self.root.validate().is_err()
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContext {
    pub root: RootContext,
    pub operation_id: Uuid,
    pub mode: AuthorityMode,
    pub config_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
    pub owner: RecordedOwner,
    pub prepared_revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseContext {
    pub operation: OperationContext,
    pub lease_id: Uuid,
}
impl LeaseContext {
    pub(super) fn recorded(&self) -> Result<JournalOperation> {
        Ok(JournalOperation::new(
            self.operation.operation_id,
            self.operation.mode,
            self.operation.config_sha256,
            self.lease_id,
            self.operation.owner.clone(),
        )?)
    }
}

/// Cannot be cloned, debug-printed or serialized. The preparation ticket may
/// claim a runtime binding once; it does not itself authorize starting a child.
pub struct PreparedTicket {
    pub(super) context: LeaseContext,
    pub(super) ticket: Ticket,
}
impl PreparedTicket {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn with_ticket<T>(&self, consume: impl FnOnce(&[u8]) -> T) -> T {
        self.ticket.expose(consume)
    }
}
/// Produced only after the runtime binding's journal commit and fresh native
/// admission. The runtime still has to check its config/image and own resources.
pub struct RuntimeStartAuthorization {
    pub(super) context: LeaseContext,
    pub(super) committed_revision: u64,
}
impl RuntimeStartAuthorization {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn committed_revision(&self) -> u64 {
        self.committed_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyReport {
    pub context: LeaseContext,
    pub runtime_digest: [u8; 32],
    pub ready_flags: u8,
    pub packet_pump_limits: Option<PacketPumpLimits>,
    pub observed_millis: u64,
}
impl ReadyReport {
    pub(super) fn validate(&self) -> Result<()> {
        let mode = self.context.operation.mode;
        if self.observed_millis == 0
            || self.runtime_digest != self.context.operation.identity_sha256
            || self.ready_flags
                != if mode == AuthorityMode::LocalProxy {
                    0b011
                } else {
                    0b111
                }
            || (mode == AuthorityMode::Tunnel) != self.packet_pump_limits.is_some()
            || self
                .packet_pump_limits
                .as_ref()
                .is_some_and(|limits| limits.validate().is_err())
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoppedReport {
    pub context: LeaseContext,
    pub engine_stopped: bool,
    pub transport_closed: bool,
    pub os_restored: bool,
    pub observed_millis: u64,
}
impl StoppedReport {
    pub(super) fn validate(&self) -> Result<()> {
        if self.observed_millis == 0
            || !self.engine_stopped
            || !self.transport_closed
            || !self.os_restored
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    pub state: AuthorityState,
    /// None means a publication outcome is uncertain, not revision zero/Off.
    pub revision: Option<u64>,
    pub root: Option<RootContext>,
}

/// Independent cleanup observations, not a wire DTO. Construction belongs to
/// native observation adapters; there is no serde or default constructor.
/// Tests exercise policy through an explicit validation-only constructor.
pub struct CleanupEvidence {
    pub(super) revision: u64,
    pub(super) lease_id: Option<Uuid>,
    pub(super) proxy_listener_closed: bool,
    pub(super) system_proxy_restored: bool,
    pub(super) tunnel_engine_stopped: bool,
    pub(super) packet_pump_closed: bool,
    pub(super) managed_tunnel_off: bool,
    pub(super) endpoints_closed: bool,
    pub(super) secret_buffers_cleared: bool,
}
impl CleanupEvidence {
    pub(super) fn exact(&self) -> bool {
        self.proxy_listener_closed
            && self.system_proxy_restored
            && self.tunnel_engine_stopped
            && self.packet_pump_closed
            && self.managed_tunnel_off
            && self.endpoints_closed
            && self.secret_buffers_cleared
    }
    #[cfg(any(test, feature = "native-service-validation"))]
    pub fn for_validation(revision: u64, lease_id: Option<Uuid>, complete: bool) -> Self {
        Self {
            revision,
            lease_id,
            proxy_listener_closed: complete,
            system_proxy_restored: complete,
            tunnel_engine_stopped: complete,
            packet_pump_closed: complete,
            managed_tunnel_off: complete,
            endpoints_closed: complete,
            secret_buffers_cleared: complete,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Desktop,
    UserAgent,
    TunnelWorker,
}
#[derive(Clone)]
pub(super) struct Peer {
    pub owner: RecordedOwner,
    pub connection: ConnectionBinding,
    pub role: Role,
}
impl Peer {
    pub(super) fn same(&self, other: &Self) -> bool {
        self.owner == other.owner && self.connection == other.connection && self.role == other.role
    }
    pub(super) fn live(&self) -> Result<()> {
        self.owner.validate()?;
        if !self.connection.is_open() {
            return Err(AuthorityError::Identity);
        }
        Ok(())
    }
}
pub(super) fn expected_role(mode: AuthorityMode) -> Role {
    if mode == AuthorityMode::Tunnel {
        Role::TunnelWorker
    } else {
        Role::UserAgent
    }
}
pub(super) fn metadata_lease_id(value: Option<&AuthorityCommittedState>) -> Option<Uuid> {
    value.and_then(|s| s.operation().map(JournalOperation::lease_id))
}
