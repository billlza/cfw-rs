use super::*;
use crate::authority::{ProxyRecoveryContext, ProxyRecoveryPurpose, ProxyRecoveryTarget};

/// A bounded, single-use observation challenge from the authenticated service.
/// It has no conversion to a preparation ticket or runtime start authorization.
pub struct ProxyRecoveryGrant {
    pub(in crate::authority) context: ProxyRecoveryContext,
    pub(in crate::authority) ticket: TicketMaterial,
}
impl ProxyRecoveryGrant {
    pub fn context(&self) -> &ProxyRecoveryContext {
        &self.context
    }
    /// Observe after receiving the challenge. Old observations cannot be
    /// substituted, and no caller-provided Boolean can create this report.
    #[cfg(windows)]
    pub fn observe_restoration(
        self,
        proxy: &crate::WindowsSystemProxy,
    ) -> std::result::Result<ProxyRecoveryReport, crate::ProxyError> {
        let identity = crate::system_proxy::user_identity()?;
        if !self
            .context
            .observer
            .matches_native(identity.user_session())
        {
            return Err(crate::ProxyError::UnsafeUser);
        }
        let target = &self.context.target;
        let context = cfw_engine_api::EngineCommandContext {
            installation_id: target.root.installation_id.to_string(),
            config_epoch: target.root.epoch,
            generation: target.root.generation,
        };
        let digest: String = target
            .operation
            .identity_sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let observed = proxy.observe_restoration(&context, &digest)?;
        Ok(ProxyRecoveryReport {
            context: self.context,
            ticket: self.ticket,
            recorded_process_id: observed.recorded_process_id(),
            recorded_process_creation_time: observed.recorded_process_creation_time(),
        })
    }
}

/// Received claims are re-admitted against the native peer and one-use
/// challenge. PID/time identify the proxy record, not proof of process exit.
#[derive(Serialize)]
pub struct ProxyRecoveryReport {
    pub(in crate::authority) context: ProxyRecoveryContext,
    pub(in crate::authority) ticket: TicketMaterial,
    pub(in crate::authority) recorded_process_id: u32,
    pub(in crate::authority) recorded_process_creation_time: u64,
}
impl ProxyRecoveryReport {
    pub(super) fn validate(&self) -> Result<()> {
        self.context.validate().map_err(|_| WireError::Malformed)?;
        if self.recorded_process_id == 0 || self.recorded_process_creation_time == 0 {
            return Err(WireError::Malformed);
        }
        Ok(())
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Payload {
            context: ProxyRecoveryContext,
            ticket: TicketMaterial,
            recorded_process_id: u32,
            recorded_process_creation_time: u64,
        }
        let value: Payload = decode(bytes)?;
        let report = Self {
            context: value.context,
            ticket: value.ticket,
            recorded_process_id: value.recorded_process_id,
            recorded_process_creation_time: value.recorded_process_creation_time,
        };
        report.validate()?;
        Ok(report)
    }
}

/// An acknowledgement of scoped observations, never global Off or Ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRecoveryReceipt {
    pub(in crate::authority) context: ProxyRecoveryContext,
    pub(in crate::authority) retired_process_count: u32,
}

/// Publication of a fully observed SystemProxy stop or recovery. A later execution
/// still needs a new generation and lease; the old runtime is not restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCleanupReceipt {
    pub(in crate::authority) recovery: ProxyRecoveryReceipt,
    pub(in crate::authority) snapshot: AuthoritySnapshot,
}
impl ProxyCleanupReceipt {
    pub fn recovery(&self) -> &ProxyRecoveryReceipt {
        &self.recovery
    }
    pub fn snapshot(&self) -> &AuthoritySnapshot {
        &self.snapshot
    }
}
impl ProxyRecoveryReceipt {
    pub fn context(&self) -> &ProxyRecoveryContext {
        &self.context
    }
    pub fn retired_process_count(&self) -> u32 {
        self.retired_process_count
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantedPayload {
    context: ProxyRecoveryContext,
    ticket: TicketMaterial,
}
#[derive(Serialize)]
struct GrantedPayloadRef<'a> {
    context: &'a ProxyRecoveryContext,
    ticket: &'a TicketMaterial,
}
pub(super) fn encode_grant(id: Uuid, grant: &ProxyRecoveryGrant) -> Result<Message> {
    envelope(
        id,
        ResponseTag::ProxyRecoveryGranted,
        &GrantedPayloadRef {
            context: &grant.context,
            ticket: &grant.ticket,
        },
    )
}
pub(super) fn decode_grant(
    bytes: &[u8],
    target: &ProxyRecoveryTarget,
    owner: &crate::authority_journal::RecordedOwner,
    purpose: ProxyRecoveryPurpose,
) -> Result<ProxyRecoveryGrant> {
    let value: GrantedPayload = decode(bytes)?;
    value.context.validate().map_err(|_| WireError::Malformed)?;
    if value.context.target != *target
        || value.context.observer != *owner
        || value.context.purpose != purpose
    {
        return Err(WireError::Correlation);
    }
    Ok(ProxyRecoveryGrant {
        context: value.context,
        ticket: value.ticket,
    })
}
pub(super) fn decode_cleanup(
    bytes: &[u8],
    report: &ProxyRecoveryReport,
    owner: &crate::authority_journal::RecordedOwner,
) -> Result<ProxyCleanupReceipt> {
    let value: ProxyCleanupReceipt = decode(bytes)?;
    let target = &report.context.target;
    if value.recovery.context != report.context
        || value.recovery.context.observer != *owner
        || report.context.purpose != ProxyRecoveryPurpose::ReconcileOff
        || value.recovery.retired_process_count == 0
        || value.snapshot.state != AuthorityState::Off
        || target.revision.checked_add(1) != value.snapshot.revision
        || value.snapshot.root.as_ref() != Some(&target.root)
    {
        return Err(WireError::Correlation);
    }
    Ok(value)
}
pub(super) fn decode_receipt(
    bytes: &[u8],
    report: &ProxyRecoveryReport,
    owner: &crate::authority_journal::RecordedOwner,
) -> Result<ProxyRecoveryReceipt> {
    let value: ProxyRecoveryReceipt = decode(bytes)?;
    if value.context != report.context
        || value.context.observer != *owner
        || value.retired_process_count == 0
    {
        return Err(WireError::Correlation);
    }
    Ok(value)
}
