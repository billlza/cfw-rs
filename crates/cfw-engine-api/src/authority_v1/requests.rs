//! Command payloads and the results the Authority returns for them.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeRequest {
    pub version: ProtocolVersion,
}
impl WireValidate for HandshakeRequest {
    fn validate(&self) -> Result<(), CodecError> {
        self.version.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeResponse {
    pub command_timeout_ms: u64,
    pub maximum_configuration_bytes: u32,
    pub maximum_credential_slots: u16,
    pub maximum_individual_secret_bytes: u32,
    pub maximum_mutating_transactions: u8,
    pub maximum_queued_events_per_peer: u16,
    pub maximum_read_only_requests: u16,
    pub maximum_total_secret_bytes: u32,
    pub preparation_lifetime_ms: u64,
    pub stop_attestation_timeout_ms: u64,
    pub version: ProtocolVersion,
}
impl HandshakeResponse {
    pub fn v1() -> Self {
        Self {
            command_timeout_ms: COMMAND_TIMEOUT_MS,
            maximum_configuration_bytes: MAX_CONFIGURATION_BYTES,
            maximum_credential_slots: MAX_CREDENTIAL_SLOTS as u16,
            maximum_individual_secret_bytes: MAX_INDIVIDUAL_SECRET_BYTES as u32,
            maximum_mutating_transactions: MAX_MUTATING_TRANSACTIONS,
            maximum_queued_events_per_peer: MAX_QUEUED_EVENTS_PER_PEER,
            maximum_read_only_requests: MAX_READ_ONLY_REQUESTS,
            maximum_total_secret_bytes: MAX_TOTAL_SECRET_BYTES as u32,
            preparation_lifetime_ms: PREPARATION_LIFETIME_MS,
            stop_attestation_timeout_ms: STOP_ATTESTATION_TIMEOUT_MS,
            version: ProtocolVersion::v1(),
        }
    }
}
impl WireValidate for HandshakeResponse {
    fn validate(&self) -> Result<(), CodecError> {
        self.version.validate()?;
        if self != &Self::v1() {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareStartRequest {
    pub configuration: ConfigurationDescriptor,
    pub expected_revision: u64,
    pub operation: OperationContext,
}
impl WireValidate for PrepareStartRequest {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        self.configuration.validate()?;
        if self.expected_revision != self.operation.authority_revision
            || (self.operation.mode == AuthorityMode::Tunnel)
                != self.configuration.tunnel_options.is_some()
            || self.operation.config_sha256 != self.configuration.config_sha256
            || self.operation.identity_sha256 != self.configuration.identity_sha256
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginStopRequest {
    pub expected_revision: u64,
    pub lease_id: Uuid,
    pub operation: OperationContext,
}
impl WireValidate for BeginStopRequest {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if self.expected_revision < self.operation.authority_revision {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopDirective {
    pub deadline_monotonic_ms: u64,
    pub lease_id: Uuid,
    pub operation: OperationContext,
    pub revision: u64,
}
impl WireValidate for StopDirective {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if self.deadline_monotonic_ms == 0 || self.revision < self.operation.authority_revision {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelPreparedRequest {
    pub expected_revision: u64,
    pub operation: OperationContext,
}
impl WireValidate for CancelPreparedRequest {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if self.expected_revision < self.operation.authority_revision {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRequest {}
impl WireValidate for SnapshotRequest {
    fn validate(&self) -> Result<(), CodecError> {
        Ok(())
    }
}

pub struct BindProxyOwnerRequest {
    pub operation: OperationContext,
    pub lease_id: Uuid,
    pub capability: OwnerCapability,
}
pub struct RedeemTunnelTicketRequest {
    pub operation: OperationContext,
    pub lease_id: Uuid,
    pub ticket: StartTicket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAcknowledgement {
    pub operation_id: Uuid,
    pub revision: u64,
}
impl WireValidate for AuthorityAcknowledgement {
    fn validate(&self) -> Result<(), CodecError> {
        if self.revision == 0 {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

pub struct PreparedStart {
    pub operation: OperationContext,
    pub lease_id: Uuid,
    pub ticket: Option<StartTicket>,
    pub owner_capability: Option<OwnerCapability>,
    pub expires_monotonic_ms: u64,
    pub preference_descriptor_sha256: String,
}
impl PreparedStart {
    pub fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        let tunnel = self.operation.mode == AuthorityMode::Tunnel;
        if tunnel != self.ticket.is_some()
            || tunnel == self.owner_capability.is_some()
            || self.expires_monotonic_ms == 0
            || !is_digest(&self.preference_descriptor_sha256)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

pub struct RedeemedTunnelStart {
    pub operation: OperationContext,
    pub lease: LeaseView,
    pub configuration: SensitiveBytes,
    pub secrets: SecretMaterial,
}
impl RedeemedTunnelStart {
    pub fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        self.lease.validate()?;
        if self.operation.mode == AuthorityMode::Tunnel && self.lease.operation == self.operation {
            Ok(())
        } else {
            Err(CodecError::BoundViolation)
        }
    }
}

#[cfg(test)]
mod tests;
