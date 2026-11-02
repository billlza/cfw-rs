//! Leases, replay cursors, snapshots, attestations and tunnel preferences.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalLease {
    pub expiry_monotonic_ms: u64,
    pub issued_monotonic_ms: u64,
    pub lease_id: Uuid,
    pub operation: OperationContext,
    pub owner_connection_nonce_sha256: String,
    pub state: LeaseState,
}
impl WireValidate for GlobalLease {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if self.issued_monotonic_ms == 0
            || self.expiry_monotonic_ms <= self.issued_monotonic_ms
            || !is_digest(&self.owner_connection_nonce_sha256)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCursor {
    pub accepted_epoch: u64,
    pub accepted_generation: u64,
    pub installation_id: Uuid,
    pub previous_record_sha256: String,
    pub revision: u64,
    pub schema_version: u16,
}
impl WireValidate for ReplayCursor {
    fn validate(&self) -> Result<(), CodecError> {
        if self.schema_version != 1
            || self.accepted_epoch == 0
            || self.accepted_generation == 0
            || self.revision == 0
            || !is_digest(&self.previous_record_sha256)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDescriptor {
    pub byte_count: u32,
    pub config_sha256: String,
    pub credential_audience: CredentialAudience,
    pub credential_slots: Vec<CredentialSlot>,
    pub identity_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_options: Option<TunnelNetworkOptions>,
}
impl WireValidate for ConfigurationDescriptor {
    fn validate(&self) -> Result<(), CodecError> {
        if self.byte_count == 0
            || self.byte_count > MAX_CONFIGURATION_BYTES
            || self.credential_slots.len() > MAX_CREDENTIAL_SLOTS
            || !is_digest(&self.config_sha256)
            || !is_digest(&self.identity_sha256)
            || self
                .tunnel_options
                .is_some_and(|options| !(1_280..=1_500).contains(&options.mtu))
        {
            return Err(CodecError::BoundViolation);
        }
        let mut pointers = BTreeSet::new();
        if self
            .credential_slots
            .iter()
            .any(|slot| !pointers.insert(slot.json_pointer()))
        {
            return Err(CodecError::BoundViolation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseView {
    pub expiry_monotonic_ms: u64,
    pub lease_id: Uuid,
    pub operation: OperationContext,
    pub state: LeaseState,
}
impl WireValidate for LeaseView {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if self.expiry_monotonic_ms == 0 {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureSummary {
    pub code: String,
}
impl WireValidate for FailureSummary {
    fn validate(&self) -> Result<(), CodecError> {
        if self.code.is_empty()
            || self.code.len() > 64
            || !self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<FailureSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_view: Option<LeaseView>,
    pub protocol_version: ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_cursor: Option<ReplayCursor>,
    pub revision: u64,
    pub state: AuthorityState,
}
impl WireValidate for AuthoritySnapshot {
    fn validate(&self) -> Result<(), CodecError> {
        self.protocol_version.validate()?;
        if let Some(cursor) = &self.replay_cursor {
            cursor.validate()?;
        }
        if let Some(lease) = &self.lease_view {
            lease.validate()?;
        }
        if let Some(failure) = &self.last_failure {
            failure.validate()?;
        }
        let valid_ownership = match self.state {
            AuthorityState::Off | AuthorityState::Recovering => self.lease_view.is_none(),
            AuthorityState::Quarantined => self.lease_view.as_ref().is_none_or(|lease| {
                self.replay_cursor.is_some() && lease.state == LeaseState::Revoked
            }),
            AuthorityState::Preparing
            | AuthorityState::Starting
            | AuthorityState::Active
            | AuthorityState::Stopping => self.replay_cursor.is_some() && self.lease_view.is_some(),
        };
        if self.revision == 0
            || self
                .replay_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.revision > self.revision)
            || !valid_ownership
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPumpLimits {
    pub maximum_packet_bytes: u16,
    pub maximum_queued_bytes: u32,
    pub maximum_queued_packets: u16,
    pub maximum_read_batch: u8,
}
impl WireValidate for PacketPumpLimits {
    fn validate(&self) -> Result<(), CodecError> {
        if !(1..=1_024).contains(&self.maximum_queued_packets)
            || !(1..=4 * 1_048_576).contains(&self.maximum_queued_bytes)
            || !(1_280..=1_500).contains(&self.maximum_packet_bytes)
            || !(1..=64).contains(&self.maximum_read_batch)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyAttestation {
    pub lease_id: Uuid,
    pub monotonic_timestamp_ms: u64,
    pub operation: OperationContext,
    pub owner_role: AuthorityRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_pump_limits: Option<PacketPumpLimits>,
    pub ready_flags: u16,
    pub runtime_digest: String,
}
impl WireValidate for ReadyAttestation {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if let Some(limits) = &self.packet_pump_limits {
            limits.validate()?;
        }
        let role_matches = match self.operation.mode {
            AuthorityMode::Tunnel => {
                self.owner_role == AuthorityRole::Provider && self.packet_pump_limits.is_some()
            }
            AuthorityMode::LocalProxy | AuthorityMode::SystemProxy => {
                self.owner_role == AuthorityRole::ProxyAgent && self.packet_pump_limits.is_none()
            }
        };
        if !role_matches
            || self.ready_flags
                != if self.operation.mode == AuthorityMode::LocalProxy {
                    0b011
                } else {
                    0b111
                }
            || self.monotonic_timestamp_ms == 0
            || !is_digest(&self.runtime_digest)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoppedAttestation {
    pub lease_id: Uuid,
    pub libbox_stopped: bool,
    pub monotonic_timestamp_ms: u64,
    pub operation: OperationContext,
    pub os_restored: bool,
    pub transport_closed: bool,
}
impl WireValidate for StoppedAttestation {
    fn validate(&self) -> Result<(), CodecError> {
        self.operation.validate()?;
        if !self.libbox_stopped
            || !self.transport_closed
            || !self.os_restored
            || self.monotonic_timestamp_ms == 0
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelPreferenceValues {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_sha256: Option<String>,
    pub is_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localized_description: Option<String>,
}
impl WireValidate for TunnelPreferenceValues {
    fn validate(&self) -> Result<(), CodecError> {
        if self
            .descriptor_sha256
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
            || self
                .localized_description
                .as_ref()
                .is_some_and(|description| {
                    description.len() > MAX_DESCRIPTION_BYTES
                        || description.chars().any(char::is_control)
                })
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceMutationReceipt {
    pub created_manager: bool,
    pub operation_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_values: Option<TunnelPreferenceValues>,
    pub written_descriptor_sha256: String,
}
impl WireValidate for PreferenceMutationReceipt {
    fn validate(&self) -> Result<(), CodecError> {
        if let Some(values) = &self.prior_values {
            values.validate()?;
        }
        if self.created_manager != self.prior_values.is_none()
            || !is_digest(&self.written_descriptor_sha256)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
