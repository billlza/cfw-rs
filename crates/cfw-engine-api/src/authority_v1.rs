//! Canonical, bounded Authority protocol v1 wire models shared with Swift fixtures.
//! Secret-bearing capability and material types deliberately implement neither serde nor Debug.

use crate::{
    BackendErrorKind, CredentialAudience, CredentialRef, CredentialSlot, TunnelNetworkOptions,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fmt};
use uuid::Uuid;

pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const MINIMUM_MINOR: u16 = 0;
pub const SUPPORTED_FEATURE_BITS: u64 = 0;
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_CONFIGURATION_BYTES: u32 = 768 * 1_024;
pub const MAX_TOTAL_SECRET_BYTES: usize = 256 * 1_024;
pub const MAX_CREDENTIAL_SLOTS: usize = 256;
pub const MAX_INDIVIDUAL_SECRET_BYTES: usize = 16 * 1_024;
pub const MAX_READ_ONLY_REQUESTS: u16 = 64;
pub const MAX_MUTATING_TRANSACTIONS: u8 = 1;
pub const MAX_QUEUED_EVENTS_PER_PEER: u16 = 32;
pub const PREPARATION_LIFETIME_MS: u64 = 10_000;
pub const COMMAND_TIMEOUT_MS: u64 = 5_000;
pub const STOP_ATTESTATION_TIMEOUT_MS: u64 = 5_000;
pub const MAX_NESTING_DEPTH: usize = 32;
pub const TICKET_BYTES: usize = 32;
pub const CAPABILITY_BYTES: usize = 32;
pub const MAX_DESCRIPTION_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    Malformed,
    Noncanonical,
    UnsupportedMajor(u16),
    UnsupportedMinor(u16),
    UnsupportedRequiredFeatures(u64),
    UnknownCommand,
    InvalidType,
    BoundViolation,
    MessageTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "authority-v1 codec rejection")
    }
}
impl std::error::Error for CodecError {}

pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: &[u8], maximum: usize) -> Result<Self, CodecError> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn expose(&self, consume: impl FnOnce(&[u8])) {
        consume(&self.0);
    }

    fn transport_copy(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct StartTicket(SensitiveBytes);
impl StartTicket {
    pub fn new(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != TICKET_BYTES {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(SensitiveBytes::new(bytes, TICKET_BYTES)?))
    }

    pub fn expose(&self, consume: impl FnOnce(&[u8])) {
        self.0.expose(consume);
    }
}

pub struct OwnerCapability(SensitiveBytes);
impl OwnerCapability {
    pub fn new(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != CAPABILITY_BYTES {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(SensitiveBytes::new(bytes, CAPABILITY_BYTES)?))
    }
}

pub struct SecretSlot {
    reference: CredentialRef,
    bytes: SensitiveBytes,
}
impl SecretSlot {
    pub fn new(reference: CredentialRef, bytes: &[u8]) -> Result<Self, CodecError> {
        Ok(Self {
            reference,
            bytes: SensitiveBytes::new(bytes, MAX_INDIVIDUAL_SECRET_BYTES)?,
        })
    }
}

pub struct SecretMaterial {
    slots: Vec<SecretSlot>,
    total_bytes: usize,
}
impl SecretMaterial {
    pub fn new(slots: Vec<SecretSlot>) -> Result<Self, CodecError> {
        if slots.len() > MAX_CREDENTIAL_SLOTS {
            return Err(CodecError::BoundViolation);
        }
        let mut references = BTreeSet::new();
        let mut total_bytes = 0usize;
        for slot in &slots {
            if !references.insert(slot.reference.id()) {
                return Err(CodecError::BoundViolation);
            }
            total_bytes = total_bytes
                .checked_add(slot.bytes.0.len())
                .ok_or(CodecError::BoundViolation)?;
            if total_bytes > MAX_TOTAL_SECRET_BYTES {
                return Err(CodecError::BoundViolation);
            }
        }
        Ok(Self { slots, total_bytes })
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn total_byte_count(&self) -> usize {
        self.total_bytes
    }
}

pub trait WireValidate {
    fn validate(&self) -> Result<(), CodecError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub feature_bits: u64,
    pub major: u16,
    pub max_message_bytes: u32,
    pub minimum_minor: u16,
    pub minor: u16,
}
impl ProtocolVersion {
    pub fn v1() -> Self {
        Self {
            feature_bits: SUPPORTED_FEATURE_BITS,
            major: MAJOR,
            max_message_bytes: MAX_ENVELOPE_BYTES as u32,
            minimum_minor: MINIMUM_MINOR,
            minor: MINOR,
        }
    }
}
impl WireValidate for ProtocolVersion {
    fn validate(&self) -> Result<(), CodecError> {
        if self.major != MAJOR {
            return Err(CodecError::UnsupportedMajor(self.major));
        }
        if self.minor != MINOR || self.minimum_minor > self.minor {
            return Err(CodecError::UnsupportedMinor(self.minor));
        }
        let unsupported = self.feature_bits & !SUPPORTED_FEATURE_BITS;
        if unsupported != 0 {
            return Err(CodecError::UnsupportedRequiredFeatures(unsupported));
        }
        if self.max_message_bytes == 0 || self.max_message_bytes as usize > MAX_ENVELOPE_BYTES {
            return Err(CodecError::BoundViolation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMode {
    SystemProxy,
    Tunnel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRole {
    Host,
    ProxyAgent,
    Provider,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityState {
    Recovering,
    Off,
    Preparing,
    Starting,
    Active,
    Stopping,
    Quarantined,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Prepared,
    Bound,
    Starting,
    Active,
    Stopping,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootContext {
    pub epoch: u64,
    pub generation: u64,
    pub installation_id: Uuid,
}
impl WireValidate for RootContext {
    fn validate(&self) -> Result<(), CodecError> {
        if self.epoch == 0 || self.generation == 0 {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContext {
    pub authority_revision: u64,
    pub config_sha256: String,
    pub identity_sha256: String,
    pub mode: AuthorityMode,
    pub operation_id: Uuid,
    pub owner_uid: u32,
    pub root: RootContext,
}
impl WireValidate for OperationContext {
    fn validate(&self) -> Result<(), CodecError> {
        self.root.validate()?;
        if self.authority_revision == 0
            || !is_digest(&self.config_sha256)
            || !is_digest(&self.identity_sha256)
        {
            Err(CodecError::BoundViolation)
        } else {
            Ok(())
        }
    }
}

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
    pub replay_cursor: ReplayCursor,
    pub revision: u64,
    pub state: AuthorityState,
}
impl WireValidate for AuthoritySnapshot {
    fn validate(&self) -> Result<(), CodecError> {
        self.protocol_version.validate()?;
        self.replay_cursor.validate()?;
        if let Some(lease) = &self.lease_view {
            lease.validate()?;
        }
        if let Some(failure) = &self.last_failure {
            failure.validate()?;
        }
        let lease_free = matches!(
            self.state,
            AuthorityState::Off | AuthorityState::Recovering | AuthorityState::Quarantined
        );
        if self.revision == 0
            || self.replay_cursor.revision > self.revision
            || lease_free != self.lease_view.is_none()
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
            AuthorityMode::SystemProxy => {
                self.owner_role == AuthorityRole::ProxyAgent && self.packet_pump_limits.is_none()
            }
        };
        if !role_matches
            || self.ready_flags != 0b111
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

pub enum Command {
    Handshake(HandshakeRequest),
    PrepareStart(PrepareStartRequest),
    BindProxyOwner(BindProxyOwnerRequest),
    RedeemTunnelTicket(RedeemTunnelTicketRequest),
    AttestReady(ReadyAttestation),
    BeginStop(BeginStopRequest),
    AttestStopped(StoppedAttestation),
    CancelPrepared(CancelPreparedRequest),
    Snapshot(SnapshotRequest),
}
impl Command {
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Handshake(_) | Self::Snapshot(_))
    }

    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Handshake(value) => value.validate(),
            Self::PrepareStart(value) => value.validate(),
            Self::BindProxyOwner(value) => {
                value.operation.validate()?;
                if value.operation.mode == AuthorityMode::SystemProxy {
                    Ok(())
                } else {
                    Err(CodecError::BoundViolation)
                }
            }
            Self::RedeemTunnelTicket(value) => {
                value.operation.validate()?;
                if value.operation.mode == AuthorityMode::Tunnel {
                    Ok(())
                } else {
                    Err(CodecError::BoundViolation)
                }
            }
            Self::AttestReady(value) => value.validate(),
            Self::BeginStop(value) => value.validate(),
            Self::AttestStopped(value) => value.validate(),
            Self::CancelPrepared(value) => value.validate(),
            Self::Snapshot(value) => value.validate(),
        }
    }
}

pub struct RequestEnvelope {
    pub major: u16,
    pub minor: u16,
    pub required_feature_bits: u64,
    pub request_id: Uuid,
    pub command: Command,
}
impl RequestEnvelope {
    pub fn new(
        request_id: Uuid,
        required_feature_bits: u64,
        command: Command,
    ) -> Result<Self, CodecError> {
        let unsupported = required_feature_bits & !SUPPORTED_FEATURE_BITS;
        if unsupported != 0 {
            return Err(CodecError::UnsupportedRequiredFeatures(unsupported));
        }
        command.validate()?;
        Ok(Self {
            major: MAJOR,
            minor: MINOR,
            required_feature_bits,
            request_id,
            command,
        })
    }
}

pub fn encode_request(envelope: &RequestEnvelope) -> Result<Vec<u8>, CodecError> {
    envelope.command.validate()?;
    let command = match &envelope.command {
        Command::Handshake(value) => tagged("handshake", value)?,
        Command::PrepareStart(value) => tagged("prepare_start", value)?,
        Command::BindProxyOwner(value) => json!({
            "kind": "bind_proxy_owner",
            "payload": {
                "capability": value.capability.0.transport_copy(),
                "lease_id": value.lease_id,
                "operation": value.operation,
            }
        }),
        Command::RedeemTunnelTicket(value) => json!({
            "kind": "redeem_tunnel_ticket",
            "payload": {
                "lease_id": value.lease_id,
                "operation": value.operation,
                "ticket": value.ticket.0.transport_copy(),
            }
        }),
        Command::AttestReady(value) => tagged("attest_ready", value)?,
        Command::BeginStop(value) => tagged("begin_stop", value)?,
        Command::AttestStopped(value) => tagged("attest_stopped", value)?,
        Command::CancelPrepared(value) => tagged("cancel_prepared", value)?,
        Command::Snapshot(value) => tagged("snapshot", value)?,
    };
    canonical_bytes(&json!({
        "command": command,
        "major": envelope.major,
        "minor": envelope.minor,
        "request_id": envelope.request_id,
        "required_feature_bits": envelope.required_feature_bits,
    }))
}

pub fn decode_request(data: &[u8]) -> Result<RequestEnvelope, CodecError> {
    let root = parse_canonical(data)?;
    exact_keys(
        &root,
        &[
            "command",
            "major",
            "minor",
            "request_id",
            "required_feature_bits",
        ],
    )?;
    let major = integer::<u16>(&root, "major")?;
    if major != MAJOR {
        return Err(CodecError::UnsupportedMajor(major));
    }
    let minor = integer::<u16>(&root, "minor")?;
    if minor != MINOR {
        return Err(CodecError::UnsupportedMinor(minor));
    }
    let required = integer::<u64>(&root, "required_feature_bits")?;
    let unsupported = required & !SUPPORTED_FEATURE_BITS;
    if unsupported != 0 {
        return Err(CodecError::UnsupportedRequiredFeatures(unsupported));
    }
    let request_id = decode_field::<Uuid>(&root, "request_id")?;
    let command_value = root.get("command").ok_or(CodecError::Malformed)?;
    let command_object = command_value.as_object().ok_or(CodecError::InvalidType)?;
    if command_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["kind", "payload"])
    {
        return Err(CodecError::Malformed);
    }
    let kind = command_object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(CodecError::InvalidType)?;
    let payload = command_object.get("payload").ok_or(CodecError::Malformed)?;
    let command = match kind {
        "handshake" => Command::Handshake(decode_value(payload)?),
        "prepare_start" => Command::PrepareStart(decode_value(payload)?),
        "bind_proxy_owner" => Command::BindProxyOwner(decode_capability(payload)?),
        "redeem_tunnel_ticket" => Command::RedeemTunnelTicket(decode_ticket(payload)?),
        "attest_ready" => Command::AttestReady(decode_value(payload)?),
        "begin_stop" => Command::BeginStop(decode_value(payload)?),
        "attest_stopped" => Command::AttestStopped(decode_value(payload)?),
        "cancel_prepared" => Command::CancelPrepared(decode_value(payload)?),
        "snapshot" => Command::Snapshot(decode_value(payload)?),
        _ => return Err(CodecError::UnknownCommand),
    };
    let envelope = RequestEnvelope::new(request_id, required, command)?;
    if encode_request(&envelope)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(envelope)
}

pub fn encode_canonical<T: Serialize + WireValidate>(value: &T) -> Result<Vec<u8>, CodecError> {
    value.validate()?;
    let value = serde_json::to_value(value).map_err(|_| CodecError::InvalidType)?;
    canonical_bytes(&value)
}

pub fn decode_canonical<T: DeserializeOwned + Serialize + WireValidate>(
    data: &[u8],
) -> Result<T, CodecError> {
    let value = parse_canonical(data)?;
    let decoded: T = serde_json::from_value(value).map_err(|_| CodecError::InvalidType)?;
    decoded.validate()?;
    if encode_canonical(&decoded)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(decoded)
}

pub fn verify_canonical_fixture<T: DeserializeOwned + Serialize + WireValidate>(
    data: &[u8],
) -> Result<(), CodecError> {
    let value: T = decode_canonical(data)?;
    if encode_canonical(&value)? == data {
        Ok(())
    } else {
        Err(CodecError::Noncanonical)
    }
}

fn parse_canonical(data: &[u8]) -> Result<Value, CodecError> {
    if data.is_empty() {
        return Err(CodecError::Malformed);
    }
    if data.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::MessageTooLarge {
            actual: data.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    let value: Value = serde_json::from_slice(data).map_err(|_| CodecError::Malformed)?;
    if !value.is_object() {
        return Err(CodecError::InvalidType);
    }
    validate_shape(&value, 1)?;
    if canonical_bytes(&value)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(value)
}

fn validate_shape(value: &Value, depth: usize) -> Result<(), CodecError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CodecError::BoundViolation);
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                validate_shape(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_shape(child, depth + 1)?;
            }
        }
        Value::Number(number) if !number.is_u64() && !number.is_i64() => {
            return Err(CodecError::InvalidType);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CodecError> {
    validate_shape(value, 1)?;
    let data = serde_json::to_vec(value).map_err(|_| CodecError::InvalidType)?;
    if data.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::MessageTooLarge {
            actual: data.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(data)
}

fn exact_keys(root: &Value, expected: &[&str]) -> Result<(), CodecError> {
    let object = root.as_object().ok_or(CodecError::InvalidType)?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

fn integer<T>(root: &Value, key: &str) -> Result<T, CodecError>
where
    T: TryFrom<u64>,
{
    root.get(key)
        .and_then(Value::as_u64)
        .ok_or(CodecError::InvalidType)
        .and_then(|value| T::try_from(value).map_err(|_| CodecError::InvalidType))
}

fn decode_field<T: DeserializeOwned>(root: &Value, key: &str) -> Result<T, CodecError> {
    let value = root.get(key).cloned().ok_or(CodecError::Malformed)?;
    serde_json::from_value(value).map_err(|_| CodecError::InvalidType)
}

fn decode_value<T: DeserializeOwned + WireValidate>(value: &Value) -> Result<T, CodecError> {
    let decoded: T = serde_json::from_value(value.clone()).map_err(|_| CodecError::InvalidType)?;
    decoded.validate()?;
    Ok(decoded)
}

fn decode_capability(value: &Value) -> Result<BindProxyOwnerRequest, CodecError> {
    exact_keys(value, &["capability", "lease_id", "operation"])?;
    let operation = decode_field::<OperationContext>(value, "operation")?;
    operation.validate()?;
    if operation.mode != AuthorityMode::SystemProxy {
        return Err(CodecError::BoundViolation);
    }
    let bytes = decode_exact_bytes(value, "capability", CAPABILITY_BYTES)?;
    Ok(BindProxyOwnerRequest {
        operation,
        lease_id: decode_field(value, "lease_id")?,
        capability: OwnerCapability::new(&bytes)?,
    })
}

fn decode_ticket(value: &Value) -> Result<RedeemTunnelTicketRequest, CodecError> {
    exact_keys(value, &["lease_id", "operation", "ticket"])?;
    let operation = decode_field::<OperationContext>(value, "operation")?;
    operation.validate()?;
    if operation.mode != AuthorityMode::Tunnel {
        return Err(CodecError::BoundViolation);
    }
    let bytes = decode_exact_bytes(value, "ticket", TICKET_BYTES)?;
    Ok(RedeemTunnelTicketRequest {
        operation,
        lease_id: decode_field(value, "lease_id")?,
        ticket: StartTicket::new(&bytes)?,
    })
}

fn decode_exact_bytes(root: &Value, key: &str, count: usize) -> Result<Vec<u8>, CodecError> {
    let values = root
        .get(key)
        .and_then(Value::as_array)
        .ok_or(CodecError::InvalidType)?;
    if values.len() != count {
        return Err(CodecError::BoundViolation);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(CodecError::InvalidType)
        })
        .collect()
}

fn tagged<T: Serialize + WireValidate>(kind: &str, value: &T) -> Result<Value, CodecError> {
    value.validate()?;
    Ok(json!({"kind": kind, "payload": value}))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum AuthorityEvent {
    Snapshot(AuthoritySnapshot),
    Revoke(StopDirective),
    Stop(StopDirective),
}
impl WireValidate for AuthorityEvent {
    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Snapshot(value) => value.validate(),
            Self::Revoke(value) | Self::Stop(value) => value.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope<T> {
    pub major: u16,
    pub minor: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Uuid>,
    pub request_id: Uuid,
    pub result: T,
}
impl<T> ResponseEnvelope<T> {
    pub fn new(request_id: Uuid, operation_id: Option<Uuid>, result: T) -> Self {
        Self {
            major: MAJOR,
            minor: MINOR,
            operation_id,
            request_id,
            result,
        }
    }
}
impl<T: WireValidate> WireValidate for ResponseEnvelope<T> {
    fn validate(&self) -> Result<(), CodecError> {
        if self.major != MAJOR {
            return Err(CodecError::UnsupportedMajor(self.major));
        }
        if self.minor != MINOR {
            return Err(CodecError::UnsupportedMinor(self.minor));
        }
        self.result.validate()
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

/// Bounded, non-secret diagnostic metadata for Authority failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDiagnostic {
    kind: BackendErrorKind,
    operation_id: Option<Uuid>,
    generation: Option<u64>,
    role: Option<AuthorityRole>,
    digest_prefix: Option<String>,
}

impl AuthorityDiagnostic {
    pub fn new(kind: BackendErrorKind) -> Self {
        Self {
            kind,
            operation_id: None,
            generation: None,
            role: None,
            digest_prefix: None,
        }
    }

    pub fn with_operation(mut self, operation_id: Uuid, generation: u64) -> Self {
        self.operation_id = Some(operation_id);
        self.generation = Some(generation);
        self
    }

    pub fn with_role(mut self, role: AuthorityRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_digest(mut self, digest: &str) -> Result<Self, CodecError> {
        if !is_digest(digest) {
            return Err(CodecError::BoundViolation);
        }
        self.digest_prefix = Some(digest[..12].to_owned());
        Ok(self)
    }
}

impl fmt::Display for AuthorityDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = serde_json::to_value(self.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "internal".to_owned());
        write!(formatter, "code={code}")?;
        if let Some(operation_id) = self.operation_id {
            write!(formatter, " operation_id={operation_id}")?;
        }
        if let Some(generation) = self.generation {
            write!(formatter, " generation={generation}")?;
        }
        if let Some(role) = self.role {
            let role = serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned());
            write!(formatter, " role={role}")?;
        }
        if let Some(prefix) = &self.digest_prefix {
            write!(formatter, " digest_prefix={prefix}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/authority-v1")
            .join(name);
        fs::read(path).expect("canonical fixture must exist")
    }

    #[test]
    fn fixed_cross_language_fixtures_decode_and_reencode() {
        verify_canonical_fixture::<HandshakeRequest>(&fixture("handshake.json")).unwrap();
        verify_canonical_fixture::<PrepareStartRequest>(&fixture("prepare-start.json")).unwrap();
        verify_canonical_fixture::<GlobalLease>(&fixture("global-lease.json")).unwrap();
        verify_canonical_fixture::<ReplayCursor>(&fixture("replay-cursor.json")).unwrap();
        verify_canonical_fixture::<AuthoritySnapshot>(&fixture("snapshot.json")).unwrap();
        verify_canonical_fixture::<ReadyAttestation>(&fixture("ready-attestation.json")).unwrap();
        verify_canonical_fixture::<StoppedAttestation>(&fixture("stopped-attestation.json"))
            .unwrap();
        verify_canonical_fixture::<PreferenceMutationReceipt>(&fixture(
            "preference-mutation-receipt.json",
        ))
        .unwrap();
        verify_canonical_fixture::<ResponseEnvelope<HandshakeResponse>>(&fixture(
            "handshake-response-envelope.json",
        ))
        .unwrap();
        decode_request(&fixture("handshake-request-envelope.json")).unwrap();
    }

    #[test]
    fn protocol_limits_are_exact() {
        assert_eq!(MAX_ENVELOPE_BYTES, 1_048_576);
        assert_eq!(MAX_CONFIGURATION_BYTES, 768 * 1_024);
        assert_eq!(MAX_TOTAL_SECRET_BYTES, 256 * 1_024);
        assert_eq!(MAX_CREDENTIAL_SLOTS, 256);
        assert_eq!(MAX_INDIVIDUAL_SECRET_BYTES, 16 * 1_024);
        assert_eq!(MAX_READ_ONLY_REQUESTS, 64);
        assert_eq!(MAX_MUTATING_TRANSACTIONS, 1);
        assert_eq!(MAX_QUEUED_EVENTS_PER_PEER, 32);
        assert_eq!(PREPARATION_LIFETIME_MS, 10_000);
        assert_eq!(COMMAND_TIMEOUT_MS, 5_000);
        assert_eq!(STOP_ATTESTATION_TIMEOUT_MS, 5_000);
    }

    #[test]
    fn strict_decoder_rejects_noncanonical_and_incompatible_envelopes() {
        let canonical = fixture("handshake-request-envelope.json");
        let with_space = [canonical.as_slice(), b" "].concat();
        assert!(matches!(
            decode_request(&with_space),
            Err(CodecError::Noncanonical)
        ));

        let duplicate = canonical.to_vec();
        let duplicate = String::from_utf8(duplicate).unwrap().replacen(
            "\"major\":1",
            "\"major\":1,\"major\":1",
            1,
        );
        assert!(matches!(
            decode_request(duplicate.as_bytes()),
            Err(CodecError::Noncanonical)
        ));

        let unknown = String::from_utf8(canonical.clone()).unwrap().replacen(
            "\"major\":1",
            "\"extra\":0,\"major\":1",
            1,
        );
        assert!(matches!(
            decode_request(unknown.as_bytes()),
            Err(CodecError::Noncanonical)
        ));

        let major =
            String::from_utf8(canonical.clone())
                .unwrap()
                .replacen("\"major\":1", "\"major\":2", 1);
        assert!(matches!(
            decode_request(major.as_bytes()),
            Err(CodecError::UnsupportedMajor(2))
        ));

        let feature = String::from_utf8(canonical).unwrap().replacen(
            "\"required_feature_bits\":0",
            "\"required_feature_bits\":1",
            1,
        );
        assert!(matches!(
            decode_request(feature.as_bytes()),
            Err(CodecError::UnsupportedRequiredFeatures(1))
        ));
    }

    #[test]
    fn strict_decoder_rejects_depth_type_and_size_bounds() {
        let mut deep = String::from("{\"x\":");
        deep.push_str(&"[".repeat(32));
        deep.push('0');
        deep.push_str(&"]".repeat(32));
        deep.push('}');
        assert_eq!(
            parse_canonical(deep.as_bytes()),
            Err(CodecError::BoundViolation)
        );
        assert_eq!(
            parse_canonical(b"{\"x\":1.0}"),
            Err(CodecError::InvalidType)
        );
        assert!(matches!(
            parse_canonical(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
            Err(CodecError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn authority_diagnostic_redacts_full_digest_and_has_only_bounded_metadata() {
        let digest = "ab".repeat(32);
        let diagnostic = AuthorityDiagnostic::new(BackendErrorKind::GlobalLeaseConflict)
            .with_operation(
                Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                7,
            )
            .with_role(AuthorityRole::Host)
            .with_digest(&digest)
            .unwrap()
            .to_string();
        assert!(diagnostic.contains("code=global_lease_conflict"));
        assert!(diagnostic.contains("generation=7"));
        assert!(diagnostic.contains("role=host"));
        assert!(diagnostic.contains("digest_prefix=abababababab"));
        assert!(!diagnostic.contains(&digest));
        assert!(!diagnostic.contains("secret"));
    }

    #[test]
    fn secret_material_enforces_slot_and_byte_bounds() {
        assert!(StartTicket::new(&[7; TICKET_BYTES]).is_ok());
        assert!(StartTicket::new(&[7; TICKET_BYTES - 1]).is_err());
        assert!(
            SensitiveBytes::new(
                &vec![0; MAX_INDIVIDUAL_SECRET_BYTES],
                MAX_INDIVIDUAL_SECRET_BYTES
            )
            .is_ok()
        );
        assert!(
            SensitiveBytes::new(
                &vec![0; MAX_INDIVIDUAL_SECRET_BYTES + 1],
                MAX_INDIVIDUAL_SECRET_BYTES
            )
            .is_err()
        );
    }
}
