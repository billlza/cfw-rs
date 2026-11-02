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
pub const MINOR: u16 = 1;
pub const MINIMUM_MINOR: u16 = 1;
pub const SUPPORTED_FEATURE_BITS: u64 = 0;
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_CONFIGURATION_BYTES: u32 = cfw_singbox_config::MAX_ENGINE_CONFIG_BYTES as u32;
pub const MAX_TOTAL_SECRET_BYTES: usize = 256 * 1_024;
pub const MAX_CREDENTIAL_SLOTS: usize = cfw_singbox_config::MAX_CREDENTIAL_SLOTS;
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

mod codec;
mod diagnostic;
mod envelopes;
mod models;
mod requests;
mod secrets;
mod state;

pub use codec::{
    decode_canonical, decode_request, encode_canonical, encode_request, verify_canonical_fixture,
};
pub use diagnostic::AuthorityDiagnostic;
pub use envelopes::{AuthorityEvent, Command, RequestEnvelope, ResponseEnvelope};
pub use models::{
    AuthorityMode, AuthorityRole, AuthorityState, LeaseState, OperationContext, ProtocolVersion,
    RootContext,
};
pub use requests::{
    AuthorityAcknowledgement, BeginStopRequest, BindProxyOwnerRequest, CancelPreparedRequest,
    HandshakeRequest, HandshakeResponse, PrepareStartRequest, PreparedStart,
    RedeemTunnelTicketRequest, RedeemedTunnelStart, SnapshotRequest, StopDirective,
};
pub use secrets::{OwnerCapability, SecretMaterial, SecretSlot, SensitiveBytes, StartTicket};
pub use state::{
    AuthoritySnapshot, ConfigurationDescriptor, FailureSummary, GlobalLease, LeaseView,
    PacketPumpLimits, PreferenceMutationReceipt, ReadyAttestation, ReplayCursor,
    StoppedAttestation, TunnelPreferenceValues,
};

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

pub trait WireValidate {
    fn validate(&self) -> Result<(), CodecError>;
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
