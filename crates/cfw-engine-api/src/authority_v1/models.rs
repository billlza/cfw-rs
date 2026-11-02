//! The protocol version, modes, roles, states and the contexts every operation carries.

use super::*;

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
        if self.minor != MINOR || self.minimum_minor != MINIMUM_MINOR {
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
    LocalProxy,
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

#[cfg(test)]
mod tests;
