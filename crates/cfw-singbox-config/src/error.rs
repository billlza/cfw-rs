use thiserror::Error;

use crate::{CredentialKind, CredentialSlotError, InvalidCredentialAudience};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("sing-box profile is too large: {actual} bytes exceeds {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("projected sing-box config is too large: {actual} bytes exceeds {maximum}")]
    ProjectedTooLarge { actual: usize, maximum: usize },
    #[error("sing-box profile JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("sing-box profile root must be an object")]
    RootMustBeObject,
    #[error("top-level key is managed by the application or unsupported: {0}")]
    UnsupportedTopLevelKey(String),
    #[error("forbidden sing-box key {key} at {path}")]
    ForbiddenKey { path: String, key: String },
    #[error("remote sing-box resources are unsupported at {path}")]
    RemoteResource { path: String },
    #[error("credential key {key} at {path} requires the shared Keychain projection")]
    CredentialRequiresKeychain { path: String, key: String },
    #[error("credential reference at {path} has kind {actual:?}, expected {expected:?}")]
    CredentialKindMismatch {
        path: String,
        expected: CredentialKind,
        actual: CredentialKind,
    },
    #[error("credential id {id} is reused with conflicting credential kinds")]
    ConflictingCredentialReference { id: String },
    #[error("credential slot contract is invalid: {0}")]
    InvalidCredentialSlot(#[from] CredentialSlotError),
    #[error("credential audience is invalid: {0}")]
    InvalidCredentialAudience(#[from] InvalidCredentialAudience),
    #[error("unsupported credential-free policy shape at {path}: {reason}")]
    UnsupportedPolicyShape { path: String, reason: String },
    #[error("sing-box profile structure exceeds {maximum} JSON nodes")]
    TooComplex { maximum: usize },
    #[error("mixed proxy port must be between 1 and 65535")]
    InvalidMixedPort,
    #[error("controller port {0} must be at least 1024 and must not reuse the mixed proxy port")]
    InvalidControllerPort(u16),
    #[error("tunnel MTU must be between 1280 and 9000, got {0}")]
    InvalidTunnelMtu(u16),
    #[error("tunnel bootstrap DNS servers are invalid: {0}")]
    InvalidBootstrapDnsServers(String),
    #[error("tunnel authenticated DNS servers are invalid: {0}")]
    InvalidAuthenticatedDnsServers(String),
    #[error("release DNS evidence projection requires Tunnel mode with IPv6 enabled")]
    InvalidReleaseDnsEvidenceMode,
    #[error("release Packet evidence projection requires Tunnel mode")]
    InvalidReleasePacketEvidenceMode,
}

impl From<serde_json::Error> for ConfigError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error.to_string())
    }
}
