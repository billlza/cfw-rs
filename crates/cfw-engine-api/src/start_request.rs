//! The request that starts, checks or authorizes one engine runtime.

use std::fmt;

use cfw_singbox_config::{CredentialAudience, CredentialSlot};
use serde::{Deserialize, Serialize};

use crate::{EngineCommandContext, EngineStartMode, TunnelNetworkOptions};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStartRequest {
    pub context: EngineCommandContext,
    /// Explicit network ownership intent, bound into the configuration digest.
    /// A local proxy request cannot be reinterpreted as System Proxy ownership.
    pub mode: EngineStartMode,
    /// Exact validated profile identity authorized to resolve every credential
    /// slot in this request. It is included in `config_digest`.
    pub credential_audience: CredentialAudience,
    pub config_json: String,
    /// SHA-256 of config_json, used to verify exact in-memory runtime bytes at
    /// every native owner boundary.
    pub config_content_digest: String,
    /// Identity digest covering configuration content and mode-specific OS
    /// network options. Runtime readiness and idempotence bind to this value.
    pub config_digest: String,
    /// Closed, secret-free instructions for the authenticated native vault.
    /// Every target points at an empty string in `config_json`; only the native
    /// boundary may replace those placeholders immediately before libbox start.
    pub credential_slots: Vec<CredentialSlot>,
    pub tunnel_options: Option<TunnelNetworkOptions>,
}

impl fmt::Debug for EngineStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineStartRequest")
            .field("context", &self.context)
            .field("mode", &self.mode)
            .field("credential_audience", &self.credential_audience)
            .field("config_json", &"[REDACTED CONFIG TEMPLATE]")
            .field("config_content_digest", &self.config_content_digest)
            .field("config_digest", &self.config_digest)
            .field("credential_slots", &self.credential_slots)
            .field("tunnel_options", &self.tunnel_options)
            .finish()
    }
}

#[cfg(test)]
mod tests;
