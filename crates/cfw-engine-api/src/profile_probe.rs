use std::fmt;

use cfw_singbox_config::{CredentialAudience, CredentialSlot};
use serde::{Deserialize, Serialize};

/// One explicitly requested batch of application-originated HTTPS probes. This
/// request has no engine generation, ownership capability or OS integration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDelayTestRequest {
    pub audience: CredentialAudience,
    pub config_json: String,
    pub credential_slots: Vec<CredentialSlot>,
    pub proxies: Vec<String>,
    pub timeout_ms: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<String>,
}

impl fmt::Debug for ProfileDelayTestRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileDelayTestRequest")
            .field("audience", &self.audience)
            .field("proxy_count", &self.proxies.len())
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileProxyDelay {
    pub name: String,
    pub delay: Option<u32>,
    pub error_kind: Option<ProfileProbeFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProbeFailure {
    Timeout,
    NotFound,
    ProbeFailed,
}
