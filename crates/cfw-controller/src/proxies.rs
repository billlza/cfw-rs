//! Proxy groups, nodes, selection and delay measurements.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ControllerError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxiesSnapshot {
    pub groups: Vec<ProxyGroup>,
    pub proxies: Vec<ProxyNode>,
}

impl From<ProxiesResponse> for ProxiesSnapshot {
    fn from(response: ProxiesResponse) -> Self {
        let mut groups = Vec::new();
        let mut proxies = Vec::new();

        for (name, entry) in response.proxies {
            if entry.hidden {
                continue;
            }
            if let Some(options) = entry.all.clone() {
                groups.push(ProxyGroup {
                    name,
                    kind: entry.kind,
                    now: entry.now,
                    options,
                    history: entry.history,
                });
            } else {
                proxies.push(ProxyNode {
                    name,
                    kind: entry.kind,
                    udp: entry.udp,
                    history: entry.history,
                });
            }
        }

        groups.sort_by(|left, right| left.name.cmp(&right.name));
        proxies.sort_by(|left, right| left.name.cmp(&right.name));
        Self { groups, proxies }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ProxiesResponse {
    proxies: HashMap<String, ProxyEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct ProxyEntry {
    hidden: bool,
    #[serde(rename = "type")]
    kind: String,
    all: Option<Vec<String>>,
    now: Option<String>,
    udp: Option<bool>,
    history: Vec<DelayHistory>,
}

impl Default for ProxyEntry {
    fn default() -> Self {
        Self {
            kind: "Unknown".into(),
            hidden: false,
            all: None,
            now: None,
            udp: None,
            history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: String,
    pub now: Option<String>,
    pub options: Vec<String>,
    pub history: Vec<DelayHistory>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyNode {
    pub name: String,
    pub kind: String,
    pub udp: Option<bool>,
    pub history: Vec<DelayHistory>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DelayHistory {
    pub time: String,
    pub delay: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct SelectProxyRequest<'a> {
    pub(crate) name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDelayResult {
    pub name: String,
    pub delay: Option<u32>,
    pub error_kind: Option<ProxyDelayFailureKind>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDelayFailureKind {
    Timeout,
    NotFound,
    ProbeFailed,
    Rejected,
    Transport,
    InvalidResponse,
    InvalidRequest,
    Unsupported,
}

impl From<&ControllerError> for ProxyDelayFailureKind {
    fn from(error: &ControllerError) -> Self {
        match error {
            ControllerError::Status { status: 504, .. } => Self::Timeout,
            ControllerError::Status { status: 404, .. } => Self::NotFound,
            ControllerError::Status { status: 503, .. } => Self::ProbeFailed,
            ControllerError::Status { .. } => Self::Rejected,
            ControllerError::Http(source) if source.is_timeout() => Self::Timeout,
            ControllerError::Http(source) if source.is_decode() || source.is_body() => {
                Self::InvalidResponse
            }
            ControllerError::Http(_) => Self::Transport,
            ControllerError::Json(_)
            | ControllerError::ResponseBodyRead { .. }
            | ControllerError::ResponseTooLarge { .. }
            | ControllerError::PayloadLimit { .. } => Self::InvalidResponse,
            ControllerError::InvalidEndpoint(_) => Self::InvalidRequest,
            ControllerError::UnsupportedByPinnedEngine { .. } => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DelayResponse {
    pub(crate) delay: u32,
}

#[cfg(test)]
mod tests;
