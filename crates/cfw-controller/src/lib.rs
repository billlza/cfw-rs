//! A client for the Clash-compatible controller API of the running engine.

use serde::{Deserialize, Serialize};

const MAX_CONTROLLER_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTROLLER_ERROR_BYTES: usize = 16 * 1024;
const MAX_CONTROLLER_CONNECTIONS: usize = 4_096;
const MAX_CONTROLLER_PROXIES: usize = 8_192;
const MAX_CONTROLLER_RULES: usize = 16_384;
const MAX_CONTROLLER_LOG_FIELDS: usize = 64;

mod client;
mod config;
mod connections;
mod endpoint;
mod error;
mod logs;
mod providers;
mod proxies;
mod response;
mod rules;

pub use client::ControllerClient;
pub use config::{ClashConfig, ConfigPatch, ControllerVersion};
pub use connections::{Connection, ConnectionMetadata, ConnectionsSnapshot};
pub use endpoint::ControllerEndpoint;
pub use error::{ControllerError, require_provider_management};
pub use logs::{StructuredLogEntry, StructuredLogField};
pub use providers::{ProviderBatchFailure, ProviderBatchResult, ProviderEntry, ProvidersSnapshot};
pub use proxies::{
    DelayHistory, ProxiesSnapshot, ProxyDelayFailureKind, ProxyDelayResult, ProxyGroup, ProxyNode,
};
pub use rules::{RuleEntry, RulesSnapshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerSnapshot {
    pub config: ClashConfig,
    pub proxies: ProxiesSnapshot,
    pub connections: ConnectionsSnapshot,
}

#[cfg(test)]
mod test_support;
