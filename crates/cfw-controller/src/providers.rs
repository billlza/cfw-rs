//! Proxy and rule providers.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidersSnapshot {
    pub proxy_providers: Vec<ProviderEntry>,
    pub rule_providers: Vec<ProviderEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderEntry {
    pub name: String,
    pub kind: String,
    pub vehicle_type: String,
    pub behavior: Option<String>,
    pub updated_at: Option<String>,
    pub proxies: Vec<String>,
    pub rules: Vec<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderBatchResult {
    pub action: String,
    pub requested: usize,
    pub succeeded: Vec<String>,
    pub failed: Vec<ProviderBatchFailure>,
}

impl ProviderBatchResult {
    pub fn is_complete_success(&self) -> bool {
        self.failed.is_empty() && self.succeeded.len() == self.requested
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderBatchFailure {
    pub name: String,
    pub error: String,
}

#[cfg(test)]
mod tests;
