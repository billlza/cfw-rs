//! Controller rules.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesSnapshot {
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleEntry {
    pub index: Option<u32>,
    #[serde(rename = "type")]
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub size: Option<i64>,
    #[serde(rename = "hitCount", alias = "hit_count")]
    pub hits: Option<u64>,
    pub provider: Option<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests;
