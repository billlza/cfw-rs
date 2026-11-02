//! Structured request log entries.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StructuredLogEntry {
    pub time: Option<String>,
    pub level: String,
    #[serde(alias = "msg")]
    pub message: String,
    pub fields: Vec<StructuredLogField>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for StructuredLogEntry {
    fn default() -> Self {
        Self {
            time: None,
            level: "info".into(),
            message: String::new(),
            fields: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StructuredLogField {
    pub key: String,
    pub value: serde_json::Value,
}

#[cfg(test)]
mod tests;
