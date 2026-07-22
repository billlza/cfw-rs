use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ConfigError, CredentialRef, profile::ProfileDocument};

pub const MAX_PROFILE_BYTES: usize = 384 * 1024;
pub const MAX_ENGINE_CONFIG_BYTES: usize = 384 * 1024;
pub const MAX_PROFILE_NODES: usize = 100_000;

const ALLOWED_PROFILE_KEYS: &[&str] = &["outbounds", "route"];

const FORBIDDEN_PROFILE_KEYS: &[&str] = &[
    "inbounds",
    "experimental",
    "log",
    "process_name",
    "process_path",
    "process_path_regex",
    "user",
    "user_id",
    "package_name",
    "script",
    "command",
    "executable",
    "url",
    "source_mac_address",
];

const CREDENTIAL_KEYS: &[&str] = &[
    "access_token",
    "api_key",
    "auth_key",
    "authorization",
    "client_secret",
    "password",
    "passwd",
    "pre_shared_key",
    "private_key",
    "psk",
    "refresh_token",
    "secret",
    "token",
    "uuid",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSingBoxProfile {
    pub(crate) canonical_json: String,
    pub(crate) document: ProfileDocument,
    digest: String,
}

impl ValidatedSingBoxProfile {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_PROFILE_BYTES {
            return Err(ConfigError::TooLarge {
                actual: input.len(),
                maximum: MAX_PROFILE_BYTES,
            });
        }

        let value: Value = serde_json::from_str(input)?;
        let object = value.as_object().ok_or(ConfigError::RootMustBeObject)?;
        for key in object.keys() {
            if !ALLOWED_PROFILE_KEYS.contains(&key.as_str()) {
                return Err(ConfigError::UnsupportedTopLevelKey(key.clone()));
            }
        }
        let mut visited_nodes = 0;
        reject_forbidden_keys(&value, "$", &mut visited_nodes)?;

        let document = serde_json::from_value::<ProfileDocument>(value)?;
        document.validate()?;
        let canonical_value = canonicalize(serde_json::to_value(&document)?);
        let canonical_json = serde_json::to_string(&canonical_value)?;
        let digest = sha256_hex(canonical_json.as_bytes());
        Ok(Self {
            canonical_json,
            document,
            digest,
        })
    }

    pub fn direct() -> Self {
        Self::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .expect("built-in direct profile must stay valid")
    }

    pub fn as_json(&self) -> &str {
        &self.canonical_json
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn credential_references(&self) -> Vec<CredentialRef> {
        self.document.credential_references()
    }

    /// True only when the effective final route selects a supported remote
    /// transport. Merely declaring an unused remote does not make a DIRECT or
    /// BLOCK final route safe for one-way legacy VPN retirement.
    pub fn routes_through_remote(&self) -> bool {
        let selected = self.document.effective_final_outbound_tag();
        self.document
            .outbounds
            .iter()
            .find(|outbound| outbound.tag() == selected)
            .is_some_and(crate::profile::ProfileOutbound::is_remote)
    }
}

fn reject_forbidden_keys(
    value: &Value,
    path: &str,
    visited_nodes: &mut usize,
) -> Result<(), ConfigError> {
    *visited_nodes = visited_nodes
        .checked_add(1)
        .ok_or(ConfigError::TooComplex {
            maximum: MAX_PROFILE_NODES,
        })?;
    if *visited_nodes > MAX_PROFILE_NODES {
        return Err(ConfigError::TooComplex {
            maximum: MAX_PROFILE_NODES,
        });
    }
    match value {
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some("remote") {
                return Err(ConfigError::RemoteResource {
                    path: path.to_string(),
                });
            }
            for (key, child) in map {
                if CREDENTIAL_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError::CredentialRequiresKeychain {
                        path: path.to_string(),
                        key: key.clone(),
                    });
                }
                if is_forbidden_profile_key(key) {
                    return Err(ConfigError::ForbiddenKey {
                        path: path.to_string(),
                        key: key.clone(),
                    });
                }
                reject_forbidden_keys(child, &format!("{path}.{key}"), visited_nodes)?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_forbidden_keys(child, &format!("{path}[{index}]"), visited_nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_forbidden_profile_key(key: &str) -> bool {
    FORBIDDEN_PROFILE_KEYS.contains(&key) || key.ends_with("_path") || key.ends_with("_url")
}

pub(crate) fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        scalar => scalar,
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
