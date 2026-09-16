use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ConfigError, CredentialRef, ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase,
    profile::ProfileDocument,
};

pub use crate::capacity::{MAX_ENGINE_CONFIG_BYTES, MAX_PROFILE_BYTES};
pub const MAX_PROFILE_NODES: usize = 100_000;

const ALLOWED_PROFILE_KEYS: &[&str] =
    &["outbounds", "route", "detours", "dns", "hosts", "providers"];

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

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedSingBoxProfile {
    pub(crate) canonical_json: String,
    pub(crate) document: ProfileDocument,
    digest: String,
    proxy_selections: std::collections::BTreeMap<String, String>,
    pub(crate) dns_projection: DnsProjection,
    pub(crate) release_packet_evidence_case: Option<ReleasePacketEvidenceCase>,
}

impl std::fmt::Debug for ValidatedSingBoxProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedSingBoxProfile")
            .field("digest", &self.digest)
            .field("outbound_count", &self.document.outbounds.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsProjection {
    Ordinary,
    ReleaseEvidence(ReleaseDnsEvidenceCase),
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
            proxy_selections: std::collections::BTreeMap::new(),
            dns_projection: DnsProjection::Ordinary,
            release_packet_evidence_case: None,
        })
    }

    pub fn direct() -> Self {
        Self::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .expect("built-in direct profile must stay valid")
    }

    /// Builds the only profile admitted for physical DNS evidence.
    ///
    /// It is always credential-free DIRECT. The selected case controls only a
    /// source-owned DNS projection whose endpoints are not caller inputs.
    pub fn release_dns_evidence(case: ReleaseDnsEvidenceCase) -> Self {
        let mut profile = Self::direct();
        profile.dns_projection = DnsProjection::ReleaseEvidence(case);
        profile
    }

    /// Builds the only profile admitted for physical Packet evidence.
    ///
    /// It is always credential-free DIRECT. A reviewed case may activate a
    /// source-owned DNS projection or the single fixed direct IPv4 host route;
    /// neither can be expressed by ordinary profile JSON.
    pub fn release_packet_evidence(case: ReleasePacketEvidenceCase) -> Self {
        let mut profile = Self::direct();
        profile.release_packet_evidence_case = Some(case);
        if let Some(dns_case) = case.dns_evidence_case() {
            profile.dns_projection = DnsProjection::ReleaseEvidence(dns_case);
        }
        profile
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

    /// Returns references in outbound/slot order for a transaction that wants
    /// to retain stable immutable IDs while rebuilding an equivalent profile.
    /// Presence and vault requests continue to use the canonical sorted view.
    pub fn credential_references_in_outbound_order(&self) -> Vec<CredentialRef> {
        self.document.credential_references_in_outbound_order()
    }

    /// True only when the effective final route selects a supported remote
    /// transport. Merely declaring an unused remote does not make a DIRECT or
    /// BLOCK final route safe for one-way legacy VPN retirement.
    pub fn routes_through_remote(&self) -> bool {
        self.document.selected_route_is_remote()
    }

    /// User choices are separate from the imported document and its credential
    /// audience. The projected configuration identity still binds each choice.
    pub fn proxy_selections(&self) -> &std::collections::BTreeMap<String, String> {
        &self.proxy_selections
    }

    /// Changes only a validated selector's runtime default. Neither the imported
    /// JSON nor its digest changes when choosing another already-declared node.
    pub fn with_selected_outbound(&self, group: &str, selected: &str) -> Result<Self, ConfigError> {
        let mut profile = self.clone();
        let selector = profile
            .document
            .outbounds
            .iter_mut()
            .find(|outbound| outbound.tag() == group);
        let Some(crate::profile::ProfileOutbound::Selector {
            outbounds, default, ..
        }) = selector
        else {
            return Err(ConfigError::UnsupportedPolicyShape {
                path: "$.outbounds".into(),
                reason: "selection requires a saved selector group".into(),
            });
        };
        if !outbounds.iter().any(|tag| tag == selected) {
            return Err(ConfigError::UnsupportedPolicyShape {
                path: "$.outbounds".into(),
                reason: "selection must name a member of the group".into(),
            });
        }
        *default = Some(selected.to_owned());
        profile
            .proxy_selections
            .insert(group.to_owned(), selected.to_owned());
        Ok(profile)
    }

    /// Retain valid manual choices. Removed groups or members use the new
    /// document's default and are explicitly reported for the update receipt.
    pub fn inherit_proxy_selections(
        &self,
        previous: &Self,
    ) -> Result<(Self, Vec<String>), ConfigError> {
        let mut profile = self.clone();
        let mut reset_groups = Vec::new();
        for (group, selected) in previous.proxy_selections() {
            let supported = profile.document.outbounds.iter().any(|outbound| {
                matches!(
                    outbound,
                    crate::profile::ProfileOutbound::Selector { tag, outbounds, .. }
                        if tag == group && outbounds.contains(selected)
                )
            });
            if supported {
                profile = profile.with_selected_outbound(group, selected)?;
            } else {
                reset_groups.push(group.clone());
            }
        }
        Ok((profile, reset_groups))
    }

    /// Editing routing/DNS may bind existing secrets to a new profile digest,
    /// but cannot silently send those secrets to a changed remote transport.
    pub fn can_rebind_credentials_from(&self, previous: &Self) -> bool {
        self.document.outbounds.iter().all(|outbound| {
            outbound.credential_refs().is_empty()
                || previous
                    .document
                    .outbounds
                    .iter()
                    .any(|old| old == outbound)
        })
    }

    /// Provider replacement can add fresh references while retaining unchanged
    /// local nodes. Reusing an old reference on a changed transport is rejected.
    pub fn retained_credential_references(
        &self,
        previous: &Self,
    ) -> Result<Vec<CredentialRef>, ConfigError> {
        let old = previous
            .credential_references()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let nodes = previous
            .document
            .outbounds
            .iter()
            .map(|node| (node.tag(), node))
            .collect::<BTreeMap<_, _>>();
        let mut retained = std::collections::BTreeSet::new();
        for outbound in &self.document.outbounds {
            let references = outbound.credential_refs();
            if references.iter().any(|reference| old.contains(*reference)) {
                if !nodes
                    .get(outbound.tag())
                    .is_some_and(|node| *node == outbound)
                {
                    return Err(ConfigError::UnsupportedPolicyShape { path:"$.outbounds".into(), reason:"an existing credential cannot be reused by a changed transport; import fresh credentials for that node".into() });
                }
                retained.extend(references.into_iter().cloned());
            }
        }
        Ok(retained.into_iter().collect())
    }

    pub fn credential_references_for_outbounds(
        &self,
        tags: &std::collections::BTreeSet<String>,
    ) -> Vec<CredentialRef> {
        self.document
            .outbounds
            .iter()
            .filter(|outbound| tags.contains(outbound.tag()))
            .flat_map(|outbound| outbound.credential_refs().into_iter().cloned())
            .collect()
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
                let policy_tag = matches!(path, "$.detours" | "$.hosts");
                if CREDENTIAL_KEYS.contains(&key.as_str()) && !policy_tag {
                    return Err(ConfigError::CredentialRequiresKeychain {
                        path: path.to_string(),
                        key: key.clone(),
                    });
                }
                let group_probe_url = key == "url"
                    && matches!(
                        map.get("type").and_then(Value::as_str),
                        Some("urltest" | "fallback" | "loadbalance")
                    )
                    && path
                        .strip_prefix("$.outbounds[")
                        .and_then(|index| index.strip_suffix(']'))
                        .is_some_and(|index| index.parse::<usize>().is_ok());
                let provider_url = key == "url"
                    && (path.starts_with("$.providers.proxies[")
                        || path.starts_with("$.providers.rules["));
                if is_forbidden_profile_key(key) && !group_probe_url && !policy_tag && !provider_url
                {
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
