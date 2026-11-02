//! The outbound collector every subscription syntax shares: unique tags,
//! routes, DNS, providers and the credentials bound to each outbound.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cfw_singbox_config::{CredentialKind, CredentialRef, MAX_OUTBOUNDS, ValidatedSingBoxProfile};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use super::{ImportedCredential, ImportedSubscription, sanitized_token};

/// Accumulates converted outbounds plus their vault-bound secrets. Shared by
/// the node-URI and Clash YAML import paths so tag uniqueness and credential
/// handling stay identical regardless of the subscription syntax.
#[derive(Debug, Default)]
pub(super) struct OutboundCollector {
    pub(super) outbounds: Vec<Value>,
    pub(super) route: Option<Value>,
    pub(super) detours: BTreeMap<String, String>,
    pub(super) dns: Option<Value>,
    pub(super) hosts: BTreeMap<String, Vec<String>>,
    pub(super) providers: Option<cfw_singbox_config::ProviderCatalog>,
    pub(super) credentials: Vec<ImportedCredential>,
    pub(super) used_tags: BTreeSet<String>,
    next_tag_suffix: BTreeMap<String, usize>,
    credential_positions: BTreeMap<CredentialRef, usize>,
    credential_namespace: Option<Uuid>,
    reusable_references: VecDeque<CredentialRef>,
}

impl OutboundCollector {
    pub(super) fn with_credential_namespace(namespace: Uuid) -> Self {
        Self {
            credential_namespace: Some(namespace),
            ..Self::default()
        }
    }

    pub(super) fn with_reusable_references(references: Vec<CredentialRef>) -> Self {
        Self {
            reusable_references: references.into(),
            ..Self::default()
        }
    }

    pub(super) fn push_entry(&mut self, entry: &str, index: usize) -> Result<(), String> {
        let scheme = entry
            .split("://")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let outbound = match scheme.as_str() {
            "http" | "https" => self.parse_http_proxy(entry, index)?,
            "socks" | "socks5" => self.parse_socks5(entry, index)?,
            "ss" => self.parse_shadowsocks(entry, index)?,
            "vmess" => self.parse_vmess(entry, index)?,
            "vless" => self.parse_vless(entry, index)?,
            "trojan" => self.parse_trojan(entry, index)?,
            "hysteria2" | "hy2" => self.parse_hysteria2(entry, index)?,
            "anytls" => self.parse_anytls(entry, index)?,
            "tuic" => self.parse_tuic(entry, index)?,
            _ => {
                return Err(format!(
                    "subscription URI scheme is unsupported: {}",
                    sanitized_token(&scheme)
                ));
            }
        };
        self.outbounds.push(outbound);
        Ok(())
    }

    pub(super) fn push_secret(
        &mut self,
        kind: CredentialKind,
        mut secret: String,
    ) -> CredentialRef {
        let mut reference = match self.reusable_references.front() {
            Some(reference) if reference.kind() == kind => self
                .reusable_references
                .pop_front()
                .expect("front reference must remain present"),
            Some(_) => {
                self.reusable_references.clear();
                self.new_credential_reference(kind)
            }
            None => self.new_credential_reference(kind),
        };

        if let Some(position) = self.credential_positions.get(&reference) {
            let existing = &self.credentials[*position];
            if existing.secret == secret {
                secret.zeroize();
                return reference;
            }
            // A formerly shared credential now carries different material in
            // this slot. Credential references are immutable vault identities,
            // so split this slot instead of provisioning one reference twice.
            reference = self.new_credential_reference(kind);
        }
        self.credential_positions
            .insert(reference.clone(), self.credentials.len());
        self.credentials.push(ImportedCredential {
            reference: reference.clone(),
            secret,
        });
        reference
    }

    fn new_credential_reference(&self, kind: CredentialKind) -> CredentialRef {
        let id = self
            .credential_namespace
            .as_ref()
            .map(|namespace| deterministic_credential_uuid(namespace, self.credentials.len(), kind))
            .unwrap_or_else(Uuid::new_v4);
        CredentialRef::new(id.hyphenated().to_string(), kind)
            .expect("generated credential UUID must stay canonical")
    }

    pub(super) fn unique_tag(&mut self, preferred: String) -> Result<String, String> {
        let sanitized = match preferred.trim().replace('\n', " ") {
            value if value.is_empty() => "proxy".to_owned(),
            value => value,
        };
        if self.used_tags.insert(sanitized.clone()) {
            return Ok(sanitized);
        }
        let next = self.next_tag_suffix.entry(sanitized.clone()).or_insert(2);
        for suffix in *next..=MAX_OUTBOUNDS {
            let candidate = format!("{sanitized}-{suffix}");
            if self.used_tags.insert(candidate.clone()) {
                *next = suffix + 1;
                return Ok(candidate);
            }
        }
        Err(format!(
            "subscription cannot assign a unique outbound tag within the {MAX_OUTBOUNDS}-entry limit"
        ))
    }

    /// Encodes the collected outbounds and runs the result through the
    /// closed profile validator, which owns every schema decision.
    pub(super) fn into_subscription(self) -> Result<ImportedSubscription, String> {
        let mut document = json!({ "outbounds": self.outbounds });
        let provider_sources = self
            .providers
            .as_ref()
            .map(cfw_singbox_config::ProviderCatalog::sources)
            .unwrap_or_default();
        if let Some(providers) = self.providers {
            document["providers"] = json!(providers);
        }
        if let Some(route) = self.route {
            document["route"] = route;
        }
        if !self.detours.is_empty() {
            document["detours"] = json!(self.detours);
        }
        if let Some(dns) = self.dns {
            document["dns"] = dns;
        }
        if !self.hosts.is_empty() {
            document["hosts"] = json!(self.hosts);
        }
        let profile_json = serde_json::to_string(&document)
            .map_err(|error| format!("failed to encode imported subscription profile: {error}"))?;
        let profile = ValidatedSingBoxProfile::parse(&profile_json)
            .and_then(|profile| profile.with_provider_sources(provider_sources))
            .map_err(|error| error.to_string())?;
        Ok(ImportedSubscription {
            profile,
            credentials: self.credentials,
        })
    }
}

fn deterministic_credential_uuid(namespace: &Uuid, index: usize, kind: CredentialKind) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"cfw-legacy-credential-reference-v1\0");
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(index.to_be_bytes());
    hasher.update([credential_kind_discriminant(kind)]);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub(super) fn credential_kind_discriminant(kind: CredentialKind) -> u8 {
    match kind {
        CredentialKind::WireGuardPrivateKey => 12,
        CredentialKind::WireGuardPreSharedKey => 13,
        CredentialKind::ShadowsocksPassword => 1,
        CredentialKind::VmessUuid => 2,
        CredentialKind::VlessUuid => 3,
        CredentialKind::TrojanPassword => 4,
        CredentialKind::Hysteria2Password => 5,
        CredentialKind::Hysteria2ObfsPassword => 6,
        CredentialKind::AnyTlsPassword => 7,
        CredentialKind::TuicUuid => 8,
        CredentialKind::TuicPassword => 9,
        CredentialKind::Socks5Username => 10,
        CredentialKind::Socks5Password => 11,
        CredentialKind::HttpProxyUsername => 14,
        CredentialKind::HttpProxyPassword => 15,
        CredentialKind::TailscaleAuthKey => 16,
    }
}

pub(super) fn credential_ref_json(reference: &CredentialRef) -> Value {
    json!({
        "id": reference.id(),
        "kind": reference.kind(),
    })
}
