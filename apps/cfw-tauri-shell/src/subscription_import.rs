use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use cfw_singbox_config::{CredentialKind, CredentialRef, MAX_OUTBOUNDS, ValidatedSingBoxProfile};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

mod clash;
mod http_proxy;
mod sing_box;
mod sip008;
mod socks5;
mod tls;
mod uri;
mod vmess;
mod wireguard;
mod yaml;
pub(crate) use clash::resources::{
    ProviderKind, ProviderRequest, materialize as materialize_providers,
    replacement as replace_provider_resources, requests as provider_requests,
    stored_requests as stored_provider_requests,
};

/// Source-only rules, groups, and comments can exceed the closed profile limit.
/// Conversion still independently enforces `cfw_singbox_config::MAX_PROFILE_BYTES`.
pub(crate) const MAX_SUBSCRIPTION_DOCUMENT_BYTES: usize =
    cfw_singbox_config::MAX_SUBSCRIPTION_SOURCE_BYTES;

const SUPPORTED_URI_SCHEMES: &[&str] = &[
    "http",
    "https",
    "socks",
    "socks5",
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hy2",
    "anytls",
    "tuic",
];
// The pinned macOS sing-box build uses Go's 64-bit `int` for AlterId.
// Source values are normalized to the closed stored 0/1 representation below.
const MAX_SOURCE_VMESS_ALTER_ID: u64 = i64::MAX as u64;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ImportedCredential {
    pub(crate) reference: CredentialRef,
    pub(crate) secret: String,
}

impl fmt::Debug for ImportedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportedCredential")
            .field("reference", &self.reference)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ImportedCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportedSubscription {
    pub(crate) profile: ValidatedSingBoxProfile,
    pub(crate) credentials: Vec<ImportedCredential>,
}

/// Accumulates converted outbounds plus their vault-bound secrets. Shared by
/// the node-URI and Clash YAML import paths so tag uniqueness and credential
/// handling stay identical regardless of the subscription syntax.
#[derive(Debug, Default)]
struct OutboundCollector {
    outbounds: Vec<Value>,
    route: Option<Value>,
    detours: BTreeMap<String, String>,
    dns: Option<Value>,
    hosts: BTreeMap<String, Vec<String>>,
    providers: Option<cfw_singbox_config::ProviderCatalog>,
    credentials: Vec<ImportedCredential>,
    used_tags: BTreeSet<String>,
    next_tag_suffix: BTreeMap<String, usize>,
    credential_positions: BTreeMap<CredentialRef, usize>,
    credential_namespace: Option<Uuid>,
    reusable_references: VecDeque<CredentialRef>,
}

#[derive(Debug, Default)]
struct TlsParts {
    enabled: bool,
    server_name: String,
    alpn: Vec<String>,
    utls: Option<Value>,
    reality: Option<Value>,
}

pub(crate) fn import_subscription_document(body: &str) -> Result<ImportedSubscription, String> {
    import_subscription_document_with_collector(body, OutboundCollector::default())
}

/// Converts a subscription with stable, secret-free credential reference IDs.
/// The namespace is owned by the migration candidate and is never derived from
/// credential material, so retries reproduce the same profile identity without
/// retaining secrets between preview and commit.
pub(crate) fn import_subscription_document_with_credential_namespace(
    body: &str,
    namespace: Uuid,
) -> Result<ImportedSubscription, String> {
    import_subscription_document_with_collector(
        body,
        OutboundCollector::with_credential_namespace(namespace),
    )
}

/// Rebuilds an updated subscription with the current profile's references in
/// outbound order. An unchanged document therefore keeps the same secret-free
/// digest and vault audience. If the credential layout diverges, new IDs are
/// generated from the first incompatible slot onward.
pub(crate) fn import_subscription_document_with_reusable_references(
    body: &str,
    references: Vec<CredentialRef>,
) -> Result<ImportedSubscription, String> {
    import_subscription_document_with_collector(
        body,
        OutboundCollector::with_reusable_references(references),
    )
}

fn import_subscription_document_with_collector(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    if body.len() > MAX_SUBSCRIPTION_DOCUMENT_BYTES {
        return Err(format!(
            "profile source exceeds the {MAX_SUBSCRIPTION_DOCUMENT_BYTES}-byte limit"
        ));
    }
    let body = strip_document_bom(body);
    if body.lines().any(|line| line.trim() == "[Interface]") {
        return wireguard::import_document(body, collector);
    }
    if let Ok(profile) = ValidatedSingBoxProfile::parse(body) {
        return Ok(ImportedSubscription {
            profile,
            credentials: Vec::new(),
        });
    }

    if matches!(body.trim_start().chars().next(), Some('{' | '[')) {
        let root: Value = serde_json::from_str(body)
            .map_err(|_| "subscription JSON document is malformed".to_owned())?;
        let object = root
            .as_object()
            .ok_or_else(|| "subscription JSON root must be an object".to_owned())?;
        if object.contains_key("proxies")
            || object.contains_key("proxy-providers")
            || object.contains_key("rule-providers")
        {
            if object.contains_key("outbounds") || object.contains_key("servers") {
                return Err("subscription JSON has ambiguous profile formats".into());
            }
            return clash::import_clash_document(body, collector);
        }
        let is_sing_box = object.contains_key("outbounds");
        let is_sip008 = object.contains_key("servers") || object.contains_key("version");
        return match (is_sing_box, is_sip008) {
            (true, false) => sing_box::import_sing_box_document(body, collector),
            (false, true) => sip008::import_sip008_document(body, collector),
            (true, true) => {
                Err("subscription JSON ambiguously declares sing-box and SIP008 roots".to_owned())
            }
            (false, false) => Err(
                "subscription JSON is neither a supported sing-box node list nor SIP008".to_owned(),
            ),
        };
    }

    if looks_like_clash_yaml(body) {
        return clash::import_clash_document(body, collector);
    }

    let candidate = decode_uri_bundle_base64(body).unwrap_or_else(|| body.trim().to_owned());
    let entries = collect_uri_entries(&candidate)?;
    for (index, entry) in entries.iter().enumerate() {
        collector.push_entry(entry, index)?;
    }
    collector.into_subscription()
}

fn strip_document_bom(body: &str) -> &str {
    body.strip_prefix('\u{feff}').unwrap_or(body)
}

/// Detects Clash/Mihomo YAML documents from actual unindented mapping keys so
/// a comment, nested value, URI parameter, or JSON string cannot select the
/// YAML parser. Malformed documents with a real Clash root marker still take
/// the YAML path and retain its specific fail-closed diagnostics.
fn looks_like_clash_yaml(body: &str) -> bool {
    const CLASH_ROOT_KEYS: &[&str] = &[
        "proxies",
        "proxy-groups",
        "proxy-providers",
        "rule-providers",
        "mixed-port",
        "redir-port",
    ];
    body.lines().any(|line| {
        if line.is_empty() || line.starts_with([' ', '\t', '#', '-']) || line.starts_with("...") {
            return false;
        }
        line.split_once(':')
            .map(|(key, _value)| key.trim_end())
            .is_some_and(|key| CLASH_ROOT_KEYS.contains(&key))
    })
}

fn decode_uri_bundle_base64(body: &str) -> Option<String> {
    let compact: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.len() < 16
        || compact.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        })
    {
        return None;
    }
    let decoded = decode_base64_text(&compact).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let text = strip_document_bom(&text).to_owned();
    let has_supported_scheme = SUPPORTED_URI_SCHEMES
        .iter()
        .any(|scheme| text.contains(&format!("{scheme}://")));
    has_supported_scheme.then_some(text)
}

fn collect_uri_entries(body: &str) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.contains("://") {
            // Echo the line number only: subscription lines carry secrets.
            return Err(format!(
                "subscription line {} is neither part of a supported JSON document nor a supported node URI",
                index + 1
            ));
        }
        let scheme = trimmed
            .split("://")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !SUPPORTED_URI_SCHEMES.contains(&scheme.as_str()) {
            return Err(format!(
                "subscription URI scheme is unsupported: {}",
                sanitized_token(&scheme)
            ));
        }
        if entries.len() == cfw_singbox_config::MAX_PROXY_NODES {
            return Err(format!(
                "subscription URI bundle has more than {} entries",
                cfw_singbox_config::MAX_PROXY_NODES
            ));
        }
        entries.push(trimmed.to_owned());
    }
    if entries.is_empty() {
        return Err(
            "subscription document is not a supported sing-box JSON document or supported node URI bundle"
                .into(),
        );
    }
    Ok(entries)
}

impl OutboundCollector {
    fn with_credential_namespace(namespace: Uuid) -> Self {
        Self {
            credential_namespace: Some(namespace),
            ..Self::default()
        }
    }

    fn with_reusable_references(references: Vec<CredentialRef>) -> Self {
        Self {
            reusable_references: references.into(),
            ..Self::default()
        }
    }

    fn push_entry(&mut self, entry: &str, index: usize) -> Result<(), String> {
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

    fn push_secret(&mut self, kind: CredentialKind, mut secret: String) -> CredentialRef {
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

    fn unique_tag(&mut self, preferred: String) -> Result<String, String> {
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
    fn into_subscription(self) -> Result<ImportedSubscription, String> {
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

fn credential_kind_discriminant(kind: CredentialKind) -> u8 {
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
    }
}

fn split_fragment_strict<'a>(
    entry: &'a str,
    protocol: &str,
) -> Result<(&'a str, Option<String>), String> {
    match entry.split_once('#') {
        Some((before, fragment)) => decode_url_component(fragment)
            .map(|fragment| (before, Some(fragment)))
            .map_err(|_| format!("{protocol} URI fragment has invalid percent-encoding")),
        None => Ok((entry, None)),
    }
}

fn split_query_strict<'a>(
    entry: &'a str,
    protocol: &str,
) -> Result<(&'a str, BTreeMap<String, String>), String> {
    match entry.split_once('?') {
        Some((before, query)) => Ok((before, strict_query_pairs(query, protocol)?)),
        None => Ok((entry, BTreeMap::new())),
    }
}

fn strict_query_pairs(encoded: &str, protocol: &str) -> Result<BTreeMap<String, String>, String> {
    let mut query = BTreeMap::new();
    for pair in encoded.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_url_component(key)
            .map_err(|_| format!("{protocol} URI query key has invalid percent-encoding"))?;
        let value = decode_url_component(value)
            .map_err(|_| format!("{protocol} URI query value has invalid percent-encoding"))?;
        if query.insert(key.clone(), value).is_some() {
            return Err(format!(
                "{protocol} URI repeats query parameter {}",
                sanitized_token(&key)
            ));
        }
    }
    Ok(query)
}

fn strict_query_map(url: &Url, protocol: &str) -> Result<BTreeMap<String, String>, String> {
    let mut query = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if query.insert(key.clone(), value.into_owned()).is_some() {
            return Err(format!(
                "{protocol} URI repeats query parameter {}",
                sanitized_token(&key)
            ));
        }
    }
    Ok(query)
}

fn validate_share_url_path(url: &Url, protocol: &str) -> Result<(), String> {
    if !matches!(url.path(), "" | "/") {
        return Err(format!("{protocol} URI path is unsupported"));
    }
    Ok(())
}

fn required_url_username(url: &Url, label: &str) -> Result<String, String> {
    let decoded = decode_url_component(url.username())?;
    if decoded.is_empty() {
        return Err(format!("{label} is missing"));
    }
    Ok(decoded)
}

fn required_url_password(url: &Url, label: &str) -> Result<String, String> {
    let encoded = url
        .password()
        .ok_or_else(|| format!("{label} is missing"))?;
    let decoded = decode_url_component(encoded)?;
    if decoded.is_empty() {
        return Err(format!("{label} is missing"));
    }
    Ok(decoded)
}

fn decoded_fragment_strict(url: &Url, protocol: &str) -> Result<Option<String>, String> {
    url.fragment()
        .map(decode_url_component)
        .transpose()
        .map_err(|_| format!("{protocol} URI fragment has invalid percent-encoding"))
}

fn consume_tls_marker(query: &mut BTreeMap<String, String>, protocol: &str) -> Result<(), String> {
    match query.remove("security") {
        None => Ok(()),
        Some(value) if value.eq_ignore_ascii_case("tls") => Ok(()),
        Some(value) => Err(format!(
            "{protocol} URI security mode is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

fn consume_required_tls_marker(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    match query.remove("security") {
        None => Ok(()),
        Some(value) if value.is_empty() || value.eq_ignore_ascii_case("tls") => Ok(()),
        Some(value) => Err(format!(
            "{protocol} URI security mode is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

fn consume_empty_or_none_parameter(
    query: &mut BTreeMap<String, String>,
    key: &str,
    feature: &str,
) -> Result<(), String> {
    match query.remove(key) {
        None => Ok(()),
        Some(value) if value.is_empty() || value.eq_ignore_ascii_case("none") => Ok(()),
        Some(value) => Err(format!(
            "{feature} is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

fn take_query_alias(
    query: &mut BTreeMap<String, String>,
    keys: &[&str],
    protocol: &str,
    field: &str,
) -> Result<Option<String>, String> {
    let mut selected = None;
    for key in keys {
        if let Some(value) = query.remove(*key) {
            if selected.is_some() {
                return Err(format!(
                    "{protocol} URI repeats {field} using multiple aliases"
                ));
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

fn consume_certificate_verification_flags(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    for key in [
        "insecure",
        "allowInsecure",
        "allow_insecure",
        "skip-cert-verify",
    ] {
        if let Some(value) = query.remove(key) {
            match parse_uri_boolean(&value, protocol, key)? {
                false => {}
                true => {
                    return Err(format!(
                        "{protocol} URI requires disabling TLS certificate verification"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn consume_unsupported_enabled_flag(
    query: &mut BTreeMap<String, String>,
    keys: &[&str],
    feature: &str,
) -> Result<(), String> {
    for key in keys {
        if let Some(value) = query.remove(*key)
            && parse_uri_boolean(&value, feature, key)?
        {
            return Err(format!("{feature} is unsupported"));
        }
    }
    Ok(())
}

fn parse_uri_boolean(value: &str, context: &str, key: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!(
            "{context} URI parameter {} must be a boolean",
            sanitized_token(key)
        )),
    }
}

fn reject_query_leftovers(query: &BTreeMap<String, String>, protocol: &str) -> Result<(), String> {
    if query.is_empty() {
        return Ok(());
    }
    let keys = query
        .keys()
        .map(|key| sanitized_token(key))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!("{protocol} URI has unsupported parameters: {keys}"))
}

fn decode_url_component(value: &str) -> Result<String, String> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|error| format!("subscription URI contains invalid percent-encoding: {error}"))
}

fn decode_base64_text(value: &str) -> Result<Vec<u8>, String> {
    let compact = value.trim();
    for candidate in [pad_base64(compact), compact.to_owned()] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
    }
    Err("input is not valid base64".into())
}

fn pad_base64(value: &str) -> String {
    match value.len() % 4 {
        0 => value.to_owned(),
        remainder => format!("{value}{}", "=".repeat(4 - remainder)),
    }
}

fn parse_hysteria2_share_url(entry: &str) -> Result<(Url, Option<Vec<String>>), String> {
    let scheme_end = entry
        .find("://")
        .ok_or_else(|| "subscription Hysteria2 URI is invalid".to_owned())?;
    if !matches!(
        entry[..scheme_end].to_ascii_lowercase().as_str(),
        "hysteria2" | "hy2"
    ) {
        return Err("subscription Hysteria2 URI is invalid".to_owned());
    }
    let authority_start = scheme_end + 3;
    let authority_end = entry[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(entry.len());
    let authority = &entry[authority_start..authority_end];
    let host_port_start = authority.rfind('@').map(|index| index + 1).unwrap_or(0);
    let host_port = &authority[host_port_start..];
    let port_start = if host_port.starts_with('[') {
        let close = host_port
            .find(']')
            .ok_or_else(|| "subscription Hysteria2 URI is invalid".to_owned())?;
        match host_port[close + 1..].strip_prefix(':') {
            Some(_) => Some(close + 2),
            None if close + 1 == host_port.len() => None,
            None => return Err("subscription Hysteria2 URI is invalid".to_owned()),
        }
    } else {
        match host_port.rfind(':') {
            Some(index) if !host_port[..index].contains(':') => Some(index + 1),
            Some(_) => return Err("subscription Hysteria2 IPv6 host must be bracketed".to_owned()),
            None => None,
        }
    };
    let Some(port_start) = port_start else {
        return Url::parse(entry)
            .map(|url| (url, None))
            .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned());
    };
    let port_text = &host_port[port_start..];
    if !port_text.contains([',', '-']) {
        return Url::parse(entry)
            .map(|url| (url, None))
            .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned());
    }

    let server_ports = normalize_hysteria2_server_ports(port_text, "Hysteria2 URI port set")?;
    let first_port = server_ports[0]
        .split_once(':')
        .map(|(start, _end)| start)
        .unwrap_or(&server_ports[0]);
    let absolute_port_start = authority_start + host_port_start + port_start;
    let normalized = format!(
        "{}{first_port}{}",
        &entry[..absolute_port_start],
        &entry[authority_end..]
    );
    Url::parse(&normalized)
        .map(|url| (url, Some(server_ports)))
        .map_err(|_| "subscription Hysteria2 URI is invalid".to_owned())
}

fn normalize_hysteria2_server_ports(value: &str, label: &str) -> Result<Vec<String>, String> {
    const MAX_ITEMS: usize = 64;
    let parse_port = |value: &str| {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0 && port.to_string() == value)
    };
    let mut normalized = Vec::new();
    let mut intervals = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() || normalized.len() == MAX_ITEMS {
            return Err(format!("{label} has an invalid item count"));
        }
        let range = match (item.split_once('-'), item.split_once(':')) {
            (Some(range), None) | (None, Some(range)) => Some(range),
            (None, None) => None,
            _ => return Err(format!("{label} has an invalid range")),
        };
        let (canonical, interval) = match range {
            Some((start, end)) => match (parse_port(start), parse_port(end)) {
                (Some(start), Some(end)) if start < end => (format!("{start}:{end}"), (start, end)),
                _ => return Err(format!("{label} has an invalid range")),
            },
            None => match parse_port(item) {
                Some(port) => (port.to_string(), (port, port)),
                None => return Err(format!("{label} has an invalid port")),
            },
        };
        if intervals
            .iter()
            .any(|(start, end)| interval.0 <= *end && *start <= interval.1)
        {
            return Err(format!("{label} has overlapping items"));
        }
        normalized.push(canonical);
        intervals.push(interval);
    }
    if normalized.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(normalized)
}

fn parse_hysteria2_hop_interval_seconds(value: &str, label: &str) -> Result<u32, String> {
    let value = value.strip_suffix('s').unwrap_or(value);
    value
        .parse::<u32>()
        .ok()
        .filter(|seconds| (1..=3_600).contains(seconds) && seconds.to_string() == value)
        .ok_or_else(|| format!("{label} must be a canonical 1..=3600 second value"))
}

fn split_host_port(value: &str) -> Result<(String, u16), String> {
    let parsed = Url::parse(&format!("tcp://{value}"))
        .map_err(|_| "subscription endpoint host or port is invalid".to_owned())?;
    Ok((host_string(&parsed)?, port_from_url(&parsed)?))
}

fn host_string(url: &Url) -> Result<String, String> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "subscription endpoint host is missing".to_owned())?;
    // URL authorities bracket IPv6 literals; the typed profile stores the
    // address itself, matching every other endpoint source format.
    Ok(host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned())
}

fn port_from_url(url: &Url) -> Result<u16, String> {
    url.port_or_known_default()
        .filter(|port| *port != 0)
        .ok_or_else(|| "subscription endpoint port is missing".to_owned())
}

fn port_from_url_or_default(url: &Url, default: u16) -> Result<u16, String> {
    match url.port() {
        Some(0) => Err("subscription endpoint port is invalid".to_owned()),
        Some(port) => Ok(port),
        None if default != 0 => Ok(default),
        None => Err("subscription endpoint port is missing".to_owned()),
    }
}

fn normalize_shadowsocks_method(method: &str) -> Result<String, String> {
    match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm"
        | "aes-256-gcm"
        | "chacha20-ietf-poly1305"
        | "xchacha20-ietf-poly1305"
        | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305" => Ok(method.to_ascii_lowercase()),
        other => Err(format!(
            "Shadowsocks method is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn normalize_shadowsocks_method_and_password(
    method: &str,
    password: &str,
) -> Result<String, String> {
    let method = normalize_shadowsocks_method(method)?;
    let key_bytes = match method.as_str() {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return Ok(method),
    };
    for encoded_key in password.split(':') {
        let mut decoded_key = STANDARD.decode(encoded_key).map_err(|_| {
            format!(
                "Shadowsocks 2022 key chain must contain canonical standard-base64 {key_bytes}-byte keys"
            )
        })?;
        let valid_length = decoded_key.len() == key_bytes;
        decoded_key.zeroize();
        if !valid_length {
            return Err(format!(
                "Shadowsocks 2022 key chain must contain canonical standard-base64 {key_bytes}-byte keys"
            ));
        }
    }
    Ok(method)
}

fn canonical_uuid_credential(value: String, label: &str) -> Result<String, String> {
    let parsed = Uuid::parse_str(&value).map_err(|_| format!("{label} is not a UUID"))?;
    if parsed.is_nil() {
        return Err(format!("{label} must not be the nil UUID"));
    }
    Ok(parsed.hyphenated().to_string())
}

fn normalize_vmess_security(security: &str) -> Result<Option<String>, String> {
    if security.is_empty() || security.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    match security.to_ascii_lowercase().as_str() {
        "none" | "zero" | "aes-128-cfb" | "aes-128-gcm" | "chacha20-poly1305" => {
            Ok(Some(security.to_ascii_lowercase()))
        }
        other => Err(format!(
            "vmess security is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn parse_vmess_alter_id(value: &str, field: &str) -> Result<u8, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{field} must be a canonical non-negative decimal integer no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        ));
    }
    let value = value.parse::<u64>().map_err(|_| {
        format!(
            "{field} must be a canonical non-negative decimal integer no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        )
    })?;
    normalize_vmess_alter_id(value, field)
}

fn normalize_vmess_alter_id(value: u64, field: &str) -> Result<u8, String> {
    if value > MAX_SOURCE_VMESS_ALTER_ID {
        return Err(format!(
            "{field} must be no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        ));
    }
    // The pinned sing-box VMess contract treats every positive alter ID as
    // the same legacy protocol mode. Keep the stored profile closed to 0/1 so
    // equivalent source spellings cannot create different canonical state.
    Ok(u8::from(value != 0))
}

fn normalize_vless_flow(flow: &str) -> Result<String, String> {
    match flow {
        "xtls-rprx-vision" => Ok(flow.to_owned()),
        other => Err(format!(
            "VLESS flow is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn normalize_v2ray_packet_encoding(value: &str, field: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "" | "none" | "raw" => Ok("raw".to_owned()),
        "packetaddr" | "packet_addr" => Ok("packet_addr".to_owned()),
        "xudp" => Ok("xudp".to_owned()),
        other => Err(format!(
            "{field} is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn normalize_v2ray_http_method(value: &str, field: &str) -> Result<String, String> {
    match value.to_ascii_uppercase().as_str() {
        "GET" | "PUT" | "POST" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => {
            Ok(value.to_ascii_uppercase())
        }
        _ => Err(format!(
            "{field} is unsupported: {}",
            sanitized_token(value)
        )),
    }
}

fn normalize_tuic_congestion_control(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "cubic" | "new_reno" | "bbr" => Ok(value.to_ascii_lowercase()),
        other => Err(format!(
            "TUIC congestion control is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn normalize_tuic_udp_relay_mode(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "native" | "quic" => Ok(value.to_ascii_lowercase()),
        other => Err(format!(
            "TUIC UDP relay mode is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn parse_utls(value: &str) -> Result<Option<Value>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let fingerprint = match value.to_ascii_lowercase().as_str() {
        "chrome" | "firefox" | "edge" | "safari" | "360" | "qq" | "ios" | "android" | "random"
        | "randomized" => value.to_ascii_lowercase(),
        other => {
            return Err(format!(
                "uTLS fingerprint is unsupported: {}",
                sanitized_token(other)
            ));
        }
    };
    Ok(Some(json!({
        "enabled": true,
        "fingerprint": fingerprint,
    })))
}

fn build_tls_parts(
    enabled: bool,
    server_name: String,
    alpn: Vec<String>,
    utls: Option<Value>,
    reality: Option<Value>,
) -> TlsParts {
    TlsParts {
        enabled,
        server_name,
        alpn,
        utls,
        reality,
    }
}

fn tls_json(tls: TlsParts) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("enabled".into(), Value::Bool(tls.enabled));
    object.insert("server_name".into(), Value::String(tls.server_name));
    if !tls.alpn.is_empty() {
        object.insert(
            "alpn".into(),
            Value::Array(tls.alpn.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(utls) = tls.utls {
        object.insert("utls".into(), utls);
    }
    if let Some(reality) = tls.reality {
        object.insert("reality".into(), reality);
    }
    Value::Object(object)
}

fn transport_from_parts(
    kind: &str,
    path: Option<String>,
    host: Option<String>,
    service_name: Option<String>,
    method: Option<String>,
) -> Result<Option<Value>, String> {
    let normalized_kind = kind.to_ascii_lowercase();
    match normalized_kind.as_str() {
        "" | "tcp" | "none" => {
            if [
                path.as_deref(),
                host.as_deref(),
                service_name.as_deref(),
                method.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !value.is_empty())
            {
                return Err("TCP subscription transport declares unsupported options".into());
            }
            Ok(None)
        }
        "http" | "h2" => {
            if service_name.as_ref().is_some_and(|value| !value.is_empty()) {
                return Err("HTTP subscription transport declares a gRPC service name".into());
            }
            let mut transport = json!({
                "type": "http",
                "path": path.unwrap_or_else(|| "/".into()),
                "host": host.map(|value| split_csv(&value)).unwrap_or_default(),
            });
            if let Some(method) = method.filter(|value| !value.is_empty()) {
                transport["method"] =
                    Value::String(normalize_v2ray_http_method(&method, "HTTP method")?);
            }
            Ok(Some(transport))
        }
        "ws" => {
            if [service_name.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "WebSocket subscription transport declares unsupported service or method options"
                        .into(),
                );
            }
            let path = path.unwrap_or_else(|| "/".into());
            let mut object = serde_json::Map::new();
            object.insert("type".into(), Value::String("ws".into()));
            object.insert("path".into(), Value::String(path));
            if let Some(host) = host
                && !host.is_empty()
            {
                object.insert("headers".into(), json!({ "Host": host }));
            }
            Ok(Some(Value::Object(object)))
        }
        "grpc" => {
            if [path.as_deref(), host.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "gRPC subscription transport declares HTTP path or host options".into(),
                );
            }
            Ok(Some(json!({
                "type": "grpc",
                "service_name": non_empty(service_name.unwrap_or_default())
                    .ok_or_else(|| "gRPC subscriptions require a non-empty serviceName".to_owned())?,
            })))
        }
        "quic" => {
            if [
                path.as_deref(),
                host.as_deref(),
                service_name.as_deref(),
                method.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !value.is_empty())
            {
                return Err("QUIC subscription transport declares unsupported options".into());
            }
            Ok(Some(json!({ "type": "quic" })))
        }
        "httpupgrade" | "http-upgrade" => {
            if [service_name.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "HTTPUpgrade subscription transport declares unsupported service or method options"
                        .into(),
                );
            }
            let mut transport = json!({
                "type": "http_upgrade",
                "path": path.unwrap_or_else(|| "/".into()),
            });
            if let Some(host) = host.filter(|value| !value.is_empty()) {
                transport["host"] = Value::String(host);
            }
            Ok(Some(transport))
        }
        other => Err(format!(
            "subscription transport is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn non_empty(value: impl Into<String>) -> Option<String> {
    let value = value.into();
    (!value.is_empty()).then_some(value)
}

/// Remote subscription tokens are never safe to echo: a short identifier-like
/// scheme, enum value, or unknown key can itself carry an access credential.
fn sanitized_token(_token: &str) -> String {
    "<redacted>".to_owned()
}

fn parse_port_value(value: &serde_json::Value) -> Result<u16, String> {
    match value {
        serde_json::Value::String(value) => value
            .parse()
            .map_err(|_| "vmess port is invalid".to_owned()),
        serde_json::Value::Number(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "vmess port is invalid".to_owned()),
        _ => Err("vmess port is invalid".into()),
    }
}

fn parse_positive_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}

fn credential_ref_json(reference: &CredentialRef) -> Value {
    json!({
        "id": reference.id(),
        "kind": reference.kind(),
    })
}

#[cfg(test)]
mod tests;
