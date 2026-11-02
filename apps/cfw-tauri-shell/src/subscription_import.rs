use std::fmt;

use cfw_singbox_config::{CredentialRef, ProfileParseError, ValidatedSingBoxProfile};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroize;

mod clash;
mod collector;
mod http_proxy;
mod hysteria2;
mod normalize;
mod share_url;
mod sing_box;
mod sip008;
mod socks5;
mod tls;
mod transport;
mod uri;
mod vmess;
mod wireguard;
mod yaml;
pub(crate) use clash::resources::{
    ProviderKind, ProviderRequest, materialize as materialize_providers,
    replacement as replace_provider_resources, requests as provider_requests,
    stored_requests as stored_provider_requests,
};

// The helpers the adapters share live in their own modules; the adapters
// reach them through this module, as they did when they lived here.
use collector::{OutboundCollector, credential_ref_json};
use hysteria2::{
    normalize_hysteria2_server_ports, parse_hysteria2_bbr_profile,
    parse_hysteria2_hop_interval_range, parse_hysteria2_hop_interval_seconds,
    parse_hysteria2_share_url,
};
use normalize::{
    canonical_uuid_credential, normalize_shadowsocks_method_and_password,
    normalize_tuic_congestion_control, normalize_tuic_udp_relay_mode, normalize_v2ray_http_method,
    normalize_v2ray_packet_encoding, normalize_vless_flow, normalize_vmess_alter_id,
    normalize_vmess_security, parse_vmess_alter_id,
};
use share_url::{
    certificate_verification_disabled, consume_certificate_verification_flags,
    consume_empty_or_none_parameter, consume_required_tls_marker, consume_tls_marker,
    consume_unsupported_enabled_flag, decode_base64_text, decode_url_component,
    decoded_fragment_strict, host_string, insecure_tls_error, non_empty, parse_port_value,
    parse_positive_u32, parse_uri_boolean, port_from_url, port_from_url_or_default,
    reject_query_leftovers, required_url_password, required_url_username, split_csv,
    split_fragment_strict, split_host_port, split_query_strict, strict_query_map, take_query_alias,
    validate_share_url_path,
};
use transport::{
    TlsParts, build_tls_parts, parse_utls, parse_utls_fingerprint, tls_json, transport_from_parts,
    utls_json,
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
    match ValidatedSingBoxProfile::parse_classified(body) {
        Ok(profile) => {
            return Ok(ImportedSubscription {
                profile,
                credentials: Vec::new(),
            });
        }
        // The typed schema read this document and rejected it. Its keys route
        // it only to the node-list adapter, which would fail on its shape with
        // a generic message, so the validator's error is the diagnosis.
        Err(ProfileParseError::Invalid(error)) if !sing_box::matches_node_list_schema(body) => {
            return Err(error.to_string());
        }
        // A node list both schemas read: the adapter renames tags and fills
        // TLS defaults, then runs the same validator in `into_subscription`.
        Err(ProfileParseError::Invalid(_)) => {}
        // Not a typed profile: the importers below reject it with their own
        // error or convert it and run the same validator.
        Err(ProfileParseError::Unrecognized(_)) => {}
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

/// Remote subscription tokens are never safe to echo: a short identifier-like
/// scheme, enum value, or unknown key can itself carry an access credential.
fn sanitized_token(_token: &str) -> String {
    "<redacted>".to_owned()
}

#[cfg(test)]
mod tests;
