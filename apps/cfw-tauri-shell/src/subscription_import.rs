use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use cfw_singbox_config::{CredentialKind, CredentialRef, MAX_OUTBOUNDS, ValidatedSingBoxProfile};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

mod clash;
mod sing_box;
mod sip008;
mod socks5;
mod yaml;

/// Source-only rules, groups, and comments can exceed the closed profile limit.
/// Conversion still independently enforces `cfw_singbox_config::MAX_PROFILE_BYTES`.
pub(crate) const MAX_SUBSCRIPTION_DOCUMENT_BYTES: usize = 512 * 1024;

const SUPPORTED_URI_SCHEMES: &[&str] = &[
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
    credentials: Vec<ImportedCredential>,
    used_tags: BTreeSet<String>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmessPayload {
    #[serde(default)]
    v: Option<VmessVersion>,
    #[serde(default)]
    ps: String,
    add: String,
    port: serde_json::Value,
    id: String,
    #[serde(default)]
    aid: VmessAid,
    #[serde(default)]
    scy: String,
    #[serde(default)]
    net: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    alpn: String,
    #[serde(default)]
    fp: String,
    #[serde(default, rename = "serviceName")]
    service_name: String,
    #[serde(default, rename = "type")]
    header_type: String,
    #[serde(default)]
    insecure: Option<VmessBoolean>,
    #[serde(default)]
    vcn: String,
    #[serde(default)]
    pcs: String,
    #[serde(default, rename = "packetEncoding")]
    packet_encoding: String,
    #[serde(default)]
    method: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessVersion {
    Text(String),
    Integer(u64),
}

impl VmessVersion {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Text(value) if value == "2" => Ok(()),
            Self::Integer(2) => Ok(()),
            Self::Text(value) => Err(format!(
                "vmess URI version is unsupported: {}",
                sanitized_token(value)
            )),
            Self::Integer(_) => Err("vmess URI version is unsupported".to_owned()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessBoolean {
    Boolean(bool),
    Text(String),
    Integer(u8),
}

impl VmessBoolean {
    fn parse(&self, field: &str) -> Result<bool, String> {
        match self {
            Self::Boolean(value) => Ok(*value),
            Self::Text(value) => parse_uri_boolean(value, "vmess", field),
            Self::Integer(0) => Ok(false),
            Self::Integer(1) => Ok(true),
            Self::Integer(_) => Err(format!("vmess URI field {field} must be a boolean")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessAid {
    Text(String),
    Integer(u64),
}

impl Default for VmessAid {
    fn default() -> Self {
        Self::Integer(0)
    }
}

impl VmessAid {
    fn parse(&self) -> Result<u8, String> {
        match self {
            Self::Text(value) => parse_vmess_alter_id(value, "vmess URI aid"),
            Self::Integer(value) => normalize_vmess_alter_id(*value, "vmess URI aid"),
        }
    }
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
        if entries.len() == MAX_OUTBOUNDS {
            return Err(format!(
                "subscription URI bundle has more than {MAX_OUTBOUNDS} entries"
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

    fn parse_shadowsocks(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let (without_fragment, tag) = split_fragment_strict(entry, "Shadowsocks")?;
        let (main, mut query) = split_query_strict(without_fragment, "Shadowsocks")?;
        if query.remove("plugin").is_some() {
            return Err("Shadowsocks plugins are unsupported in subscription imports".into());
        }
        reject_query_leftovers(&query, "Shadowsocks")?;
        let raw = main
            .strip_prefix("ss://")
            .ok_or_else(|| "invalid Shadowsocks URI".to_owned())?;
        let (credentials_part, host_port_part, legacy_full_base64) =
            if let Some((left, right)) = raw.rsplit_once('@') {
                (left.to_owned(), right.to_owned(), false)
            } else {
                let decoded = String::from_utf8(decode_base64_text(raw).map_err(|error| {
                    format!("Shadowsocks URI credentials are invalid base64: {error}")
                })?)
                .map_err(|_| "Shadowsocks URI credentials are not UTF-8".to_owned())?;
                let (left, right) = decoded
                    .rsplit_once('@')
                    .ok_or_else(|| "Shadowsocks URI must contain host and port".to_owned())?;
                (left.to_owned(), right.to_owned(), true)
            };
        let (method, password, base64_userinfo) = if legacy_full_base64 {
            let (method, password) = credentials_part
                .split_once(':')
                .ok_or_else(|| "Shadowsocks URI must contain method and password".to_owned())?;
            (method.to_owned(), password.to_owned(), true)
        } else if let Some((method, password)) = credentials_part.split_once(':') {
            (
                decode_url_component(method)?,
                decode_url_component(password)?,
                false,
            )
        } else {
            let encoded = decode_url_component(&credentials_part)?;
            let decoded = String::from_utf8(decode_base64_text(&encoded).map_err(|error| {
                format!("Shadowsocks URI method/password envelope is invalid base64: {error}")
            })?)
            .map_err(|_| "Shadowsocks URI method/password envelope is not UTF-8".to_owned())?;
            let (method, password) = decoded
                .split_once(':')
                .ok_or_else(|| "Shadowsocks URI must contain method and password".to_owned())?;
            (method.to_owned(), password.to_owned(), true)
        };
        let method = normalize_shadowsocks_method_and_password(&method, &password)?;
        if method.starts_with("2022-") && base64_userinfo {
            return Err(
                "Shadowsocks 2022 credentials must use percent-encoded plain userinfo".to_owned(),
            );
        }
        let (server, server_port) = split_host_port(&host_port_part)?;
        let reference = self.push_secret(CredentialKind::ShadowsocksPassword, password);
        let tag = self.unique_tag(tag.unwrap_or_else(|| format!("ss-{index}")))?;
        Ok(json!({
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": server_port,
            "method": method,
            "credential_ref": credential_ref_json(&reference),
        }))
    }

    fn parse_vmess(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let encoded = entry
            .trim()
            .strip_prefix("vmess://")
            .ok_or_else(|| "invalid vmess URI".to_owned())?;
        let authority_end = encoded.find(['?', '#']).unwrap_or(encoded.len());
        if encoded[..authority_end].contains('@') {
            return self.parse_vmess_url(entry, index);
        }
        let payload = String::from_utf8(
            decode_base64_text(encoded)
                .map_err(|error| format!("vmess URI payload is invalid base64: {error}"))?,
        )
        .map_err(|_| "vmess URI payload is not UTF-8".to_owned())?;
        let payload: VmessPayload = serde_json::from_str(&payload)
            .map_err(|_| "vmess URI payload does not match the supported schema".to_owned())?;
        if let Some(version) = &payload.v {
            version.validate()?;
        }
        if !matches!(payload.header_type.as_str(), "" | "none") {
            return Err(format!(
                "vmess header type is unsupported: {}",
                sanitized_token(&payload.header_type)
            ));
        }
        if payload
            .insecure
            .as_ref()
            .map(|value| value.parse("insecure"))
            .transpose()?
            .unwrap_or(false)
        {
            return Err("vmess URI requires disabling TLS certificate verification".into());
        }
        if !payload.vcn.is_empty() {
            return Err("vmess certificate domain verification is unsupported".into());
        }
        if !payload.pcs.is_empty() {
            return Err("vmess pinned certificate verification is unsupported".into());
        }
        let packet_encoding = non_empty(payload.packet_encoding)
            .map(|value| normalize_v2ray_packet_encoding(&value, "vmess packet encoding"))
            .transpose()?;
        let alter_id = payload.aid.parse()?;
        let reference = self.push_secret(
            CredentialKind::VmessUuid,
            canonical_uuid_credential(payload.id, "VMess UUID")?,
        );
        let tag =
            self.unique_tag(non_empty(payload.ps).unwrap_or_else(|| format!("vmess-{index}")))?;
        let server_port = parse_port_value(&payload.port)?;
        let tls = match payload.tls.to_ascii_lowercase().as_str() {
            "" | "none" => None,
            "tls" => {
                let parts = build_tls_parts(
                    true,
                    non_empty(payload.sni).unwrap_or_else(|| payload.add.clone()),
                    split_csv(&payload.alpn),
                    parse_utls(payload.fp.as_str())?,
                    None,
                );
                Some(tls_json(parts))
            }
            other => {
                return Err(format!(
                    "vmess TLS mode is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        let transport = transport_from_parts(
            payload.net.as_str(),
            non_empty(payload.path),
            non_empty(payload.host),
            non_empty(payload.service_name),
            non_empty(payload.method),
        )?;
        let mut outbound = json!({
            "type": "vmess",
            "tag": tag,
            "server": payload.add,
            "server_port": server_port,
            "credential_ref": credential_ref_json(&reference),
        });
        if alter_id != 0 {
            outbound["alter_id"] = Value::from(alter_id);
        }
        if let Some(security) = normalize_vmess_security(payload.scy.as_str())? {
            outbound["security"] = Value::String(security);
        }
        if let Some(packet_encoding) = packet_encoding {
            outbound["packet_encoding"] = Value::String(packet_encoding);
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        Ok(outbound)
    }

    fn parse_vmess_url(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry)
            .map_err(|_| "subscription VMess URL-shaped URI is invalid".to_owned())?;
        validate_share_url_path(&url, "VMess")?;
        if url.password().is_some() {
            return Err("VMess URI must encode its UUID as the single user-info component".into());
        }
        let mut query = strict_query_map(&url, "VMess")?;
        consume_certificate_verification_flags(&mut query, "VMess")?;
        let uuid =
            canonical_uuid_credential(required_url_username(&url, "VMess UUID")?, "VMess UUID")?;
        let server = host_string(&url)?;
        let encryption = query.remove("encryption").unwrap_or_else(|| "auto".into());
        if encryption.is_empty() {
            return Err("VMess URI encryption must not be empty".to_owned());
        }
        let encryption = match encryption.to_ascii_lowercase().as_str() {
            "auto" => None,
            "none" | "aes-128-gcm" | "chacha20-poly1305" => Some(encryption.to_ascii_lowercase()),
            other => {
                return Err(format!(
                    "VMess URL-shaped encryption is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        let security = query.remove("security").unwrap_or_else(|| "none".into());
        let tls = match security.to_ascii_lowercase().as_str() {
            "none" => None,
            "tls" => Some(tls_json(build_tls_parts(
                true,
                query.remove("sni").unwrap_or_else(|| server.clone()),
                split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                None,
            ))),
            other => {
                return Err(format!(
                    "VMess URL-shaped security mode is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        consume_empty_or_none_parameter(&mut query, "headerType", "VMess header type")?;
        let packet_encoding = take_query_alias(
            &mut query,
            &["packetEncoding", "packet-encoding"],
            "VMess",
            "packet encoding",
        )?
        .map(|value| normalize_v2ray_packet_encoding(&value, "VMess packet encoding"))
        .transpose()?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "VMess",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        reject_query_leftovers(&query, "VMess")?;

        let reference = self.push_secret(CredentialKind::VmessUuid, uuid);
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "VMess")?.unwrap_or_else(|| format!("vmess-{index}")),
        )?;
        let mut outbound = json!({
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(encryption) = encryption {
            outbound["security"] = Value::String(encryption);
        }
        if let Some(packet_encoding) = packet_encoding {
            outbound["packet_encoding"] = Value::String(packet_encoding);
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        Ok(outbound)
    }

    fn parse_vless(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription VLESS URI is invalid".to_owned())?;
        validate_share_url_path(&url, "VLESS")?;
        if url.password().is_some() {
            return Err("VLESS URI must encode its UUID as the single user-info component".into());
        }
        let mut query = strict_query_map(&url, "VLESS")?;
        consume_certificate_verification_flags(&mut query, "VLESS")?;
        match query.remove("encryption") {
            None => {}
            Some(value) if value.is_empty() || value.eq_ignore_ascii_case("none") => {}
            Some(value) => {
                return Err(format!(
                    "VLESS encryption is unsupported: {}",
                    sanitized_token(&value)
                ));
            }
        }
        let reference = self.push_secret(
            CredentialKind::VlessUuid,
            canonical_uuid_credential(required_url_username(&url, "VLESS UUID")?, "VLESS UUID")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "VLESS")?.unwrap_or_else(|| format!("vless-{index}")),
        )?;
        let server = host_string(&url)?;
        let security = query.remove("security").unwrap_or_else(|| "none".into());
        let tls = match security.to_ascii_lowercase().as_str() {
            "none" | "" => None,
            "tls" => Some(tls_json(build_tls_parts(
                true,
                query.remove("sni").unwrap_or_else(|| server.clone()),
                split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                None,
            ))),
            "reality" => {
                let public_key = query
                    .remove("pbk")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "VLESS Reality public key is missing".to_owned())?;
                let short_id = query.remove("sid").unwrap_or_default();
                Some(tls_json(build_tls_parts(
                    true,
                    query.remove("sni").unwrap_or_else(|| server.clone()),
                    split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                    parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                    Some(json!({
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id,
                    })),
                )))
            }
            _ => {
                return Err(format!(
                    "VLESS security mode is unsupported: {}",
                    sanitized_token(&security)
                ));
            }
        };
        consume_empty_or_none_parameter(&mut query, "headerType", "VLESS header type")?;
        let packet_encoding = take_query_alias(
            &mut query,
            &["packetEncoding", "packet-encoding"],
            "VLESS",
            "packet encoding",
        )?;
        let packet_encoding = packet_encoding
            .map(|value| normalize_v2ray_packet_encoding(&value, "VLESS packet encoding"))
            .transpose()?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "VLESS",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        let flow = query.remove("flow").filter(|value| !value.is_empty());
        reject_query_leftovers(&query, "VLESS")?;
        let mut outbound = json!({
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(flow) = flow {
            outbound["flow"] = Value::String(normalize_vless_flow(&flow)?);
        }
        if let Some(packet_encoding) = packet_encoding {
            outbound["packet_encoding"] = Value::String(packet_encoding);
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        Ok(outbound)
    }

    fn parse_trojan(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription Trojan URI is invalid".to_owned())?;
        validate_share_url_path(&url, "Trojan")?;
        if url.password().is_some() {
            return Err("Trojan URI password must percent-encode reserved separators".into());
        }
        let mut query = strict_query_map(&url, "Trojan")?;
        consume_required_tls_marker(&mut query, "Trojan")?;
        consume_certificate_verification_flags(&mut query, "Trojan")?;
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::TrojanPassword,
            required_url_username(&url, "Trojan password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "Trojan")?.unwrap_or_else(|| format!("trojan-{index}")),
        )?;
        consume_empty_or_none_parameter(&mut query, "headerType", "Trojan header type")?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "Trojan",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
            None,
        ));
        reject_query_leftovers(&query, "Trojan")?;
        Ok(json!({
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
            "transport": transport,
        }))
    }

    fn parse_hysteria2(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let (url, server_ports) = parse_hysteria2_share_url(entry)?;
        validate_share_url_path(&url, "Hysteria2")?;
        if url.password().is_some() {
            return Err(
                "Hysteria2 URI must encode its password as the single user-info component".into(),
            );
        }
        let mut query = strict_query_map(&url, "Hysteria2")?;
        consume_tls_marker(&mut query, "Hysteria2")?;
        consume_certificate_verification_flags(&mut query, "Hysteria2")?;
        if query.remove("fp").is_some() {
            return Err("Hysteria2 does not support uTLS".into());
        }
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::Hysteria2Password,
            required_url_username(&url, "Hysteria2 password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "Hysteria2")?.unwrap_or_else(|| format!("hy2-{index}")),
        )?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            None,
            None,
        ));
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port_from_url_or_default(&url, 443)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
        });
        if let Some(server_ports) = server_ports {
            outbound["server_ports"] = json!(server_ports);
        }
        if let Some(value) = take_query_alias(
            &mut query,
            &["hop-interval", "hop_interval"],
            "Hysteria2",
            "hop interval",
        )? {
            outbound["hop_interval_seconds"] = json!(parse_hysteria2_hop_interval_seconds(
                &value,
                "Hysteria2 hop interval"
            )?);
        }
        if let Some(value) = query.remove("upmbps") {
            outbound["up_mbps"] = json!(parse_positive_u32(&value, "Hysteria2 upmbps")?);
        }
        if let Some(value) = query.remove("downmbps") {
            outbound["down_mbps"] = json!(parse_positive_u32(&value, "Hysteria2 downmbps")?);
        }
        if let Some(obfs) = query.remove("obfs")
            && !obfs.is_empty()
        {
            if obfs != "salamander" {
                return Err(format!(
                    "Hysteria2 obfs mode is unsupported: {}",
                    sanitized_token(&obfs)
                ));
            }
            let obfs_secret = query
                .remove("obfs-password")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Hysteria2 obfs password is missing".to_owned())?;
            let reference = self.push_secret(CredentialKind::Hysteria2ObfsPassword, obfs_secret);
            outbound["obfs"] = json!({
                "type": "salamander",
                "credential_ref": credential_ref_json(&reference),
            });
        }
        reject_query_leftovers(&query, "Hysteria2")?;
        Ok(outbound)
    }

    fn parse_anytls(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription AnyTLS URI is invalid".to_owned())?;
        validate_share_url_path(&url, "AnyTLS")?;
        if url.password().is_some() {
            return Err(
                "AnyTLS URI must encode its password as the single user-info component".into(),
            );
        }
        let mut query = strict_query_map(&url, "AnyTLS")?;
        consume_tls_marker(&mut query, "AnyTLS")?;
        consume_certificate_verification_flags(&mut query, "AnyTLS")?;
        let server = host_string(&url)?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
            None,
        ));
        reject_query_leftovers(&query, "AnyTLS")?;
        let reference = self.push_secret(
            CredentialKind::AnyTlsPassword,
            required_url_username(&url, "AnyTLS password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "AnyTLS")?.unwrap_or_else(|| format!("anytls-{index}")),
        )?;
        Ok(json!({
            "type": "anytls",
            "tag": tag,
            "server": server,
            "server_port": port_from_url_or_default(&url, 443)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
        }))
    }

    fn parse_tuic(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription TUIC URI is invalid".to_owned())?;
        validate_share_url_path(&url, "TUIC")?;
        let mut query = strict_query_map(&url, "TUIC")?;
        consume_tls_marker(&mut query, "TUIC")?;
        consume_certificate_verification_flags(&mut query, "TUIC")?;
        consume_unsupported_enabled_flag(
            &mut query,
            &["zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt"],
            "TUIC 0-RTT handshake",
        )?;
        consume_unsupported_enabled_flag(
            &mut query,
            &["udp_over_stream", "udp-over-stream"],
            "TUIC UDP-over-stream",
        )?;
        let server = host_string(&url)?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            None,
            None,
        ));
        let congestion_control = query
            .remove("congestion_control")
            .map(|value| normalize_tuic_congestion_control(&value))
            .transpose()?;
        let udp_relay_mode = query
            .remove("udp_relay_mode")
            .map(|value| normalize_tuic_udp_relay_mode(&value))
            .transpose()?;
        reject_query_leftovers(&query, "TUIC")?;

        let uuid_reference = self.push_secret(
            CredentialKind::TuicUuid,
            canonical_uuid_credential(required_url_username(&url, "TUIC UUID")?, "TUIC UUID")?,
        );
        let password_reference = self.push_secret(
            CredentialKind::TuicPassword,
            required_url_password(&url, "TUIC password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "TUIC")?.unwrap_or_else(|| format!("tuic-{index}")),
        )?;
        let mut outbound = json!({
            "type": "tuic",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "uuid_credential_ref": credential_ref_json(&uuid_reference),
            "password_credential_ref": credential_ref_json(&password_reference),
            "tls": tls,
        });
        if let Some(value) = congestion_control {
            outbound["congestion_control"] = Value::String(value);
        }
        if let Some(value) = udp_relay_mode {
            outbound["udp_relay_mode"] = Value::String(value);
        }
        Ok(outbound)
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

        if let Some(existing) = self
            .credentials
            .iter()
            .find(|credential| credential.reference == reference)
        {
            if existing.secret == secret {
                secret.zeroize();
                return reference;
            }
            // A formerly shared credential now carries different material in
            // this slot. Credential references are immutable vault identities,
            // so split this slot instead of provisioning one reference twice.
            reference = self.new_credential_reference(kind);
        }
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
        for suffix in 2..=MAX_OUTBOUNDS {
            let candidate = format!("{sanitized}-{suffix}");
            if self.used_tags.insert(candidate.clone()) {
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
        let profile_json = serde_json::to_string(&json!({ "outbounds": self.outbounds }))
            .map_err(|error| format!("failed to encode imported subscription profile: {error}"))?;
        let profile =
            ValidatedSingBoxProfile::parse(&profile_json).map_err(|error| error.to_string())?;
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
mod tests {
    use std::fmt::Write as _;

    use cfw_singbox_config::{EngineSettings, ProjectionMode};

    use super::*;

    const SYNTHETIC_VM_UUID: &str = "00000000-0000-4000-8000-000000000001";
    const SYNTHETIC_PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn vmess_uri_with_aid(aid: Option<Value>) -> String {
        let mut payload = json!({
            "ps": "Synthetic VMess",
            "add": "vmess.example.com",
            "port": 443,
            "id": SYNTHETIC_VM_UUID,
        });
        if let Some(aid) = aid {
            payload
                .as_object_mut()
                .expect("VMess fixture payload must be an object")
                .insert("aid".into(), aid);
        }
        format!("vmess://{}", STANDARD.encode(payload.to_string()))
    }

    fn clash_vmess_with_alter_id(value: Option<&str>) -> String {
        let alter_id = value
            .map(|value| format!("    alterId: {value}\n"))
            .unwrap_or_default();
        format!(
            "proxies:\n  - name: Synthetic VMess\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n{alter_id}"
        )
    }

    fn assert_single_vmess_alter_id(document: &str, expected: u8) {
        let imported = import_subscription_document(document).expect("valid VMess fixture");
        assert_eq!(imported.credentials.len(), 1);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile JSON");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["type"], "vmess");
        if expected == 0 {
            assert!(
                outbound.get("alter_id").is_none(),
                "AEAD alter_id must remain the omitted canonical default"
            );
        } else {
            assert_eq!(outbound["alter_id"], expected);
        }

        let projected = imported
            .profile
            .project(
                SYNTHETIC_PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("runtime VMess projection");
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
        let runtime_vmess = runtime["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|outbound| outbound["type"] == "vmess")
            .expect("runtime VMess outbound");
        if expected == 0 {
            assert!(
                runtime_vmess.get("alter_id").is_none(),
                "AEAD runtime alter_id must remain omitted"
            );
        } else {
            assert_eq!(runtime_vmess["alter_id"], expected);
        }
    }

    fn synthetic_46_node_clash_fixture() -> String {
        let mut document = String::from("proxies:\n");
        for index in 0..34_u16 {
            writeln!(
                document,
                "  - name: SS-{index:02}\n    type: ss\n    server: ss-{index:02}.example.com\n    port: {}\n    cipher: aes-256-gcm\n    password: synthetic-ss-secret-{index:02}",
                10_000 + index
            )
            .expect("write synthetic Shadowsocks fixture");
        }
        for index in 0..12_u16 {
            writeln!(
                document,
                "  - name: VMess-{index:02}\n    type: vmess\n    server: vmess-{index:02}.example.com\n    port: 443\n    uuid: 00000000-0000-4000-8000-{index:012x}\n    alterId: 1\n    cipher: auto"
            )
            .expect("write synthetic VMess fixture");
        }
        document
    }

    #[test]
    fn passes_through_typed_sing_box_json_without_credentials() {
        let imported =
            import_subscription_document(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
                .expect("typed profile");
        assert_eq!(
            imported.profile.as_json(),
            r#"{"outbounds":[{"tag":"direct","type":"direct"}]}"#
        );
        assert!(imported.credentials.is_empty());
    }

    #[test]
    fn imports_restricted_upstream_sing_box_node_list_json() {
        let document = json!({
            "outbounds": [
                {
                    "type": "shadowsocks", "tag": "SS", "server": "ss.example.com",
                    "server_port": 8388, "method": "aes-256-gcm", "password": "ss-secret"
                },
                {
                    "type": "vmess", "tag": "VMess", "server": "vm.example.com",
                    "server_port": 443, "uuid": "11111111-1111-4111-8111-111111111111",
                    "security": "auto", "packet_encoding": "xudp",
                    "tls": { "enabled": true, "server_name": "vm.example.com", "min_version": "1.2" },
                    "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "edge.example.com" } }
                },
                {
                    "type": "vless", "tag": "VLESS", "server": "v.example.com",
                    "server_port": 443, "uuid": "22222222-2222-4222-8222-222222222222",
                    "packet_encoding": "packetaddr",
                    "tls": { "enabled": true, "server_name": "v.example.com" },
                    "transport": { "type": "http", "method": "GET", "path": "/h2", "host": ["one.example", "two.example"] }
                },
                {
                    "type": "trojan", "tag": "Trojan", "server": "t.example.com",
                    "server_port": 443, "password": "trojan-secret",
                    "tls": { "enabled": true, "server_name": "t.example.com" },
                    "transport": { "type": "grpc", "service_name": "tunnel" }
                },
                {
                    "type": "hysteria2", "tag": "HY2", "server": "hy.example.com",
                    "server_port": 443, "password": "hy-secret",
                    "tls": { "enabled": true, "server_name": "hy.example.com", "alpn": "h3" },
                    "obfs": { "type": "salamander", "password": "mask-secret" }
                },
                {
                    "type": "anytls", "tag": "AnyTLS", "server": "a.example.com",
                    "server_port": 443, "password": "any-secret",
                    "tls": { "enabled": true, "server_name": "a.example.com" }
                },
                {
                    "type": "tuic", "tag": "TUIC", "server": "q.example.com",
                    "server_port": 443, "uuid": "33333333-3333-4333-8333-333333333333",
                    "password": "tuic-secret", "congestion_control": "bbr",
                    "udp_relay_mode": "quic", "zero_rtt_handshake": false,
                    "tls": { "enabled": true, "server_name": "q.example.com", "alpn": ["h3"] }
                }
            ]
        });
        let imported = import_subscription_document(&document.to_string())
            .expect("restricted upstream sing-box JSON");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical source profile");
        assert_eq!(profile["outbounds"].as_array().expect("outbounds").len(), 7);
        assert_eq!(profile["outbounds"][1]["packet_encoding"], "xudp");
        assert_eq!(profile["outbounds"][2]["transport"]["type"], "http");
        assert_eq!(profile["outbounds"][2]["transport"]["method"], "GET");
        assert_eq!(profile["outbounds"][4]["obfs"]["type"], "salamander");
        assert_eq!(imported.credentials.len(), 9);
        for secret in [
            "ss-secret",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "trojan-secret",
            "hy-secret",
            "mask-secret",
            "any-secret",
            "33333333-3333-4333-8333-333333333333",
            "tuic-secret",
        ] {
            assert!(!imported.profile.as_json().contains(secret));
        }
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("upstream sing-box source projection");
        }
    }

    #[test]
    fn imports_sip008_json_with_vault_credentials_and_root_metadata() {
        let document = json!({
            "version": 1,
            "servers": [
                {
                    "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                    "remarks": "Tokyo",
                    "server": "tokyo.example.com",
                    "server_port": 8388,
                    "password": "sip008-secret-one",
                    "method": "chacha20-ietf-poly1305"
                },
                {
                    "id": "7842c068-c667-41f2-8f7d-04feece3cb67",
                    "remarks": "Tokyo",
                    "server": "osaka.example.com",
                    "server_port": 443,
                    "password": "sip008-secret-two",
                    "method": "aes-256-gcm",
                    "plugin": "",
                    "plugin_opts": ""
                }
            ],
            "bytes_used": 1024,
            "bytes_remaining": 2048,
            "provider_notice": { "plan": "synthetic" }
        });
        let imported = import_subscription_document(&document.to_string()).expect("SIP008 JSON");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical SIP008 profile");
        assert_eq!(profile["outbounds"][0]["type"], "shadowsocks");
        assert_eq!(profile["outbounds"][0]["tag"], "Tokyo");
        assert_eq!(profile["outbounds"][1]["tag"], "Tokyo-2");
        assert_eq!(imported.credentials.len(), 2);
        assert_eq!(imported.credentials[0].secret, "sip008-secret-one");
        assert_eq!(imported.credentials[1].secret, "sip008-secret-two");
        assert!(!imported.profile.as_json().contains("sip008-secret"));
    }

    #[test]
    fn sip008_rejects_ambiguous_identity_plugins_and_invalid_usage_metadata() {
        let valid_server = json!({
            "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
            "remarks": "Synthetic",
            "server": "ss.example.com",
            "server_port": 8388,
            "password": "TopSecretValue!",
            "method": "aes-256-gcm"
        });
        for (label, document, expected) in [
            (
                "duplicate server id",
                json!({ "version": 1, "servers": [valid_server.clone(), valid_server.clone()] }),
                "unique non-nil UUIDs",
            ),
            (
                "plugin",
                json!({
                    "version": 1,
                    "servers": [{
                        "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                        "remarks": "Synthetic",
                        "server": "ss.example.com",
                        "server_port": 8388,
                        "password": "TopSecretValue!",
                        "method": "aes-256-gcm",
                        "plugin": "v2ray-plugin"
                    }]
                }),
                "plugins are unsupported",
            ),
            (
                "remaining without used",
                json!({
                    "version": 1,
                    "servers": [valid_server.clone()],
                    "bytes_remaining": 1
                }),
                "requires bytes_used",
            ),
        ] {
            let error = import_subscription_document(&document.to_string()).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        }
    }

    #[test]
    fn document_classification_is_structural_and_bom_tolerant() {
        assert!(looks_like_clash_yaml("proxies:\n  - name: node\n"));
        assert!(looks_like_clash_yaml("mixed-port: 7890\n"));
        assert!(!looks_like_clash_yaml("# proxies:\nnot-a-document\n"));
        assert!(!looks_like_clash_yaml("metadata:\n  proxies: nested\n"));
        assert!(!looks_like_clash_yaml("note: proxies: is only a value\n"));

        let upstream_json = json!({
            "outbounds": [{
                "type": "shadowsocks",
                "tag": "proxies:",
                "server": "ss.example.com",
                "server_port": 8388,
                "method": "aes-256-gcm",
                "password": "json-secret"
            }]
        });
        let imported = import_subscription_document(&upstream_json.to_string())
            .expect("JSON string containing a Clash marker");
        assert_eq!(imported.credentials[0].secret, "json-secret");

        let uri = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#BOM";
        let imported = import_subscription_document(&format!("\u{feff}{uri}"))
            .expect("plain URI bundle with BOM");
        assert_eq!(imported.credentials[0].secret, "secret");

        let encoded = STANDARD.encode(format!("\u{feff}{uri}\n"));
        let imported = import_subscription_document(&encoded).expect("base64 bundle with BOM");
        assert_eq!(imported.credentials[0].secret, "secret");

        let error = import_subscription_document(r#"{"note":"proxies:""#)
            .expect_err("malformed JSON must not fall through to YAML");
        assert_eq!(error, "subscription JSON document is malformed");
    }

    #[test]
    fn imports_sip002_shadowsocks_2022_plain_userinfo_and_key_chains() {
        const KEY_256: &str = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=";
        let uri = "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3";
        let imported = import_subscription_document(uri).expect("official SIP002 2022 URI");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile JSON");
        assert_eq!(profile["outbounds"][0]["method"], "2022-blake3-aes-256-gcm");
        assert_eq!(imported.credentials[0].secret, KEY_256);
        assert!(!imported.profile.as_json().contains(KEY_256));

        let multi_user = json!({
            "outbounds": [{
                "type": "shadowsocks",
                "tag": "Multi-user",
                "server": "ss.example.com",
                "server_port": 8388,
                "method": "2022-blake3-aes-256-gcm",
                "password": format!("{KEY_256}:{KEY_256}")
            }]
        });
        let imported = import_subscription_document(&multi_user.to_string())
            .expect("sing-box 2022 multi-user key chain");
        assert_eq!(
            imported.credentials[0].secret,
            format!("{KEY_256}:{KEY_256}")
        );
    }

    #[test]
    fn shadowsocks_2022_rejects_base64_userinfo_and_legacy_full_envelopes() {
        const KEY_256: &str = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=";
        let encoded_userinfo = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{KEY_256}"));
        let legacy_full = STANDARD.encode(format!(
            "2022-blake3-aes-256-gcm:{KEY_256}@ss.example.com:8388"
        ));
        for (label, document) in [
            (
                "base64 userinfo",
                format!("ss://{encoded_userinfo}@ss.example.com:8388#Encoded"),
            ),
            ("legacy full envelope", format!("ss://{legacy_full}")),
        ] {
            let error = import_subscription_document(&document).expect_err(label);
            assert!(
                error.contains("percent-encoded plain userinfo"),
                "{label}: {error}"
            );
            assert!(!error.contains(KEY_256), "{label}: {error}");
        }
    }

    #[test]
    fn shadowsocks_2022_key_validation_precedes_vault_staging_for_every_container() {
        const WRONG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
        let documents = [
            (
                "SIP002 URI",
                format!("ss://2022-blake3-aes-256-gcm:{WRONG_KEY}@ss.example.com:8388#Wrong"),
            ),
            (
                "SIP008 JSON",
                json!({
                    "version": 1,
                    "servers": [{
                        "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                        "remarks": "Wrong",
                        "server": "ss.example.com",
                        "server_port": 8388,
                        "method": "2022-blake3-aes-256-gcm",
                        "password": WRONG_KEY
                    }]
                })
                .to_string(),
            ),
            (
                "Clash YAML",
                format!(
                    "proxies:\n  - name: Wrong\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: 2022-blake3-aes-256-gcm\n    password: {WRONG_KEY}\n"
                ),
            ),
            (
                "sing-box JSON",
                json!({
                    "outbounds": [{
                        "type": "shadowsocks",
                        "tag": "Wrong",
                        "server": "ss.example.com",
                        "server_port": 8388,
                        "method": "2022-blake3-aes-256-gcm",
                        "password": WRONG_KEY
                    }]
                })
                .to_string(),
            ),
        ];
        for (label, document) in documents {
            let error = import_subscription_document(&document).expect_err(label);
            assert!(error.contains("32-byte keys"), "{label}: {error}");
            assert!(!error.contains(WRONG_KEY), "{label}: {error}");
        }

        let error = import_subscription_document(
            "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA@ss.example.com:8388",
        )
        .expect_err("unpadded Base64 is noncanonical");
        assert!(error.contains("canonical standard-base64 16-byte keys"));
    }

    #[test]
    fn shadowsocks_uri_decodes_each_plain_component_exactly_once() {
        let imported = import_subscription_document(
            "ss://aes-256-gcm:literal%252Fvalue@ss.example.com:8388#Plain",
        )
        .expect("plain SIP002 credentials");
        assert_eq!(imported.credentials[0].secret, "literal%2Fvalue");

        let envelope = URL_SAFE_NO_PAD.encode("aes-256-gcm:literal%2Fvalue");
        let imported =
            import_subscription_document(&format!("ss://{envelope}@ss.example.com:8388#Base64"))
                .expect("base64 SIP002 credentials");
        assert_eq!(imported.credentials[0].secret, "literal%2Fvalue");
    }

    #[test]
    fn imports_url_shaped_vmess_aead_links() {
        let imported = import_subscription_document(
            "vmess://44efe52b-e143-46b5-a9e7-aadbfd77eb9c@vm.example.com:443?type=ws&security=tls&encryption=aes-128-gcm&host=edge.example.com&path=%2Fws&sni=vm.example.com#VMess-URL",
        )
        .expect("URL-shaped VMess AEAD");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("VMess URL profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["type"], "vmess");
        assert_eq!(outbound["tag"], "VMess-URL");
        assert_eq!(outbound["security"], "aes-128-gcm");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "edge.example.com");
        assert_eq!(outbound["tls"]["server_name"], "vm.example.com");
        assert_eq!(
            imported.credentials[0].secret,
            "44efe52b-e143-46b5-a9e7-aadbfd77eb9c"
        );
        assert!(outbound.get("alter_id").is_none());
    }

    #[test]
    fn uuid_credentials_are_validated_before_vault_staging() {
        for (label, document) in [
            (
                "URL VMess",
                "vmess://not-a-uuid@vm.example.com:443?security=tls",
            ),
            ("VLESS", "vless://not-a-uuid@v.example.com:443?security=tls"),
            (
                "TUIC",
                "tuic://not-a-uuid:TopSecretValue!@q.example.com:443?sni=q.example.com",
            ),
        ] {
            let error = import_subscription_document(document).expect_err(label);
            assert!(error.contains("UUID"), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        }
    }

    #[test]
    fn upstream_sing_box_json_rejects_full_configs_and_unsafe_semantics() {
        for (label, document, expected) in [
            (
                "root DNS",
                r#"{"dns":{},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
                "supported node-list schema",
            ),
            (
                "insecure TLS",
                r#"{"outbounds":[{"type":"trojan","tag":"T","server":"t.example","server_port":443,"password":"TopSecretValue!","tls":{"enabled":true,"server_name":"t.example","insecure":true}}]}"#,
                "disabling TLS certificate verification",
            ),
            (
                "unknown outbound field",
                r#"{"outbounds":[{"type":"shadowsocks","tag":"S","server":"s.example","server_port":8388,"method":"aes-256-gcm","password":"TopSecretValue123","TopSecretValue123":"TopSecretValue123"}]}"#,
                "supported node-list schema",
            ),
            (
                "TUIC 0-RTT",
                r#"{"outbounds":[{"type":"tuic","tag":"Q","server":"q.example","server_port":443,"uuid":"33333333-3333-4333-8333-333333333333","password":"TopSecretValue!","zero_rtt_handshake":true,"tls":{"enabled":true,"server_name":"q.example"}}]}"#,
                "0-RTT is unsupported",
            ),
        ] {
            let error = import_subscription_document(document).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
            assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
        }
    }

    #[test]
    fn vmess_uri_aid_normalizes_positive_legacy_values_and_rejects_noncanonical_input() {
        for (aid, expected) in [
            (None, 0),
            (Some(json!(0)), 0),
            (Some(json!("0")), 0),
            (Some(json!(1)), 1),
            (Some(json!("1")), 1),
            (Some(json!(2)), 1),
            (Some(json!("2")), 1),
            (Some(json!(64)), 1),
            (Some(json!("64")), 1),
            (Some(json!(256)), 1),
            (Some(json!(u32::MAX)), 1),
            (Some(json!(u32::MAX.to_string())), 1),
            (Some(json!(u64::from(u32::MAX) + 1)), 1),
            (Some(json!((u64::from(u32::MAX) + 1).to_string())), 1),
            (Some(json!(i64::MAX)), 1),
            (Some(json!(i64::MAX.to_string())), 1),
        ] {
            assert_single_vmess_alter_id(&vmess_uri_with_aid(aid), expected);
        }

        for (label, aid) in [
            ("null", Value::Null),
            ("empty", json!("")),
            ("leading zero", json!("01")),
            ("plus", json!("+1")),
            ("negative string", json!("-1")),
            ("negative number", json!(-1)),
            ("over bound number", json!(i64::MAX as u64 + 1)),
            (
                "over bound string",
                json!((i64::MAX as u64 + 1).to_string()),
            ),
            ("overflow string", json!("18446744073709551616")),
            ("float", json!(1.0)),
            ("boolean", json!(true)),
            ("mapping", json!({ "value": 1 })),
            ("sequence", json!([1])),
        ] {
            let error =
                import_subscription_document(&vmess_uri_with_aid(Some(aid))).expect_err(label);
            assert!(
                error.contains("vmess URI aid") || error.contains("vmess URI payload"),
                "{label}: {error}"
            );
            assert!(!error.contains(SYNTHETIC_VM_UUID), "{label}: {error}");
        }
    }

    #[test]
    fn clash_vmess_alter_id_normalizes_positive_legacy_values_and_rejects_noncanonical_input() {
        for (value, expected) in [
            (None, 0),
            (Some("0"), 0),
            (Some("\"0\""), 0),
            (Some("1"), 1),
            (Some("\"1\""), 1),
            (Some("2"), 1),
            (Some("\"2\""), 1),
            (Some("64"), 1),
            (Some("\"64\""), 1),
            (Some("256"), 1),
            (Some("4294967295"), 1),
            (Some("\"4294967295\""), 1),
            (Some("4294967296"), 1),
            (Some("\"4294967296\""), 1),
            (Some("9223372036854775807"), 1),
            (Some("\"9223372036854775807\""), 1),
        ] {
            assert_single_vmess_alter_id(&clash_vmess_with_alter_id(value), expected);
        }

        for (label, value) in [
            ("null", "null"),
            ("empty", "\"\""),
            ("leading zero", "01"),
            ("plus", "+1"),
            ("negative", "-1"),
            ("over bound", "9223372036854775808"),
            ("quoted over bound", "\"9223372036854775808\""),
            ("overflow", "\"18446744073709551616\""),
            ("float", "1.0"),
            ("boolean", "true"),
            ("mapping", "{ value: 1 }"),
            ("sequence", "[1]"),
        ] {
            let error = import_subscription_document(&clash_vmess_with_alter_id(Some(value)))
                .expect_err(label);
            assert!(error.contains("proxies[0].alterId"), "{label}: {error}");
            assert!(!error.contains(SYNTHETIC_VM_UUID), "{label}: {error}");
        }
    }

    #[test]
    fn synthetic_46_node_legacy_fixture_preserves_vmess_and_projects_one_selector() {
        let imported = import_subscription_document(&synthetic_46_node_clash_fixture())
            .expect("46-node synthetic Clash fixture");
        assert_eq!(imported.credentials.len(), 46);
        assert_eq!(
            imported
                .credentials
                .iter()
                .filter(|credential| {
                    credential.reference.kind() == CredentialKind::ShadowsocksPassword
                })
                .count(),
            34
        );
        assert_eq!(
            imported
                .credentials
                .iter()
                .filter(|credential| credential.reference.kind() == CredentialKind::VmessUuid)
                .count(),
            12
        );

        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical 46-node profile");
        let profile_outbounds = profile["outbounds"].as_array().expect("profile outbounds");
        assert_eq!(profile_outbounds.len(), 46);
        assert_eq!(
            profile_outbounds
                .iter()
                .filter(|outbound| outbound["type"] == "shadowsocks")
                .count(),
            34
        );
        assert_eq!(
            profile_outbounds
                .iter()
                .filter(|outbound| { outbound["type"] == "vmess" && outbound["alter_id"] == 1 })
                .count(),
            12
        );
        assert!(!imported.profile.as_json().contains("synthetic-ss-secret"));

        let expected_tags = profile_outbounds
            .iter()
            .map(|outbound| outbound["tag"].clone())
            .collect::<Vec<_>>();
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projected = imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("runtime projection for 46-node fixture");
            assert_eq!(projected.credential_slots().len(), 46);
            let runtime: Value =
                serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
            let runtime_outbounds = runtime["outbounds"].as_array().expect("runtime outbounds");
            assert_eq!(runtime_outbounds.len(), 47);
            assert_eq!(
                runtime_outbounds
                    .iter()
                    .filter(|outbound| { outbound["type"] == "vmess" && outbound["alter_id"] == 1 })
                    .count(),
                12
            );
            assert_eq!(
                runtime_outbounds
                    .iter()
                    .filter(|outbound| outbound["type"] == "selector")
                    .count(),
                1
            );
            let selector = runtime_outbounds
                .iter()
                .find(|outbound| outbound["type"] == "selector")
                .expect("app-owned selector");
            let selector_tag = selector["tag"].as_str().expect("selector tag");
            assert_eq!(selector["outbounds"], Value::Array(expected_tags.clone()));
            assert_eq!(
                selector["outbounds"]
                    .as_array()
                    .expect("selector options")
                    .len(),
                46
            );
            assert_eq!(runtime["route"]["final"], selector_tag);
            let authenticated_dns = runtime["dns"]["servers"]
                .as_array()
                .expect("DNS servers")
                .iter()
                .filter(|server| server["type"] == "https")
                .collect::<Vec<_>>();
            assert!(!authenticated_dns.is_empty());
            assert!(
                authenticated_dns
                    .iter()
                    .all(|server| server["detour"] == selector_tag)
            );
        }
    }

    #[test]
    fn imports_base64_uri_bundle_with_shadowsocks_and_trojan() {
        let bundle = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Tokyo\ntrojan://hunter2@trojan.example.com:443?type=grpc&serviceName=tunnel&sni=trojan.example.com#Work";
        let encoded = STANDARD.encode(bundle.as_bytes());
        let imported = import_subscription_document(&encoded).expect("base64 URI bundle");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        assert_eq!(profile["outbounds"][0]["type"], "shadowsocks");
        assert_eq!(profile["outbounds"][1]["type"], "trojan");
        assert_eq!(imported.credentials.len(), 2);
        assert_eq!(
            imported.credentials[0].reference.kind(),
            CredentialKind::ShadowsocksPassword
        );
        assert_eq!(imported.credentials[0].secret, "secret");
        assert_eq!(
            imported.credentials[1].reference.kind(),
            CredentialKind::TrojanPassword
        );
        assert_eq!(imported.credentials[1].secret, "hunter2");
    }

    #[test]
    fn imports_url_safe_padded_base64_uri_bundle() {
        let bundle = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#测试\n";
        let encoded = URL_SAFE.encode(bundle.as_bytes());
        assert!(
            encoded.contains('-') || encoded.contains('_'),
            "fixture must exercise the URL-safe alphabet"
        );
        assert!(encoded.ends_with('='), "fixture must exercise padding");

        let imported = import_subscription_document(&encoded).expect("URL-safe padded bundle");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        assert_eq!(profile["outbounds"][0]["type"], "trojan");
        assert_eq!(profile["outbounds"][0]["tag"], "测试");
        assert_eq!(imported.credentials[0].secret, "hunter2");
    }

    #[test]
    fn uri_bundle_enforces_the_outbound_limit_before_conversion() {
        let entry = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Repeated";
        let at_limit = std::iter::repeat_n(entry, MAX_OUTBOUNDS)
            .collect::<Vec<_>>()
            .join("\n");
        let imported = import_subscription_document(&at_limit).expect("URI bundle at limit");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        let outbounds = profile["outbounds"].as_array().expect("outbounds array");
        assert_eq!(outbounds.len(), MAX_OUTBOUNDS);
        assert_eq!(outbounds[0]["tag"], "Repeated");
        assert_eq!(outbounds[MAX_OUTBOUNDS - 1]["tag"], "Repeated-128");

        let over_limit = format!("{at_limit}\n{entry}");
        let error = import_subscription_document(&over_limit).expect_err("129th URI must fail");
        assert_eq!(
            error,
            format!("subscription URI bundle has more than {MAX_OUTBOUNDS} entries")
        );
    }

    #[test]
    fn migration_credential_references_are_stable_and_namespace_bound() {
        let body = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#Work";
        let namespace =
            Uuid::parse_str("aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa").expect("migration namespace");
        let other_namespace = Uuid::parse_str("bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb")
            .expect("other migration namespace");
        let first = import_subscription_document_with_credential_namespace(body, namespace)
            .expect("first deterministic import");
        let replay = import_subscription_document_with_credential_namespace(body, namespace)
            .expect("deterministic replay");
        let other = import_subscription_document_with_credential_namespace(body, other_namespace)
            .expect("other candidate import");

        assert_eq!(first.profile, replay.profile);
        assert_eq!(
            first.credentials[0].reference,
            replay.credentials[0].reference
        );
        assert_ne!(
            first.credentials[0].reference,
            other.credentials[0].reference
        );
        assert_ne!(first.profile.digest(), other.profile.digest());
        assert_eq!(
            first.credentials[0]
                .reference
                .id()
                .parse::<Uuid>()
                .expect("credential UUID")
                .get_version_num(),
            5
        );
    }

    #[test]
    fn subscription_updates_reuse_references_in_outbound_order() {
        let body = "trojan://first@one.example:443#One\nss://YWVzLTI1Ni1nY206c2Vjb25k@two.example:8388#Two";
        let initial = import_subscription_document(body).expect("initial subscription");
        let references = initial.profile.credential_references_in_outbound_order();
        let replay =
            import_subscription_document_with_reusable_references(body, references.clone())
                .expect("stable subscription update");
        assert_eq!(replay.profile, initial.profile);
        assert_eq!(
            replay.profile.credential_references_in_outbound_order(),
            references
        );
        assert_eq!(
            replay
                .credentials
                .iter()
                .map(|credential| credential.reference.clone())
                .collect::<Vec<_>>(),
            references
        );

        let changed_layout = import_subscription_document_with_reusable_references(
            "ss://YWVzLTI1Ni1nY206bmV3@new.example:8388#New",
            references.clone(),
        )
        .expect("changed credential layout");
        assert_ne!(
            changed_layout.credentials[0].reference, references[0],
            "a kind mismatch must not repurpose an immutable reference"
        );
    }

    #[test]
    fn subscription_updates_handle_shared_references_without_duplicate_provisioning() {
        let initial = import_subscription_document(
            "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
        )
        .expect("initial subscription");
        let shared = initial.credentials[0].reference.clone();

        let unchanged = import_subscription_document_with_reusable_references(
            "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
            vec![shared.clone(), shared.clone()],
        )
        .expect("shared credential update");
        assert_eq!(unchanged.credentials.len(), 1);
        assert_eq!(unchanged.credentials[0].reference, shared);
        assert_eq!(
            unchanged.profile.credential_references_in_outbound_order(),
            vec![shared.clone(), shared.clone()]
        );

        let split = import_subscription_document_with_reusable_references(
            "trojan://first@one.example:443#One\ntrojan://second@two.example:443#Two",
            vec![shared.clone(), shared.clone()],
        )
        .expect("split credential update");
        assert_eq!(split.credentials.len(), 2);
        assert_eq!(split.credentials[0].reference, shared);
        assert_ne!(
            split.credentials[1].reference, split.credentials[0].reference,
            "different material must receive a distinct immutable reference"
        );
        assert_eq!(split.credentials[0].secret, "first");
        assert_eq!(split.credentials[1].secret, "second");
    }

    #[test]
    fn credential_kind_discriminants_are_append_only() {
        assert_eq!(
            [
                CredentialKind::ShadowsocksPassword,
                CredentialKind::VmessUuid,
                CredentialKind::VlessUuid,
                CredentialKind::TrojanPassword,
                CredentialKind::Hysteria2Password,
                CredentialKind::Hysteria2ObfsPassword,
                CredentialKind::AnyTlsPassword,
                CredentialKind::TuicUuid,
                CredentialKind::TuicPassword,
                CredentialKind::Socks5Username,
                CredentialKind::Socks5Password,
            ]
            .map(credential_kind_discriminant),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
    }

    #[test]
    fn imports_vmess_with_websocket_tls() {
        let payload = json!({
            "ps": "VMess",
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-1111-4111-8111-111111111111",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "path": "/ws",
            "host": "edge.example.com",
            "tls": "tls",
            "sni": "vmess.example.com",
            "alpn": "h2,http/1.1",
            "fp": "chrome"
        });
        let entry = format!("vmess://{}", STANDARD.encode(payload.to_string()));
        let imported = import_subscription_document(&entry).expect("vmess URI");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        assert_eq!(profile["outbounds"][0]["type"], "vmess");
        assert_eq!(profile["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(
            profile["outbounds"][0]["tls"]["utls"]["fingerprint"],
            "chrome"
        );
        assert_eq!(
            imported.credentials[0].reference.kind(),
            CredentialKind::VmessUuid
        );
    }

    #[test]
    fn imports_vless_reality_and_hysteria2_links() {
        let imported = import_subscription_document(
            "vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#Reality\nhy2://supersecret@hy2.example.com:8443?sni=hy2.example.com&upmbps=100&downmbps=200&obfs=salamander&obfs-password=mask#HY2",
        )
        .expect("vless and hy2 URIs");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        assert_eq!(profile["outbounds"][0]["type"], "vless");
        assert_eq!(profile["outbounds"][0]["packet_encoding"], "xudp");
        assert_eq!(profile["outbounds"][0]["tls"]["reality"]["enabled"], true);
        assert_eq!(profile["outbounds"][1]["type"], "hysteria2");
        assert_eq!(profile["outbounds"][1]["obfs"]["type"], "salamander");
        assert_eq!(imported.credentials.len(), 3);
        assert_eq!(
            imported.credentials[0].reference.kind(),
            CredentialKind::VlessUuid
        );
        assert_eq!(
            imported.credentials[1].reference.kind(),
            CredentialKind::Hysteria2Password
        );
        assert_eq!(
            imported.credentials[2].reference.kind(),
            CredentialKind::Hysteria2ObfsPassword
        );
        let projected = imported
            .profile
            .project(
                SYNTHETIC_PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("VLESS packet encoding projection");
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
        assert_eq!(runtime["outbounds"][0]["packet_encoding"], "xudp");
    }

    #[test]
    fn hysteria2_and_anytls_omitted_ports_default_to_443() {
        let imported = import_subscription_document(
            "hysteria2://user%3Apass@hy.example/?sni=hy.example#HY2\nanytls://letmein@any.example/?sni=any.example#AnyTLS",
        )
        .expect("official omitted-port URI forms");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        let outbounds = profile["outbounds"].as_array().expect("outbounds");
        assert_eq!(outbounds[0]["server_port"], 443);
        assert_eq!(outbounds[1]["server_port"], 443);
        assert_eq!(imported.credentials[0].secret, "user:pass");
        assert_eq!(imported.credentials[1].secret, "letmein");
        assert!(!imported.profile.as_json().contains("user:pass"));
        assert!(!imported.profile.as_json().contains("letmein"));

        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("omitted-port runtime projection");
        }
    }

    #[test]
    fn hysteria2_port_hopping_projects_from_uri_clash_and_sing_box() {
        let documents = [
            (
                "official URI",
                "hysteria2://hy-secret@hy.example.com:443,5000-5002/?sni=hy.example.com#URI-Hop"
                    .to_owned(),
                None,
            ),
            (
                "Clash",
                "proxies:\n  - name: Clash-Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 443,5000-5002\n    hop-interval: 30\n    password: hy-secret\n    sni: hy.example.com\n"
                    .to_owned(),
                Some(30),
            ),
            (
                "sing-box",
                json!({
                    "outbounds": [{
                        "type": "hysteria2",
                        "tag": "SingBox-Hop",
                        "server": "hy.example.com",
                        "server_ports": ["443", "5000:5002"],
                        "hop_interval": "15s",
                        "password": "hy-secret",
                        "tls": { "enabled": true, "server_name": "hy.example.com" }
                    }]
                })
                .to_string(),
                Some(15),
            ),
        ];

        for (label, document, hop_interval) in documents {
            let imported = import_subscription_document(&document).expect(label);
            let profile: Value = serde_json::from_str(imported.profile.as_json())
                .expect("canonical Hysteria2 hopping profile");
            let outbound = &profile["outbounds"][0];
            assert_eq!(outbound["server_port"], 443, "{label}");
            assert_eq!(outbound["server_ports"], json!(["443", "5000:5002"]));
            match hop_interval {
                Some(seconds) => {
                    assert_eq!(outbound["hop_interval_seconds"], seconds, "{label}")
                }
                None => assert!(outbound.get("hop_interval_seconds").is_none(), "{label}"),
            }
            assert_eq!(imported.credentials[0].secret, "hy-secret");

            for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
                let projected = imported
                    .profile
                    .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                    .expect("Hysteria2 hopping projection");
                let runtime: Value = serde_json::from_str(projected.as_json())
                    .expect("Hysteria2 hopping runtime JSON");
                let runtime_hysteria2 = runtime["outbounds"]
                    .as_array()
                    .expect("runtime outbounds")
                    .iter()
                    .find(|candidate| candidate["type"] == "hysteria2")
                    .expect("runtime Hysteria2 outbound");
                assert_eq!(
                    runtime_hysteria2["server_ports"],
                    json!(["443:443", "5000:5002"]),
                    "{label}"
                );
                if let Some(seconds) = hop_interval {
                    assert_eq!(
                        runtime_hysteria2["hop_interval"],
                        format!("{seconds}s"),
                        "{label}"
                    );
                }
            }
        }
    }

    #[test]
    fn hysteria2_port_hopping_rejects_ambiguous_or_unprojectable_ranges() {
        for (label, document, expected) in [
            (
                "overlap",
                "hysteria2://hy-secret@hy.example.com:443,440-450/?sni=hy.example.com#Overlap",
                "overlapping",
            ),
            (
                "leading zero",
                "hysteria2://hy-secret@hy.example.com:0443,5000-5002/?sni=hy.example.com#LeadingZero",
                "invalid port",
            ),
            (
                "random hop interval unsupported by pinned engine",
                "proxies:\n  - name: Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 15-30\n    password: TopSecretValue!\n",
                "canonical 1..=3600 second",
            ),
        ] {
            let error = import_subscription_document(document).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        }
    }

    #[test]
    fn legacy_uri_formats_reject_unrepresented_or_ambiguous_semantics() {
        for (label, uri, expected) in [
            (
                "Shadowsocks unknown parameter",
                "ss://YWVzLTI1Ni1nY206VG9wU2VjcmV0VmFsdWUh@ss.example.com:8388?uot=1#S",
                "unsupported parameters",
            ),
            (
                "VLESS duplicate SNI",
                "vless://11111111-1111-4111-8111-111111111111@v.example:443?security=tls&sni=one.example&sni=two.example#V",
                "repeats query parameter",
            ),
            (
                "VLESS packet encoding",
                "vless://11111111-1111-4111-8111-111111111111@v.example:443?packetEncoding=TopSecretValue123#V",
                "packet encoding is unsupported",
            ),
            (
                "VLESS encryption",
                "vless://11111111-1111-4111-8111-111111111111@v.example:443?encryption=mlkem768x25519plus#V",
                "encryption is unsupported",
            ),
            (
                "Trojan HTTP header",
                "trojan://TopSecretValue%21@t.example:443?type=tcp&headerType=http#T",
                "header type is unsupported",
            ),
            (
                "Trojan TCP path",
                "trojan://TopSecretValue%21@t.example:443?type=tcp&path=%2Fws#T",
                "unsupported options",
            ),
            (
                "QUIC transport options",
                "vless://11111111-1111-4111-8111-111111111111@v.example:443?type=quic&path=%2Fhidden#V",
                "QUIC subscription transport declares unsupported options",
            ),
        ] {
            let error = import_subscription_document(uri).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
            assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
        }
    }

    #[test]
    fn vmess_explicit_safe_metadata_is_consumed_and_unknown_fields_fail_closed() {
        let safe = json!({
            "v": "2",
            "ps": "VMess",
            "add": "vmess.example.com",
            "port": "443",
            "id": SYNTHETIC_VM_UUID,
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "insecure": "0",
            "vcn": "",
            "pcs": "",
            "packetEncoding": "xudp"
        });
        let imported =
            import_subscription_document(&format!("vmess://{}", STANDARD.encode(safe.to_string())))
                .expect("safe explicit VMess metadata");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical VMess profile");
        assert_eq!(profile["outbounds"][0]["packet_encoding"], "xudp");
        let projected = imported
            .profile
            .project(
                SYNTHETIC_PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("VMess packet encoding projection");
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime VMess projection");
        assert_eq!(runtime["outbounds"][0]["packet_encoding"], "xudp");

        for (label, key, value) in [
            ("unknown field", "mystery", json!("TopSecretValue!")),
            ("insecure TLS", "insecure", json!(true)),
            ("certificate domain", "vcn", json!("certificate.example")),
            ("certificate pin", "pcs", json!("TopSecretValue!")),
            ("HTTP header", "type", json!("http")),
        ] {
            let mut payload = safe.clone();
            payload
                .as_object_mut()
                .expect("VMess fixture object")
                .insert(key.to_owned(), value);
            let uri = format!("vmess://{}", STANDARD.encode(payload.to_string()));
            let error = import_subscription_document(&uri).expect_err(label);
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        }
    }

    #[test]
    fn imports_closed_http_httpupgrade_and_quic_transport_matrix() {
        let vmess_quic = json!({
            "v": "2",
            "ps": "VMess QUIC",
            "add": "vmess.example.com",
            "port": "443",
            "id": SYNTHETIC_VM_UUID,
            "aid": "0",
            "net": "quic",
            "type": "none",
            "tls": "tls",
            "sni": "vmess.example.com"
        });
        let document = format!(
            "vless://11111111-1111-4111-8111-111111111111@v.example:443?type=http&method=GET&path=%2Fh2&host=one.example%2Ctwo.example&headerType=none#HTTP\n\
             trojan://TopSecretValue%21@t.example:443?type=httpupgrade&path=%2Fup&host=edge.example#Upgrade\n\
             vmess://{}",
            STANDARD.encode(vmess_quic.to_string())
        );
        let imported = import_subscription_document(&document).expect("V2Ray transport matrix");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical transport profile");
        let outbounds = profile["outbounds"]
            .as_array()
            .expect("transport outbounds");
        assert_eq!(outbounds[0]["transport"]["type"], "http");
        assert_eq!(outbounds[0]["transport"]["method"], "GET");
        assert_eq!(
            outbounds[0]["transport"]["host"],
            json!(["one.example", "two.example"])
        );
        assert_eq!(outbounds[1]["transport"]["type"], "http_upgrade");
        assert_eq!(outbounds[1]["transport"]["host"], "edge.example");
        assert_eq!(outbounds[2]["transport"]["type"], "quic");

        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projected = imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("transport matrix projection");
            let runtime: Value =
                serde_json::from_str(projected.as_json()).expect("runtime transport projection");
            assert_eq!(runtime["outbounds"][0]["transport"]["type"], "http");
            assert_eq!(runtime["outbounds"][0]["transport"]["method"], "GET");
            assert_eq!(runtime["outbounds"][1]["transport"]["type"], "httpupgrade");
            assert_eq!(runtime["outbounds"][2]["transport"]["type"], "quic");
        }
    }

    #[test]
    fn imports_clash_h2_httpupgrade_and_quic_transport_matrix() {
        let document = r#"
proxies:
  - name: H2
    type: vless
    server: v.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: h2
    h2-opts:
      path: /h2
      host: [one.example, two.example]
  - name: Upgrade
    type: trojan
    server: t.example
    port: 443
    password: TopSecretValue!
    network: httpupgrade
    http-upgrade-opts:
      path: /up
      host: edge.example
  - name: QUIC
    type: vmess
    server: q.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    alterId: 0
    network: quic
    tls: true
    servername: q.example
"#;
        let imported = import_subscription_document(document).expect("Clash transport matrix");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical Clash transports");
        assert_eq!(profile["outbounds"][0]["transport"]["type"], "http");
        assert_eq!(profile["outbounds"][1]["transport"]["type"], "http_upgrade");
        assert_eq!(profile["outbounds"][2]["transport"]["type"], "quic");
        assert!(!imported.profile.as_json().contains("TopSecretValue!"));
    }

    #[test]
    fn imports_mihomo_vmess_http_options_and_closed_framing_flags() {
        let document = r#"
proxies:
  - name: HTTP
    type: vmess
    server: vm.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    global-padding: false
    authenticated-length: false
    network: http
    http-opts:
      method: GET
      path: [/tunnel]
      headers:
        Host: [edge.example]
"#;
        let imported = import_subscription_document(document).expect("Mihomo VMess HTTP options");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical Mihomo profile");
        let transport = &profile["outbounds"][0]["transport"];
        assert_eq!(transport["type"], "http");
        assert_eq!(transport["method"], "GET");
        assert_eq!(transport["path"], "/tunnel");
        assert_eq!(transport["host"], json!(["edge.example"]));

        let projected = imported
            .profile
            .project(
                SYNTHETIC_PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("Mihomo HTTP runtime projection");
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime Mihomo profile");
        assert_eq!(runtime["outbounds"][0]["transport"]["method"], "GET");

        for flag in ["global-padding", "authenticated-length"] {
            let rejected = document.replace(&format!("{flag}: false"), &format!("{flag}: true"));
            let error = import_subscription_document(&rejected).expect_err("active VMess framing");
            assert!(error.contains("not represented by the pinned runtime schema"));
        }

        let secret_header = document.replace(
            "Host: [edge.example]",
            "TopSecretValue123: [TopSecretValue123]",
        );
        let error =
            import_subscription_document(&secret_header).expect_err("unsupported custom header");
        assert!(error.contains("unsupported keys"));
        assert!(!error.contains("TopSecretValue123"));
    }

    #[test]
    fn imports_anytls_and_tuic_links_with_closed_options_and_vault_credentials() {
        let imported = import_subscription_document(
            "anytls://any%3Atls-secret@anytls.example.com:443?security=tls&sni=front.example.com&alpn=h2,http%2F1.1&fp=chrome&insecure=0#AnyTLS\ntuic://11111111-1111-4111-8111-111111111111:tuic%3Asecret@tuic.example.com:10443?security=tls&sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic&zero_rtt_handshake=false&udp_over_stream=0#TUIC",
        )
        .expect("AnyTLS and TUIC URIs");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        let outbounds = profile["outbounds"].as_array().expect("outbounds");
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["type"], "anytls");
        assert_eq!(outbounds[0]["tls"]["server_name"], "front.example.com");
        assert_eq!(outbounds[0]["tls"]["alpn"], json!(["h2", "http/1.1"]));
        assert_eq!(outbounds[0]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbounds[1]["type"], "tuic");
        assert_eq!(outbounds[1]["congestion_control"], "bbr");
        assert_eq!(outbounds[1]["udp_relay_mode"], "quic");
        assert_eq!(outbounds[1]["tls"]["alpn"], json!(["h3"]));

        assert_eq!(imported.credentials.len(), 3);
        assert_eq!(
            imported.credentials[0].reference.kind(),
            CredentialKind::AnyTlsPassword
        );
        assert_eq!(imported.credentials[0].secret, "any:tls-secret");
        assert_eq!(
            imported.credentials[1].reference.kind(),
            CredentialKind::TuicUuid
        );
        assert_eq!(
            imported.credentials[1].secret,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            imported.credentials[2].reference.kind(),
            CredentialKind::TuicPassword
        );
        assert_eq!(imported.credentials[2].secret, "tuic:secret");
        for secret in [
            "any:tls-secret",
            "11111111-1111-4111-8111-111111111111",
            "tuic:secret",
        ] {
            assert!(!imported.profile.as_json().contains(secret));
        }

        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projected = imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("runtime projection");
            assert_eq!(projected.credential_slots().len(), 3);
            assert_eq!(
                projected.credential_slots()[0].json_pointer(),
                "/outbounds/0/password"
            );
            assert_eq!(
                projected.credential_slots()[1].json_pointer(),
                "/outbounds/1/uuid"
            );
            assert_eq!(
                projected.credential_slots()[2].json_pointer(),
                "/outbounds/1/password"
            );
        }
    }

    #[test]
    fn tls_protocol_uri_imports_fail_closed_on_unrepresented_semantics() {
        for (label, uri, expected) in [
            (
                "Hysteria2 unknown parameter",
                "hy2://TopSecretValue%21@hy2.example.com:443?TopSecretValue123=1",
                "unsupported parameters",
            ),
            (
                "Hysteria2 uTLS",
                "hy2://TopSecretValue%21@hy2.example.com:443?fp=chrome",
                "does not support uTLS",
            ),
            (
                "Hysteria2 Reality",
                "hy2://TopSecretValue%21@hy2.example.com:443?security=reality",
                "security mode is unsupported",
            ),
            (
                "Hysteria2 insecure TLS",
                "hy2://TopSecretValue%21@hy2.example.com:443?insecure=true",
                "disabling TLS certificate verification",
            ),
            (
                "AnyTLS unknown parameter",
                "anytls://TopSecretValue%21@anytls.example.com:443?TopSecretValue123=1",
                "unsupported parameters",
            ),
            (
                "AnyTLS duplicate parameter",
                "anytls://TopSecretValue%21@anytls.example.com:443?sni=one.example.com&sni=two.example.com",
                "repeats query parameter",
            ),
            (
                "AnyTLS insecure TLS",
                "anytls://TopSecretValue%21@anytls.example.com:443?insecure=true",
                "disabling TLS certificate verification",
            ),
            (
                "TUIC missing password",
                "tuic://11111111-1111-4111-8111-111111111111@tuic.example.com:443",
                "TUIC password is missing",
            ),
            (
                "TUIC 0-RTT",
                "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?zero_rtt_handshake=true",
                "0-RTT handshake is unsupported",
            ),
            (
                "TUIC UDP-over-stream",
                "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?udp_over_stream=1",
                "UDP-over-stream is unsupported",
            ),
            (
                "TUIC uTLS",
                "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?fp=chrome",
                "unsupported parameters",
            ),
            (
                "TUIC congestion control",
                "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?congestion_control=reno",
                "congestion control is unsupported",
            ),
            (
                "TUIC UDP relay",
                "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?udp_relay_mode=stream",
                "UDP relay mode is unsupported",
            ),
        ] {
            let error = import_subscription_document(uri).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
            assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
        }
    }

    #[test]
    fn imports_clash_meta_yaml_across_all_supported_types() {
        let document = r#"
mixed-port: 7890
dns:
  enable: true
proxies:
  - name: "SS Tokyo"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "0123"
    udp: true
  - name: VMess Edge
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: vmess.example.com
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
  - name: Reality
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    flow: xtls-rprx-vision
    encryption: ""
    packet-encoding: xudp
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: Work
    type: trojan
    server: trojan.example.com
    port: 443
    password: hunter2
    sni: trojan.example.com
    alpn:
      - h2
      - http/1.1
    network: grpc
    grpc-opts:
      grpc-service-name: tunnel
  - name: Work
    type: hysteria2
    server: hy2.example.com
    port: 8443
    password: supersecret
    sni: hy2.example.com
    up: "100 Mbps"
    down: "200"
    obfs: salamander
    obfs-password: mask
  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: anytls-secret
    tls: true
    sni: front.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 10443
    uuid: 33333333-3333-4333-8333-333333333333
    password: tuic-secret
    sni: tuic.example.com
    alpn: [h3]
    congestion-controller: new_reno
    udp-relay-mode: quic
    reduce-rtt: false
    udp-over-stream: false
    disable-sni: false
proxy-groups:
  - name: PROXY
    type: select
rules:
  - MATCH,PROXY
"#;
        let imported = import_subscription_document(document).expect("Clash Meta YAML");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        let outbounds = profile["outbounds"].as_array().expect("outbounds array");
        assert_eq!(outbounds.len(), 7);

        assert_eq!(outbounds[0]["type"], "shadowsocks");
        assert_eq!(outbounds[0]["tag"], "SS Tokyo");
        assert_eq!(outbounds[0]["method"], "aes-256-gcm");

        assert_eq!(outbounds[1]["type"], "vmess");
        assert_eq!(outbounds[1]["tls"]["server_name"], "vmess.example.com");
        assert_eq!(outbounds[1]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbounds[1]["transport"]["type"], "ws");
        assert_eq!(outbounds[1]["transport"]["path"], "/ws");
        assert_eq!(
            outbounds[1]["transport"]["headers"]["Host"],
            "edge.example.com"
        );
        assert!(
            outbounds[1].get("security").is_none(),
            "auto is the default"
        );

        assert_eq!(outbounds[2]["type"], "vless");
        assert_eq!(outbounds[2]["flow"], "xtls-rprx-vision");
        assert_eq!(outbounds[2]["packet_encoding"], "xudp");
        assert_eq!(outbounds[2]["tls"]["server_name"], "www.example.com");
        assert_eq!(outbounds[2]["tls"]["reality"]["enabled"], true);
        assert_eq!(
            outbounds[2]["tls"]["reality"]["public_key"],
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
        );
        assert_eq!(
            outbounds[2]["tls"]["reality"]["short_id"],
            "0123456789abcdef"
        );

        assert_eq!(outbounds[3]["type"], "trojan");
        assert_eq!(outbounds[3]["tag"], "Work");
        assert_eq!(outbounds[3]["tls"]["alpn"][0], "h2");
        assert_eq!(outbounds[3]["transport"]["type"], "grpc");
        assert_eq!(outbounds[3]["transport"]["service_name"], "tunnel");

        assert_eq!(outbounds[4]["type"], "hysteria2");
        assert_eq!(
            outbounds[4]["tag"], "Work-2",
            "duplicate names get suffixes"
        );
        assert_eq!(outbounds[4]["up_mbps"], 100);
        assert_eq!(outbounds[4]["down_mbps"], 200);
        assert_eq!(outbounds[4]["obfs"]["type"], "salamander");

        assert_eq!(outbounds[5]["type"], "anytls");
        assert_eq!(outbounds[5]["tls"]["server_name"], "front.example.com");
        assert_eq!(outbounds[5]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbounds[5]["tls"]["reality"]["enabled"], true);

        assert_eq!(outbounds[6]["type"], "tuic");
        assert_eq!(outbounds[6]["congestion_control"], "new_reno");
        assert_eq!(outbounds[6]["udp_relay_mode"], "quic");
        assert_eq!(outbounds[6]["tls"]["alpn"], json!(["h3"]));

        let secrets: Vec<&str> = imported
            .credentials
            .iter()
            .map(|credential| credential.secret.as_str())
            .collect();
        assert_eq!(
            secrets,
            [
                "0123",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "hunter2",
                "supersecret",
                "mask",
                "anytls-secret",
                "33333333-3333-4333-8333-333333333333",
                "tuic-secret",
            ],
            "secrets keep exact source bytes, including leading zeros"
        );
        assert_eq!(
            imported.credentials[5].reference.kind(),
            CredentialKind::Hysteria2ObfsPassword
        );
        assert_eq!(
            imported.credentials[6].reference.kind(),
            CredentialKind::AnyTlsPassword
        );
        assert_eq!(
            imported.credentials[7].reference.kind(),
            CredentialKind::TuicUuid
        );
        assert_eq!(
            imported.credentials[8].reference.kind(),
            CredentialKind::TuicPassword
        );
        let stored = imported.profile.as_json();
        for secret in [
            "hunter2",
            "supersecret",
            "mask",
            "anytls-secret",
            "33333333-3333-4333-8333-333333333333",
            "tuic-secret",
        ] {
            assert!(
                !stored.contains(secret),
                "stored profile must not embed secrets"
            );
        }
    }

    #[test]
    fn clash_yaml_conversion_fails_closed_without_echoing_secrets() {
        let unsupported_type = "proxies:\n  - name: node\n    type: wireguard\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n";
        let error =
            import_subscription_document(unsupported_type).expect_err("unsupported proxy type");
        assert!(error.contains("proxies[0]"), "{error}");
        assert!(!error.contains("wireguard"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let insecure = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    skip-cert-verify: true\n";
        let error = import_subscription_document(insecure).expect_err("skip-cert-verify");
        assert!(
            error.contains("disabling TLS certificate verification"),
            "{error}"
        );
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let unknown_key = "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    TopSecretValue123: 5\n";
        let error = import_subscription_document(unknown_key).expect_err("unknown key");
        assert!(error.contains("unsupported keys"), "{error}");
        assert!(!error.contains("TopSecretValue123"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let alias_bomb = "proxies: &a\n  - name: node\nmore: *a\n";
        let error = import_subscription_document(alias_bomb).expect_err("aliases rejected");
        assert!(error.contains("anchors are not supported"), "{error}");

        let missing_proxies = "mixed-port: 7890\n";
        let error = import_subscription_document(missing_proxies).expect_err("no proxies");
        assert!(error.contains("no proxies list"), "{error}");

        let overlapping_ports = "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    ports: 20000-30000,25000-31000\n";
        let error =
            import_subscription_document(overlapping_ports).expect_err("overlapping port ranges");
        assert!(error.contains("overlapping"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");

        for (label, document, expected) in [
            (
                "TUIC 0-RTT",
                "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    reduce-rtt: true\n",
                "0-RTT",
            ),
            (
                "TUIC uTLS",
                "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
                "does not support uTLS",
            ),
            (
                "Hysteria2 uTLS",
                "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
                "does not support uTLS",
            ),
        ] {
            let error = import_subscription_document(document).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        }
    }

    #[test]
    fn rejects_unsupported_uri_schemes() {
        let error = import_subscription_document("shadowtls://token@example.com:443#ShadowTLS")
            .expect_err("unsupported scheme");
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn uri_bundle_errors_never_echo_line_content() {
        let error = import_subscription_document("not json and not a uri TopSecretValue!")
            .expect_err("unrecognized document");
        assert!(!error.contains("TopSecretValue!"), "{error}");
        assert!(error.contains("subscription line 1"), "{error}");
    }
}
