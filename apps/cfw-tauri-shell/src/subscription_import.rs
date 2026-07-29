use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cfw_singbox_config::{CredentialKind, CredentialRef, ValidatedSingBoxProfile};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroize;

mod clash;
mod yaml;

const SUPPORTED_URI_SCHEMES: &[&str] = &["ss", "vmess", "vless", "trojan", "hysteria2", "hy2"];

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
struct VmessPayload {
    #[serde(default)]
    ps: String,
    add: String,
    port: serde_json::Value,
    id: String,
    #[serde(default)]
    aid: String,
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
}

pub(crate) fn import_subscription_document(body: &str) -> Result<ImportedSubscription, String> {
    if let Ok(profile) = ValidatedSingBoxProfile::parse(body) {
        return Ok(ImportedSubscription {
            profile,
            credentials: Vec::new(),
        });
    }

    if looks_like_clash_yaml(body) {
        return clash::import_clash_document(body);
    }

    let candidate = decode_uri_bundle_base64(body).unwrap_or_else(|| body.trim().to_owned());
    let entries = collect_uri_entries(&candidate)?;
    let mut collector = OutboundCollector::default();
    for (index, entry) in entries.iter().enumerate() {
        collector.push_entry(entry, index)?;
    }
    collector.into_subscription()
}

/// Detects Clash/Mihomo YAML documents so they take the conversion path
/// instead of the node-URI path. The needles are top-level keys that only
/// appear in Clash configurations.
fn looks_like_clash_yaml(body: &str) -> bool {
    let lowercase = body.to_ascii_lowercase();
    [
        "proxies:",
        "proxy-groups:",
        "proxy-providers:",
        "rule-providers:",
        "mixed-port:",
        "redir-port:",
    ]
    .into_iter()
    .any(|needle| lowercase.contains(needle))
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
    fn push_entry(&mut self, entry: &str, index: usize) -> Result<(), String> {
        let scheme = entry
            .split("://")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let outbound = match scheme.as_str() {
            "ss" => self.parse_shadowsocks(entry, index)?,
            "vmess" => self.parse_vmess(entry, index)?,
            "vless" => self.parse_vless(entry, index)?,
            "trojan" => self.parse_trojan(entry, index)?,
            "hysteria2" | "hy2" => self.parse_hysteria2(entry, index)?,
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
        let (without_fragment, tag) = split_fragment(entry);
        let (main, query) = split_query(without_fragment);
        if query.contains_key("plugin") {
            return Err("Shadowsocks plugins are unsupported in subscription imports".into());
        }
        let raw = main
            .strip_prefix("ss://")
            .ok_or_else(|| "invalid Shadowsocks URI".to_owned())?;
        let (credentials_part, host_port_part) = if let Some((left, right)) = raw.rsplit_once('@') {
            (left.to_owned(), right.to_owned())
        } else {
            let decoded = String::from_utf8(decode_base64_text(raw).map_err(|error| {
                format!("Shadowsocks URI credentials are invalid base64: {error}")
            })?)
            .map_err(|_| "Shadowsocks URI credentials are not UTF-8".to_owned())?;
            decoded
                .rsplit_once('@')
                .map(|(left, right)| (left.to_owned(), right.to_owned()))
                .ok_or_else(|| "Shadowsocks URI must contain host and port".to_owned())?
        };
        let decoded_credentials = decode_url_component(&credentials_part)?;
        let credential_text = if decoded_credentials.contains(':') {
            decoded_credentials
        } else {
            String::from_utf8(decode_base64_text(&decoded_credentials).map_err(|error| {
                format!("Shadowsocks URI method/password envelope is invalid base64: {error}")
            })?)
            .map_err(|_| "Shadowsocks URI method/password envelope is not UTF-8".to_owned())?
        };
        let (method, password) = credential_text
            .split_once(':')
            .ok_or_else(|| "Shadowsocks URI must contain method and password".to_owned())?;
        let (server, server_port) = split_host_port(&host_port_part)?;
        let reference = self.push_secret(
            CredentialKind::ShadowsocksPassword,
            decode_url_component(password)?,
        );
        let tag = self.unique_tag(tag.unwrap_or_else(|| format!("ss-{index}")));
        Ok(json!({
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": server_port,
            "method": normalize_shadowsocks_method(method)?,
            "credential_ref": credential_ref_json(&reference),
        }))
    }

    fn parse_vmess(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let encoded = entry
            .trim()
            .strip_prefix("vmess://")
            .ok_or_else(|| "invalid vmess URI".to_owned())?;
        let payload = String::from_utf8(
            decode_base64_text(encoded)
                .map_err(|error| format!("vmess URI payload is invalid base64: {error}"))?,
        )
        .map_err(|_| "vmess URI payload is not UTF-8".to_owned())?;
        let payload: VmessPayload = serde_json::from_str(&payload)
            .map_err(|error| format!("vmess URI payload is invalid JSON: {error}"))?;
        if !payload.aid.is_empty() && payload.aid != "0" {
            return Err("vmess alterId is unsupported; only aid=0 is accepted".into());
        }
        let reference = self.push_secret(CredentialKind::VmessUuid, payload.id.clone());
        let tag =
            self.unique_tag(non_empty(payload.ps).unwrap_or_else(|| format!("vmess-{index}")));
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
        )?;
        let mut outbound = json!({
            "type": "vmess",
            "tag": tag,
            "server": payload.add,
            "server_port": server_port,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(security) = normalize_vmess_security(payload.scy.as_str())? {
            outbound["security"] = Value::String(security);
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
        let query = query_map(&url);
        let reference = self.push_secret(
            CredentialKind::VlessUuid,
            decode_url_component(url.username())?,
        );
        let tag =
            self.unique_tag(decoded_fragment(&url).unwrap_or_else(|| format!("vless-{index}")));
        let server = host_string(&url)?;
        let security = query.get("security").map(String::as_str).unwrap_or("none");
        let tls = match security {
            "none" | "" => None,
            "tls" => Some(tls_json(build_tls_parts(
                true,
                query.get("sni").cloned().unwrap_or_else(|| server.clone()),
                split_csv(query.get("alpn").map(String::as_str).unwrap_or_default()),
                parse_utls(query.get("fp").map(String::as_str).unwrap_or_default())?,
                None,
            ))),
            "reality" => {
                let public_key = required_query(&query, "pbk", "VLESS Reality public key")?;
                let short_id = query.get("sid").cloned().unwrap_or_default();
                Some(tls_json(build_tls_parts(
                    true,
                    query.get("sni").cloned().unwrap_or_else(|| server.clone()),
                    split_csv(query.get("alpn").map(String::as_str).unwrap_or_default()),
                    parse_utls(query.get("fp").map(String::as_str).unwrap_or_default())?,
                    Some(json!({
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id,
                    })),
                )))
            }
            other => {
                return Err(format!(
                    "VLESS security mode is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        let transport = transport_from_parts(
            query.get("type").map(String::as_str).unwrap_or("tcp"),
            query.get("path").cloned(),
            query.get("host").cloned(),
            query
                .get("serviceName")
                .cloned()
                .or_else(|| query.get("service_name").cloned()),
        )?;
        let mut outbound = json!({
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(flow) = query.get("flow")
            && !flow.is_empty()
        {
            outbound["flow"] = Value::String(normalize_vless_flow(flow)?);
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
        let query = query_map(&url);
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::TrojanPassword,
            decode_url_component(url.username())?,
        );
        let tag =
            self.unique_tag(decoded_fragment(&url).unwrap_or_else(|| format!("trojan-{index}")));
        let transport = transport_from_parts(
            query.get("type").map(String::as_str).unwrap_or("tcp"),
            query.get("path").cloned(),
            query.get("host").cloned(),
            query
                .get("serviceName")
                .cloned()
                .or_else(|| query.get("service_name").cloned()),
        )?;
        let tls = tls_json(build_tls_parts(
            true,
            query.get("sni").cloned().unwrap_or_else(|| server.clone()),
            split_csv(query.get("alpn").map(String::as_str).unwrap_or_default()),
            parse_utls(query.get("fp").map(String::as_str).unwrap_or_default())?,
            None,
        ));
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
        let url =
            Url::parse(entry).map_err(|_| "subscription Hysteria2 URI is invalid".to_owned())?;
        let query = query_map(&url);
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::Hysteria2Password,
            decode_url_component(url.username())?,
        );
        let tag = self.unique_tag(decoded_fragment(&url).unwrap_or_else(|| format!("hy2-{index}")));
        let tls = tls_json(build_tls_parts(
            true,
            query.get("sni").cloned().unwrap_or_else(|| server.clone()),
            split_csv(query.get("alpn").map(String::as_str).unwrap_or_default()),
            None,
            None,
        ));
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
        });
        if let Some(value) = query.get("upmbps") {
            outbound["up_mbps"] = json!(parse_positive_u32(value, "Hysteria2 upmbps")?);
        }
        if let Some(value) = query.get("downmbps") {
            outbound["down_mbps"] = json!(parse_positive_u32(value, "Hysteria2 downmbps")?);
        }
        if let Some(obfs) = query.get("obfs")
            && !obfs.is_empty()
        {
            if obfs != "salamander" {
                return Err(format!(
                    "Hysteria2 obfs mode is unsupported: {}",
                    sanitized_token(obfs)
                ));
            }
            let obfs_secret = required_query(&query, "obfs-password", "Hysteria2 obfs password")?;
            let reference = self.push_secret(CredentialKind::Hysteria2ObfsPassword, obfs_secret);
            outbound["obfs"] = json!({
                "type": "salamander",
                "credential_ref": credential_ref_json(&reference),
            });
        }
        Ok(outbound)
    }

    fn push_secret(&mut self, kind: CredentialKind, secret: String) -> CredentialRef {
        let reference = CredentialRef::new(Uuid::new_v4().hyphenated().to_string(), kind)
            .expect("generated credential UUID must stay canonical");
        self.credentials.push(ImportedCredential {
            reference: reference.clone(),
            secret,
        });
        reference
    }

    fn unique_tag(&mut self, preferred: String) -> String {
        let sanitized = preferred.trim().replace('\n', " ");
        if sanitized.is_empty() {
            return self.unique_tag("proxy".into());
        }
        if self.used_tags.insert(sanitized.clone()) {
            return sanitized;
        }
        for suffix in 2..=10_000 {
            let candidate = format!("{sanitized}-{suffix}");
            if self.used_tags.insert(candidate.clone()) {
                return candidate;
            }
        }
        unreachable!("bounded duplicate suffix search must terminate");
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

fn split_fragment(entry: &str) -> (&str, Option<String>) {
    match entry.split_once('#') {
        Some((before, fragment)) => (before, decode_url_component(fragment).ok()),
        None => (entry, None),
    }
}

fn split_query(entry: &str) -> (&str, BTreeMap<String, String>) {
    match entry.split_once('?') {
        Some((before, query)) => (before, parse_query(query)),
        None => (entry, BTreeMap::new()),
    }
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                decode_url_component(key).unwrap_or_else(|_| key.to_owned()),
                decode_url_component(value).unwrap_or_else(|_| value.to_owned()),
            )
        })
        .collect()
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs().into_owned().collect()
}

fn decoded_fragment(url: &Url) -> Option<String> {
    url.fragment()
        .and_then(|fragment| decode_url_component(fragment).ok())
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

fn split_host_port(value: &str) -> Result<(String, u16), String> {
    let parsed = Url::parse(&format!("tcp://{value}"))
        .map_err(|_| "subscription endpoint host or port is invalid".to_owned())?;
    Ok((host_string(&parsed)?, port_from_url(&parsed)?))
}

fn host_string(url: &Url) -> Result<String, String> {
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "subscription endpoint host is missing".to_owned())
}

fn port_from_url(url: &Url) -> Result<u16, String> {
    url.port_or_known_default()
        .filter(|port| *port != 0)
        .ok_or_else(|| "subscription endpoint port is missing".to_owned())
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

fn normalize_vless_flow(flow: &str) -> Result<String, String> {
    match flow {
        "xtls-rprx-vision" => Ok(flow.to_owned()),
        other => Err(format!(
            "VLESS flow is unsupported: {}",
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
) -> Result<Option<Value>, String> {
    match kind {
        "" | "tcp" | "none" => Ok(None),
        "ws" => {
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
        "grpc" => Ok(Some(json!({
            "type": "grpc",
            "service_name": non_empty(service_name.unwrap_or_default())
                .ok_or_else(|| "gRPC subscriptions require a non-empty serviceName".to_owned())?,
        }))),
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

/// Renders an untrusted token for an error message without echoing arbitrary
/// subscription content: only short identifier-like tokens appear verbatim,
/// so secrets and node names can never leak through error strings.
fn sanitized_token(token: &str) -> String {
    const MAX_ECHOED_BYTES: usize = 32;
    if !token.is_empty()
        && token.len() <= MAX_ECHOED_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        token.to_owned()
    } else {
        "<non-identifier value>".to_owned()
    }
}

fn required_query(
    query: &BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    query
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} is missing"))
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
    use super::*;

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
            "vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision#Reality\nhy2://supersecret@hy2.example.com:8443?sni=hy2.example.com&upmbps=100&downmbps=200&obfs=salamander&obfs-password=mask#HY2",
        )
        .expect("vless and hy2 URIs");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
        assert_eq!(profile["outbounds"][0]["type"], "vless");
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
        assert_eq!(outbounds.len(), 5);

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
            ],
            "secrets keep exact source bytes, including leading zeros"
        );
        assert_eq!(
            imported.credentials[5].reference.kind(),
            CredentialKind::Hysteria2ObfsPassword
        );
        let stored = imported.profile.as_json();
        for secret in ["hunter2", "supersecret", "mask"] {
            assert!(
                !stored.contains(secret),
                "stored profile must not embed secrets"
            );
        }
    }

    #[test]
    fn clash_yaml_conversion_fails_closed_without_echoing_secrets() {
        let unsupported_type = "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n";
        let error =
            import_subscription_document(unsupported_type).expect_err("unsupported proxy type");
        assert!(error.contains("proxies[0]"), "{error}");
        assert!(error.contains("tuic"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let insecure = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    skip-cert-verify: true\n";
        let error = import_subscription_document(insecure).expect_err("skip-cert-verify");
        assert!(
            error.contains("disabling TLS certificate verification"),
            "{error}"
        );
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let unknown_key = "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    mystery-knob: 5\n";
        let error = import_subscription_document(unknown_key).expect_err("unknown key");
        assert!(error.contains("mystery-knob"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");

        let alias_bomb = "proxies: &a\n  - name: node\nmore: *a\n";
        let error = import_subscription_document(alias_bomb).expect_err("aliases rejected");
        assert!(error.contains("anchors are not supported"), "{error}");

        let missing_proxies = "mixed-port: 7890\n";
        let error = import_subscription_document(missing_proxies).expect_err("no proxies");
        assert!(error.contains("no proxies list"), "{error}");

        let port_hopping = "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    ports: 20000-30000\n";
        let error = import_subscription_document(port_hopping).expect_err("port hopping");
        assert!(error.contains("port hopping"), "{error}");
        assert!(!error.contains("TopSecretValue!"), "{error}");
    }

    #[test]
    fn rejects_unsupported_uri_schemes() {
        let error = import_subscription_document("tuic://token@example.com:443#TUIC")
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
