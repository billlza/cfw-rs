//! Clash/Mihomo YAML subscription conversion.
//!
//! Airport subscription endpoints negotiate on the `User-Agent` header and
//! answer Clash Meta clients with a YAML document whose `proxies` list carries
//! the modern protocol set (VLESS/Reality, Hysteria2, and the classic types).
//! This module converts exactly that list into the closed typed profile
//! schema; it is an import syntax, not a second configuration system.
//!
//! Conversion contract:
//!
//! - Only `proxies` is read. Listeners, DNS, rules, and `proxy-groups` are
//!   owned by the app's deterministic projection and are deliberately not
//!   converted; the other top-level sections of a Clash document are part of
//!   its envelope and carry no per-node state.
//! - Every key of a proxy entry is either mapped onto the typed schema,
//!   listed in [`IGNORED_TUNING_KEYS`] (local socket tuning with no effect on
//!   destination, trust, or framing), or fails the import with the key name.
//! - Requests this app refuses to honour fail closed instead of being
//!   silently dropped: `skip-cert-verify: true`, Shadowsocks plugins,
//!   `udp-over-tcp`, `smux`, proxy chaining via `dialer-proxy`, TLS
//!   certificate pinning via `fingerprint`, and every proxy type outside the
//!   closed schema. Hysteria2 port hopping accepts only canonical
//!   canonical non-overlapping port sets and one fixed 1..=3600 second hop
//!   interval are normalized into the pinned sing-box 1.13 fields; Mihomo's
//!   newer randomized interval range remains rejected.
//! - `servername`/`sni`, `alpn`, and `client-fingerprint` are only mapped
//!   while TLS is enabled; without TLS they have no wire effect in Clash
//!   either, so dropping them preserves semantics.
//! - Node secrets keep their exact source bytes (the YAML loader never
//!   applies number resolution to them) and leave this module only as
//!   credential-vault entries, never inside the stored profile.

use cfw_singbox_config::{CredentialKind, MAX_OUTBOUNDS};
use serde_json::{Value, json};

use super::yaml::{YamlMapping, YamlScalar, YamlValue, load_single_document};
use super::{
    ImportedSubscription, OutboundCollector, build_tls_parts, canonical_uuid_credential,
    credential_ref_json, normalize_hysteria2_server_ports,
    normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_http_method, normalize_v2ray_packet_encoding,
    normalize_vless_flow, normalize_vmess_security, parse_hysteria2_hop_interval_seconds,
    parse_utls, parse_vmess_alter_id, sanitized_token, tls_json, transport_from_parts,
};

/// Proxy-entry keys that only tune local socket behaviour. They change
/// neither the destination, nor credentials, nor TLS trust, nor framing, so
/// the projection's own defaults apply and the keys are accepted and ignored.
const IGNORED_TUNING_KEYS: &[&str] = &[
    "udp",
    "tfo",
    "mptcp",
    "ip-version",
    "interface-name",
    "routing-mark",
];

/// Converts one Clash/Mihomo YAML document into a validated subscription.
pub(super) fn import_clash_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let root = load_single_document(body)?;
    let YamlValue::Mapping(root) = root else {
        return Err("Clash subscription document must be a YAML mapping".to_owned());
    };
    let proxies = root
        .into_entries()
        .into_iter()
        .find_map(|(key, value)| (key == "proxies").then_some(value))
        .ok_or_else(|| "Clash subscription document has no proxies list".to_owned())?;
    let YamlValue::Sequence(proxies) = proxies else {
        return Err("Clash proxies must be a YAML sequence".to_owned());
    };
    if proxies.is_empty() {
        return Err("Clash subscription document contains no proxies".to_owned());
    }
    if proxies.len() > MAX_OUTBOUNDS {
        return Err(format!(
            "Clash subscription document has {} proxies; at most {MAX_OUTBOUNDS} are supported",
            proxies.len()
        ));
    }

    for (index, proxy) in proxies.into_iter().enumerate() {
        let context = format!("proxies[{index}]");
        let YamlValue::Mapping(proxy) = proxy else {
            return Err(format!("{context} must be a YAML mapping"));
        };
        let outbound = convert_proxy(&mut collector, ProxyFields::new(proxy, context))?;
        collector.outbounds.push(outbound);
    }
    collector.into_subscription()
}

fn convert_proxy(
    collector: &mut OutboundCollector,
    mut fields: ProxyFields,
) -> Result<Value, String> {
    let kind = fields.require_string("type")?;
    let name = fields.require_string("name")?;
    enforce_common_guards(&mut fields)?;
    let outbound = match kind.as_str() {
        "ss" => convert_shadowsocks(collector, &mut fields, name)?,
        "vmess" => convert_vmess(collector, &mut fields, name)?,
        "vless" => convert_vless(collector, &mut fields, name)?,
        "trojan" => convert_trojan(collector, &mut fields, name)?,
        "hysteria2" => convert_hysteria2(collector, &mut fields, name)?,
        "anytls" => convert_anytls(collector, &mut fields, name)?,
        "tuic" => convert_tuic(collector, &mut fields, name)?,
        other => {
            return Err(format!(
                "{} has a proxy type outside the supported set (ss, vmess, vless, trojan, hysteria2, anytls, tuic): {}",
                fields.context(),
                sanitized_token(other)
            ));
        }
    };
    fields.reject_leftovers()?;
    Ok(outbound)
}

/// Fails closed on requests the closed schema cannot honour, independent of
/// the proxy type.
fn enforce_common_guards(fields: &mut ProxyFields) -> Result<(), String> {
    if fields.take_bool("skip-cert-verify")?.unwrap_or(false) {
        return Err(format!(
            "{} requires disabling TLS certificate verification, which this app refuses",
            fields.context()
        ));
    }
    for (key, reason) in [
        ("dialer-proxy", "proxy chaining"),
        ("smux", "stream multiplexing"),
        ("fingerprint", "TLS certificate pinning"),
    ] {
        if fields.take(key).is_some() {
            return Err(format!(
                "{} uses {reason} ({key}), which is not supported",
                fields.context()
            ));
        }
    }
    Ok(())
}

fn convert_shadowsocks(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    if fields.take("plugin").is_some() || fields.take("plugin-opts").is_some() {
        return Err(format!(
            "{} uses a Shadowsocks plugin, which is unsupported in subscription imports",
            fields.context()
        ));
    }
    if fields.take_bool("udp-over-tcp")?.unwrap_or(false) {
        return Err(format!(
            "{} requires udp-over-tcp, which is not supported",
            fields.context()
        ));
    }
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let source_method = fields.require_string("cipher")?;
    let password = fields.require_string("password")?;
    let method = normalize_shadowsocks_method_and_password(&source_method, &password)?;
    let reference = collector.push_secret(CredentialKind::ShadowsocksPassword, password);
    let tag = collector.unique_tag(name)?;
    Ok(json!({
        "type": "shadowsocks",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "method": method,
        "credential_ref": credential_ref_json(&reference),
    }))
}

fn convert_vmess(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    for (key, feature) in [
        ("global-padding", "VMess global padding"),
        ("authenticated-length", "VMess authenticated length framing"),
    ] {
        if fields.take_bool(key)?.unwrap_or(false) {
            return Err(format!(
                "{} enables {feature}, which is not represented by the pinned runtime schema",
                fields.context()
            ));
        }
    }
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let alter_id = match fields.take("alterId") {
        None => 0,
        Some(YamlValue::Scalar(value)) if !value.is_null() => {
            parse_vmess_alter_id(value.text(), &format!("{}.alterId", fields.context()))?
        }
        Some(YamlValue::Scalar(_)) => {
            return Err(format!(
                "{}.alterId must be a non-negative decimal integer",
                fields.context()
            ));
        }
        Some(_) => {
            return Err(format!(
                "{}.alterId must be a scalar value",
                fields.context()
            ));
        }
    };
    let security = match fields.take_string("cipher")? {
        None => None,
        Some(cipher) => normalize_vmess_security(&cipher)?,
    };
    let packet_encoding = fields
        .take_string("packet-encoding")?
        .map(|value| normalize_v2ray_packet_encoding(&value, "VMess packet encoding"))
        .transpose()?;
    let reference = collector.push_secret(
        CredentialKind::VmessUuid,
        canonical_uuid_credential(fields.require_string("uuid")?, "Clash VMess UUID")?,
    );
    let tls = collect_tls(fields)?;
    let transport = collect_transport(fields)?;
    let tag = collector.unique_tag(name)?;
    let mut outbound = json!({
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "credential_ref": credential_ref_json(&reference),
    });
    if alter_id != 0 {
        outbound["alter_id"] = Value::from(alter_id);
    }
    if let Some(security) = security {
        outbound["security"] = Value::String(security);
    }
    if let Some(packet_encoding) = packet_encoding {
        outbound["packet_encoding"] = Value::String(packet_encoding);
    }
    if let Some(tls) = tls.into_optional_json(&fields.context, &server, false)? {
        outbound["tls"] = tls;
    }
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    Ok(outbound)
}

fn convert_vless(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let flow = match fields.take_string("flow")? {
        None => None,
        Some(flow) if flow.is_empty() => None,
        Some(flow) => Some(normalize_vless_flow(&flow)?),
    };
    match fields.take_string("encryption")? {
        None => {}
        Some(value) if value.is_empty() || value.eq_ignore_ascii_case("none") => {}
        Some(value) => {
            return Err(format!(
                "{} uses unsupported VLESS encryption: {}",
                fields.context(),
                sanitized_token(&value)
            ));
        }
    }
    let packet_encoding = fields
        .take_string("packet-encoding")?
        .map(|value| normalize_v2ray_packet_encoding(&value, "VLESS packet encoding"))
        .transpose()?;
    let reference = collector.push_secret(
        CredentialKind::VlessUuid,
        canonical_uuid_credential(fields.require_string("uuid")?, "Clash VLESS UUID")?,
    );
    let tls = collect_tls(fields)?;
    let transport = collect_transport(fields)?;
    let tag = collector.unique_tag(name)?;
    let mut outbound = json!({
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "credential_ref": credential_ref_json(&reference),
    });
    if let Some(flow) = flow {
        outbound["flow"] = Value::String(flow);
    }
    if let Some(packet_encoding) = packet_encoding {
        outbound["packet_encoding"] = Value::String(packet_encoding);
    }
    if let Some(tls) = tls.into_optional_json(&fields.context, &server, true)? {
        outbound["tls"] = tls;
    }
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    Ok(outbound)
}

fn convert_trojan(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let reference = collector.push_secret(
        CredentialKind::TrojanPassword,
        fields.require_string("password")?,
    );
    let tls = collect_tls(fields)?;
    let transport = collect_transport(fields)?;
    let tag = collector.unique_tag(name)?;
    let tls = tls.into_required_json(&fields.context, &server)?;
    let mut outbound = json!({
        "type": "trojan",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "credential_ref": credential_ref_json(&reference),
        "tls": tls,
    });
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    Ok(outbound)
}

fn convert_hysteria2(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let ports = match (fields.take_string("ports")?, fields.take_string("mport")?) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "{} repeats Hysteria2 port hopping with ports and mport",
                fields.context()
            ));
        }
        (Some(value), None) | (None, Some(value)) => Some(normalize_hysteria2_server_ports(
            &value,
            "Clash Hysteria2 ports",
        )?),
        (None, None) => None,
    };
    let hop_interval_seconds = fields
        .take_string("hop-interval")?
        .map(|value| parse_hysteria2_hop_interval_seconds(&value, "Clash Hysteria2 hop-interval"))
        .transpose()?;
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let reference = collector.push_secret(
        CredentialKind::Hysteria2Password,
        fields.require_string("password")?,
    );
    let up_mbps = fields
        .take_string("up")?
        .map(|value| parse_bandwidth_mbps(&value, &fields.context, "up"))
        .transpose()?;
    let down_mbps = fields
        .take_string("down")?
        .map(|value| parse_bandwidth_mbps(&value, &fields.context, "down"))
        .transpose()?;
    let obfs = match fields.take_string("obfs")? {
        None => None,
        Some(mode) if mode.is_empty() => None,
        Some(mode) if mode == "salamander" => {
            let password = fields.require_string("obfs-password")?;
            let reference = collector.push_secret(CredentialKind::Hysteria2ObfsPassword, password);
            Some(json!({
                "type": "salamander",
                "credential_ref": credential_ref_json(&reference),
            }))
        }
        Some(other) => {
            return Err(format!(
                "Hysteria2 obfs mode is unsupported: {}",
                sanitized_token(&other)
            ));
        }
    };
    let tls = collect_tls(fields)?;
    let tag = collector.unique_tag(name)?;
    let tls = tls.into_quic_required_json(&fields.context, &server)?;
    let mut outbound = json!({
        "type": "hysteria2",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "credential_ref": credential_ref_json(&reference),
        "tls": tls,
    });
    if let Some(ports) = ports {
        outbound["server_ports"] = json!(ports);
    }
    if let Some(seconds) = hop_interval_seconds {
        outbound["hop_interval_seconds"] = json!(seconds);
    }
    if let Some(up_mbps) = up_mbps {
        outbound["up_mbps"] = json!(up_mbps);
    }
    if let Some(down_mbps) = down_mbps {
        outbound["down_mbps"] = json!(down_mbps);
    }
    if let Some(obfs) = obfs {
        outbound["obfs"] = obfs;
    }
    Ok(outbound)
}

fn convert_anytls(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let reference = collector.push_secret(
        CredentialKind::AnyTlsPassword,
        fields.require_string("password")?,
    );
    let tls = collect_tls(fields)?.into_anytls_required_json(&fields.context, &server)?;
    let tag = collector.unique_tag(name)?;
    Ok(json!({
        "type": "anytls",
        "tag": tag,
        "server": server,
        "server_port": server_port,
        "credential_ref": credential_ref_json(&reference),
        "tls": tls,
    }))
}

fn convert_tuic(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    for (key, feature) in [
        ("reduce-rtt", "TUIC 0-RTT handshake"),
        ("udp-over-stream", "TUIC UDP-over-stream"),
        ("disable-sni", "TUIC disabled SNI"),
    ] {
        if fields.take_bool(key)?.unwrap_or(false) {
            return Err(format!(
                "{} requires {feature}, which is unsupported",
                fields.context()
            ));
        }
    }
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let uuid_reference = collector.push_secret(
        CredentialKind::TuicUuid,
        canonical_uuid_credential(fields.require_string("uuid")?, "Clash TUIC UUID")?,
    );
    let password_reference = collector.push_secret(
        CredentialKind::TuicPassword,
        fields.require_string("password")?,
    );
    let congestion_control = fields
        .take_string("congestion-controller")?
        .map(|value| normalize_tuic_congestion_control(&value))
        .transpose()?;
    let udp_relay_mode = fields
        .take_string("udp-relay-mode")?
        .map(|value| normalize_tuic_udp_relay_mode(&value))
        .transpose()?;
    let tls = collect_tls(fields)?.into_quic_required_json(&fields.context, &server)?;
    let tag = collector.unique_tag(name)?;
    let mut outbound = json!({
        "type": "tuic",
        "tag": tag,
        "server": server,
        "server_port": server_port,
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

/// TLS-related keys shared by the TLS-capable proxy types.
struct TlsFields {
    enabled_flag: Option<bool>,
    server_name: Option<String>,
    alpn: Vec<String>,
    client_fingerprint: Option<String>,
    reality: Option<(String, String)>,
}

fn collect_tls(fields: &mut ProxyFields) -> Result<TlsFields, String> {
    let enabled_flag = fields.take_bool("tls")?;
    let servername = fields
        .take_string("servername")?
        .filter(|value| !value.is_empty());
    let sni = fields.take_string("sni")?.filter(|value| !value.is_empty());
    let server_name = match (servername, sni) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!(
                "{} declares conflicting servername and sni values",
                fields.context()
            ));
        }
        (a, b) => a.or(b),
    };
    let alpn = fields.take_string_list("alpn")?.unwrap_or_default();
    let client_fingerprint = fields.take_string("client-fingerprint")?;
    let reality = match fields.take("reality-opts") {
        None => None,
        Some(value) => {
            let mut reality = ProxyFields::from_nested(value, fields, "reality-opts")?;
            let public_key = reality.require_string("public-key")?;
            let short_id = reality.take_string("short-id")?.unwrap_or_default();
            reality.reject_leftovers()?;
            Some((public_key, short_id))
        }
    };
    Ok(TlsFields {
        enabled_flag,
        server_name,
        alpn,
        client_fingerprint,
        reality,
    })
}

impl TlsFields {
    /// TLS object for proxy types where TLS is optional (vmess, vless).
    fn into_optional_json(
        self,
        context: &str,
        server: &str,
        reality_allowed: bool,
    ) -> Result<Option<Value>, String> {
        if self.reality.is_some() {
            if !reality_allowed {
                return Err(format!("{context} does not support Reality"));
            }
            if self.enabled_flag != Some(true) {
                return Err(format!("{context} declares reality-opts without tls: true"));
            }
        }
        if self.enabled_flag != Some(true) {
            // Without TLS, servername/alpn/client-fingerprint have no wire
            // effect in Clash either; dropping them preserves semantics.
            return Ok(None);
        }
        self.build(server).map(Some)
    }

    /// TLS object for always-TLS stream protocols that allow uTLS but not Reality.
    fn into_required_json(self, context: &str, server: &str) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, false)
    }

    fn into_quic_required_json(self, context: &str, server: &str) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, false, false)
    }

    fn into_anytls_required_json(self, context: &str, server: &str) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, true)
    }

    fn into_required_json_with_capabilities(
        self,
        context: &str,
        server: &str,
        utls_allowed: bool,
        reality_allowed: bool,
    ) -> Result<Value, String> {
        if self.reality.is_some() && !reality_allowed {
            return Err(format!("{context} does not support Reality"));
        }
        if self.client_fingerprint.is_some() && !utls_allowed {
            return Err(format!("{context} does not support uTLS"));
        }
        if self.enabled_flag == Some(false) {
            return Err(format!(
                "{context} declares tls: false for an always-TLS proxy type"
            ));
        }
        self.build(server)
    }

    fn build(self, server: &str) -> Result<Value, String> {
        let utls = match self.client_fingerprint.as_deref() {
            None => None,
            Some(fingerprint) => parse_utls(fingerprint)?,
        };
        let reality = self.reality.map(|(public_key, short_id)| {
            json!({
                "enabled": true,
                "public_key": public_key,
                "short_id": short_id,
            })
        });
        Ok(tls_json(build_tls_parts(
            true,
            self.server_name.unwrap_or_else(|| server.to_owned()),
            self.alpn,
            utls,
            reality,
        )))
    }
}

/// Maps `network` plus its option mapping onto the typed transport shape.
fn collect_transport(fields: &mut ProxyFields) -> Result<Option<Value>, String> {
    let network = fields.take_string("network")?.unwrap_or_default();
    let ws_opts = fields.take("ws-opts");
    let grpc_opts = fields.take("grpc-opts");
    let h2_opts = fields.take("h2-opts");
    let http_opts = fields.take("http-opts");
    let http_upgrade_opts = fields.take("http-upgrade-opts");
    if ws_opts.is_some() && network != "ws" {
        return Err(format!(
            "{} declares ws-opts without network: ws",
            fields.context()
        ));
    }
    if grpc_opts.is_some() && network != "grpc" {
        return Err(format!(
            "{} declares grpc-opts without network: grpc",
            fields.context()
        ));
    }
    if h2_opts.is_some() && !matches!(network.as_str(), "h2" | "http") {
        return Err(format!(
            "{} declares h2-opts without network: h2",
            fields.context()
        ));
    }
    if http_opts.is_some() && network != "http" {
        return Err(format!(
            "{} declares http-opts without network: http",
            fields.context()
        ));
    }
    if http_upgrade_opts.is_some() && !matches!(network.as_str(), "httpupgrade" | "http-upgrade") {
        return Err(format!(
            "{} declares http-upgrade-opts without network: httpupgrade",
            fields.context()
        ));
    }
    match network.as_str() {
        "" | "tcp" => Ok(None),
        "h2" => {
            let (path, host) = match h2_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "h2-opts")?;
                    let path = take_single_transport_value(&mut options, "path")?;
                    let host = options
                        .take_string_or_list("host")?
                        .map(|hosts| hosts.join(","));
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("http", path, host, None, None)
        }
        "http" => {
            if http_opts.is_some() && h2_opts.is_some() {
                return Err(format!(
                    "{} declares both http-opts and h2-opts for network: http",
                    fields.context()
                ));
            }
            let (path, host, method) = if let Some(value) = http_opts {
                let mut options = ProxyFields::from_nested(value, fields, "http-opts")?;
                let path = take_single_transport_value(&mut options, "path")?;
                let method = options
                    .take_string("method")?
                    .filter(|value| !value.is_empty())
                    .map(|value| normalize_v2ray_http_method(&value, "Mihomo HTTP method"))
                    .transpose()?
                    .or_else(|| Some("GET".to_owned()));
                let host = match options.take("headers") {
                    None => None,
                    Some(headers) => {
                        let mut headers = ProxyFields::from_nested(headers, &options, "headers")?;
                        let upper = headers.take_string_or_list("Host")?;
                        let lower = headers.take_string_or_list("host")?;
                        let host = match (upper, lower) {
                            (Some(a), Some(b)) if a != b => {
                                return Err(format!(
                                    "{} declares conflicting Host header values",
                                    headers.context()
                                ));
                            }
                            (a, b) => a.or(b).map(|values| values.join(",")),
                        };
                        headers.reject_leftovers()?;
                        host
                    }
                };
                options.reject_leftovers()?;
                (path, host, method)
            } else {
                let (path, host) = match h2_opts {
                    None => (None, None),
                    Some(value) => {
                        let mut options = ProxyFields::from_nested(value, fields, "h2-opts")?;
                        let path = take_single_transport_value(&mut options, "path")?;
                        let host = options
                            .take_string_or_list("host")?
                            .map(|hosts| hosts.join(","));
                        options.reject_leftovers()?;
                        (path, host)
                    }
                };
                (path, host, Some("GET".to_owned()))
            };
            transport_from_parts("http", path, host, None, method)
        }
        "ws" => {
            let (path, host) = match ws_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "ws-opts")?;
                    let path = options.take_string("path")?;
                    let host = match options.take("headers") {
                        None => None,
                        Some(headers) => {
                            let mut headers =
                                ProxyFields::from_nested(headers, &options, "headers")?;
                            let host = match (
                                headers.take_string("Host")?,
                                headers.take_string("host")?,
                            ) {
                                (Some(a), Some(b)) if a != b => {
                                    return Err(format!(
                                        "{} declares conflicting Host header values",
                                        headers.context()
                                    ));
                                }
                                (a, b) => a.or(b),
                            };
                            headers.reject_leftovers()?;
                            host
                        }
                    };
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("ws", path, host, None, None)
        }
        "grpc" => {
            let service_name = match grpc_opts {
                None => None,
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "grpc-opts")?;
                    let service_name = options.take_string("grpc-service-name")?;
                    options.reject_leftovers()?;
                    service_name
                }
            };
            transport_from_parts("grpc", None, None, service_name, None)
        }
        "quic" => transport_from_parts("quic", None, None, None, None),
        "httpupgrade" | "http-upgrade" => {
            let (path, host) = match http_upgrade_opts {
                None => (None, None),
                Some(value) => {
                    let mut options = ProxyFields::from_nested(value, fields, "http-upgrade-opts")?;
                    let path = options.take_string("path")?;
                    let host = options.take_string("host")?;
                    options.reject_leftovers()?;
                    (path, host)
                }
            };
            transport_from_parts("httpupgrade", path, host, None, None)
        }
        other => transport_from_parts(other, None, None, None, None),
    }
}

fn take_single_transport_value(
    fields: &mut ProxyFields,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(values) = fields.take_string_or_list(key)? else {
        return Ok(None);
    };
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(format!(
            "{}.{key} declares multiple alternatives that cannot be projected deterministically",
            fields.context()
        )),
    }
}

/// Parses Clash Hysteria2 bandwidth values: a positive integer with an
/// optional case-insensitive `Mbps` suffix.
fn parse_bandwidth_mbps(value: &str, context: &str, key: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    let digits = if bytes.len() >= 4 && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b"mbps") {
        trimmed[..trimmed.len() - 4].trim_end()
    } else {
        trimmed
    };
    digits
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| format!("{context} {key} must be a positive integer number of Mbps"))
}

/// One proxy entry whose keys are consumed exactly once. Whatever is left
/// after conversion is either a documented tuning key or an error.
struct ProxyFields {
    context: String,
    entries: Vec<(String, YamlValue)>,
}

impl ProxyFields {
    fn new(mapping: YamlMapping, context: String) -> Self {
        Self {
            context,
            entries: mapping.into_entries(),
        }
    }

    /// Wraps a nested option mapping (`ws-opts`, `reality-opts`, ...).
    fn from_nested(value: YamlValue, parent: &ProxyFields, key: &str) -> Result<Self, String> {
        let YamlValue::Mapping(mapping) = value else {
            return Err(format!("{}.{key} must be a YAML mapping", parent.context()));
        };
        Ok(Self::new(mapping, format!("{}.{key}", parent.context)))
    }

    fn context(&self) -> &str {
        &self.context
    }

    fn take(&mut self, key: &str) -> Option<YamlValue> {
        let index = self.entries.iter().position(|(name, _)| name == key)?;
        Some(self.entries.remove(index).1)
    }

    fn take_scalar(&mut self, key: &str) -> Result<Option<YamlScalar>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Scalar(scalar)) => {
                if scalar.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(scalar))
                }
            }
            Some(_) => Err(format!("{}.{key} must be a scalar value", self.context)),
        }
    }

    /// Takes a key as text, preserving the exact source bytes.
    fn take_string(&mut self, key: &str) -> Result<Option<String>, String> {
        Ok(self
            .take_scalar(key)?
            .map(|scalar| scalar.text().to_owned()))
    }

    fn require_string(&mut self, key: &str) -> Result<String, String> {
        self.take_string(key)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{}.{key} is missing", self.context))
    }

    /// Takes a key as a YAML boolean. Quoted strings are not booleans.
    fn take_bool(&mut self, key: &str) -> Result<Option<bool>, String> {
        match self.take_scalar(key)? {
            None => Ok(None),
            Some(scalar) => scalar
                .as_bool()
                .map(Some)
                .ok_or_else(|| format!("{}.{key} must be a YAML boolean", self.context)),
        }
    }

    fn require_port(&mut self) -> Result<u16, String> {
        let text = self.require_string("port")?;
        text.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("{}.port is not a valid port", self.context))
    }

    fn take_string_list(&mut self, key: &str) -> Result<Option<Vec<String>>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Sequence(items)) => items
                .into_iter()
                .map(|item| match item {
                    YamlValue::Scalar(scalar) if !scalar.is_null() => Ok(scalar.text().to_owned()),
                    _ => Err(format!(
                        "{}.{key} entries must be scalar values",
                        self.context
                    )),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(format!("{}.{key} must be a YAML sequence", self.context)),
        }
    }

    fn take_string_or_list(&mut self, key: &str) -> Result<Option<Vec<String>>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Scalar(scalar)) if !scalar.is_null() => {
                Ok(Some(vec![scalar.text().to_owned()]))
            }
            Some(YamlValue::Scalar(_)) => Ok(None),
            Some(YamlValue::Sequence(items)) => items
                .into_iter()
                .map(|item| match item {
                    YamlValue::Scalar(scalar) if !scalar.is_null() => Ok(scalar.text().to_owned()),
                    _ => Err(format!(
                        "{}.{key} entries must be scalar values",
                        self.context
                    )),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(format!(
                "{}.{key} must be a scalar or YAML sequence",
                self.context
            )),
        }
    }

    /// Accepts documented tuning keys and fails the import on anything else.
    fn reject_leftovers(&mut self) -> Result<(), String> {
        self.entries
            .retain(|(key, _)| !IGNORED_TUNING_KEYS.contains(&key.as_str()));
        if self.entries.is_empty() {
            return Ok(());
        }
        let keys = self
            .entries
            .iter()
            .map(|(key, _)| sanitized_token(key))
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!("{} has unsupported keys: {keys}", self.context))
    }
}
