//! One converter per supported Clash proxy type.

use cfw_singbox_config::{CredentialKind, UtlsFingerprint};
use serde_json::{Value, json};

use super::transport_options::collect_transport;
use super::{
    OutboundCollector, ProxyFields, Socks5Network, YamlValue, canonical_uuid_credential,
    collect_tls, credential_ref_json, normalize_hysteria2_server_ports,
    normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_packet_encoding, normalize_vless_flow,
    normalize_vmess_security, parse_hysteria2_bbr_profile, parse_hysteria2_hop_interval_range,
    parse_vmess_alter_id, sanitized_token,
};

pub(super) fn convert_socks5(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    for (key, feature) in [
        ("tls", "SOCKS5 over TLS"),
        ("udp-over-tcp", "SOCKS5 UDP-over-TCP"),
    ] {
        if fields.take_bool(key)?.unwrap_or(false) {
            return Err(format!(
                "{} requires {feature}, which is not supported",
                fields.context()
            ));
        }
    }
    // Clash defaults UDP support off for SOCKS5. Consume this before the
    // generic tuning-key filter so the imported node never gains UDP access.
    let network = if fields.take_bool("udp")?.unwrap_or(false) {
        None
    } else {
        Some(Socks5Network::Tcp)
    };
    collector.socks5_outbound(
        name,
        fields.require_string("server")?,
        fields.require_port()?,
        fields.take_string("username")?,
        fields.take_string("password")?,
        network,
    )
}

pub(super) fn convert_http_proxy(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let port = fields.require_port()?;
    if fields.take_bool("udp")?.unwrap_or(false) {
        return Err("HTTP CONNECT proxies cannot carry UDP".into());
    }
    let username = fields.take_string("username")?;
    let password = fields.take_string("password")?;
    let tls = collect_tls(fields)?;
    // Mihomo's HTTP outbound has no client-fingerprint, so it never took the
    // global one either.
    let tls = tls.into_optional_json(&fields.context, &server, false, None)?;
    collector.http_proxy_outbound(name, server, port, username, password, tls)
}

pub(super) fn convert_wireguard(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let mut addresses = Vec::new();
    for (field, prefix) in [("ip", 32), ("ipv6", 128)] {
        if let Some(value) = fields.take_string(field)? {
            addresses.push(if value.contains('/') {
                value
            } else {
                format!("{value}/{prefix}")
            });
        }
    }
    super::wireguard::convert(
        collector,
        super::wireguard::WireGuardNode {
            name,
            server,
            server_port,
            local_addresses: addresses,
            private_key: fields.require_string("private-key")?,
            public_key: fields.require_string("public-key")?,
            pre_shared_key: fields.take_string("pre-shared-key")?,
            mtu: fields
                .take_string("mtu")?
                .map(|value| value.parse::<u16>())
                .transpose()
                .map_err(|_| "WireGuard MTU is invalid")?
                .unwrap_or(1420),
            keepalive: fields
                .take_string("persistent-keepalive")?
                .map(|value| value.parse::<u16>())
                .transpose()
                .map_err(|_| "WireGuard keepalive is invalid")?
                .unwrap_or(0),
        },
    )
}

pub(super) fn convert_shadowsocks(
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

pub(super) fn convert_vmess(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
    global_fingerprint: Option<UtlsFingerprint>,
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
    if let Some(tls) =
        tls.into_optional_json(&fields.context, &server, false, global_fingerprint)?
    {
        outbound["tls"] = tls;
    }
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    Ok(outbound)
}

pub(super) fn convert_vless(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
    global_fingerprint: Option<UtlsFingerprint>,
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
    if let Some(tls) = tls.into_optional_json(&fields.context, &server, true, global_fingerprint)? {
        outbound["tls"] = tls;
    }
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    Ok(outbound)
}

pub(super) fn convert_trojan(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
    global_fingerprint: Option<UtlsFingerprint>,
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
    let tls = tls.into_required_json(&fields.context, &server, global_fingerprint)?;
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

pub(super) fn convert_hysteria2(
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
    let hop_interval = fields
        .take_string("hop-interval")?
        .map(|value| parse_hysteria2_hop_interval_range(&value, "Clash Hysteria2 hop-interval"))
        .transpose()?;
    let bbr_profile = fields
        .take_string("bbr-profile")?
        .map(|value| parse_hysteria2_bbr_profile(&value, "Clash Hysteria2 bbr-profile"))
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
        Some(mode) if mode == "gecko" => {
            let password = fields.require_string("obfs-password")?;
            let reference = collector.push_secret(CredentialKind::Hysteria2ObfsPassword, password);
            let mut obfs = json!({
                "type": "gecko",
                "credential_ref": credential_ref_json(&reference),
            });
            for (key, field) in [
                ("obfs-min-packet-size", "min_packet_size"),
                ("obfs-max-packet-size", "max_packet_size"),
            ] {
                if let Some(value) = fields.take_string(key)? {
                    let size = value
                        .parse::<u16>()
                        .ok()
                        .filter(|size| size.to_string() == value)
                        .ok_or_else(|| {
                            format!("{}.{key} must be a canonical packet size", fields.context())
                        })?;
                    obfs[field] = json!(size);
                }
            }
            Some(obfs)
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
    if let Some((minimum, maximum)) = hop_interval {
        outbound["hop_interval_seconds"] = json!(minimum);
        if let Some(maximum) = maximum {
            outbound["hop_interval_max_seconds"] = json!(maximum);
        }
    }
    if let Some(profile) = bbr_profile {
        outbound["bbr_profile"] = json!(profile);
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

pub(super) fn convert_anytls(
    collector: &mut OutboundCollector,
    fields: &mut ProxyFields,
    name: String,
    global_fingerprint: Option<UtlsFingerprint>,
) -> Result<Value, String> {
    let server = fields.require_string("server")?;
    let server_port = fields.require_port()?;
    let reference = collector.push_secret(
        CredentialKind::AnyTlsPassword,
        fields.require_string("password")?,
    );
    let tls = collect_tls(fields)?.into_anytls_required_json(
        &fields.context,
        &server,
        global_fingerprint,
    )?;
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

pub(super) fn convert_tuic(
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

/// Parses Clash Hysteria2 bandwidth values: a positive integer with an
/// optional case-insensitive `Mbps` suffix.
pub(super) fn parse_bandwidth_mbps(value: &str, context: &str, key: &str) -> Result<u32, String> {
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
