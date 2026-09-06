//! Restricted adapter for upstream sing-box node-list JSON.
//!
//! This is deliberately not a full sing-box configuration loader. Only one
//! root `outbounds` array is accepted, every source field is typed, inline
//! secrets are extracted into the vault batch, and the result is revalidated
//! as the application's closed secret-free profile.

use std::collections::BTreeMap;

use cfw_singbox_config::CredentialKind;
use serde::Deserialize;
use serde_json::{Value, json};

use super::socks5::Network as Socks5Network;
use super::{
    ImportedSubscription, OutboundCollector, build_tls_parts, canonical_uuid_credential,
    credential_ref_json, normalize_hysteria2_server_ports,
    normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_packet_encoding, normalize_vless_flow,
    normalize_vmess_alter_id, normalize_vmess_security, parse_hysteria2_hop_interval_seconds,
    parse_utls, tls_json,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDocument {
    outbounds: Vec<SourceOutbound>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SourceOutbound {
    Socks {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        network: Option<Socks5Network>,
        #[serde(default)]
        udp_over_tcp: bool,
    },
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        method: String,
        password: String,
        #[serde(default)]
        plugin: String,
        #[serde(default)]
        plugin_opts: String,
        #[serde(default)]
        network: Option<Value>,
        #[serde(default)]
        udp_over_tcp: Option<Value>,
        #[serde(default)]
        multiplex: Option<Value>,
    },
    Vmess {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        #[serde(default)]
        security: String,
        #[serde(default)]
        alter_id: u64,
        #[serde(default)]
        global_padding: bool,
        #[serde(default)]
        authenticated_length: bool,
        #[serde(default)]
        network: Option<Value>,
        #[serde(default)]
        packet_encoding: Option<String>,
        #[serde(default)]
        multiplex: Option<Value>,
        #[serde(default)]
        tls: Option<SourceTls>,
        #[serde(default)]
        transport: Option<SourceTransport>,
    },
    Vless {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        #[serde(default)]
        flow: String,
        #[serde(default)]
        network: Option<Value>,
        #[serde(default)]
        packet_encoding: Option<String>,
        #[serde(default)]
        multiplex: Option<Value>,
        #[serde(default)]
        tls: Option<SourceTls>,
        #[serde(default)]
        transport: Option<SourceTransport>,
    },
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        #[serde(default)]
        network: Option<Value>,
        #[serde(default)]
        multiplex: Option<Value>,
        tls: SourceTls,
        #[serde(default)]
        transport: Option<SourceTransport>,
    },
    Hysteria2 {
        tag: String,
        server: String,
        #[serde(default)]
        server_port: Option<u16>,
        password: String,
        tls: SourceTls,
        #[serde(default)]
        up_mbps: Option<u32>,
        #[serde(default)]
        down_mbps: Option<u32>,
        #[serde(default)]
        obfs: Option<SourceHysteria2Obfs>,
        #[serde(default)]
        server_ports: Option<StringList>,
        #[serde(default)]
        hop_interval: Option<String>,
        #[serde(default)]
        network: Option<Value>,
        #[serde(default)]
        brutal_debug: bool,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: SourceTls,
        #[serde(default)]
        idle_session_check_interval: Option<Value>,
        #[serde(default)]
        idle_session_timeout: Option<Value>,
        #[serde(default)]
        min_idle_session: Option<i64>,
    },
    Tuic {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        password: String,
        tls: SourceTls,
        #[serde(default)]
        congestion_control: Option<String>,
        #[serde(default)]
        udp_relay_mode: Option<String>,
        #[serde(default)]
        udp_over_stream: bool,
        #[serde(default)]
        zero_rtt_handshake: bool,
        #[serde(default)]
        heartbeat: Option<Value>,
        #[serde(default)]
        network: Option<Value>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceHysteria2Obfs {
    #[serde(rename = "type")]
    kind: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    disable_sni: bool,
    #[serde(default)]
    alpn: StringList,
    #[serde(default)]
    min_version: String,
    #[serde(default)]
    utls: Option<SourceUtls>,
    #[serde(default)]
    reality: Option<SourceReality>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceUtls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceReality {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    short_id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum StringList {
    #[default]
    Empty,
    One(String),
    Many(Vec<String>),
}

impl StringList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::Empty => Vec::new(),
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum SourceTransport {
    #[serde(rename = "http")]
    Http {
        #[serde(default = "default_path")]
        path: String,
        #[serde(default)]
        host: StringList,
        #[serde(default)]
        method: String,
        #[serde(default)]
        headers: BTreeMap<String, StringList>,
    },
    #[serde(rename = "ws")]
    Websocket {
        #[serde(default = "default_path")]
        path: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
    #[serde(rename = "grpc")]
    Grpc { service_name: String },
    #[serde(rename = "quic")]
    Quic,
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        #[serde(default = "default_path")]
        path: String,
        #[serde(default)]
        host: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
}

pub(super) fn import_sing_box_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let source: SourceDocument = serde_json::from_str(body).map_err(|_| {
        "sing-box source JSON does not match the supported node-list schema".to_owned()
    })?;
    if source.outbounds.is_empty() {
        return Err("sing-box source JSON contains no outbounds".into());
    }
    if source.outbounds.len() > cfw_singbox_config::MAX_OUTBOUNDS {
        return Err(format!(
            "sing-box source JSON has more than {} outbounds",
            cfw_singbox_config::MAX_OUTBOUNDS
        ));
    }
    for outbound in source.outbounds {
        let outbound = convert_outbound(&mut collector, outbound)?;
        collector.outbounds.push(outbound);
    }
    collector.into_subscription()
}

fn convert_outbound(
    collector: &mut OutboundCollector,
    source: SourceOutbound,
) -> Result<Value, String> {
    match source {
        SourceOutbound::Socks {
            tag,
            server,
            server_port,
            version,
            username,
            password,
            network,
            udp_over_tcp,
        } => {
            if version.as_deref().is_some_and(|version| version != "5") {
                return Err("sing-box SOCKS import requires protocol version 5".into());
            }
            if udp_over_tcp {
                return Err("sing-box SOCKS5 UDP-over-TCP is unsupported".into());
            }
            collector.socks5_outbound(tag, server, server_port, username, password, network)
        }
        SourceOutbound::Shadowsocks {
            tag,
            server,
            server_port,
            method,
            password,
            plugin,
            plugin_opts,
            network,
            udp_over_tcp,
            multiplex,
        } => {
            reject_present(network, "Shadowsocks network restriction")?;
            reject_present(udp_over_tcp, "Shadowsocks UDP-over-TCP")?;
            reject_present(multiplex, "Shadowsocks multiplexing")?;
            if !plugin.is_empty() || !plugin_opts.is_empty() {
                return Err("sing-box Shadowsocks plugins are unsupported".into());
            }
            let method = normalize_shadowsocks_method_and_password(&method, &password)?;
            let reference = collector.push_secret(CredentialKind::ShadowsocksPassword, password);
            Ok(json!({
                "type": "shadowsocks",
                "tag": collector.unique_tag(tag)?,
                "server": server,
                "server_port": server_port,
                "method": method,
                "credential_ref": credential_ref_json(&reference),
            }))
        }
        SourceOutbound::Vmess {
            tag,
            server,
            server_port,
            uuid,
            security,
            alter_id,
            global_padding,
            authenticated_length,
            network,
            packet_encoding,
            multiplex,
            tls,
            transport,
        } => {
            reject_present(network, "VMess network restriction")?;
            reject_present(multiplex, "VMess multiplexing")?;
            if global_padding || authenticated_length {
                return Err("sing-box VMess padding modes are unsupported".into());
            }
            let reference = collector.push_secret(
                CredentialKind::VmessUuid,
                canonical_uuid_credential(uuid, "sing-box VMess UUID")?,
            );
            let mut outbound = remote(
                "vmess",
                collector.unique_tag(tag)?,
                server.clone(),
                server_port,
                "credential_ref",
                credential_ref_json(&reference),
            );
            let alter_id = normalize_vmess_alter_id(alter_id, "sing-box VMess alter_id")?;
            if alter_id != 0 {
                outbound["alter_id"] = json!(alter_id);
            }
            if let Some(security) = normalize_vmess_security(&security)? {
                outbound["security"] = Value::String(security);
            }
            insert_packet_encoding(&mut outbound, packet_encoding, "VMess")?;
            insert_optional_tls(&mut outbound, tls, &server)?;
            insert_transport(&mut outbound, transport)?;
            Ok(outbound)
        }
        SourceOutbound::Vless {
            tag,
            server,
            server_port,
            uuid,
            flow,
            network,
            packet_encoding,
            multiplex,
            tls,
            transport,
        } => {
            reject_present(network, "VLESS network restriction")?;
            reject_present(multiplex, "VLESS multiplexing")?;
            let reference = collector.push_secret(
                CredentialKind::VlessUuid,
                canonical_uuid_credential(uuid, "sing-box VLESS UUID")?,
            );
            let mut outbound = remote(
                "vless",
                collector.unique_tag(tag)?,
                server.clone(),
                server_port,
                "credential_ref",
                credential_ref_json(&reference),
            );
            if !flow.is_empty() {
                outbound["flow"] = Value::String(normalize_vless_flow(&flow)?);
            }
            insert_packet_encoding(&mut outbound, packet_encoding, "VLESS")?;
            insert_optional_tls(&mut outbound, tls, &server)?;
            insert_transport(&mut outbound, transport)?;
            Ok(outbound)
        }
        SourceOutbound::Trojan {
            tag,
            server,
            server_port,
            password,
            network,
            multiplex,
            tls,
            transport,
        } => {
            reject_present(network, "Trojan network restriction")?;
            reject_present(multiplex, "Trojan multiplexing")?;
            let reference = collector.push_secret(CredentialKind::TrojanPassword, password);
            let mut outbound = remote(
                "trojan",
                collector.unique_tag(tag)?,
                server.clone(),
                server_port,
                "credential_ref",
                credential_ref_json(&reference),
            );
            outbound["tls"] = source_tls(tls, &server, true)?;
            insert_transport(&mut outbound, transport)?;
            Ok(outbound)
        }
        SourceOutbound::Hysteria2 {
            tag,
            server,
            server_port,
            password,
            tls,
            up_mbps,
            down_mbps,
            obfs,
            server_ports,
            hop_interval,
            network,
            brutal_debug,
        } => {
            reject_present(network, "Hysteria2 network restriction")?;
            if brutal_debug {
                return Err("sing-box Hysteria2 brutal debug is unsupported".into());
            }
            let server_ports = server_ports
                .map(|values| {
                    normalize_hysteria2_server_ports(
                        &values.into_vec().join(","),
                        "sing-box Hysteria2 server_ports",
                    )
                })
                .transpose()?;
            let server_port = match (server_port, server_ports.as_ref()) {
                (Some(0), _) => return Err("sing-box Hysteria2 server_port is invalid".into()),
                (Some(port), _) => port,
                (None, Some(ports)) => ports[0]
                    .split_once(':')
                    .map(|(start, _end)| start)
                    .unwrap_or(&ports[0])
                    .parse::<u16>()
                    .expect("normalized Hysteria2 port must parse"),
                (None, None) => return Err("sing-box Hysteria2 server port is missing".into()),
            };
            let hop_interval_seconds = hop_interval
                .map(|value| {
                    parse_hysteria2_hop_interval_seconds(&value, "sing-box Hysteria2 hop_interval")
                })
                .transpose()?;
            if hop_interval_seconds.is_some() && server_ports.is_none() {
                return Err("sing-box Hysteria2 hop_interval requires server_ports".into());
            }
            let reference = collector.push_secret(CredentialKind::Hysteria2Password, password);
            let mut outbound = remote(
                "hysteria2",
                collector.unique_tag(tag)?,
                server.clone(),
                server_port,
                "credential_ref",
                credential_ref_json(&reference),
            );
            if let Some(server_ports) = server_ports {
                outbound["server_ports"] = json!(server_ports);
            }
            if let Some(seconds) = hop_interval_seconds {
                outbound["hop_interval_seconds"] = json!(seconds);
            }
            outbound["tls"] = source_tls(tls, &server, true)?;
            if let Some(value) = up_mbps {
                outbound["up_mbps"] = json!(value);
            }
            if let Some(value) = down_mbps {
                outbound["down_mbps"] = json!(value);
            }
            if let Some(obfs) = obfs {
                if obfs.kind != "salamander" || obfs.password.is_empty() {
                    return Err(
                        "sing-box Hysteria2 obfuscation is unsupported or incomplete".into(),
                    );
                }
                let reference =
                    collector.push_secret(CredentialKind::Hysteria2ObfsPassword, obfs.password);
                outbound["obfs"] = json!({
                    "type": "salamander",
                    "credential_ref": credential_ref_json(&reference),
                });
            }
            Ok(outbound)
        }
        SourceOutbound::AnyTls {
            tag,
            server,
            server_port,
            password,
            tls,
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
        } => {
            reject_present(
                idle_session_check_interval,
                "AnyTLS idle-session check interval",
            )?;
            reject_present(idle_session_timeout, "AnyTLS idle-session timeout")?;
            reject_present(min_idle_session, "AnyTLS minimum idle sessions")?;
            let reference = collector.push_secret(CredentialKind::AnyTlsPassword, password);
            let mut outbound = remote(
                "anytls",
                collector.unique_tag(tag)?,
                server.clone(),
                server_port,
                "credential_ref",
                credential_ref_json(&reference),
            );
            outbound["tls"] = source_tls(tls, &server, true)?;
            Ok(outbound)
        }
        SourceOutbound::Tuic {
            tag,
            server,
            server_port,
            uuid,
            password,
            tls,
            congestion_control,
            udp_relay_mode,
            udp_over_stream,
            zero_rtt_handshake,
            heartbeat,
            network,
        } => {
            reject_present(heartbeat, "TUIC heartbeat tuning")?;
            reject_present(network, "TUIC network restriction")?;
            if udp_over_stream {
                return Err("sing-box TUIC UDP-over-stream is unsupported".into());
            }
            if zero_rtt_handshake {
                return Err("sing-box TUIC 0-RTT is unsupported".into());
            }
            let uuid_reference = collector.push_secret(
                CredentialKind::TuicUuid,
                canonical_uuid_credential(uuid, "sing-box TUIC UUID")?,
            );
            let password_reference = collector.push_secret(CredentialKind::TuicPassword, password);
            let mut outbound = json!({
                "type": "tuic",
                "tag": collector.unique_tag(tag)?,
                "server": server.clone(),
                "server_port": server_port,
                "uuid_credential_ref": credential_ref_json(&uuid_reference),
                "password_credential_ref": credential_ref_json(&password_reference),
                "tls": source_tls(tls, &server, true)?,
            });
            if let Some(value) = congestion_control {
                outbound["congestion_control"] =
                    Value::String(normalize_tuic_congestion_control(&value)?);
            }
            if let Some(value) = udp_relay_mode {
                outbound["udp_relay_mode"] = Value::String(normalize_tuic_udp_relay_mode(&value)?);
            }
            Ok(outbound)
        }
    }
}

fn remote(
    kind: &str,
    tag: String,
    server: String,
    server_port: u16,
    credential_key: &str,
    credential: Value,
) -> Value {
    let mut outbound = json!({
        "type": kind,
        "tag": tag,
        "server": server,
        "server_port": server_port,
    });
    outbound[credential_key] = credential;
    outbound
}

fn insert_packet_encoding(
    outbound: &mut Value,
    packet_encoding: Option<String>,
    protocol: &str,
) -> Result<(), String> {
    if let Some(value) = packet_encoding {
        outbound["packet_encoding"] = Value::String(normalize_v2ray_packet_encoding(
            &value,
            &format!("sing-box {protocol} packet encoding"),
        )?);
    }
    Ok(())
}

fn insert_optional_tls(
    outbound: &mut Value,
    tls: Option<SourceTls>,
    server: &str,
) -> Result<(), String> {
    if let Some(tls) = tls {
        if tls.enabled {
            outbound["tls"] = source_tls(tls, server, true)?;
        } else if tls.has_disabled_semantics() {
            return Err("disabled sing-box TLS contains active options".into());
        }
    }
    Ok(())
}

fn source_tls(tls: SourceTls, server: &str, required: bool) -> Result<Value, String> {
    if required && !tls.enabled {
        return Err("sing-box outbound requires enabled TLS".into());
    }
    if tls.insecure {
        return Err("sing-box outbound requires disabling TLS certificate verification".into());
    }
    if tls.disable_sni {
        return Err("sing-box outbound disables SNI, which is unsupported".into());
    }
    if !tls.min_version.is_empty()
        && tls.min_version != cfw_singbox_config::MINIMUM_REMOTE_TLS_VERSION
    {
        return Err("sing-box TLS min_version cannot be represented exactly".into());
    }
    let utls = match tls.utls {
        None => None,
        Some(utls) if !utls.enabled && utls.fingerprint.is_empty() => None,
        Some(utls) if utls.enabled => Some(
            parse_utls(&utls.fingerprint)?
                .ok_or_else(|| "enabled sing-box uTLS requires a fingerprint".to_owned())?,
        ),
        Some(_) => return Err("disabled sing-box uTLS contains active options".into()),
    };
    let reality = match tls.reality {
        None => None,
        Some(reality)
            if !reality.enabled && reality.public_key.is_empty() && reality.short_id.is_empty() =>
        {
            None
        }
        Some(reality) if reality.enabled => Some(json!({
            "enabled": true,
            "public_key": reality.public_key,
            "short_id": reality.short_id,
        })),
        Some(_) => return Err("disabled sing-box Reality contains active options".into()),
    };
    Ok(tls_json(build_tls_parts(
        true,
        if tls.server_name.is_empty() {
            server.to_owned()
        } else {
            tls.server_name
        },
        tls.alpn.into_vec(),
        utls,
        reality,
    )))
}

impl SourceTls {
    fn has_disabled_semantics(&self) -> bool {
        !self.server_name.is_empty()
            || self.insecure
            || self.disable_sni
            || !matches!(self.alpn, StringList::Empty)
            || !self.min_version.is_empty()
            || self.utls.is_some()
            || self.reality.is_some()
    }
}

fn insert_transport(
    outbound: &mut Value,
    transport: Option<SourceTransport>,
) -> Result<(), String> {
    let Some(transport) = transport else {
        return Ok(());
    };
    outbound["transport"] = match transport {
        SourceTransport::Http {
            path,
            host,
            method,
            mut headers,
        } => {
            let explicit_host = host.into_vec();
            let upper_host = headers.remove("Host").map(StringList::into_vec);
            let lower_host = headers.remove("host").map(StringList::into_vec);
            let header_host = match (upper_host, lower_host) {
                (Some(a), Some(b)) if a != b => {
                    return Err("sing-box HTTP transport declares conflicting Host headers".into());
                }
                (a, b) => a.or(b).unwrap_or_default(),
            };
            if !headers.is_empty() {
                return Err("sing-box HTTP headers other than Host are unsupported".into());
            }
            let host = match (explicit_host.is_empty(), header_host.is_empty()) {
                (false, false) if explicit_host != header_host => {
                    return Err(
                        "sing-box HTTP transport declares conflicting host authorities".into(),
                    );
                }
                (false, _) => explicit_host,
                (true, _) => header_host,
            };
            let mut value = json!({
                "type": "http",
                "path": path,
                "host": host,
            });
            if !method.is_empty() {
                value["method"] = Value::String(super::normalize_v2ray_http_method(
                    &method,
                    "sing-box HTTP method",
                )?);
            }
            value
        }
        SourceTransport::Websocket { path, mut headers } => {
            let host = headers.remove("Host").or_else(|| headers.remove("host"));
            if !headers.is_empty() {
                return Err("sing-box WebSocket headers other than Host are unsupported".into());
            }
            let mut value = json!({ "type": "ws", "path": path });
            if let Some(host) = host {
                value["headers"] = json!({ "Host": host });
            }
            value
        }
        SourceTransport::Grpc { service_name } => json!({
            "type": "grpc",
            "service_name": service_name,
        }),
        SourceTransport::Quic => json!({ "type": "quic" }),
        SourceTransport::HttpUpgrade {
            path,
            host,
            headers,
        } => {
            if !headers.is_empty() {
                return Err("sing-box HTTPUpgrade custom headers are unsupported".into());
            }
            let mut value = json!({ "type": "http_upgrade", "path": path });
            if !host.is_empty() {
                value["host"] = Value::String(host);
            }
            value
        }
    };
    Ok(())
}

fn reject_present<T>(value: Option<T>, feature: &str) -> Result<(), String> {
    if value.is_some() {
        Err(format!("sing-box source uses unsupported {feature}"))
    } else {
        Ok(())
    }
}

fn default_path() -> String {
    "/".to_owned()
}
