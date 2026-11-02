//! One source outbound as a profile outbound.

use cfw_singbox_config::CredentialKind;
use serde_json::{Value, json};

use super::source::{SourceOutbound, SourceTls};
use super::tls_transport::{insert_transport, source_tls};
use super::{
    OutboundCollector, canonical_uuid_credential, credential_ref_json,
    normalize_hysteria2_server_ports, normalize_shadowsocks_method_and_password,
    normalize_tuic_congestion_control, normalize_tuic_udp_relay_mode,
    normalize_v2ray_packet_encoding, normalize_vless_flow, normalize_vmess_alter_id,
    normalize_vmess_security, parse_hysteria2_bbr_profile, parse_hysteria2_hop_interval_seconds,
};

pub(super) fn convert_outbound(
    collector: &mut OutboundCollector,
    source: SourceOutbound,
) -> Result<Value, String> {
    match source {
        SourceOutbound::Http {
            tag,
            server,
            server_port,
            username,
            password,
            tls,
        } => {
            let mut outbound = collector.http_proxy_outbound(
                tag,
                server.clone(),
                server_port,
                username,
                password,
                None,
            )?;
            insert_optional_tls(&mut outbound, tls, &server)?;
            Ok(outbound)
        }
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
            hop_interval_max,
            bbr_profile,
            disable_chrome_parrot,
            network,
            brutal_debug,
        } => {
            reject_present(network, "Hysteria2 network restriction")?;
            if brutal_debug {
                return Err("sing-box Hysteria2 brutal debug is unsupported".into());
            }
            // Without the Chrome QUIC parrot the handshake is a plain
            // quic-go fingerprint; the option is refused, not dropped.
            if disable_chrome_parrot {
                return Err("sing-box Hysteria2 disable_chrome_parrot is unsupported".into());
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
            let hop_interval_max_seconds = hop_interval_max
                .map(|value| {
                    parse_hysteria2_hop_interval_seconds(
                        &value,
                        "sing-box Hysteria2 hop_interval_max",
                    )
                })
                .transpose()?;
            let bbr_profile = bbr_profile
                .map(|value| parse_hysteria2_bbr_profile(&value, "sing-box Hysteria2 bbr_profile"))
                .transpose()?;
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
            if let Some(seconds) = hop_interval_max_seconds {
                outbound["hop_interval_max_seconds"] = json!(seconds);
            }
            if let Some(profile) = bbr_profile {
                outbound["bbr_profile"] = json!(profile);
            }
            outbound["tls"] = source_tls(tls, &server, true)?;
            if let Some(value) = up_mbps {
                outbound["up_mbps"] = json!(value);
            }
            if let Some(value) = down_mbps {
                outbound["down_mbps"] = json!(value);
            }
            if let Some(obfs) = obfs {
                let gecko = obfs.kind == "gecko";
                let sized = obfs.min_packet_size.is_some() || obfs.max_packet_size.is_some();
                if !(gecko || obfs.kind == "salamander") || obfs.password.is_empty() {
                    return Err(
                        "sing-box Hysteria2 obfuscation is unsupported or incomplete".into(),
                    );
                }
                if sized && !gecko {
                    return Err("sing-box Hysteria2 packet sizes apply only to gecko obfs".into());
                }
                let reference =
                    collector.push_secret(CredentialKind::Hysteria2ObfsPassword, obfs.password);
                let mut projected = json!({
                    "type": obfs.kind,
                    "credential_ref": credential_ref_json(&reference),
                });
                if let Some(size) = obfs.min_packet_size {
                    projected["min_packet_size"] = json!(size);
                }
                if let Some(size) = obfs.max_packet_size {
                    projected["max_packet_size"] = json!(size);
                }
                outbound["obfs"] = projected;
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

pub(super) fn remote(
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

pub(super) fn insert_packet_encoding(
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

pub(super) fn insert_optional_tls(
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

pub(super) fn reject_present<T>(value: Option<T>, feature: &str) -> Result<(), String> {
    if value.is_some() {
        Err(format!("sing-box source uses unsupported {feature}"))
    } else {
        Ok(())
    }
}
