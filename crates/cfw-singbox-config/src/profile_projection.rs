use std::collections::BTreeSet;
use std::net::IpAddr;

use serde_json::{Map, Value, json};

use crate::profile::{
    OutboundTls, ProfileDocument, ProfileOutbound, V2RayPacketEncoding, V2RayTransport,
};
use crate::{ConfigError, CredentialSlot, CredentialTarget, MINIMUM_REMOTE_TLS_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DomainResolverTags<'a> {
    pub(crate) server: &'a str,
    pub(crate) fallback_server: &'a str,
}

#[derive(Debug)]
pub(crate) struct RuntimeOutboundProjection {
    pub(crate) outbounds: Vec<Value>,
    pub(crate) credential_slots: Vec<CredentialSlot>,
    pub(crate) selected_outbound: String,
    pub(crate) injected_route_final: Option<String>,
}

const APP_SELECTOR_TAG: &str = "cfw-proxy-selector";

impl ProfileDocument {
    pub(crate) fn runtime_outbounds(
        &self,
        bootstrap_resolver: DomainResolverTags<'_>,
    ) -> Result<RuntimeOutboundProjection, ConfigError> {
        let mut outbounds = Vec::with_capacity(self.outbounds.len() + 1);
        let mut slots = Vec::new();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let (projected, mut outbound_slots) =
                outbound.runtime_projection(index, bootstrap_resolver)?;
            outbounds.push(projected);
            slots.append(&mut outbound_slots);
        }

        let profile_final = self.effective_final_outbound_tag().to_owned();
        let remote_tags = self
            .outbounds
            .iter()
            .filter(|outbound| outbound.is_remote())
            .map(|outbound| outbound.tag().to_owned())
            .collect::<Vec<_>>();
        let has_explicit_final = self
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            .is_some();
        let inject_selector =
            !has_explicit_final && self.outbounds[0].is_remote() && remote_tags.len() >= 2;
        let injected_route_final = inject_selector.then(|| self.selector_tag());
        if let Some(selector_tag) = injected_route_final.as_ref() {
            outbounds.push(json!({
                "type": "selector",
                "tag": selector_tag,
                "outbounds": remote_tags,
                "default": profile_final,
                "interrupt_exist_connections": false,
            }));
        }
        let selected_outbound = injected_route_final
            .clone()
            .unwrap_or_else(|| profile_final.clone());
        Ok(RuntimeOutboundProjection {
            outbounds,
            credential_slots: slots,
            selected_outbound,
            injected_route_final,
        })
    }

    fn selector_tag(&self) -> String {
        let profile_tags = self
            .outbounds
            .iter()
            .map(ProfileOutbound::tag)
            .collect::<BTreeSet<_>>();
        if !profile_tags.contains(APP_SELECTOR_TAG) {
            return APP_SELECTOR_TAG.to_owned();
        }
        for suffix in 2..=self.outbounds.len() + 1 {
            let candidate = format!("{APP_SELECTOR_TAG}-{suffix}");
            if !profile_tags.contains(candidate.as_str()) {
                return candidate;
            }
        }
        unreachable!("a bounded selector tag search must find a free tag")
    }
}

impl ProfileOutbound {
    fn runtime_projection(
        &self,
        index: usize,
        bootstrap_resolver: DomainResolverTags<'_>,
    ) -> Result<(Value, Vec<CredentialSlot>), ConfigError> {
        let (mut object, slots) = match self {
            Self::Direct { tag } => (base_outbound("direct", tag), Vec::new()),
            Self::Block { tag } => (base_outbound("block", tag), Vec::new()),
            Self::Shadowsocks {
                tag,
                server,
                server_port,
                method,
                credential_ref,
            } => {
                let mut object =
                    remote_outbound("shadowsocks", tag, server, *server_port, bootstrap_resolver);
                object.insert("method".into(), serde_json::to_value(method)?);
                object.insert("password".into(), Value::String(String::new()));
                (
                    object,
                    vec![CredentialSlot::new(
                        credential_ref.clone(),
                        CredentialTarget::ShadowsocksPassword,
                        index,
                    )?],
                )
            }
            Self::Vmess {
                tag,
                server,
                server_port,
                credential_ref,
                alter_id,
                security,
                packet_encoding,
                tls,
                transport,
            } => {
                let mut object =
                    remote_outbound("vmess", tag, server, *server_port, bootstrap_resolver);
                object.insert("uuid".into(), Value::String(String::new()));
                object.insert("security".into(), serde_json::to_value(security)?);
                if alter_id.is_legacy() {
                    object.insert("alter_id".into(), Value::from(1));
                }
                insert_packet_encoding(&mut object, packet_encoding.as_ref());
                insert_tls_transport(&mut object, tls.as_ref(), transport.as_ref())?;
                (
                    object,
                    vec![CredentialSlot::new(
                        credential_ref.clone(),
                        CredentialTarget::VmessUuid,
                        index,
                    )?],
                )
            }
            Self::Vless {
                tag,
                server,
                server_port,
                credential_ref,
                flow,
                packet_encoding,
                tls,
                transport,
            } => {
                let mut object =
                    remote_outbound("vless", tag, server, *server_port, bootstrap_resolver);
                object.insert("uuid".into(), Value::String(String::new()));
                if let Some(flow) = flow {
                    object.insert("flow".into(), serde_json::to_value(flow)?);
                }
                insert_packet_encoding(&mut object, packet_encoding.as_ref());
                insert_tls_transport(&mut object, tls.as_ref(), transport.as_ref())?;
                (
                    object,
                    vec![CredentialSlot::new(
                        credential_ref.clone(),
                        CredentialTarget::VlessUuid,
                        index,
                    )?],
                )
            }
            Self::Trojan {
                tag,
                server,
                server_port,
                credential_ref,
                tls,
                transport,
            } => {
                let mut object =
                    remote_outbound("trojan", tag, server, *server_port, bootstrap_resolver);
                object.insert("password".into(), Value::String(String::new()));
                insert_tls_transport(&mut object, Some(tls), transport.as_ref())?;
                (
                    object,
                    vec![CredentialSlot::new(
                        credential_ref.clone(),
                        CredentialTarget::TrojanPassword,
                        index,
                    )?],
                )
            }
            Self::Hysteria2 {
                tag,
                server,
                server_port,
                server_ports,
                hop_interval_seconds,
                credential_ref,
                tls,
                up_mbps,
                down_mbps,
                obfs,
            } => {
                let mut object =
                    remote_outbound("hysteria2", tag, server, *server_port, bootstrap_resolver);
                if let Some(server_ports) = server_ports {
                    // The pinned sing-quic parser accepts only explicit
                    // start:end ranges. Keep the profile model's compact
                    // single-port form, but close each singleton at the
                    // runtime boundary consumed by libbox.
                    let runtime_server_ports = server_ports
                        .iter()
                        .map(|item| {
                            if item.contains(':') {
                                item.clone()
                            } else {
                                format!("{item}:{item}")
                            }
                        })
                        .collect::<Vec<_>>();
                    object.insert("server_ports".into(), json!(runtime_server_ports));
                }
                if let Some(seconds) = hop_interval_seconds {
                    object.insert("hop_interval".into(), json!(format!("{seconds}s")));
                }
                object.insert("password".into(), Value::String(String::new()));
                object.insert("tls".into(), project_tls(tls)?);
                if let Some(value) = up_mbps {
                    object.insert("up_mbps".into(), json!(value));
                }
                if let Some(value) = down_mbps {
                    object.insert("down_mbps".into(), json!(value));
                }
                let mut slots = vec![CredentialSlot::new(
                    credential_ref.clone(),
                    CredentialTarget::Hysteria2Password,
                    index,
                )?];
                if let Some(obfs) = obfs {
                    object.insert(
                        "obfs".into(),
                        json!({
                            "type": obfs.kind,
                            "password": "",
                        }),
                    );
                    slots.push(CredentialSlot::new(
                        obfs.credential_ref.clone(),
                        CredentialTarget::Hysteria2ObfsPassword,
                        index,
                    )?);
                }
                (object, slots)
            }
            Self::AnyTls {
                tag,
                server,
                server_port,
                credential_ref,
                tls,
            } => {
                let mut object =
                    remote_outbound("anytls", tag, server, *server_port, bootstrap_resolver);
                object.insert("password".into(), Value::String(String::new()));
                object.insert("tls".into(), project_tls(tls)?);
                (
                    object,
                    vec![CredentialSlot::new(
                        credential_ref.clone(),
                        CredentialTarget::AnyTlsPassword,
                        index,
                    )?],
                )
            }
            Self::Tuic {
                tag,
                server,
                server_port,
                uuid_credential_ref,
                password_credential_ref,
                tls,
                congestion_control,
                udp_relay_mode,
            } => {
                let mut object =
                    remote_outbound("tuic", tag, server, *server_port, bootstrap_resolver);
                object.insert("uuid".into(), Value::String(String::new()));
                object.insert("password".into(), Value::String(String::new()));
                object.insert("tls".into(), project_tls(tls)?);
                object.insert("zero_rtt_handshake".into(), Value::Bool(false));
                if let Some(value) = congestion_control {
                    object.insert("congestion_control".into(), serde_json::to_value(value)?);
                }
                if let Some(value) = udp_relay_mode {
                    object.insert("udp_relay_mode".into(), serde_json::to_value(value)?);
                }
                (
                    object,
                    vec![
                        CredentialSlot::new(
                            uuid_credential_ref.clone(),
                            CredentialTarget::TuicUuid,
                            index,
                        )?,
                        CredentialSlot::new(
                            password_credential_ref.clone(),
                            CredentialTarget::TuicPassword,
                            index,
                        )?,
                    ],
                )
            }
        };
        Ok((Value::Object(std::mem::take(&mut object)), slots))
    }
}

fn base_outbound(kind: &str, tag: &str) -> Map<String, Value> {
    Map::from_iter([
        ("type".to_owned(), Value::String(kind.to_owned())),
        ("tag".to_owned(), Value::String(tag.to_owned())),
    ])
}

fn remote_outbound(
    kind: &str,
    tag: &str,
    server: &str,
    port: u16,
    bootstrap_resolver: DomainResolverTags<'_>,
) -> Map<String, Value> {
    let mut object = base_outbound(kind, tag);
    object.insert("server".into(), Value::String(server.to_owned()));
    object.insert("server_port".into(), json!(port));
    if server.parse::<IpAddr>().is_err() {
        object.insert(
            "domain_resolver".into(),
            json!({
                "server": bootstrap_resolver.server,
                "fallback_server": bootstrap_resolver.fallback_server,
            }),
        );
    }
    object
}

fn insert_tls_transport(
    object: &mut Map<String, Value>,
    tls: Option<&OutboundTls>,
    transport: Option<&V2RayTransport>,
) -> Result<(), ConfigError> {
    if let Some(tls) = tls {
        object.insert("tls".into(), project_tls(tls)?);
    }
    if let Some(transport) = transport {
        object.insert("transport".into(), project_transport(transport));
    }
    Ok(())
}

fn insert_packet_encoding(
    object: &mut Map<String, Value>,
    packet_encoding: Option<&V2RayPacketEncoding>,
) {
    if let Some(packet_encoding) = packet_encoding {
        let value = match packet_encoding {
            V2RayPacketEncoding::Raw => "",
            V2RayPacketEncoding::PacketAddr => "packetaddr",
            V2RayPacketEncoding::Xudp => "xudp",
        };
        object.insert("packet_encoding".into(), Value::String(value.into()));
    }
}

fn project_tls(tls: &OutboundTls) -> Result<Value, ConfigError> {
    let mut object = Map::new();
    object.insert("enabled".into(), Value::Bool(tls.enabled));
    object.insert("server_name".into(), Value::String(tls.server_name.clone()));
    if tls.enabled {
        object.insert(
            "min_version".into(),
            Value::String(MINIMUM_REMOTE_TLS_VERSION.to_owned()),
        );
    }
    if !tls.alpn.is_empty() {
        object.insert("alpn".into(), serde_json::to_value(&tls.alpn)?);
    }
    if let Some(utls) = &tls.utls {
        object.insert(
            "utls".into(),
            json!({ "enabled": utls.enabled, "fingerprint": utls.fingerprint }),
        );
    }
    if let Some(reality) = &tls.reality {
        object.insert(
            "reality".into(),
            json!({
                "enabled": reality.enabled,
                "public_key": reality.public_key,
                "short_id": reality.short_id,
            }),
        );
    }
    Ok(Value::Object(object))
}

fn project_transport(transport: &V2RayTransport) -> Value {
    match transport {
        V2RayTransport::Http { method, path, host } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("http".into())),
                ("path".into(), Value::String(path.clone())),
                ("host".into(), json!(host)),
            ]);
            if let Some(method) = method {
                object.insert("method".into(), Value::String(method.as_str().into()));
            }
            Value::Object(object)
        }
        V2RayTransport::Websocket { path, headers } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("ws".into())),
                ("path".into(), Value::String(path.clone())),
            ]);
            if let Some(headers) = headers {
                object.insert("headers".into(), json!({ "Host": headers.host }));
            }
            Value::Object(object)
        }
        V2RayTransport::Grpc { service_name } => json!({
            "type": "grpc",
            "service_name": service_name,
        }),
        V2RayTransport::Quic => json!({ "type": "quic" }),
        V2RayTransport::HttpUpgrade { path, host } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("httpupgrade".into())),
                ("path".into(), Value::String(path.clone())),
            ]);
            if let Some(host) = host {
                object.insert("host".into(), Value::String(host.clone()));
            }
            Value::Object(object)
        }
    }
}
