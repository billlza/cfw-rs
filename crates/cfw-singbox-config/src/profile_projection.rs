use std::net::IpAddr;

use serde_json::{Value, json};

use crate::profile::ProfileOutbound;
use crate::{ConfigError, CredentialSlot, CredentialTarget};
use fields::{base_outbound, insert_packet_encoding, insert_tls_transport, remote_outbound};

mod document;
mod fields;

pub use document::AppSelector;
pub(crate) use fields::project_tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DomainResolverTags<'a> {
    pub(crate) server: &'a str,
    pub(crate) fallback_servers: &'a [String],
}

impl DomainResolverTags<'_> {
    fn value(self) -> Value {
        let tags = std::iter::once(self.server.to_owned())
            .chain(self.fallback_servers.iter().cloned())
            .collect::<Vec<_>>();
        crate::dns_policy::resolver_value(&tags)
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeOutboundProjection {
    pub(crate) outbounds: Vec<Value>,
    pub(crate) endpoints: Vec<Value>,
    pub(crate) credential_slots: Vec<CredentialSlot>,
    pub(crate) selected_outbound: String,
    pub(crate) direct_outbound: String,
    pub(crate) global_outbound: String,
    pub(crate) injected_route_final: Option<String>,
}

impl ProfileOutbound {
    fn runtime_projection(
        &self,
        index: usize,
        profile_id: &str,
        bootstrap_resolver: DomainResolverTags<'_>,
    ) -> Result<(Value, Vec<CredentialSlot>), ConfigError> {
        let (mut object, slots) = match self {
            Self::WireGuard {
                tag,
                server,
                server_port,
                local_addresses,
                private_key_credential_ref,
                peer_public_key,
                peer_allowed_ips,
                pre_shared_key_credential_ref,
                mtu,
                persistent_keepalive_seconds,
            } => {
                let mut object = base_outbound("wireguard", tag);
                object.insert("system".into(), json!(false));
                object.insert("address".into(), json!(local_addresses));
                object.insert("mtu".into(), json!(mtu));
                object.insert("private_key".into(), json!(""));
                let mut peer = json!({"address": server, "port": server_port, "public_key": peer_public_key,
                    "allowed_ips": peer_allowed_ips, "persistent_keepalive_interval": persistent_keepalive_seconds});
                let mut slots = vec![CredentialSlot::new(
                    private_key_credential_ref.clone(),
                    CredentialTarget::WireGuardPrivateKey,
                    index,
                )?];
                if let Some(reference) = pre_shared_key_credential_ref {
                    peer["pre_shared_key"] = json!("");
                    slots.push(CredentialSlot::new(
                        reference.clone(),
                        CredentialTarget::WireGuardPreSharedKey,
                        index,
                    )?);
                }
                object.insert("peers".into(), json!([peer]));
                if server.parse::<IpAddr>().is_err() {
                    object.insert("domain_resolver".into(), bootstrap_resolver.value());
                }
                (object, slots)
            }
            Self::Tailscale {
                tag,
                auth_key_credential_ref,
                exit_node,
                control_server,
                hostname,
                accept_routes,
                exit_node_allow_lan_access,
            } => {
                let mut object = base_outbound("tailscale", tag);
                // The node's key lives with the profile, inside the runtime's own
                // working directory, so the agent and the tunnel daemon each keep
                // their own registration and no other profile can reuse it.
                object.insert(
                    "state_directory".into(),
                    json!(format!("tailscale/{profile_id}")),
                );
                object.insert("auth_key".into(), json!(""));
                if let Some(server) = control_server {
                    object.insert("control_url".into(), json!(server));
                }
                if let Some(hostname) = hostname {
                    object.insert("hostname".into(), json!(hostname));
                }
                if *accept_routes {
                    object.insert("accept_routes".into(), json!(true));
                }
                object.insert("exit_node".into(), json!(exit_node));
                if *exit_node_allow_lan_access {
                    object.insert("exit_node_allow_lan_access".into(), json!(true));
                }
                // The coordination server and the DERP relays are domain names
                // the endpoint dials itself.
                object.insert("domain_resolver".into(), bootstrap_resolver.value());
                let slots = vec![CredentialSlot::new(
                    auth_key_credential_ref.clone(),
                    CredentialTarget::TailscaleAuthKey,
                    index,
                )?];
                (object, slots)
            }
            Self::Direct { tag } => (base_outbound("direct", tag), Vec::new()),
            Self::Block { tag } => (base_outbound("block", tag), Vec::new()),
            Self::Selector {
                tag,
                outbounds,
                default,
            } => {
                let mut object = base_outbound("selector", tag);
                object.insert("outbounds".into(), json!(outbounds));
                if let Some(default) = default {
                    object.insert("default".into(), json!(default));
                }
                object.insert("interrupt_exist_connections".into(), Value::Bool(false));
                (object, Vec::new())
            }
            Self::UrlTest {
                tag,
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                lazy,
                hidden,
                ..
            }
            | Self::Fallback {
                tag,
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                lazy,
                hidden,
            }
            | Self::LoadBalance {
                tag,
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                lazy,
                hidden,
                ..
            } => {
                let mut object = match self {
                    Self::UrlTest { tolerance_ms, .. } => {
                        let mut object = base_outbound("urltest", tag);
                        object.insert("tolerance".into(), json!(tolerance_ms));
                        object
                    }
                    Self::LoadBalance { strategy, .. } => {
                        let mut object = base_outbound("loadbalance", tag);
                        object.insert("strategy".into(), json!(strategy));
                        object
                    }
                    _ => base_outbound("fallback", tag),
                };
                object.insert("outbounds".into(), json!(outbounds));
                object.insert("url".into(), json!(url));
                if let Some(lazy) = lazy {
                    object.insert("lazy".into(), json!(lazy));
                }
                if let Some(hidden) = hidden {
                    object.insert("hidden".into(), json!(hidden));
                }
                object.insert("interval".into(), json!(format!("{interval_seconds}s")));
                object.insert(
                    "idle_timeout".into(),
                    json!(format!("{idle_timeout_seconds}s")),
                );
                object.insert("interrupt_exist_connections".into(), Value::Bool(false));
                (object, Vec::new())
            }
            Self::Socks5 {
                tag,
                server,
                server_port,
                authentication,
                network,
            } => {
                let mut object =
                    remote_outbound("socks", tag, server, *server_port, bootstrap_resolver);
                object.insert("version".into(), Value::String("5".into()));
                if let Some(network) = network {
                    object.insert("network".into(), serde_json::to_value(network)?);
                }
                let mut slots = Vec::new();
                if let Some(authentication) = authentication {
                    object.insert("username".into(), Value::String(String::new()));
                    object.insert("password".into(), Value::String(String::new()));
                    slots.push(CredentialSlot::new(
                        authentication.username_credential_ref.clone(),
                        CredentialTarget::Socks5Username,
                        index,
                    )?);
                    slots.push(CredentialSlot::new(
                        authentication.password_credential_ref.clone(),
                        CredentialTarget::Socks5Password,
                        index,
                    )?);
                }
                (object, slots)
            }
            Self::Http {
                tag,
                server,
                server_port,
                authentication,
                tls,
            } => {
                let mut object =
                    remote_outbound("http", tag, server, *server_port, bootstrap_resolver);
                insert_tls_transport(&mut object, tls.as_ref(), None)?;
                let mut slots = Vec::new();
                if let Some(authentication) = authentication {
                    object.insert("username".into(), Value::String(String::new()));
                    slots.push(CredentialSlot::new(
                        authentication.username_credential_ref.clone(),
                        CredentialTarget::HttpProxyUsername,
                        index,
                    )?);
                    if let Some(password) = &authentication.password_credential_ref {
                        object.insert("password".into(), Value::String(String::new()));
                        slots.push(CredentialSlot::new(
                            password.clone(),
                            CredentialTarget::HttpProxyPassword,
                            index,
                        )?);
                    }
                }
                (object, slots)
            }
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
                hop_interval_max_seconds,
                credential_ref,
                tls,
                up_mbps,
                down_mbps,
                obfs,
                bbr_profile,
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
                if let Some(seconds) = hop_interval_max_seconds {
                    object.insert("hop_interval_max".into(), json!(format!("{seconds}s")));
                }
                object.insert("password".into(), Value::String(String::new()));
                object.insert("tls".into(), project_tls(tls)?);
                if let Some(value) = up_mbps {
                    object.insert("up_mbps".into(), json!(value));
                }
                if let Some(value) = down_mbps {
                    object.insert("down_mbps".into(), json!(value));
                }
                if let Some(profile) = bbr_profile {
                    object.insert("bbr_profile".into(), json!(profile));
                }
                let mut slots = vec![CredentialSlot::new(
                    credential_ref.clone(),
                    CredentialTarget::Hysteria2Password,
                    index,
                )?];
                if let Some(obfs) = obfs {
                    let mut projected = json!({
                        "type": obfs.kind,
                        "password": "",
                    });
                    if let Some(size) = obfs.min_packet_size {
                        projected["min_packet_size"] = json!(size);
                    }
                    if let Some(size) = obfs.max_packet_size {
                        projected["max_packet_size"] = json!(size);
                    }
                    object.insert("obfs".into(), projected);
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
