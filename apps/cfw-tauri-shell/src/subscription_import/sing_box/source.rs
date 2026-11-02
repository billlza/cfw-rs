//! The node-list document as the adapter reads it: every source field is
//! typed, and an unknown field is an error.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::Socks5Network;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceDocument {
    pub(super) outbounds: Vec<SourceOutbound>,
    #[serde(default)]
    pub(super) endpoints: Vec<SourceEndpoint>,
}

/// The upstream endpoint fields, each either carried into the closed profile
/// or refused by name: this Mac only uses an exit node, so every field that
/// would make it advertise, serve or own an interface is rejected rather
/// than dropped.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum SourceEndpoint {
    Tailscale {
        tag: String,
        #[serde(default)]
        auth_key: String,
        #[serde(default)]
        exit_node: String,
        #[serde(default)]
        control_url: String,
        #[serde(default)]
        hostname: String,
        #[serde(default)]
        accept_routes: bool,
        #[serde(default)]
        exit_node_allow_lan_access: bool,
        #[serde(default)]
        ephemeral: bool,
        #[serde(default)]
        state_directory: Option<Value>,
        #[serde(default)]
        advertise_routes: Option<Value>,
        #[serde(default)]
        advertise_exit_node: bool,
        #[serde(default)]
        advertise_tags: Option<Value>,
        #[serde(default)]
        listen_port: Option<Value>,
        #[serde(default)]
        relay_server_port: Option<Value>,
        #[serde(default)]
        relay_server_static_endpoints: Option<Value>,
        #[serde(default)]
        system_interface: bool,
        #[serde(default)]
        system_interface_name: Option<Value>,
        #[serde(default)]
        system_interface_mtu: Option<Value>,
        #[serde(default)]
        udp_timeout: Option<Value>,
        #[serde(default)]
        ssh_server: Option<Value>,
        #[serde(default)]
        taildrop_directory: Option<Value>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum SourceOutbound {
    Http {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        tls: Option<SourceTls>,
    },
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
        hop_interval_max: Option<String>,
        #[serde(default)]
        bbr_profile: Option<String>,
        #[serde(default)]
        disable_chrome_parrot: bool,
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
pub(super) struct SourceHysteria2Obfs {
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) password: String,
    #[serde(default)]
    pub(super) min_packet_size: Option<u16>,
    #[serde(default)]
    pub(super) max_packet_size: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceTls {
    #[serde(default)]
    pub(super) certificate_sha256: Vec<String>,
    #[serde(default)]
    pub(super) certificate_public_key_sha256: Vec<String>,
    #[serde(default)]
    pub(super) enabled: bool,
    #[serde(default)]
    pub(super) server_name: String,
    #[serde(default)]
    pub(super) insecure: bool,
    #[serde(default)]
    pub(super) disable_sni: bool,
    #[serde(default)]
    pub(super) alpn: StringList,
    #[serde(default)]
    pub(super) min_version: String,
    #[serde(default)]
    pub(super) curve_preferences: Vec<String>,
    #[serde(default)]
    pub(super) ech: Option<SourceEch>,
    #[serde(default)]
    pub(super) utls: Option<SourceUtls>,
    #[serde(default)]
    pub(super) reality: Option<SourceReality>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceEch {
    pub(super) enabled: bool,
    pub(super) config: StringList,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceUtls {
    #[serde(default)]
    pub(super) enabled: bool,
    #[serde(default)]
    pub(super) fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceReality {
    #[serde(default)]
    pub(super) enabled: bool,
    #[serde(default)]
    pub(super) public_key: String,
    #[serde(default)]
    pub(super) short_id: String,
    #[serde(default)]
    pub(super) support_x25519mlkem768: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub(super) enum StringList {
    #[default]
    Empty,
    One(String),
    Many(Vec<String>),
}

impl StringList {
    pub(super) fn into_vec(self) -> Vec<String> {
        match self {
            Self::Empty => Vec::new(),
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum SourceTransport {
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

fn default_path() -> String {
    "/".to_owned()
}
