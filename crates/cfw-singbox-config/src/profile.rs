use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::CredentialRef;

/// Maximum number of outbounds one profile may declare. Public so importers
/// can bound conversion work before handing a document to the validator.
pub const MAX_OUTBOUNDS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileDocument {
    pub(crate) outbounds: Vec<ProfileOutbound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route: Option<ProfileRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileRoute {
    #[serde(rename = "final")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) final_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProfileOutbound {
    Direct {
        tag: String,
    },
    Block {
        tag: String,
    },
    Socks5 {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        authentication: Option<Socks5Authentication>,
        #[serde(skip_serializing_if = "Option::is_none")]
        network: Option<Socks5Network>,
    },
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        method: ShadowsocksMethod,
        credential_ref: CredentialRef,
    },
    Vmess {
        tag: String,
        server: String,
        server_port: u16,
        credential_ref: CredentialRef,
        #[serde(default, skip_serializing_if = "VmessAlterId::is_aead")]
        alter_id: VmessAlterId,
        #[serde(default, skip_serializing_if = "VmessSecurity::is_auto")]
        security: VmessSecurity,
        #[serde(skip_serializing_if = "Option::is_none")]
        packet_encoding: Option<V2RayPacketEncoding>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls: Option<OutboundTls>,
        #[serde(skip_serializing_if = "Option::is_none")]
        transport: Option<V2RayTransport>,
    },
    Vless {
        tag: String,
        server: String,
        server_port: u16,
        credential_ref: CredentialRef,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<VlessFlow>,
        #[serde(skip_serializing_if = "Option::is_none")]
        packet_encoding: Option<V2RayPacketEncoding>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls: Option<OutboundTls>,
        #[serde(skip_serializing_if = "Option::is_none")]
        transport: Option<V2RayTransport>,
    },
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        credential_ref: CredentialRef,
        tls: OutboundTls,
        #[serde(skip_serializing_if = "Option::is_none")]
        transport: Option<V2RayTransport>,
    },
    Hysteria2 {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_ports: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hop_interval_seconds: Option<u32>,
        credential_ref: CredentialRef,
        tls: OutboundTls,
        #[serde(skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2Obfs>,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        tag: String,
        server: String,
        server_port: u16,
        credential_ref: CredentialRef,
        tls: OutboundTls,
    },
    Tuic {
        tag: String,
        server: String,
        server_port: u16,
        uuid_credential_ref: CredentialRef,
        password_credential_ref: CredentialRef,
        tls: OutboundTls,
        #[serde(skip_serializing_if = "Option::is_none")]
        congestion_control: Option<TuicCongestionControl>,
        #[serde(skip_serializing_if = "Option::is_none")]
        udp_relay_mode: Option<TuicUdpRelayMode>,
    },
}

/// A SOCKS5 authenticated profile always owns both references. Keeping the
/// pair in one optional value prevents a partial pair from becoming anonymous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Socks5Authentication {
    pub(crate) username_credential_ref: CredentialRef,
    pub(crate) password_credential_ref: CredentialRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Socks5Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ShadowsocksMethod {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    Xchacha20IetfPoly1305,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm2022,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm2022,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly13052022,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum VmessSecurity {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "zero")]
    Zero,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub(crate) enum VmessAlterId {
    #[default]
    Aead,
    Legacy,
}

impl VmessAlterId {
    pub(crate) fn is_aead(&self) -> bool {
        *self == Self::Aead
    }

    pub(crate) fn is_legacy(&self) -> bool {
        *self == Self::Legacy
    }
}

impl TryFrom<u8> for VmessAlterId {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Aead),
            1 => Ok(Self::Legacy),
            _ => Err("VMess alter_id must be 0 (AEAD) or 1 (legacy protocol)".to_owned()),
        }
    }
}

impl From<VmessAlterId> for u8 {
    fn from(value: VmessAlterId) -> Self {
        match value {
            VmessAlterId::Aead => 0,
            VmessAlterId::Legacy => 1,
        }
    }
}

impl VmessSecurity {
    fn is_auto(&self) -> bool {
        *self == Self::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum VlessFlow {
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}

/// The closed UDP packet framing choices shared by VMess and VLESS. `Raw`
/// projects to sing-box's empty wire value; it is distinct from an omitted
/// VLESS field because the pinned engine defaults omitted VLESS to XUDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum V2RayPacketEncoding {
    Raw,
    PacketAddr,
    Xudp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutboundTls {
    pub(crate) enabled: bool,
    pub(crate) server_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) utls: Option<UtlsOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reality: Option<RealityOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UtlsOptions {
    pub(crate) enabled: bool,
    pub(crate) fingerprint: UtlsFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UtlsFingerprint {
    Chrome,
    Firefox,
    Edge,
    Safari,
    #[serde(rename = "360")]
    Browser360,
    Qq,
    Ios,
    Android,
    Random,
    Randomized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealityOptions {
    pub(crate) enabled: bool,
    pub(crate) public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) short_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum V2RayTransport {
    Http {
        #[serde(skip_serializing_if = "Option::is_none")]
        method: Option<V2RayHttpMethod>,
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
    },
    #[serde(rename = "ws")]
    Websocket {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<WebsocketHeaders>,
    },
    Grpc {
        service_name: String,
    },
    Quic,
    HttpUpgrade {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum V2RayHttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "OPTIONS")]
    Options,
}

impl V2RayHttpMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebsocketHeaders {
    #[serde(rename = "Host")]
    pub(crate) host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hysteria2Obfs {
    #[serde(rename = "type")]
    pub(crate) kind: Hysteria2ObfsType,
    pub(crate) credential_ref: CredentialRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hysteria2ObfsType {
    Salamander,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TuicCongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TuicUdpRelayMode {
    Native,
    Quic,
}

fn default_websocket_path() -> String {
    "/".to_owned()
}

impl ProfileDocument {
    pub(crate) fn effective_final_outbound_tag(&self) -> &str {
        self.route
            .as_ref()
            .and_then(|route| route.final_tag.as_deref())
            .unwrap_or_else(|| self.outbounds[0].tag())
    }

    pub(crate) fn credential_references(&self) -> Vec<CredentialRef> {
        self.outbounds
            .iter()
            .flat_map(ProfileOutbound::credential_refs)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(crate) fn credential_references_in_outbound_order(&self) -> Vec<CredentialRef> {
        self.outbounds
            .iter()
            .flat_map(ProfileOutbound::credential_refs)
            .cloned()
            .collect()
    }
}

impl ProfileOutbound {
    pub(crate) fn is_remote(&self) -> bool {
        !matches!(self, Self::Direct { .. } | Self::Block { .. })
    }

    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Block { tag }
            | Self::Socks5 { tag, .. }
            | Self::Shadowsocks { tag, .. }
            | Self::Vmess { tag, .. }
            | Self::Vless { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Hysteria2 { tag, .. }
            | Self::AnyTls { tag, .. }
            | Self::Tuic { tag, .. } => tag,
        }
    }

    pub(crate) fn credential_refs(&self) -> Vec<&CredentialRef> {
        match self {
            Self::Direct { .. } | Self::Block { .. } => Vec::new(),
            Self::Socks5 { authentication, .. } => match authentication {
                Some(authentication) => vec![
                    &authentication.username_credential_ref,
                    &authentication.password_credential_ref,
                ],
                None => Vec::new(),
            },
            Self::Hysteria2 {
                credential_ref,
                obfs,
                ..
            } => {
                let mut references = vec![credential_ref];
                if let Some(obfs) = obfs {
                    references.push(&obfs.credential_ref);
                }
                references
            }
            Self::Shadowsocks { credential_ref, .. }
            | Self::Vmess { credential_ref, .. }
            | Self::Vless { credential_ref, .. }
            | Self::Trojan { credential_ref, .. }
            | Self::AnyTls { credential_ref, .. } => vec![credential_ref],
            Self::Tuic {
                uuid_credential_ref,
                password_credential_ref,
                ..
            } => vec![uuid_credential_ref, password_credential_ref],
        }
    }
}
