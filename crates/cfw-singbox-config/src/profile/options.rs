//! Protocol options of the remote outbounds: authentication, ciphers, flows,
//! packet encodings, and Hysteria2 and TUIC tuning.

use serde::{Deserialize, Serialize};

use crate::CredentialRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LoadBalanceStrategy {
    ConsistentHashing,
    StickySessions,
    RoundRobin,
}

/// A SOCKS5 authenticated profile always owns both references. Keeping the
/// pair in one optional value prevents a partial pair from becoming anonymous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Socks5Authentication {
    pub(crate) username_credential_ref: CredentialRef,
    pub(crate) password_credential_ref: CredentialRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpProxyAuthentication {
    pub(crate) username_credential_ref: CredentialRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password_credential_ref: Option<CredentialRef>,
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
    pub(super) fn is_auto(&self) -> bool {
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
pub(crate) struct Hysteria2Obfs {
    #[serde(rename = "type")]
    pub(crate) kind: Hysteria2ObfsType,
    pub(crate) credential_ref: CredentialRef,
    /// Gecko packet size bounds; the runtime defaults are used when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) min_packet_size: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_packet_size: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hysteria2ObfsType {
    Salamander,
    Gecko,
}

/// BBR tuning for uploads that are not rate-limited by `up_mbps` (Brutal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hysteria2BbrProfile {
    Standard,
    Conservative,
    Aggressive,
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
