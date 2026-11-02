use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::CredentialRef;

/// Maximum number of outbounds one profile may declare. Public so importers
/// can bound conversion work before handing a document to the validator.
pub use crate::capacity::MAX_OUTBOUNDS;

mod options;
mod tls;
mod transport;

pub(crate) use options::{
    HttpProxyAuthentication, Hysteria2BbrProfile, Hysteria2Obfs, Hysteria2ObfsType,
    LoadBalanceStrategy, ShadowsocksMethod, Socks5Authentication, Socks5Network,
    TuicCongestionControl, TuicUdpRelayMode, V2RayPacketEncoding, VlessFlow, VmessAlterId,
    VmessSecurity,
};
pub use tls::UtlsFingerprint;
pub(crate) use tls::{OutboundTls, TlsCurve, TlsMinimumVersion};
pub(crate) use transport::V2RayTransport;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileDocument {
    pub(crate) outbounds: Vec<ProfileOutbound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) providers: Option<crate::providers::ProviderCatalog>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route: Option<ProfileRoute>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) detours: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dns: Option<crate::dns_policy::ProfileDns>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) hosts: std::collections::BTreeMap<String, Vec<std::net::IpAddr>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileRoute {
    #[serde(rename = "final")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) final_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) rules: Vec<crate::routing::ProfileRule>,
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
    Selector {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default: Option<String>,
    },
    #[serde(rename = "urltest")]
    UrlTest {
        tag: String,
        outbounds: Vec<String>,
        url: String,
        interval_seconds: u32,
        tolerance_ms: u16,
        idle_timeout_seconds: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lazy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hidden: Option<bool>,
    },
    Fallback {
        tag: String,
        outbounds: Vec<String>,
        url: String,
        interval_seconds: u32,
        idle_timeout_seconds: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lazy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hidden: Option<bool>,
    },
    #[serde(rename = "loadbalance")]
    LoadBalance {
        tag: String,
        outbounds: Vec<String>,
        url: String,
        interval_seconds: u32,
        idle_timeout_seconds: u32,
        strategy: LoadBalanceStrategy,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lazy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hidden: Option<bool>,
    },
    #[serde(rename = "wireguard")]
    WireGuard {
        tag: String,
        server: String,
        server_port: u16,
        local_addresses: Vec<String>,
        private_key_credential_ref: CredentialRef,
        peer_public_key: String,
        #[serde(default = "default_wireguard_allowed_ips")]
        peer_allowed_ips: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pre_shared_key_credential_ref: Option<CredentialRef>,
        mtu: u16,
        persistent_keepalive_seconds: u16,
    },
    /// A tailnet node that sends its traffic through one exit node. The Mac
    /// never advertises routes or an exit node of its own.
    Tailscale {
        tag: String,
        auth_key_credential_ref: CredentialRef,
        exit_node: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        accept_routes: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        exit_node_allow_lan_access: bool,
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
    Http {
        tag: String,
        server: String,
        server_port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        authentication: Option<HttpProxyAuthentication>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tls: Option<OutboundTls>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        hop_interval_max_seconds: Option<u32>,
        credential_ref: CredentialRef,
        tls: OutboundTls,
        #[serde(skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2Obfs>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bbr_profile: Option<Hysteria2BbrProfile>,
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

fn default_wireguard_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
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
    pub(crate) fn server(&self) -> Option<&str> {
        match self {
            Self::Direct { .. }
            | Self::Block { .. }
            | Self::Selector { .. }
            | Self::UrlTest { .. }
            | Self::Fallback { .. }
            | Self::LoadBalance { .. }
            | Self::Tailscale { .. } => None,
            Self::WireGuard { server, .. }
            | Self::Socks5 { server, .. }
            | Self::Http { server, .. }
            | Self::Shadowsocks { server, .. }
            | Self::Vmess { server, .. }
            | Self::Vless { server, .. }
            | Self::Trojan { server, .. }
            | Self::Hysteria2 { server, .. }
            | Self::AnyTls { server, .. }
            | Self::Tuic { server, .. } => Some(server),
        }
    }

    pub(crate) fn is_remote(&self) -> bool {
        !matches!(
            self,
            Self::Direct { .. }
                | Self::Block { .. }
                | Self::Selector { .. }
                | Self::UrlTest { .. }
                | Self::Fallback { .. }
                | Self::LoadBalance { .. }
        )
    }

    /// Whether the runtime places this outbound in sing-box's `endpoints`
    /// array rather than `outbounds`.
    pub(crate) fn is_endpoint(&self) -> bool {
        matches!(self, Self::WireGuard { .. } | Self::Tailscale { .. })
    }

    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Block { tag }
            | Self::Selector { tag, .. }
            | Self::UrlTest { tag, .. }
            | Self::Fallback { tag, .. }
            | Self::LoadBalance { tag, .. }
            | Self::WireGuard { tag, .. }
            | Self::Tailscale { tag, .. }
            | Self::Socks5 { tag, .. }
            | Self::Http { tag, .. }
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
            Self::WireGuard {
                private_key_credential_ref,
                pre_shared_key_credential_ref,
                ..
            } => std::iter::once(private_key_credential_ref)
                .chain(pre_shared_key_credential_ref.iter())
                .collect(),
            Self::Tailscale {
                auth_key_credential_ref,
                ..
            } => vec![auth_key_credential_ref],
            Self::Direct { .. }
            | Self::Block { .. }
            | Self::Selector { .. }
            | Self::UrlTest { .. }
            | Self::Fallback { .. }
            | Self::LoadBalance { .. } => Vec::new(),
            Self::Socks5 { authentication, .. } => match authentication {
                Some(authentication) => vec![
                    &authentication.username_credential_ref,
                    &authentication.password_credential_ref,
                ],
                None => Vec::new(),
            },
            Self::Http { authentication, .. } => {
                authentication
                    .as_ref()
                    .map_or_else(Vec::new, |authentication| {
                        std::iter::once(&authentication.username_credential_ref)
                            .chain(authentication.password_credential_ref.iter())
                            .collect()
                    })
            }
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

    pub(crate) fn group_members(&self) -> Option<&[String]> {
        match self {
            Self::Selector { outbounds, .. }
            | Self::UrlTest { outbounds, .. }
            | Self::Fallback { outbounds, .. }
            | Self::LoadBalance { outbounds, .. } => Some(outbounds),
            _ => None,
        }
    }
}
