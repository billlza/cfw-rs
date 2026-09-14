//! Application-owned runtime settings, independent of profile and projection code.
use crate::{ClashApiEndpoint, ConfigError, DEFAULT_CLASH_API_PORT};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Preferred loopback TCP port for the application-owned mixed inbound.
///
/// The application shell may choose a different bounded port before it
/// projects a runtime configuration. Keeping the preferred value in the
/// projection crate prevents the selection policy and default settings from
/// drifting apart.
pub const DEFAULT_MIXED_PORT: u16 = 7890;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedDnsServer {
    /// Numeric address avoids a resolver dependency before the encrypted DNS
    /// transport exists.
    pub address: IpAddr,
    /// TLS identity verified independently from the numeric dial address.
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSettings {
    pub mixed_port: u16,
    /// Loopback port of the application-owned clash-compatible controller. The
    /// address and the secret are not settings: see [`crate::ClashApiEndpoint`].
    pub controller_port: u16,
    pub enable_ipv6: bool,
    /// Whether ordinary DNS answers may advertise IPv6 destinations. This is
    /// independent of IPv6 packet capture, so an IPv4-only proxy exit never
    /// requires removing IPv6 from the Tunnel's protected route coverage.
    #[serde(default = "ipv6_dns_default", skip_serializing_if = "is_true")]
    pub ipv6_dns_enabled: bool,
    pub bypass_private_networks: bool,
    pub tunnel_mtu: u16,
    #[serde(default, skip_serializing_if = "EngineLogLevel::is_default")]
    pub log_level: EngineLogLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_proxy: Option<LanProxySettings>,
    /// Numeric resolvers dialled directly by libbox only while resolving a
    /// domain-named proxy endpoint. Defaults retain two independent endpoints;
    /// profile DNS can explicitly replace this with one to eight numeric servers.
    /// Engine startup never depends on the host resolver.
    pub bootstrap_dns_servers: [IpAddr; 2],
    /// HTTPS resolvers used for all ordinary engine DNS in both modes,
    /// including every hijacked Tunnel query. Their connections are detoured
    /// through the selected outbound and never use the direct bootstrap role.
    pub authenticated_dns_servers: [AuthenticatedDnsServer; 2],
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            mixed_port: DEFAULT_MIXED_PORT,
            controller_port: DEFAULT_CLASH_API_PORT,
            enable_ipv6: true,
            ipv6_dns_enabled: true,
            bypass_private_networks: true,
            tunnel_mtu: 1_500,
            log_level: EngineLogLevel::Info,
            lan_proxy: None,
            // Independent operators with strong connectivity in mainland
            // China. Callers can replace both numeric endpoints from trusted
            // pre-activation network state; domains are impossible by type.
            bootstrap_dns_servers: [
                IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
                IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
            ],
            authenticated_dns_servers: [
                AuthenticatedDnsServer {
                    address: IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                    server_name: "dns.alidns.com".to_owned(),
                },
                AuthenticatedDnsServer {
                    address: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    server_name: "cloudflare-dns.com".to_owned(),
                },
            ],
        }
    }
}

impl EngineSettings {
    /// Resolves the application-owned controller endpoint these settings open.
    ///
    /// The port comes from settings and is bounded; the loopback address and the
    /// per-run secret are owned by the application.
    pub fn clash_api_endpoint(&self) -> Result<ClashApiEndpoint, ConfigError> {
        ClashApiEndpoint::resolve(self.controller_port, self.mixed_port)
    }

    pub(crate) fn validate_listener_settings(&self) -> Result<(), ConfigError> {
        if let Some(lan) = &self.lan_proxy {
            lan.validate()?;
            if lan.port == self.mixed_port || lan.port == self.controller_port {
                return Err(invalid_settings(
                    "LAN, local proxy and controller ports must be distinct",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Fatal,
    Silent,
}

impl EngineLogLevel {
    fn is_default(&self) -> bool {
        *self == Self::Info
    }
}

/// LAN sharing is a separate listener; the local/controller endpoints stay
/// loopback-only. An explicit source allowlist precedes every routing action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanProxySettings {
    pub listen: Ipv4Addr,
    pub port: u16,
    pub allowed_source_cidrs: Vec<String>,
}

impl LanProxySettings {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if (!self.listen.is_unspecified() && !self.listen.is_private()) || self.port < 1024 {
            return Err(invalid_settings(
                "LAN sharing requires a private IPv4 or wildcard listener and a non-privileged port",
            ));
        }
        if self.allowed_source_cidrs.is_empty() || self.allowed_source_cidrs.len() > 32 {
            return Err(invalid_settings(
                "LAN sharing requires one to 32 trusted private IPv4 source ranges",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for cidr in &self.allowed_source_cidrs {
            let Some((address, prefix)) = cidr.split_once('/') else {
                return Err(invalid_settings("LAN source ranges must be IPv4 CIDRs"));
            };
            let address: Ipv4Addr = address
                .parse()
                .map_err(|_| invalid_settings("invalid LAN source IPv4 address"))?;
            let prefix: u32 = prefix
                .parse()
                .map_err(|_| invalid_settings("invalid LAN source prefix"))?;
            if prefix > 32 {
                return Err(invalid_settings("invalid LAN source prefix"));
            }
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            let value = u32::from(address);
            if value & mask != value
                || !address.is_private()
                || !Ipv4Addr::from(value | !mask).is_private()
                || format!("{address}/{prefix}") != *cidr
                || !seen.insert(cidr)
            {
                return Err(invalid_settings(
                    "LAN source ranges must be distinct canonical CIDRs within private IPv4 networks",
                ));
            }
        }
        Ok(())
    }
}

/// Persisted user choices. Automatic port selection is represented by None,
/// independently from the actual loopback port of a running engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePreferences {
    pub preferred_mixed_port: Option<u16>,
    pub log_level: EngineLogLevel,
    pub tunnel_mtu: u16,
    #[serde(default = "ipv6_dns_default", skip_serializing_if = "is_true")]
    pub ipv6_dns_enabled: bool,
    pub allow_lan: bool,
    pub lan_proxy: Option<LanProxySettings>,
}

impl Default for RuntimePreferences {
    fn default() -> Self {
        Self {
            preferred_mixed_port: None,
            log_level: EngineLogLevel::Info,
            tunnel_mtu: 1500,
            ipv6_dns_enabled: true,
            allow_lan: false,
            lan_proxy: None,
        }
    }
}

impl RuntimePreferences {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.allow_lan && self.lan_proxy.is_none() {
            return Err(invalid_settings(
                "configure the LAN listener and trusted source ranges before enabling sharing",
            ));
        }
        if self.preferred_mixed_port.is_some_and(|port| port < 1024) {
            return Err(invalid_settings(
                "the proxy port must be 1024..=65535, or automatic",
            ));
        }
        if !(1280..=9000).contains(&self.tunnel_mtu) {
            return Err(invalid_settings("TUN MTU must be 1280..=9000"));
        }
        if let Some(lan) = &self.lan_proxy {
            lan.validate()?;
        }
        Ok(())
    }

    pub fn apply_to(&self, mut settings: EngineSettings) -> Result<EngineSettings, ConfigError> {
        self.validate()?;
        if let Some(port) = self.preferred_mixed_port {
            settings.mixed_port = port;
        }
        settings.log_level = self.log_level;
        settings.tunnel_mtu = self.tunnel_mtu;
        settings.ipv6_dns_enabled = self.ipv6_dns_enabled;
        settings.lan_proxy = self.lan_proxy.clone().filter(|_| self.allow_lan);
        settings.validate_listener_settings()?;
        // The endpoint allocator chooses a distinct controller after applying
        // a user-selected mixed port; projection validates the final tuple.
        Ok(settings)
    }
}

fn invalid_settings(reason: &str) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: "$.runtime_settings".into(),
        reason: reason.into(),
    }
}

const fn ipv6_dns_default() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}
