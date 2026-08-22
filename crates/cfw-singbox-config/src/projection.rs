use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    ConfigError, CredentialAudience, CredentialSlot, DirectIpv4HostRoutes,
    MINIMUM_REMOTE_TLS_VERSION, ValidatedSingBoxProfile,
    controller::{ClashApiEndpoint, DEFAULT_CLASH_API_PORT},
    credentials::validate_slots,
    profile_projection::DomainResolverTags,
    sha256_hex,
    validation::{DnsProjection, canonicalize},
};

const BOOTSTRAP_DNS_PRIMARY_TAG: &str = "cfw-bootstrap-dns-0";
const BOOTSTRAP_DNS_FALLBACK_TAG: &str = "cfw-bootstrap-dns-1";
const AUTHENTICATED_DNS_PRIMARY_TAG: &str = "cfw-authenticated-dns-0";
const AUTHENTICATED_DNS_SECONDARY_TAG: &str = "cfw-authenticated-dns-1";

/// Preferred loopback TCP port for the application-owned mixed inbound.
///
/// The application shell may choose a different bounded port before it
/// projects a runtime configuration. Keeping the preferred value in the
/// projection crate prevents the selection policy and default settings from
/// drifting apart.
pub const DEFAULT_MIXED_PORT: u16 = 7890;

/// Schema of the configuration identity document shared with the macOS engine
/// owner protocol. This changes whenever fields that cross that boundary gain
/// new closed vocabulary.
pub const CONFIGURATION_IDENTITY_SCHEMA_VERSION: u16 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAddressPlan {
    pub ipv4_address: &'static str,
    pub ipv4_prefix_length: u8,
    pub ipv4_dns_peer: &'static str,
    pub ipv6_address: &'static str,
    pub ipv6_prefix_length: u8,
    pub ipv6_dns_peer: &'static str,
}

pub const TUNNEL_ADDRESS_PLAN: TunnelAddressPlan = TunnelAddressPlan {
    ipv4_address: "198.18.64.1",
    ipv4_prefix_length: 30,
    ipv4_dns_peer: "198.18.64.2",
    ipv6_address: "2001:2:0:64::1",
    ipv6_prefix_length: 126,
    ipv6_dns_peer: "2001:2:0:64::2",
};

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
    pub bypass_private_networks: bool,
    pub tunnel_mtu: u16,
    /// Numeric resolvers dialled directly by libbox only while resolving a
    /// domain-named proxy endpoint. Exactly two are retained so engine startup
    /// never depends on the host resolver and fallback remains bounded.
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
            bypass_private_networks: true,
            tunnel_mtu: 1_500,
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
                    address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                    server_name: "doh.pub".to_owned(),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMode {
    SystemProxy,
    Tunnel,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProjectedConfig {
    mode: ProjectionMode,
    credential_audience: CredentialAudience,
    json: String,
    credential_slots: Vec<CredentialSlot>,
    clash_api: ClashApiEndpoint,
    configuration_digest: String,
    direct_ipv4_hosts: DirectIpv4HostRoutes,
    digest: String,
}

impl fmt::Debug for ProjectedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedConfig")
            .field("mode", &self.mode)
            .field("credential_audience", &self.credential_audience)
            .field("credential_slots", &self.credential_slots)
            .field("clash_api", &self.clash_api)
            .field("configuration_digest", &self.configuration_digest)
            .field("direct_ipv4_hosts", &self.direct_ipv4_hosts)
            .field("digest", &self.digest)
            .field("json", &"[REDACTED CONFIG TEMPLATE]")
            .finish()
    }
}

impl ProjectedConfig {
    pub fn mode(&self) -> ProjectionMode {
        self.mode
    }

    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.credential_audience
    }

    pub fn as_json(&self) -> &str {
        &self.json
    }

    pub fn credential_slots(&self) -> &[CredentialSlot] {
        &self.credential_slots
    }

    /// The application-owned controller this configuration exposes.
    pub fn clash_api(&self) -> ClashApiEndpoint {
        self.clash_api
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    pub fn direct_ipv4_hosts(&self) -> DirectIpv4HostRoutes {
        self.direct_ipv4_hosts
    }
}

impl ValidatedSingBoxProfile {
    pub fn project(
        &self,
        profile_id: &str,
        mode: ProjectionMode,
        settings: &EngineSettings,
    ) -> Result<ProjectedConfig, ConfigError> {
        let credential_audience = CredentialAudience::new(profile_id, self.digest())?;
        if !(1_280..=9_000).contains(&settings.tunnel_mtu) {
            return Err(ConfigError::InvalidTunnelMtu(settings.tunnel_mtu));
        }
        if self.release_packet_evidence_case.is_some() && mode != ProjectionMode::Tunnel {
            return Err(ConfigError::InvalidReleasePacketEvidenceMode);
        }
        if self.dns_projection == DnsProjection::Ordinary {
            validate_bootstrap_dns_servers(settings)?;
        }
        let direct_ipv4_hosts = self
            .release_packet_evidence_case
            .map_or_else(DirectIpv4HostRoutes::none, |case| case.direct_ipv4_hosts());

        let runtime_outbounds = self.document.runtime_outbounds(DomainResolverTags {
            server: BOOTSTRAP_DNS_PRIMARY_TAG,
            fallback_server: BOOTSTRAP_DNS_FALLBACK_TAG,
        })?;
        let selected_outbound = runtime_outbounds.selected_outbound.clone();
        let injected_route_final = runtime_outbounds.injected_route_final.clone();
        let outbounds = runtime_outbounds.outbounds;
        let credential_slots = runtime_outbounds.credential_slots;
        let clash_api = settings.clash_api_endpoint()?;
        let mut root = Map::new();
        root.insert("log".into(), json!({ "level": "info", "timestamp": true }));
        // `experimental` is forbidden in imported profiles; the clash-compatible
        // controller exists only because the application injects it here, bound
        // to loopback and to this run's secret.
        root.insert("experimental".into(), clash_api.experimental_value());
        root.insert("outbounds".into(), Value::Array(outbounds));

        let (dns_servers, dns_rule_server, default_domain_resolver) = match self.dns_projection {
            DnsProjection::Ordinary => {
                validate_authenticated_dns_servers(settings)?;
                let mut servers = settings
                    .bootstrap_dns_servers
                    .iter()
                    .enumerate()
                    .map(|(index, address)| {
                        json!({
                            "type": "udp",
                            "tag": format!("cfw-bootstrap-dns-{index}"),
                            "server": address.to_string(),
                            "server_port": 53
                        })
                    })
                    .collect::<Vec<_>>();
                servers.extend(settings.authenticated_dns_servers.iter().enumerate().map(
                    |(index, address)| {
                        json!({
                            "type": "https",
                            "tag": format!("cfw-authenticated-dns-{index}"),
                            "server": address.address.to_string(),
                            "server_port": 443,
                            "path": "/dns-query",
                            "detour": selected_outbound.as_str(),
                            "connect_timeout": "5s",
                            "tls": {
                                "enabled": true,
                                "server_name": address.server_name.as_str(),
                                "min_version": MINIMUM_REMOTE_TLS_VERSION
                            }
                        })
                    },
                ));
                (
                    servers,
                    AUTHENTICATED_DNS_PRIMARY_TAG,
                    json!({
                        "server": AUTHENTICATED_DNS_PRIMARY_TAG,
                        "fallback_server": AUTHENTICATED_DNS_SECONDARY_TAG,
                    }),
                )
            }
            DnsProjection::ReleaseEvidence(case) => {
                if mode != ProjectionMode::Tunnel || !settings.enable_ipv6 {
                    return Err(ConfigError::InvalidReleaseDnsEvidenceMode);
                }
                let endpoint = case.endpoint();
                (
                    vec![json!({
                        "type": "udp",
                        "tag": endpoint.tag,
                        "server": endpoint.address.to_string(),
                        "server_port": endpoint.port,
                        "detour": selected_outbound.as_str(),
                    })],
                    endpoint.tag,
                    json!({ "server": endpoint.tag }),
                )
            }
        };

        let inbound = match mode {
            ProjectionMode::SystemProxy => {
                if settings.mixed_port == 0 {
                    return Err(ConfigError::InvalidMixedPort);
                }
                json!({
                    "type": "mixed",
                    "tag": "cfw-system-proxy",
                    "listen": "127.0.0.1",
                    "listen_port": settings.mixed_port
                })
            }
            ProjectionMode::Tunnel => {
                let mut addresses = vec![format!(
                    "{}/{}",
                    TUNNEL_ADDRESS_PLAN.ipv4_address, TUNNEL_ADDRESS_PLAN.ipv4_prefix_length
                )];
                if settings.enable_ipv6 {
                    addresses.push(format!(
                        "{}/{}",
                        TUNNEL_ADDRESS_PLAN.ipv6_address, TUNNEL_ADDRESS_PLAN.ipv6_prefix_length
                    ));
                }
                json!({
                    "type": "tun",
                    "tag": "cfw-tunnel",
                    "address": addresses,
                    // NetworkExtension owns route installation. The embedded
                    // engine only processes packets supplied by the public
                    // packet-flow adapter and never mutates host routes.
                    "auto_route": false,
                    "stack": "system",
                    "mtu": settings.tunnel_mtu
                })
            }
        };
        root.insert("inbounds".into(), Value::Array(vec![inbound]));
        root.insert(
            "dns".into(),
            json!({
                "servers": dns_servers,
                "rules": [{
                    // The pinned source patch retries both rejected responses
                    // and bounded transport errors against the final server.
                    // Upstream 1.13 alone does not.
                    "ip_accept_any": true,
                    "action": "route",
                    "server": dns_rule_server
                }],
                "final": match self.dns_projection {
                    DnsProjection::Ordinary => AUTHENTICATED_DNS_SECONDARY_TAG,
                    DnsProjection::ReleaseEvidence(case) => case.endpoint().tag,
                },
                "strategy": if settings.enable_ipv6 { "prefer_ipv4" } else { "ipv4_only" }
            }),
        );

        let mut route = Map::new();
        if let Some(final_tag) = self
            .document
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            .cloned()
            .or(injected_route_final)
        {
            route.insert("final".into(), Value::String(final_tag));
        }
        route.insert("default_domain_resolver".into(), default_domain_resolver);
        if mode == ProjectionMode::Tunnel {
            route.insert(
                "rules".into(),
                json!([{ "port": 53, "action": "hijack-dns" }]),
            );
        }
        if !route.is_empty() {
            root.insert("route".into(), Value::Object(route));
        }

        let template = Value::Object(root);
        validate_slots(&template, &credential_slots)?;
        let canonical_template = canonicalize(template);
        let json = serde_json::to_string(&canonical_template)?;
        if json.len() > crate::MAX_ENGINE_CONFIG_BYTES {
            return Err(ConfigError::ProjectedTooLarge {
                actual: json.len(),
                maximum: crate::MAX_ENGINE_CONFIG_BYTES,
            });
        }
        let configuration_digest = sha256_hex(json.as_bytes());
        let network_options = match mode {
            ProjectionMode::SystemProxy => Value::Null,
            ProjectionMode::Tunnel => json!({
                "bypass_private_networks": settings.bypass_private_networks,
                "direct_ipv4_hosts": direct_ipv4_hosts,
                "ipv6_enabled": settings.enable_ipv6,
                "mtu": settings.tunnel_mtu,
            }),
        };
        let identity = canonicalize(json!({
            "configuration_sha256": configuration_digest,
            "credential_audience": credential_audience,
            "credential_slots": credential_slots,
            "mode": match mode {
                ProjectionMode::SystemProxy => "system_proxy",
                ProjectionMode::Tunnel => "tunnel",
            },
            "network_options": network_options,
            "schema_version": CONFIGURATION_IDENTITY_SCHEMA_VERSION,
        }));
        let digest = sha256_hex(serde_json::to_string(&identity)?.as_bytes());
        Ok(ProjectedConfig {
            mode,
            credential_audience,
            json,
            credential_slots,
            clash_api,
            configuration_digest,
            direct_ipv4_hosts,
            digest,
        })
    }
}

fn validate_bootstrap_dns_servers(settings: &EngineSettings) -> Result<(), ConfigError> {
    let unique = settings
        .bootstrap_dns_servers
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if unique.len() != settings.bootstrap_dns_servers.len() {
        return Err(ConfigError::InvalidBootstrapDnsServers(
            "the two numeric endpoints must be distinct".to_owned(),
        ));
    }
    for address in settings.bootstrap_dns_servers {
        if !settings.enable_ipv6 && address.is_ipv6() {
            return Err(ConfigError::InvalidBootstrapDnsServers(format!(
                "IPv6 endpoint {address} is unavailable while IPv6 is disabled"
            )));
        }
        if dns_address_is_unusable(address) {
            return Err(ConfigError::InvalidBootstrapDnsServers(format!(
                "endpoint {address} is loopback, link-local, multicast, documentation, or reserved for the tunnel"
            )));
        }
    }
    Ok(())
}

fn validate_authenticated_dns_servers(settings: &EngineSettings) -> Result<(), ConfigError> {
    let unique_addresses = settings
        .authenticated_dns_servers
        .iter()
        .map(|server| server.address)
        .collect::<BTreeSet<_>>();
    if unique_addresses.len() != settings.authenticated_dns_servers.len() {
        return Err(ConfigError::InvalidAuthenticatedDnsServers(
            "the two authenticated DNS endpoints must be distinct".to_owned(),
        ));
    }
    for server in &settings.authenticated_dns_servers {
        if !settings.enable_ipv6 && server.address.is_ipv6() {
            return Err(ConfigError::InvalidAuthenticatedDnsServers(format!(
                "authenticated IPv6 endpoint {} is unavailable while IPv6 is disabled",
                server.address
            )));
        }
        if dns_address_is_unusable(server.address) || !is_valid_tls_dns_name(&server.server_name) {
            return Err(ConfigError::InvalidAuthenticatedDnsServers(format!(
                "authenticated endpoint {} has an unusable address or TLS server name",
                server.address
            )));
        }
    }
    Ok(())
}

fn is_valid_tls_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.trim() == name
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn dns_address_is_unusable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}
