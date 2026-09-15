pub use crate::engine_settings::{AuthenticatedDnsServer, DEFAULT_MIXED_PORT, EngineSettings};

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    ConfigError, CredentialAudience, CredentialSlot, DirectIpv4HostRoutes,
    MINIMUM_REMOTE_TLS_VERSION, ValidatedSingBoxProfile,
    controller::ClashApiEndpoint,
    credentials::validate_slots,
    profile_projection::DomainResolverTags,
    sha256_hex,
    validation::{DnsProjection, canonicalize},
};

const AUTHENTICATED_DNS_PRIMARY_TAG: &str = "cfw-authenticated-dns-0";
const AUTHENTICATED_DNS_SECONDARY_TAG: &str = "cfw-authenticated-dns-1";

/// Schema of the configuration identity document shared with the macOS engine
/// owner protocol. This changes whenever fields that cross that boundary gain
/// new closed vocabulary.
pub const CONFIGURATION_IDENTITY_SCHEMA_VERSION: u16 = 7;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionMode {
    LocalProxy,
    SystemProxy,
    Tunnel,
    TunnelSystemProxy,
}

impl ProjectionMode {
    pub const fn has_tunnel(self) -> bool {
        matches!(self, Self::Tunnel | Self::TunnelSystemProxy)
    }
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
    /// A transient, outbound-only view for explicit node latency tests. The
    /// normal projection remains the source of protocol/DNS/credential policy;
    /// listeners, system routes, persistence and autonomous tests are excluded.
    pub fn proxy_probe_json(&self) -> Result<String, ConfigError> {
        let mut root: Map<String, Value> = serde_json::from_str(&self.json)?;
        root.retain(|key, _| matches!(key.as_str(), "outbounds" | "endpoints" | "dns"));
        let mut original: Value = serde_json::from_str(&self.json)?;
        if let Some(resolver) = original["route"].get_mut("default_domain_resolver") {
            root.insert(
                "route".into(),
                json!({"default_domain_resolver": resolver.take()}),
            );
        }
        if let Some(Value::Array(outbounds)) = root.get_mut("outbounds") {
            for outbound in outbounds {
                if matches!(
                    outbound["type"].as_str(),
                    Some("urltest" | "fallback" | "loadbalance")
                ) {
                    *outbound = json!({
                        "type": "selector",
                        "tag": outbound["tag"],
                        "outbounds": outbound["outbounds"],
                    });
                }
            }
        }
        Ok(serde_json::to_string(&root)?)
    }

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
        settings.validate_listener_settings()?;
        let credential_audience = CredentialAudience::new(profile_id, self.digest())?;
        if !(1_280..=9_000).contains(&settings.tunnel_mtu) {
            return Err(ConfigError::InvalidTunnelMtu(settings.tunnel_mtu));
        }
        if self.release_packet_evidence_case.is_some() && mode != ProjectionMode::Tunnel {
            return Err(ConfigError::InvalidReleasePacketEvidenceMode);
        }
        let default_bootstrap = settings
            .bootstrap_dns_servers
            .iter()
            .copied()
            .map(crate::dns_policy::BootstrapDnsServer::Address)
            .collect::<Vec<_>>();
        let bootstrap_servers = self
            .document
            .dns
            .as_ref()
            .and_then(|dns| dns.bootstrap_servers.as_deref())
            .unwrap_or(&default_bootstrap);
        if self.dns_projection == DnsProjection::Ordinary {
            crate::dns_policy::validate_bootstrap_pool(bootstrap_servers)?;
        }
        let direct_ipv4_hosts = self
            .release_packet_evidence_case
            .map_or_else(DirectIpv4HostRoutes::none, |case| case.direct_ipv4_hosts());

        let bootstrap_tags =
            crate::dns_policy::resolver_tags("cfw-bootstrap-dns", bootstrap_servers.len());
        let bootstrap_resolver = crate::dns_policy::resolver_value(&bootstrap_tags);
        let runtime_outbounds = self.document.runtime_outbounds(DomainResolverTags {
            server: &bootstrap_tags[0],
            fallback_servers: &bootstrap_tags[1..],
        })?;
        let selected_outbound = runtime_outbounds.selected_outbound.clone();
        let direct_outbound = runtime_outbounds.direct_outbound.clone();
        let global_outbound = runtime_outbounds.global_outbound.clone();
        let injected_route_final = runtime_outbounds.injected_route_final.clone();
        let outbounds = runtime_outbounds.outbounds;
        let credential_slots = runtime_outbounds.credential_slots;
        let clash_api = settings.clash_api_endpoint()?;
        let mut root = Map::new();
        root.insert(
            "log".into(),
            json!({ "level": settings.log_level, "timestamp": true }),
        );
        if settings.log_level == crate::EngineLogLevel::Silent {
            root.insert("log".into(), json!({"disabled":true}));
        }
        // `experimental` is forbidden in imported profiles; the clash-compatible
        // controller exists only because the application injects it here, bound
        // to loopback and to this run's secret.
        root.insert("experimental".into(), clash_api.experimental_value());
        root.insert("outbounds".into(), Value::Array(outbounds));
        if !runtime_outbounds.endpoints.is_empty() {
            root.insert(
                "endpoints".into(),
                Value::Array(runtime_outbounds.endpoints),
            );
        }

        let mut profile_dns_rules = None;
        let mut profile_dns_policies = Vec::new();
        let mut profile_dns_rule_sets = Vec::new();
        let (mut dns_servers, dns_rule_server, dns_final_server, default_domain_resolver) =
            match self.dns_projection {
                DnsProjection::Ordinary => {
                    let mut servers = bootstrap_servers
                        .iter()
                        .enumerate()
                        .map(|(index, server)| {
                            server.project(
                                &format!("cfw-bootstrap-dns-{index}"),
                                settings.enable_ipv6,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if self.document.dns.is_some() {
                        let projected = crate::dns_policy::project_profile_dns(
                            &self.document,
                            &selected_outbound,
                            &bootstrap_resolver,
                            settings.enable_ipv6,
                        )?;
                        servers.extend(projected.servers);
                        profile_dns_rules = Some(projected.rules);
                        profile_dns_policies = projected.policies;
                        profile_dns_rule_sets = projected.rule_sets;
                        (
                            servers,
                            "cfw-profile-dns-0".to_owned(),
                            projected.final_server,
                            projected.default_resolver,
                        )
                    } else {
                        validate_authenticated_dns_servers(settings)?;
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
                            AUTHENTICATED_DNS_PRIMARY_TAG.to_owned(),
                            AUTHENTICATED_DNS_SECONDARY_TAG.to_owned(),
                            json!({
                                "server": AUTHENTICATED_DNS_PRIMARY_TAG,
                                "fallback_server": AUTHENTICATED_DNS_SECONDARY_TAG,
                            }),
                        )
                    }
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
                        endpoint.tag.to_owned(),
                        endpoint.tag.to_owned(),
                        json!({ "server": endpoint.tag }),
                    )
                }
            };
        // The pinned runtime rejects an explicit detour to an empty DIRECT
        // outbound. Its ordinary dialer already implements that exact policy.
        // This is selected DIRECT behavior, never a fallback after proxy failure.
        if self.document.outbounds.iter().any(|outbound| {
            matches!(outbound, crate::profile::ProfileOutbound::Direct { tag } if tag == &selected_outbound)
        }) {
            for server in &mut dns_servers {
                server.as_object_mut().expect("DNS projection is an object").remove("detour");
            }
        }

        let inbound = match mode {
            ProjectionMode::LocalProxy | ProjectionMode::SystemProxy => {
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
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => {
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
        let mut inbounds = vec![inbound];
        if mode == ProjectionMode::TunnelSystemProxy {
            if settings.mixed_port == 0 {
                return Err(ConfigError::InvalidMixedPort);
            }
            inbounds.push(json!({
                "type": "mixed",
                "tag": "cfw-system-proxy",
                "listen": "127.0.0.1",
                "listen_port": settings.mixed_port,
            }));
        }
        if let Some(lan) = &settings.lan_proxy {
            inbounds.push(crate::lan::inbound(lan));
        }
        root.insert("inbounds".into(), Value::Array(inbounds));
        let dns_ipv6 = settings.enable_ipv6
            && settings.ipv6_dns_enabled
            && self
                .document
                .dns
                .as_ref()
                .is_none_or(|policy| policy.ipv6 != Some(false));
        root.insert(
            "dns".into(),
            json!({
                "servers": dns_servers,

                "rules": profile_dns_rules.unwrap_or_else(|| {
                    let mut rules = Vec::new();
                    crate::dns_policy::append_evaluated_server(
                        &mut rules, &dns_rule_server, &json!({"domain_regex":".*"}), None,
                    );
                    rules
                }),
                "final": dns_final_server,
                "strategy": if dns_ipv6 { "prefer_ipv4" } else { "ipv4_only" }
            }),
        );
        if !profile_dns_policies.is_empty() {
            root.get_mut("dns").expect("DNS configuration")["policies"] =
                json!(profile_dns_policies);
        }
        let fake_ip = self.dns_projection == DnsProjection::Ordinary
            && crate::dns_policy::augment_dns(
                &self.document,
                root.get_mut("dns").expect("app-owned DNS settings"),
                mode.has_tunnel(),
                dns_ipv6,
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
        let (mut rules, mut rule_sets) = self.document.project_rules(&selected_outbound);
        for resource in profile_dns_rule_sets {
            if !rule_sets
                .iter()
                .any(|existing| existing["tag"] == resource["tag"])
            {
                rule_sets.push(resource);
            }
        }
        rules.splice(
            0..0,
            [
                json!({"clash_mode": "Direct", "action": "route", "outbound": direct_outbound}),
                json!({"clash_mode": "Global", "action": "route", "outbound": global_outbound}),
            ],
        );
        crate::dns_policy::add_connection_dns_rules(
            &self.document,
            &mut rules,
            &direct_outbound,
            route
                .get("final")
                .and_then(Value::as_str)
                .unwrap_or(&selected_outbound),
        );
        if mode.has_tunnel() {
            rules.insert(0, json!({ "port": 53, "action": "hijack-dns" }));
        }
        if let Some(lan) = &settings.lan_proxy {
            rules.insert(0, crate::lan::access_rule(lan));
        }
        if !rules.is_empty() {
            route.insert("rules".into(), Value::Array(rules));
        }
        let needs_routing_cache = !rule_sets.is_empty();
        if needs_routing_cache {
            route.insert("rule_set".into(), Value::Array(rule_sets));
        }
        if needs_routing_cache || fake_ip {
            let mut cache =
                json!({"enabled": true, "path": "routing-cache.db", "cache_id": profile_id});
            if fake_ip {
                cache["store_fakeip"] = json!(true);
            }
            root.get_mut("experimental")
                .expect("app-owned experimental settings")["cache_file"] = cache;
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
        let mut network_options = match mode {
            ProjectionMode::LocalProxy | ProjectionMode::SystemProxy => Value::Null,
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => json!({
                "bypass_private_networks": settings.bypass_private_networks,
                "direct_ipv4_hosts": direct_ipv4_hosts,
                "ipv6_enabled": settings.enable_ipv6,
                "mtu": settings.tunnel_mtu,
            }),
        };
        if mode == ProjectionMode::TunnelSystemProxy {
            network_options["system_proxy_port"] = json!(settings.mixed_port);
        }
        let identity = canonicalize(json!({
            "configuration_sha256": configuration_digest,
            "credential_audience": credential_audience,
            "credential_slots": credential_slots,
            "mode": match mode {
                ProjectionMode::LocalProxy => "local_proxy",
                ProjectionMode::SystemProxy => "system_proxy",
                ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => "tunnel",
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
