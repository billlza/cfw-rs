//! The `dns` section: the servers, rules and policies of one projection, and
//! the application-owned DNS-over-HTTPS servers with the checks their pools pass.

use super::*;
use crate::dns_policy::BootstrapDnsServer;

const AUTHENTICATED_DNS_PRIMARY_TAG: &str = "cfw-authenticated-dns-0";
const AUTHENTICATED_DNS_SECONDARY_TAG: &str = "cfw-authenticated-dns-1";

/// The projected `dns` section and what the route and cache take from it.
pub(super) struct ProjectedDns {
    pub(super) section: Value,
    /// Whether the section answers with fake IPs, which the cache file stores.
    pub(super) fake_ip: bool,
    pub(super) rule_sets: Vec<Value>,
    pub(super) default_domain_resolver: Value,
}

impl ValidatedSingBoxProfile {
    /// The DNS servers, rules and policies of one projection: the profile's
    /// own policy, else the application's authenticated pool (with the
    /// domestic resolvers when mainland China direct routes DNS), or the
    /// single resolver of a release DNS evidence case.
    pub(super) fn project_dns(
        &self,
        mode: ProjectionMode,
        settings: &EngineSettings,
        bootstrap_servers: &[BootstrapDnsServer],
        selected_outbound: &str,
        bootstrap_resolver: &Value,
        mainland_dns: bool,
    ) -> Result<ProjectedDns, ConfigError> {
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
                            selected_outbound,
                            bootstrap_resolver,
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
                        let pool = if mainland_dns {
                            crate::mainland::foreign_resolvers()
                        } else {
                            settings.authenticated_dns_servers.clone()
                        };
                        validate_authenticated_dns_pool(&pool, settings.enable_ipv6)?;
                        servers.extend(pool.iter().enumerate().map(|(index, server)| {
                            doh_server(
                                &format!("cfw-authenticated-dns-{index}"),
                                server,
                                Some(selected_outbound),
                            )
                        }));
                        if mainland_dns {
                            servers.extend(crate::mainland::dns_servers(|tag, server| {
                                doh_server(tag, server, None)
                            }));
                        }
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
                            "detour": selected_outbound,
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
            matches!(outbound, crate::profile::ProfileOutbound::Direct { tag } if tag == selected_outbound)
        }) {
            for server in &mut dns_servers {
                server.as_object_mut().expect("DNS projection is an object").remove("detour");
            }
        }

        let dns_ipv6 = self.effective_ipv6_dns_enabled(settings);
        let mut section = json!({
            "servers": dns_servers,

            "rules": profile_dns_rules.unwrap_or_else(|| {
                let mut rules = if mainland_dns {
                    crate::mainland::dns_rules()
                } else {
                    Vec::new()
                };
                crate::dns_policy::append_evaluated_server(
                    &mut rules, &dns_rule_server, &json!({"domain_regex":".*"}), None,
                );
                rules
            }),
            "final": dns_final_server,
            "strategy": if dns_ipv6 { "prefer_ipv4" } else { "ipv4_only" }
        });
        if !profile_dns_policies.is_empty() {
            section["policies"] = json!(profile_dns_policies);
        }
        let fake_ip = self.dns_projection == DnsProjection::Ordinary
            && crate::dns_policy::augment_dns(
                &self.document,
                &mut section,
                mode.has_tunnel(),
                dns_ipv6,
            );
        Ok(ProjectedDns {
            section,
            fake_ip,
            rule_sets: profile_dns_rule_sets,
            default_domain_resolver,
        })
    }
}

/// One application-owned DNS-over-HTTPS server. Without `detour` the
/// ordinary dialer goes DIRECT.
pub(super) fn doh_server(
    tag: &str,
    server: &crate::engine_settings::AuthenticatedDnsServer,
    detour: Option<&str>,
) -> Value {
    let mut value = json!({
        "type": "https",
        "tag": tag,
        "server": server.address.to_string(),
        "server_port": 443,
        "path": "/dns-query",
        "connect_timeout": "5s",
        "tls": {
            "enabled": true,
            "server_name": server.server_name.as_str(),
            "min_version": MINIMUM_REMOTE_TLS_VERSION
        }
    });
    if let Some(detour) = detour {
        value["detour"] = json!(detour);
    }
    value
}

/// The checks every DNS-over-HTTPS pool the application owns must pass.
pub(crate) fn validate_authenticated_dns_pool(
    servers: &[crate::engine_settings::AuthenticatedDnsServer],
    enable_ipv6: bool,
) -> Result<(), ConfigError> {
    let unique_addresses = servers
        .iter()
        .map(|server| server.address)
        .collect::<BTreeSet<_>>();
    if unique_addresses.len() != servers.len() {
        return Err(ConfigError::InvalidAuthenticatedDnsServers(
            "the two authenticated DNS endpoints must be distinct".to_owned(),
        ));
    }
    for server in servers {
        if !enable_ipv6 && server.address.is_ipv6() {
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
