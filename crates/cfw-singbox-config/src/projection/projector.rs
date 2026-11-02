//! The engine configuration projected from a validated profile.

use super::inbounds::inbounds;
use super::route::RouteSources;
use super::*;
use crate::dns_policy::BootstrapDnsServer;

impl ValidatedSingBoxProfile {
    /// A manual DNS choice wins over the imported policy without changing
    /// the profile or the Tunnel's IPv6 packet-capture setting.
    pub fn effective_ipv6_dns_enabled(&self, settings: &EngineSettings) -> bool {
        settings.enable_ipv6
            && settings.ipv6_dns_enabled.unwrap_or_else(|| {
                self.document
                    .dns
                    .as_ref()
                    .is_none_or(|policy| policy.ipv6 != Some(false))
            })
    }

    pub fn project(
        &self,
        profile_id: &str,
        mode: ProjectionMode,
        settings: &EngineSettings,
    ) -> Result<ProjectedConfig, ConfigError> {
        self.project_with_tunnel_stack(profile_id, mode, settings, TunnelStack::System)
    }

    /// Use the native backend's packet stack. The existing `project` entry point
    /// retains the CFM NetworkExtension contract and its exact template bytes.
    pub fn project_with_tunnel_stack(
        &self,
        profile_id: &str,
        mode: ProjectionMode,
        settings: &EngineSettings,
        tunnel_stack: TunnelStack,
    ) -> Result<ProjectedConfig, ConfigError> {
        settings.validate_listener_settings()?;
        let credential_audience = CredentialAudience::new(profile_id, self.digest())?;
        if !(1_280..=9_000).contains(&settings.tunnel_mtu) {
            return Err(ConfigError::InvalidTunnelMtu(settings.tunnel_mtu));
        }
        if self.release_packet_evidence_case.is_some() && mode != ProjectionMode::Tunnel {
            return Err(ConfigError::InvalidReleasePacketEvidenceMode);
        }
        let bootstrap_servers = self.bootstrap_dns_servers(settings)?;
        let direct_ipv4_hosts = self
            .release_packet_evidence_case
            .map_or_else(DirectIpv4HostRoutes::none, |case| case.direct_ipv4_hosts());

        let bootstrap_tags =
            crate::dns_policy::resolver_tags("cfw-bootstrap-dns", bootstrap_servers.len());
        let bootstrap_resolver = crate::dns_policy::resolver_value(&bootstrap_tags);
        let runtime_outbounds = self.document.runtime_outbounds(
            profile_id,
            DomainResolverTags {
                server: &bootstrap_tags[0],
                fallback_servers: &bootstrap_tags[1..],
            },
            self.proxy_selections(),
        )?;
        let selected_outbound = runtime_outbounds.selected_outbound.clone();
        let direct_outbound = runtime_outbounds.direct_outbound.clone();
        let global_outbound = runtime_outbounds.global_outbound.clone();
        let injected_route_final = runtime_outbounds.injected_route_final.clone();
        // Mainland China direct applies only where it can work: a profile
        // whose selected route is remote, because its datasets download
        // through that route and its foreign DNS pool uses it. It never
        // changes a release evidence projection, whatever that profile routes.
        let mainland = settings.mainland_china_direct
            && self.dns_projection == DnsProjection::Ordinary
            && self.release_packet_evidence_case.is_none()
            && self.document.selected_route_is_remote();
        let mainland_dns = mainland && self.document.dns.is_none();
        let mut outbounds = runtime_outbounds.outbounds;
        if mainland_dns {
            // DIRECT dials resolve through the DNS rules, so mainland names
            // reach the domestic resolvers and other names the proxied pool.
            for outbound in &mut outbounds {
                if outbound["type"] == "direct" {
                    outbound["domain_resolver"] = json!({"policy": "default"});
                }
            }
        }
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

        let dns = self.project_dns(
            mode,
            settings,
            &bootstrap_servers,
            &selected_outbound,
            &bootstrap_resolver,
            mainland_dns,
        )?;
        root.insert(
            "inbounds".into(),
            Value::Array(inbounds(mode, settings, tunnel_stack)?),
        );
        root.insert("dns".into(), dns.section);
        let route = self.project_route(
            mode,
            tunnel_stack,
            settings,
            RouteSources {
                selected_outbound: &selected_outbound,
                direct_outbound: &direct_outbound,
                global_outbound: &global_outbound,
                injected_route_final,
                default_domain_resolver: dns.default_domain_resolver,
                profile_dns_rule_sets: dns.rule_sets,
                mainland,
            },
        );
        // The routing cache keeps the rule sets the route names and the
        // fake-IP store between runs.
        let needs_routing_cache = route.contains_key("rule_set");
        if needs_routing_cache || dns.fake_ip {
            let mut cache =
                json!({"enabled": true, "path": ROUTING_CACHE_PATH, "cache_id": profile_id});
            if dns.fake_ip {
                cache["store_fakeip"] = json!(true);
            }
            root.get_mut("experimental")
                .expect("app-owned experimental settings")["cache_file"] = cache;
        }
        if !route.is_empty() {
            root.insert("route".into(), Value::Object(route));
        }
        seal(
            Value::Object(root),
            mode,
            settings,
            credential_audience,
            credential_slots,
            clash_api,
            direct_ipv4_hosts,
        )
    }

    /// The resolvers for the host names of DNS and proxy servers: the
    /// profile's own bootstrap pool, else the one its DNS policy inherits,
    /// else the application's defaults.
    fn bootstrap_dns_servers(
        &self,
        settings: &EngineSettings,
    ) -> Result<Vec<BootstrapDnsServer>, ConfigError> {
        let default_bootstrap = settings
            .bootstrap_dns_servers
            .iter()
            .copied()
            .map(crate::dns_policy::BootstrapDnsServer::Address)
            .collect::<Vec<_>>();
        let explicit_bootstrap = self
            .document
            .dns
            .as_ref()
            .and_then(|dns| dns.bootstrap_servers.as_deref());
        let inherited_bootstrap = if explicit_bootstrap.is_none() {
            self.document
                .dns
                .as_ref()
                .map(|dns| dns.inherited_bootstrap_servers(settings.enable_ipv6))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let bootstrap_servers = explicit_bootstrap
            .or_else(|| (!inherited_bootstrap.is_empty()).then_some(inherited_bootstrap.as_slice()))
            .unwrap_or(&default_bootstrap);
        if self.dns_projection == DnsProjection::Ordinary {
            crate::dns_policy::validate_bootstrap_pool(bootstrap_servers)?;
        }
        Ok(bootstrap_servers.to_vec())
    }
}

/// Checks a projected template's credential slots and size, and binds its
/// digest, mode and network options into the configuration identity.
fn seal(
    template: Value,
    mode: ProjectionMode,
    settings: &EngineSettings,
    credential_audience: CredentialAudience,
    credential_slots: Vec<CredentialSlot>,
    clash_api: ClashApiEndpoint,
    direct_ipv4_hosts: DirectIpv4HostRoutes,
) -> Result<ProjectedConfig, ConfigError> {
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
    let digest = configuration_identity_digest(
        &configuration_digest,
        &credential_audience,
        &credential_slots,
        mode,
        &network_options,
    )?;
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
