//! The engine configuration projected from a validated profile.

use super::dns_servers::doh_server;
use super::*;

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
                                Some(selected_outbound.as_str()),
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
                    "tag": SYSTEM_PROXY_INBOUND_TAG,
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
                    "tag": TUNNEL_INBOUND_TAG,
                    "address": addresses,
                    // The native platform owner installs routes. This engine
                    // processes only the packets supplied by that owner.
                    "auto_route": false,
                    "stack": tunnel_stack.as_str(),
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
                "tag": SYSTEM_PROXY_INBOUND_TAG,
                "listen": "127.0.0.1",
                "listen_port": settings.mixed_port,
            }));
        }
        if let Some(lan) = &settings.lan_proxy {
            inbounds.push(crate::lan::inbound(lan));
        }
        root.insert("inbounds".into(), Value::Array(inbounds));
        let dns_ipv6 = self.effective_ipv6_dns_enabled(settings);
        root.insert(
            "dns".into(),
            json!({
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
        let appended = if mainland {
            crate::mainland::route_rules(&direct_outbound, &selected_outbound).to_vec()
        } else {
            Vec::new()
        };
        let (mut rules, mut rule_sets) = self.document.project_rules(&selected_outbound, &appended);
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
            // DNS leak protection applies to every ordinary Tunnel projection,
            // whatever the selected route, and never to release evidence.
            if settings.dns_leak_protection
                && self.dns_projection == DnsProjection::Ordinary
                && self.release_packet_evidence_case.is_none()
            {
                rules.insert(1, crate::dns_leak::route_rule());
            }
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
                json!({"enabled": true, "path": ROUTING_CACHE_PATH, "cache_id": profile_id});
            if fake_ip {
                cache["store_fakeip"] = json!(true);
            }
            root.get_mut("experimental")
                .expect("app-owned experimental settings")["cache_file"] = cache;
        }
        // The Windows packet-endpoint stack runs the engine as an ordinary
        // process while its platform owner routes the default route into the
        // tunnel adapter. Outside any Network Extension exemption, its own
        // sockets must bind to the physical default interface or they would
        // loop back into the tunnel.
        if mode.has_tunnel() && tunnel_stack == TunnelStack::Gvisor {
            route.insert("auto_detect_interface".into(), Value::Bool(true));
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
}
