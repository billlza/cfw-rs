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

/// Compute the shared native-boundary identity without changing its schema.
/// This is a canonical digest calculation, not request/lease authorization;
/// callers separately validate mode, options and credential-slot semantics.
pub fn configuration_identity_digest(
    configuration_sha256: &str,
    credential_audience: &CredentialAudience,
    credential_slots: &[CredentialSlot],
    mode: ProjectionMode,
    network_options: &impl Serialize,
) -> Result<String, serde_json::Error> {
    let identity = canonicalize(json!({
        "configuration_sha256": configuration_sha256,
        "credential_audience": credential_audience,
        "credential_slots": credential_slots,
        "mode": match mode {
            ProjectionMode::LocalProxy => "local_proxy",
            ProjectionMode::SystemProxy => "system_proxy",
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => "tunnel",
        },
        "network_options": serde_json::to_value(network_options)?,
        "schema_version": CONFIGURATION_IDENTITY_SCHEMA_VERSION,
    }));
    Ok(sha256_hex(serde_json::to_string(&identity)?.as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAddressPlan {
    pub ipv4_address: &'static str,
    pub ipv4_prefix_length: u8,
    pub ipv4_dns_peer: &'static str,
    pub ipv6_address: &'static str,
    pub ipv6_prefix_length: u8,
    pub ipv6_dns_peer: &'static str,
}

/// Application-owned identities in every projection. Native admission
/// boundaries compare these exact values; they are not profile choices.
pub const SYSTEM_PROXY_INBOUND_TAG: &str = "cfw-system-proxy";
pub const TUNNEL_INBOUND_TAG: &str = "cfw-tunnel";
/// Relative to the engine's private working directory.
pub const ROUTING_CACHE_PATH: &str = "routing-cache.db";

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

/// Packet-processing implementation selected by the trusted native backend.
/// This is not an imported profile field or a user preference. It is selected
/// before canonicalization so both configuration digests bind the actual stack.
/// `Gvisor` is the Windows packet-endpoint stack, whose tunnel projections
/// also bind the engine's outbound sockets to the physical default interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStack {
    System,
    Gvisor,
}

impl TunnelStack {
    const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Gvisor => "gvisor",
        }
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

/// Every rule-set tag `value` names, through logical sub-rules and response
/// filters included. The probe's rules name only tags by then
/// ([`retain_loadable_rules`]).
fn rule_set_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                match (key.as_str(), nested) {
                    ("rule_set", Value::Array(tags)) => {
                        names.extend(tags.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                    _ => rule_set_names(nested, names),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                rule_set_names(item, names);
            }
        }
        _ => {}
    }
}

/// Whether every rule set `value` names, through logical sub-rules and
/// response filters included, is a tag in `loadable`. The projection names
/// rule sets in arrays; any other form counts as not loadable.
fn names_only(value: &Value, loadable: &BTreeSet<String>) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .all(|(key, nested)| match (key.as_str(), nested) {
                ("rule_set", Value::Array(tags)) => tags
                    .iter()
                    .all(|tag| tag.as_str().is_some_and(|tag| loadable.contains(tag))),
                ("rule_set", _) => false,
                _ => names_only(nested, loadable),
            }),
        Value::Array(items) => items.iter().all(|item| names_only(item, loadable)),
        _ => true,
    }
}

/// Whether `rule` reads a response: sing-box binds a `respond` rule, and a rule
/// with `match_response` in its logical tree, to the latest anonymous evaluate
/// before it, and refuses one with none (v1.14.4 `dns/router.go`).
fn reads_response(rule: &Value) -> bool {
    fn matches_response(rule: &Value) -> bool {
        rule["match_response"] == Value::Bool(true)
            || rule["rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(matches_response))
    }
    rule["action"] == "respond" || matches_response(rule)
}

/// Keeps the rules of `rules` that name only rule sets in `loadable`. A reader
/// of an evaluate that is left out goes with it: it would otherwise read an
/// older, unrelated response, or none.
fn retain_loadable_rules(rules: Option<&mut Value>, loadable: &BTreeSet<String>) {
    if let Some(Value::Array(rules)) = rules {
        let mut evaluate_kept = true;
        rules.retain(|rule| {
            let keep = names_only(rule, loadable) && (evaluate_kept || !reads_response(rule));
            if rule["action"] == "evaluate" && rule.get("tag").is_none() {
                evaluate_kept = keep;
            }
            keep
        });
    }
}

/// The probe configuration and credentials derived from one projection, with
/// the tags the probe cannot measure.
pub(crate) struct ProxyProbeTemplate {
    pub(crate) json: String,
    pub(crate) credential_slots: Vec<CredentialSlot>,
    pub(crate) excluded_tags: Vec<String>,
}

fn projected_tag(outbound: &Value) -> String {
    outbound["tag"]
        .as_str()
        .expect("every projected outbound carries a tag")
        .to_owned()
}

impl ProjectedConfig {
    /// A transient, outbound-only view for explicit node latency tests. The
    /// normal projection remains the source of protocol/DNS/credential policy;
    /// listeners, system routes, persistence and autonomous tests are excluded.
    ///
    /// The probe has no rule-set cache, so a remote dataset would be fetched
    /// through the proxy under test before every measurement. DNS rules that
    /// name any rule set other than an inline one are therefore left out of
    /// `dns.rules` and of every DNS policy, together with the rules that read
    /// the response of an evaluate left out, and queries they would match
    /// fall through to the rules after them. The inline sets the remaining
    /// rules name are kept: sing-box refuses a rule that names an undeclared
    /// set.
    ///
    /// Tailscale endpoints stay with the running core (see below), and the
    /// template names the tags it therefore cannot measure.
    pub(crate) fn proxy_probe_template(&self) -> Result<ProxyProbeTemplate, ConfigError> {
        let mut root: Map<String, Value> = serde_json::from_str(&self.json)?;
        root.retain(|key, _| matches!(key.as_str(), "outbounds" | "endpoints" | "dns"));
        let mut original: Value = serde_json::from_str(&self.json)?;
        let inline: Vec<Value> = original["route"]["rule_set"]
            .as_array()
            .map(|resources| {
                resources
                    .iter()
                    .filter(|resource| resource["type"] == "inline")
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let loadable: BTreeSet<String> = inline
            .iter()
            .filter_map(|resource| resource["tag"].as_str().map(str::to_owned))
            .collect();
        if let Some(dns) = root.get_mut("dns") {
            retain_loadable_rules(dns.get_mut("rules"), &loadable);
            if let Some(Value::Array(policies)) = dns.get_mut("policies") {
                for policy in policies {
                    retain_loadable_rules(policy.get_mut("rules"), &loadable);
                }
            }
        }
        let mut named = BTreeSet::new();
        if let Some(dns) = root.get("dns") {
            rule_set_names(dns, &mut named);
        }
        let kept: Vec<Value> = inline
            .into_iter()
            .filter(|resource| {
                resource["tag"]
                    .as_str()
                    .is_some_and(|tag| named.contains(tag))
            })
            .collect();
        let mut route = Map::new();
        if let Some(resolver) = original["route"].get_mut("default_domain_resolver") {
            route.insert("default_domain_resolver".into(), resolver.take());
        }
        if !kept.is_empty() {
            route.insert("rule_set".into(), Value::Array(kept));
        }
        if !route.is_empty() {
            root.insert("route".into(), Value::Object(route));
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
        // A Tailscale endpoint registers a tailnet node from its persistent
        // state directory. A transient probe would register a second node from
        // the same key, or fail outright on a single-use key, so the probe
        // leaves those endpoints out together with every group left without a
        // member, and the slots of the remaining endpoints move up with them.
        let mut excluded = BTreeSet::new();
        let mut endpoint_positions = Vec::new();
        if let Some(Value::Array(endpoints)) = root.get_mut("endpoints") {
            let mut kept = Vec::with_capacity(endpoints.len());
            for endpoint in endpoints.drain(..) {
                if endpoint["type"] == "tailscale" {
                    excluded.insert(projected_tag(&endpoint));
                    endpoint_positions.push(None);
                } else {
                    endpoint_positions.push(Some(kept.len()));
                    kept.push(endpoint);
                }
            }
            *endpoints = kept;
        }
        if root
            .get("endpoints")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            root.remove("endpoints");
        }
        if let Some(Value::Array(outbounds)) = root.get_mut("outbounds") {
            while !excluded.is_empty() {
                let mut emptied = Vec::new();
                for outbound in outbounds.iter_mut() {
                    if outbound["type"] != "selector" {
                        continue;
                    }
                    let tag = projected_tag(outbound);
                    let Some(Value::Array(members)) = outbound.get_mut("outbounds") else {
                        continue;
                    };
                    members.retain(|member| {
                        !member
                            .as_str()
                            .is_some_and(|member| excluded.contains(member))
                    });
                    if members.is_empty() {
                        emptied.push(tag);
                    } else if outbound["default"]
                        .as_str()
                        .is_some_and(|default| excluded.contains(default))
                    {
                        outbound
                            .as_object_mut()
                            .expect("selector projection is an object")
                            .remove("default");
                    }
                }
                if emptied.is_empty() {
                    break;
                }
                outbounds.retain(|outbound| !emptied.contains(&projected_tag(outbound)));
                excluded.extend(emptied);
            }
        }
        let credential_slots = self
            .credential_slots
            .iter()
            .filter_map(|slot| {
                if slot.target().container() != "endpoints" {
                    return Some(Ok(slot.clone()));
                }
                let position = endpoint_positions
                    .get(usize::from(slot.outbound_index()))
                    .copied()
                    .expect("every endpoint slot indexes a projected endpoint");
                position.map(|index| {
                    CredentialSlot::new(slot.reference().clone(), slot.target(), index)
                        .map_err(ConfigError::from)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let template = Value::Object(root);
        validate_slots(&template, &credential_slots)?;
        Ok(ProxyProbeTemplate {
            json: serde_json::to_string(&template)?,
            credential_slots,
            excluded_tags: excluded.into_iter().collect(),
        })
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

/// What an explicit node latency test runs: the outbound-only probe
/// configuration and the credentials it needs, from one projection
/// ([`ValidatedSingBoxProfile::project_proxy_probe`]).
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyProbe {
    credential_audience: CredentialAudience,
    credential_slots: Vec<CredentialSlot>,
    json: String,
    excluded_tags: Vec<String>,
}

impl fmt::Debug for ProxyProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyProbe")
            .field("credential_audience", &self.credential_audience)
            .field("credential_slots", &self.credential_slots)
            .field("excluded_tags", &self.excluded_tags)
            .field("json", &"[REDACTED CONFIG TEMPLATE]")
            .finish()
    }
}

impl ProxyProbe {
    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.credential_audience
    }

    pub fn credential_slots(&self) -> &[CredentialSlot] {
        &self.credential_slots
    }

    pub fn as_json(&self) -> &str {
        &self.json
    }

    /// Tags the probe cannot measure: Tailscale endpoints, whose node state
    /// belongs to the running core, and groups left without a member.
    pub fn excluded_tags(&self) -> &[String] {
        &self.excluded_tags
    }
}

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

    /// The transient, outbound-only configuration explicit node latency tests
    /// run, with its credential audience and slots, all from one projection
    /// made with mainland China direct off: the probe keeps the DNS servers
    /// and rules but no rule sets, and the switch's DNS rules name rule sets.
    pub fn project_proxy_probe(
        &self,
        profile_id: &str,
        mode: ProjectionMode,
        settings: &EngineSettings,
    ) -> Result<ProxyProbe, ConfigError> {
        let settings = EngineSettings {
            mainland_china_direct: false,
            ..settings.clone()
        };
        let projected = self.project(profile_id, mode, &settings)?;
        let template = projected.proxy_probe_template()?;
        Ok(ProxyProbe {
            json: template.json,
            credential_audience: projected.credential_audience,
            credential_slots: template.credential_slots,
            excluded_tags: template.excluded_tags,
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

/// One application-owned DNS-over-HTTPS server. Without `detour` the
/// ordinary dialer goes DIRECT.
fn doh_server(
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
