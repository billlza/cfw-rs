//! User-selected DNS transports. Listener ownership and bootstrap resolvers
//! remain application-owned; each resolver retains its explicit traffic role.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

use crate::{ConfigError, profile::OutboundTls};

mod bootstrap;
mod matcher;
mod project;
pub(crate) use bootstrap::{BootstrapDnsServer, validate_bootstrap_pool};
pub(crate) use project::{
    add_connection_dns_rules, project_profile_dns, resolver_tags, resolver_value,
};

pub(crate) const MAX_DNS_RESOLVERS: usize = 8;
const MAX_DNS_POLICIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileDns {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) use_system_hosts: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) direct_follow_policy: bool,
    pub(crate) servers: Vec<ProfileDnsServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bootstrap_servers: Option<Vec<BootstrapDnsServer>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) nameserver_policy: Vec<DomainDnsPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) proxy_server_policy: Vec<DomainDnsPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_servers: Option<Vec<ProfileDnsServer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) direct_servers: Option<Vec<ProfileDnsServer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_servers: Option<Vec<ProfileDnsServer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_filter: Option<DnsFallbackFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fake_ip: Option<FakeIpPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainDnsPolicy {
    pub(crate) domain: String,
    pub(crate) servers: Vec<ProfileDnsServer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsFallbackFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) geoip_code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) geosite: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ip_cidr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FakeIpPolicy {
    pub(crate) exclude: Vec<String>,
}

pub(crate) const HOSTS_DNS_TAG: &str = "cfw-profile-hosts";
const FAKE_IP_DNS_TAG: &str = "cfw-fake-ip";
const FAKE_IP_RANGE: &str = "198.19.0.0/16";
const FAKE_IP_V6_RANGE: &str = "2001:2:ffff::/48";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DnsResolverRoute {
    #[default]
    Selected,
    Direct,
    Rules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ProfileDnsServer {
    Udp {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
    },
    Tcp {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
    },
    Tls {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
        tls: OutboundTls,
    },
    Quic {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
        tls: OutboundTls,
    },
    Https {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
        path: String,
        tls: OutboundTls,
    },
    #[serde(rename = "h3")]
    Http3 {
        server: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<DnsResolverRoute>,
        server_port: u16,
        path: String,
        tls: OutboundTls,
    },
}

impl ProfileDns {
    pub(crate) fn implicit_endpoint_resolver(
        &self,
        host: &str,
    ) -> Result<Option<Value>, ConfigError> {
        if self.proxy_servers.is_some()
            || !self
                .servers
                .iter()
                .all(|server| server.route() == Some(DnsResolverRoute::Direct))
        {
            return Ok(None);
        }
        if self
            .nameserver_policy
            .iter()
            .flat_map(|policy| &policy.servers)
            .chain(self.fallback_servers.iter().flatten())
            .any(|server| server.route() != Some(DnsResolverRoute::Direct))
        {
            return Err(invalid(
                "proxy endpoint DNS may form a resolver route cycle; set an explicit direct proxy_servers resolver pool",
            ));
        }
        // Run the same domain and response filters for proxy endpoint lookups.
        // DNS endpoints themselves still terminate at explicit numeric bootstrap.
        let _ = host;
        Ok(Some(json!({"policy":"default"})))
    }

    pub(crate) fn validate(
        &self,
        document: &crate::profile::ProfileDocument,
    ) -> Result<(), ConfigError> {
        validate_pool(&self.servers)?;
        if self
            .all_servers()
            .any(|server| server.route() == Some(DnsResolverRoute::Rules))
            && self.proxy_servers.is_none()
        {
            return Err(invalid(
                "DNS routing rules require an explicit proxy_servers pool to break proxy endpoint resolver cycles",
            ));
        }
        for pool in [
            &self.proxy_servers,
            &self.direct_servers,
            &self.fallback_servers,
        ]
        .into_iter()
        .flatten()
        {
            validate_pool(pool)?;
        }
        for pool in [&self.proxy_servers].into_iter().flatten() {
            if pool.iter().any(|server| {
                matches!(
                    server.route(),
                    Some(DnsResolverRoute::Selected | DnsResolverRoute::Rules)
                )
            }) {
                return Err(invalid(
                    "proxy endpoint DNS cannot depend on the selected proxy; this would create a resolver route cycle",
                ));
            }
        }
        if !self.proxy_server_policy.is_empty() && self.proxy_servers.is_none() {
            return Err(invalid("proxy_server_policy requires proxy_servers"));
        }
        for policies in [&self.nameserver_policy, &self.proxy_server_policy] {
            if policies.len() > MAX_DNS_POLICIES {
                return Err(invalid("DNS policy exceeds 256 entries"));
            }
            let mut domains = std::collections::BTreeSet::new();
            for policy in policies {
                matcher::DnsMatcher::parse(&policy.domain)?.condition(document)?;
                if !domains.insert(policy.domain.clone()) {
                    return Err(invalid("DNS policy selectors must be distinct"));
                }
                validate_pool(&policy.servers)?;
            }
        }
        if self
            .proxy_server_policy
            .iter()
            .flat_map(|policy| &policy.servers)
            .any(|server| {
                matches!(
                    server.route(),
                    Some(DnsResolverRoute::Selected | DnsResolverRoute::Rules)
                )
            })
        {
            return Err(invalid(
                "proxy endpoint DNS policy cannot depend on the selected proxy",
            ));
        }
        if let Some(bootstrap) = &self.bootstrap_servers {
            validate_bootstrap_pool(bootstrap)?;
        }
        // All DNS endpoint names terminate at numeric bootstrap resolvers. DNS
        // servers cannot reference another DNS role, so cycles are unrepresentable.
        if self.all_servers().any(|server| server.address().is_none())
            && self.bootstrap_servers.is_none()
        {
            return Err(invalid(
                "domain-named DNS resolvers require explicit numeric bootstrap_servers",
            ));
        }
        if self.servers.len() + self.fallback_servers.as_ref().map_or(0, Vec::len)
            > MAX_DNS_RESOLVERS
        {
            return Err(invalid(
                "ordinary and fallback DNS pools exceed the eight-attempt query budget",
            ));
        }
        if let Some(filter) = &self.fallback_filter {
            if self.fallback_servers.is_none() {
                return Err(invalid("DNS fallback_filter requires fallback_servers"));
            }
            if filter.domain.len() > MAX_DNS_POLICIES
                || filter.ip_cidr.len() > MAX_DNS_POLICIES
                || filter.geosite.len() > 32
            {
                return Err(invalid("DNS fallback filter exceeds 256 entries"));
            }
            if let Some(code) = &filter.geoip_code
                && (code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_lowercase()))
            {
                return Err(invalid(
                    "DNS GeoIP code requires a lowercase two-letter country code",
                ));
            }
            for code in &filter.geosite {
                matcher::validate_geosite(code)?;
            }
            for domain in &filter.domain {
                matcher::DnsMatcher::parse(domain)?.condition(document)?;
            }
            for cidr in &filter.ip_cidr {
                let Some((address, prefix)) = cidr.split_once('/') else {
                    return Err(invalid("DNS fallback IP filter requires CIDR prefixes"));
                };
                let address: IpAddr = address
                    .parse()
                    .map_err(|_| invalid("DNS fallback IP filter contains an invalid address"))?;
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| invalid("DNS fallback IP filter contains an invalid prefix"))?;
                if prefix > if address.is_ipv4() { 32 } else { 128 } {
                    return Err(invalid("DNS fallback IP filter prefix is out of range"));
                }
            }
        }
        if let Some(fake) = &self.fake_ip {
            if fake.exclude.len() > 512 {
                return Err(invalid("fake-IP filter exceeds 512 entries"));
            }
            for entry in &fake.exclude {
                matcher::DnsMatcher::parse(entry)?.condition(document)?;
            }
        }
        Ok(())
    }

    fn all_servers(&self) -> impl Iterator<Item = &ProfileDnsServer> {
        self.servers
            .iter()
            .chain(self.proxy_servers.iter().flatten())
            .chain(self.direct_servers.iter().flatten())
            .chain(self.fallback_servers.iter().flatten())
            .chain(
                self.nameserver_policy
                    .iter()
                    .chain(&self.proxy_server_policy)
                    .flat_map(|policy| &policy.servers),
            )
    }
}

fn validate_pool(servers: &[ProfileDnsServer]) -> Result<(), ConfigError> {
    if servers.is_empty() || servers.len() > MAX_DNS_RESOLVERS {
        return Err(invalid("DNS resolver pools require one to eight entries"));
    }
    for (index, server) in servers.iter().enumerate() {
        server.validate(index)?;
        if servers[..index].contains(server) {
            return Err(invalid("DNS resolver pool entries must be distinct"));
        }
    }
    Ok(())
}

pub(crate) fn validate_hosts(
    hosts: &std::collections::BTreeMap<String, Vec<IpAddr>>,
) -> Result<(), ConfigError> {
    if hosts.len() > 256 {
        return Err(invalid("hosts overrides exceed 256 entries"));
    }
    for (name, addresses) in hosts {
        crate::profile_validation::validate_server_name(name, "$.hosts")?;
        if name != &name.to_ascii_lowercase()
            || addresses.is_empty()
            || addresses.len() > 8
            || addresses
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != addresses.len()
            || addresses
                .iter()
                .any(|address| crate::profile_validation::remote_endpoint_ip_is_unusable(*address))
        {
            return Err(invalid(
                "hosts requires lowercase DNS names and distinct unicast addresses",
            ));
        }
    }
    Ok(())
}

pub(crate) fn augment_dns(
    document: &crate::profile::ProfileDocument,
    dns: &mut Value,
    tunnel: bool,
    ipv6: bool,
) -> bool {
    let mut prefix_rules = Vec::new();
    if !ipv6 {
        prefix_rules.push(json!({"query_type":["AAAA"],"action":"predefined","rcode":"NOERROR"}));
    }
    if !document.hosts.is_empty() {
        dns["servers"]
            .as_array_mut()
            .expect("DNS servers")
            .push(json!({
                "type":"hosts","tag":HOSTS_DNS_TAG,"predefined":document.hosts
            }));
        prefix_rules.push(json!({"domain":document.hosts.keys().collect::<Vec<_>>(),"action":"route","server":HOSTS_DNS_TAG}));
    }
    if document
        .dns
        .as_ref()
        .is_some_and(|policy| policy.use_system_hosts)
    {
        dns["servers"].as_array_mut().expect("DNS servers").push(json!({"type":"hosts","tag":"cfw-system-hosts","path":["/etc/hosts"],"strict":true,"fallback_on_missing":true,"predefined":document.hosts}));
        dns["system_hosts"] = json!("cfw-system-hosts");
    }
    let fake_ip = document
        .dns
        .as_ref()
        .and_then(|dns| dns.fake_ip.as_ref())
        .filter(|_| tunnel);
    if let Some(fake) = fake_ip {
        let mut server = json!({"type":"fakeip","tag":FAKE_IP_DNS_TAG,"inet4_range":FAKE_IP_RANGE});
        if ipv6 {
            server["inet6_range"] = json!(FAKE_IP_V6_RANGE);
        }
        dns["servers"]
            .as_array_mut()
            .expect("DNS servers")
            .push(server);
        let mut exclusions = Vec::new();
        for entry in &fake.exclude {
            let rule = matcher::DnsMatcher::parse(entry)
                .expect("validated fake-IP exclusion")
                .condition(document)
                .expect("validated DNS provider");
            exclusions.push(rule);
        }
        let query_types = if ipv6 { vec!["A", "AAAA"] } else { vec!["A"] };
        let mut rule = if exclusions.is_empty() {
            json!({"query_type":query_types})
        } else {
            json!({"type":"logical","mode":"and","rules":[{"query_type":query_types},
                {"type":"logical","mode":"or","rules":exclusions,"invert":true}]})
        };
        rule["action"] = json!("route");
        rule["server"] = json!(FAKE_IP_DNS_TAG);
        prefix_rules.push(rule);
    }
    dns["strategy"] = json!(if ipv6 { "prefer_ipv4" } else { "ipv4_only" });
    dns["rules"]
        .as_array_mut()
        .expect("DNS rules")
        .splice(0..0, prefix_rules);
    fake_ip.is_some()
}

impl ProfileDnsServer {
    pub(crate) fn host(&self) -> &str {
        match self {
            Self::Udp { server, .. }
            | Self::Tcp { server, .. }
            | Self::Tls { server, .. }
            | Self::Quic { server, .. }
            | Self::Https { server, .. }
            | Self::Http3 { server, .. } => server,
        }
    }

    fn route(&self) -> Option<DnsResolverRoute> {
        match self {
            Self::Udp { route, .. }
            | Self::Tcp { route, .. }
            | Self::Tls { route, .. }
            | Self::Quic { route, .. }
            | Self::Https { route, .. }
            | Self::Http3 { route, .. } => *route,
        }
    }

    pub(crate) fn address(&self) -> Option<IpAddr> {
        self.host().parse().ok()
    }

    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        crate::profile_validation::validate_server_name(self.host(), "$.dns.servers.server")?;
        let port = match self {
            Self::Udp { server_port, .. }
            | Self::Tcp { server_port, .. }
            | Self::Tls { server_port, .. }
            | Self::Quic { server_port, .. }
            | Self::Https { server_port, .. }
            | Self::Http3 { server_port, .. } => *server_port,
        };
        if port == 0 {
            return Err(invalid("DNS resolver port must be nonzero"));
        }
        match self {
            Self::Udp { .. } | Self::Tcp { .. } => {}
            Self::Tls { tls, .. }
            | Self::Quic { tls, .. }
            | Self::Https { tls, .. }
            | Self::Http3 { tls, .. } => {
                tls.validate(&format!("$.dns.servers[{index}]"))?;
                if !tls.enabled || tls.utls.is_some() || tls.reality.is_some() {
                    return Err(invalid("encrypted DNS requires authenticated standard TLS"));
                }
            }
        }
        if let Self::Https { path, .. } | Self::Http3 { path, .. } = self
            && (!path.starts_with('/')
                || path.starts_with("//")
                || path.len() > 2048
                || path.chars().any(char::is_whitespace)
                || path.contains('#'))
        {
            return Err(invalid("DNS HTTPS path is invalid"));
        }
        Ok(())
    }

    pub(crate) fn project(
        &self,
        tag: &str,
        outbound: Option<&str>,
        bootstrap: &Value,
    ) -> Result<Value, ConfigError> {
        let mut value = serde_json::to_value(self)?;
        value["tag"] = json!(tag);
        value
            .as_object_mut()
            .expect("DNS server object")
            .remove("route");
        if let Some(outbound) =
            outbound.filter(|_| self.route().unwrap_or_default() == DnsResolverRoute::Selected)
        {
            value["detour"] = json!(outbound);
        }
        if self.address().is_none() {
            value["domain_resolver"] = bootstrap.clone();
        }
        if self.route() == Some(DnsResolverRoute::Rules) {
            value["respect_rules"] = json!(true);
        }
        value["connect_timeout"] = json!("5s");
        if let Self::Tls { tls, .. }
        | Self::Quic { tls, .. }
        | Self::Https { tls, .. }
        | Self::Http3 { tls, .. } = self
        {
            value["tls"] = crate::profile_projection::project_tls(tls)?;
        }
        Ok(value)
    }
}

fn invalid(reason: &str) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: "$.dns".into(),
        reason: reason.into(),
    }
}
