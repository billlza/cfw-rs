//! User-selected DNS transports. Listener ownership and bootstrap resolvers
//! remain application-owned; queries use the selected outbound.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

use crate::{ConfigError, profile::OutboundTls};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileDns {
    pub(crate) servers: Vec<ProfileDnsServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bootstrap_servers: Option<[IpAddr; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fake_ip: Option<FakeIpPolicy>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ProfileDnsServer {
    Udp {
        server: IpAddr,
        server_port: u16,
    },
    Tcp {
        server: IpAddr,
        server_port: u16,
    },
    Tls {
        server: IpAddr,
        server_port: u16,
        tls: OutboundTls,
    },
    Quic {
        server: IpAddr,
        server_port: u16,
        tls: OutboundTls,
    },
    Https {
        server: IpAddr,
        server_port: u16,
        path: String,
        tls: OutboundTls,
    },
    #[serde(rename = "h3")]
    Http3 {
        server: IpAddr,
        server_port: u16,
        path: String,
        tls: OutboundTls,
    },
}

impl ProfileDns {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.servers.is_empty() || self.servers.len() > 2 {
            return Err(invalid(
                "DNS requires a primary resolver and at most one explicit fallback",
            ));
        }
        if self.servers.len() == 2 && self.servers[0] == self.servers[1] {
            return Err(invalid("DNS primary and fallback must be distinct"));
        }
        for (index, server) in self.servers.iter().enumerate() {
            server.validate(index)?;
        }
        if let Some(bootstrap) = &self.bootstrap_servers
            && (bootstrap[0] == bootstrap[1]
                || bootstrap.iter().any(|address| {
                    crate::profile_validation::remote_endpoint_ip_is_unusable(*address)
                }))
        {
            return Err(invalid(
                "bootstrap DNS requires two distinct unicast resolvers",
            ));
        }
        if let Some(fake) = &self.fake_ip {
            if fake.exclude.len() > 512 {
                return Err(invalid("fake-IP filter exceeds 512 entries"));
            }
            for entry in &fake.exclude {
                let suffix = entry
                    .strip_prefix("+.")
                    .or_else(|| entry.strip_prefix("*."))
                    .unwrap_or(entry);
                if suffix != "*" {
                    crate::profile_validation::validate_server_name(
                        suffix,
                        "$.dns.fake_ip.exclude",
                    )?;
                }
            }
        }
        Ok(())
    }
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
            let rule = if let Some(suffix) = entry.strip_prefix("+.") {
                json!({"domain_suffix":suffix})
            } else if let Some(suffix) = entry.strip_prefix("*.") {
                json!({"domain_regex":format!("(?i)^[^.]+\\.{}\\.?$",suffix.replace('.', "\\."))})
            } else if entry == "*" {
                json!({"domain_regex":"^[^.]+\\.?$"})
            } else {
                json!({"domain":entry})
            };
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
    pub(crate) fn address(&self) -> IpAddr {
        match self {
            Self::Udp { server, .. }
            | Self::Tcp { server, .. }
            | Self::Tls { server, .. }
            | Self::Quic { server, .. }
            | Self::Https { server, .. }
            | Self::Http3 { server, .. } => *server,
        }
    }

    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        let address = self.address();
        if crate::profile_validation::remote_endpoint_ip_is_unusable(address) {
            return Err(invalid("DNS resolver is not a reachable unicast address"));
        }
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

    pub(crate) fn project(&self, tag: &str, outbound: &str) -> Result<Value, ConfigError> {
        let mut value = serde_json::to_value(self)?;
        value["tag"] = json!(tag);
        value["detour"] = json!(outbound);
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
