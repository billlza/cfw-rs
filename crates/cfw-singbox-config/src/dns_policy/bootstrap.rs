//! Bootstrap transports terminate at numeric addresses and never depend on a
//! proxy, another resolver name, or a silent plaintext fallback.
use super::{DnsResolverRoute, ProfileDnsServer, invalid};
use crate::ConfigError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum BootstrapDnsServer {
    Address(IpAddr),
    Transport(Box<ProfileDnsServer>),
}

impl BootstrapDnsServer {
    pub(crate) fn address(&self) -> Option<IpAddr> {
        match self {
            Self::Address(address) => Some(*address),
            Self::Transport(server) => server.address(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let address = self.address().ok_or_else(|| {
            invalid(
                "bootstrap transport requires a numeric server address; it cannot resolve itself",
            )
        })?;
        if crate::profile_validation::remote_endpoint_ip_is_unusable(address) {
            return Err(invalid(
                "bootstrap address must be a usable unicast address",
            ));
        }
        if let Self::Transport(server) = self {
            server.validate(0)?;
            if matches!(
                server.route(),
                Some(DnsResolverRoute::Selected | DnsResolverRoute::Rules)
            ) {
                return Err(invalid(
                    "bootstrap transport cannot depend on a selected proxy",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn project(&self, tag: &str, ipv6: bool) -> Result<Value, ConfigError> {
        self.validate()?;
        if !ipv6 && self.address().is_some_and(|address| address.is_ipv6()) {
            return Err(ConfigError::InvalidBootstrapDnsServers(
                "IPv6 bootstrap is unavailable while IPv6 is disabled".into(),
            ));
        }
        match self {
            Self::Address(address) => {
                Ok(json!({"type":"udp","tag":tag,"server":address.to_string(),"server_port":53}))
            }
            Self::Transport(server) => server.project(tag, None, &Value::Null),
        }
    }
}

pub(crate) fn validate_bootstrap_pool(servers: &[BootstrapDnsServer]) -> Result<(), ConfigError> {
    if servers.is_empty() || servers.len() > super::MAX_DNS_RESOLVERS {
        return Err(invalid(
            "bootstrap DNS requires one to eight distinct numeric resolver transports",
        ));
    }
    let mut identities = Vec::new();
    for server in servers {
        server.validate()?;
        let mut identity = server.project("bootstrap", true)?;
        identity
            .as_object_mut()
            .expect("projected bootstrap object")
            .remove("connect_timeout");
        if identities.contains(&identity) {
            return Err(invalid("bootstrap DNS transports must be distinct"));
        }
        identities.push(identity);
    }
    Ok(())
}
