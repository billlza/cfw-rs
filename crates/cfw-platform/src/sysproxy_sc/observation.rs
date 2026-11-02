//! Each network service's proxy settings, and whether they are exactly the
//! product's loopback endpoint or cleared.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::CFString;
use objc2_system_configuration::{
    kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy,
    kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable,
    kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
};

use crate::network_observation::{NetworkProxyProtocolObservation, NetworkServiceObservation};
use crate::sysproxy_sc::ConfigDict;
use crate::sysproxy_sc::store::{
    ProxyConfiguration, ProxyPreferences, ProxyService, current_services, service_id, service_name,
};
use crate::sysproxy_sc::values::{as_config_dict, enabled_flag, number_value, string_value};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProxyProtocolState {
    pub(super) enabled: bool,
    pub(super) server: Option<String>,
    pub(super) port: Option<u16>,
}

impl From<ProxyProtocolState> for NetworkProxyProtocolObservation {
    fn from(state: ProxyProtocolState) -> Self {
        Self {
            enabled: state.enabled,
            server: state.server,
            port: state.port,
        }
    }
}

pub(crate) fn read_protocol(
    dict: &ConfigDict,
    enable: &CFString,
    host: &CFString,
    port: &CFString,
    label: &str,
) -> Result<ProxyProtocolState> {
    let enabled = enabled_flag(dict, enable, label)?;
    let server =
        string_value(dict, host, &format!("{label} server"))?.filter(|server| !server.is_empty());
    let port = number_value(dict, port, &format!("{label} port"))?
        .map(|port| {
            u16::try_from(port).with_context(|| format!("{label} port is outside the u16 range"))
        })
        .transpose()?;
    Ok(ProxyProtocolState {
        enabled,
        server,
        port,
    })
}

/// The proxy settings one configuration dictionary holds.
#[derive(Debug, Default)]
struct ProxySettings {
    web: ProxyProtocolState,
    secure_web: ProxyProtocolState,
    socks: ProxyProtocolState,
    pac_enabled: bool,
    wpad_enabled: bool,
}

fn read_settings(configuration: &ConfigDict) -> Result<ProxySettings> {
    Ok(ProxySettings {
        web: read_protocol(
            configuration,
            unsafe { kSCPropNetProxiesHTTPEnable },
            unsafe { kSCPropNetProxiesHTTPProxy },
            unsafe { kSCPropNetProxiesHTTPPort },
            "HTTP proxy",
        )?,
        secure_web: read_protocol(
            configuration,
            unsafe { kSCPropNetProxiesHTTPSEnable },
            unsafe { kSCPropNetProxiesHTTPSProxy },
            unsafe { kSCPropNetProxiesHTTPSPort },
            "HTTPS proxy",
        )?,
        socks: read_protocol(
            configuration,
            unsafe { kSCPropNetProxiesSOCKSEnable },
            unsafe { kSCPropNetProxiesSOCKSProxy },
            unsafe { kSCPropNetProxiesSOCKSPort },
            "SOCKS proxy",
        )?,
        pac_enabled: enabled_flag(
            configuration,
            unsafe { kSCPropNetProxiesProxyAutoConfigEnable },
            "PAC proxy configuration",
        )?,
        wpad_enabled: enabled_flag(
            configuration,
            unsafe { kSCPropNetProxiesProxyAutoDiscoveryEnable },
            "proxy auto-discovery",
        )?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyObservation {
    pub(super) service_id: String,
    pub(super) display_name: String,
    pub(super) web: ProxyProtocolState,
    pub(super) secure_web: ProxyProtocolState,
    pub(super) socks: ProxyProtocolState,
    pub(super) pac_enabled: bool,
    pub(super) wpad_enabled: bool,
}

/// A service's live proxy settings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServiceProxies {
    /// The service has no Proxies protocol, so it carries no proxy.
    NoProtocol {
        display_name: String,
    },
    Observed(ProxyObservation),
}

/// Reads a service's proxy settings. A Proxies protocol without a
/// configuration dictionary is an error.
pub(crate) fn observe_service(service: &impl ProxyService) -> Result<ServiceProxies> {
    let id = service_id(service)?;
    let display_name = service_name(service, &id)?;
    let configuration = match service.proxy_configuration() {
        ProxyConfiguration::NoProtocol => {
            return Ok(ServiceProxies::NoProtocol { display_name });
        }
        ProxyConfiguration::Unconfigured => {
            bail!("network service {display_name} has no proxy configuration")
        }
        ProxyConfiguration::Configured(configuration) => configuration,
    };
    let ProxySettings {
        web,
        secure_web,
        socks,
        pac_enabled,
        wpad_enabled,
    } = read_settings(as_config_dict(&configuration))?;
    Ok(ServiceProxies::Observed(ProxyObservation {
        service_id: id,
        display_name,
        web,
        secure_web,
        socks,
        pac_enabled,
        wpad_enabled,
    }))
}

/// Reads a service's proxy settings; a service without a Proxies protocol is
/// an error.
pub(crate) fn read_observation(service: &impl ProxyService) -> Result<ProxyObservation> {
    match observe_service(service)? {
        ServiceProxies::Observed(observation) => Ok(observation),
        ServiceProxies::NoProtocol { display_name } => {
            bail!("network service {display_name} has no Proxies protocol")
        }
    }
}

/// Read-only diagnostics view of the current network set.
///
/// Unlike [`read_observation`], a service that carries no Proxies protocol or no
/// proxy configuration is reported as "nothing enabled" instead of failing, so a
/// single unusual service cannot make diagnostics unavailable. Nothing here
/// writes, commits, or applies preferences.
pub(crate) fn observe_network_services<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
) -> Result<Vec<NetworkServiceObservation>> {
    let preferences = open()?;
    let services = current_services(&preferences)?;
    let mut observations = Vec::with_capacity(services.len());
    for (order, service) in services.iter().enumerate() {
        let id = service_id(service)?;
        let display_name = service_name(service, &id)?;
        let settings = match service.proxy_configuration() {
            ProxyConfiguration::Configured(configuration) => {
                read_settings(as_config_dict(&configuration))?
            }
            ProxyConfiguration::NoProtocol | ProxyConfiguration::Unconfigured => {
                ProxySettings::default()
            }
        };
        observations.push(NetworkServiceObservation {
            service_id: id,
            display_name,
            order,
            web: settings.web.into(),
            secure_web: settings.secure_web.into(),
            socks: settings.socks.into(),
            pac_enabled: settings.pac_enabled,
            wpad_enabled: settings.wpad_enabled,
        });
    }
    Ok(observations)
}

pub(crate) fn protocol_matches_product(protocol: &ProxyProtocolState, expected_port: u16) -> bool {
    protocol.enabled
        && protocol.server.as_deref() == Some("127.0.0.1")
        && protocol.port == Some(expected_port)
}

pub(crate) fn observation_matches_product(
    observation: &ProxyObservation,
    expected_port: u16,
) -> bool {
    !observation.pac_enabled
        && !observation.wpad_enabled
        && protocol_matches_product(&observation.web, expected_port)
        && protocol_matches_product(&observation.secure_web, expected_port)
        && protocol_matches_product(&observation.socks, expected_port)
}

fn protocol_is_cleared(protocol: &ProxyProtocolState) -> bool {
    !protocol.enabled && protocol.server.is_none() && protocol.port.is_none()
}

pub(crate) fn observation_is_cleared(observation: &ProxyObservation) -> bool {
    !observation.pac_enabled
        && !observation.wpad_enabled
        && protocol_is_cleared(&observation.web)
        && protocol_is_cleared(&observation.secure_web)
        && protocol_is_cleared(&observation.socks)
}

#[cfg(test)]
mod tests;
