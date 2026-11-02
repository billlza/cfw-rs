//! Each network service's proxy settings, and whether they are exactly the
//! product's loopback endpoint or cleared.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::CFString;
use objc2_system_configuration::{
    SCNetworkService, kSCNetworkProtocolTypeProxies, kSCPropNetProxiesHTTPEnable,
    kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy, kSCPropNetProxiesHTTPSEnable,
    kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable,
    kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
};

use crate::network_observation::{NetworkProxyProtocolObservation, NetworkServiceObservation};
use crate::sysproxy_sc::ConfigDict;
use crate::sysproxy_sc::preferences::{
    PreferencesSession, current_services, service_id, service_name,
};
use crate::sysproxy_sc::values::{as_config_dict, enabled_flag, number_value, string_value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyProtocolState {
    pub(super) enabled: bool,
    pub(super) server: Option<String>,
    pub(super) port: Option<u16>,
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

pub(crate) fn read_observation(service: &SCNetworkService) -> Result<ProxyObservation> {
    let id = service_id(service)?;
    let display_name = service_name(service, &id)?;
    let Some(protocol) = service.protocol(unsafe { kSCNetworkProtocolTypeProxies }) else {
        bail!("network service {display_name} has no Proxies protocol")
    };
    let configuration = protocol
        .configuration()
        .with_context(|| format!("network service {display_name} has no proxy configuration"))?;
    let configuration = as_config_dict(&configuration);
    Ok(ProxyObservation {
        service_id: id,
        display_name,
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

/// Read-only diagnostics view of the current network set.
///
/// Unlike [`read_observation`], a service that carries no Proxies protocol or no
/// proxy configuration is reported as "nothing enabled" instead of failing, so a
/// single unusual service cannot make diagnostics unavailable. Nothing here
/// writes, commits, or applies preferences.
pub(crate) fn observe_network_services() -> Result<Vec<NetworkServiceObservation>> {
    let session = PreferencesSession::open()?;
    let services = current_services(&session.preferences)?;
    let mut observations = Vec::with_capacity(services.len());
    for (order, service) in services.iter().enumerate() {
        let id = service_id(service)?;
        let display_name = service_name(service, &id)?;
        let configuration = service
            .protocol(unsafe { kSCNetworkProtocolTypeProxies })
            .and_then(|protocol| protocol.configuration());
        let Some(configuration) = configuration else {
            observations.push(NetworkServiceObservation {
                service_id: id,
                display_name,
                order,
                web: NetworkProxyProtocolObservation::default(),
                secure_web: NetworkProxyProtocolObservation::default(),
                socks: NetworkProxyProtocolObservation::default(),
                pac_enabled: false,
                wpad_enabled: false,
            });
            continue;
        };
        let configuration = as_config_dict(&configuration);
        observations.push(NetworkServiceObservation {
            service_id: id,
            display_name,
            order,
            web: observe_protocol(
                configuration,
                unsafe { kSCPropNetProxiesHTTPEnable },
                unsafe { kSCPropNetProxiesHTTPProxy },
                unsafe { kSCPropNetProxiesHTTPPort },
                "HTTP proxy",
            )?,
            secure_web: observe_protocol(
                configuration,
                unsafe { kSCPropNetProxiesHTTPSEnable },
                unsafe { kSCPropNetProxiesHTTPSProxy },
                unsafe { kSCPropNetProxiesHTTPSPort },
                "HTTPS proxy",
            )?,
            socks: observe_protocol(
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
        });
    }
    Ok(observations)
}

fn observe_protocol(
    dict: &ConfigDict,
    enable: &CFString,
    host: &CFString,
    port: &CFString,
    label: &str,
) -> Result<NetworkProxyProtocolObservation> {
    let state = read_protocol(dict, enable, host, port, label)?;
    Ok(NetworkProxyProtocolObservation {
        enabled: state.enabled,
        server: state.server,
        port: state.port,
    })
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
