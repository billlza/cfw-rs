//! Read-only observation of the current network services and their proxy state.
//!
//! This exists for diagnostics only. It reads SystemConfiguration preferences
//! and spawns no process: the historical `networksetup`, `scutil`, and `route`
//! invocations are gone, so the fields those tools supplied (default-route
//! interface, hardware port, BSD device) are not reported here.
//!
//! Nothing in this module can enable, disable, or otherwise write a proxy, DNS,
//! or route setting.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::MacOsPlatformService;

const NETWORK_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_NETWORK_OBSERVATION_BYTES: usize = 1024 * 1024;
const MAX_NETWORK_OBSERVATION_ERROR_BYTES: usize = 64 * 1024;

/// Fixed-tool snapshot used to prove ownership or absence of legacy routes.
/// The platform adapter owns process execution; callers receive only bounded,
/// UTF-8 observation text and cannot choose an executable or arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRoutingObservation {
    pub interfaces: String,
    pub ipv4_routes: String,
    pub ipv6_routes: String,
    pub dns: String,
}

/// One protocol slot of a service's proxy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkProxyProtocolObservation {
    pub enabled: bool,
    pub server: Option<String>,
    pub port: Option<u16>,
}

/// One service of the current network set, in set order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkServiceObservation {
    pub service_id: String,
    pub display_name: String,
    /// Position in the current network set, zero-based.
    pub order: usize,
    pub web: NetworkProxyProtocolObservation,
    pub secure_web: NetworkProxyProtocolObservation,
    pub socks: NetworkProxyProtocolObservation,
    pub pac_enabled: bool,
    pub wpad_enabled: bool,
}

impl NetworkServiceObservation {
    /// True when any proxy mode of this service is currently enabled, whoever
    /// owns it. Diagnostics uses this to highlight services that still carry a
    /// proxy after the legacy network was retired.
    pub fn any_proxy_enabled(&self) -> bool {
        self.web.enabled
            || self.secure_web.enabled
            || self.socks.enabled
            || self.pac_enabled
            || self.wpad_enabled
    }
}

impl MacOsPlatformService {
    /// Captures interfaces, IPv4/IPv6 route tables, and scoped DNS state using
    /// fixed absolute macOS tools under one shared timeout/output policy.
    pub fn observe_network_routing(&self) -> Result<NetworkRoutingObservation> {
        #[cfg(target_os = "macos")]
        {
            Ok(NetworkRoutingObservation {
                interfaces: run_network_observation("/sbin/ifconfig", &[])?,
                ipv4_routes: run_network_observation("/usr/sbin/netstat", &["-rn", "-f", "inet"])?,
                ipv6_routes: run_network_observation("/usr/sbin/netstat", &["-rn", "-f", "inet6"])?,
                dns: run_network_observation("/usr/sbin/scutil", &["--dns"])?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("network routing observation is only available on macOS")
        }
    }

    /// Observes every service of the current network set.
    ///
    /// A service without a proxy configuration is reported with all modes
    /// disabled rather than failing the whole observation, so one unusual
    /// service (a VPN, for example) cannot make diagnostics unavailable.
    pub fn observe_network_services(&self) -> Result<Vec<NetworkServiceObservation>> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::observe_network_services()
        }
        #[cfg(not(target_os = "macos"))]
        {
            anyhow::bail!("network service observation is only available on macOS")
        }
    }
}

#[cfg(target_os = "macos")]
fn run_network_observation(program: &str, args: &[&str]) -> Result<String> {
    let output = crate::bounded_command::run_bounded_command(
        program,
        args,
        NETWORK_OBSERVATION_TIMEOUT,
        MAX_NETWORK_OBSERVATION_BYTES,
        MAX_NETWORK_OBSERVATION_ERROR_BYTES,
    )
    .with_context(|| format!("network observation command {program} failed"))?;
    let stderr = String::from_utf8(output.stderr).with_context(|| {
        format!("network observation command {program} returned non-UTF-8 stderr")
    })?;
    if !output.status.success() {
        bail!(
            "network observation command {program} failed with status {}: {}",
            output.status,
            stderr.trim()
        );
    }
    if !stderr.trim().is_empty() {
        bail!(
            "network observation command {program} succeeded with unexpected stderr: {}",
            stderr.trim()
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("network observation command {program} returned non-UTF-8 output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_reports_any_enabled_proxy_mode() {
        let base = NetworkServiceObservation {
            service_id: "service-uuid".into(),
            display_name: "Wi-Fi".into(),
            order: 0,
            web: NetworkProxyProtocolObservation::default(),
            secure_web: NetworkProxyProtocolObservation::default(),
            socks: NetworkProxyProtocolObservation::default(),
            pac_enabled: false,
            wpad_enabled: false,
        };
        assert!(!base.any_proxy_enabled());

        for mutate in [
            (|observation: &mut NetworkServiceObservation| observation.web.enabled = true)
                as fn(&mut NetworkServiceObservation),
            |observation| observation.secure_web.enabled = true,
            |observation| observation.socks.enabled = true,
            |observation| observation.pac_enabled = true,
            |observation| observation.wpad_enabled = true,
        ] {
            let mut observation = base.clone();
            mutate(&mut observation);
            assert!(observation.any_proxy_enabled());
        }
    }

    #[test]
    fn observation_payload_has_a_closed_shape() {
        let error = serde_json::from_value::<NetworkServiceObservation>(serde_json::json!({
            "service_id": "service-uuid",
            "display_name": "Wi-Fi",
            "order": 0,
            "web": { "enabled": false, "server": null, "port": null },
            "secure_web": { "enabled": false, "server": null, "port": null },
            "socks": { "enabled": false, "server": null, "port": null },
            "pac_enabled": false,
            "wpad_enabled": false,
            "pac_url": "http://attacker.example/proxy.pac",
        }))
        .expect_err("unexpected diagnostics fields must be rejected");
        assert!(error.to_string().contains("pac_url"));
    }
}
