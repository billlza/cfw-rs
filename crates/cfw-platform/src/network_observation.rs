//! Read-only observation of the current network services and their proxy state.
//!
//! This exists for diagnostics only. It reads SystemConfiguration preferences
//! and spawns no process: the historical `networksetup`, `scutil`, and `route`
//! invocations are gone, so the fields those tools supplied (default-route
//! interface, hardware port, BSD device) are not reported here.
//!
//! Nothing in this module can enable, disable, or otherwise write a proxy, DNS,
//! or route setting.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::MacOsPlatformService;

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
