use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::MacOsPlatformService;

/// A service whose live SystemConfiguration state, rather than a mutable
/// historical file, proved that all three legacy proxy protocols were applied
/// by this product at the expected loopback port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyProxyServiceIdentity {
    pub(crate) service_id: String,
    pub(crate) display_name: String,
}

impl LegacyProxyServiceIdentity {
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// In-memory, live-observation authority for one cutover attempt.
///
/// The legacy `system-proxy-snapshot.json` is intentionally not read. It was
/// writable by arbitrary processes running as the user and therefore cannot
/// authenticate historical host, port, bypass, PAC, or WPAD values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyProxyCutoverPlan {
    pub(crate) services: Vec<LegacyProxyServiceIdentity>,
    pub(crate) expected_port: u16,
}

impl LegacyProxyCutoverPlan {
    pub fn service_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.services.iter().map(|service| service.service_id())
    }

    pub fn expected_port(&self) -> u16 {
        self.expected_port
    }

    pub fn services(&self) -> &[LegacyProxyServiceIdentity] {
        &self.services
    }

    pub fn for_recovery(
        services: Vec<LegacyProxyServiceIdentity>,
        expected_port: u16,
    ) -> Result<Self> {
        let plan = Self {
            services,
            expected_port,
        };
        #[cfg(target_os = "macos")]
        crate::sysproxy_sc::validate_plan(&plan)?;
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy recovery is only available on macOS");
        Ok(plan)
    }
}

impl MacOsPlatformService {
    /// Captures only services whose current HTTP, HTTPS and SOCKS settings all
    /// equal the exact product-applied `127.0.0.1:expected_port` value, with
    /// PAC and WPAD disabled. No historical snapshot content is trusted.
    pub fn prepare_legacy_proxy_cutover(
        &self,
        expected_port: u16,
    ) -> Result<LegacyProxyCutoverPlan> {
        if expected_port == 0 {
            bail!("legacy proxy ownership requires a non-zero applied port")
        }
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::capture_legacy_applied_proxy(expected_port)
        }
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy preparation is only available on macOS")
    }

    /// Clears only the three product-owned enable/server/port triples. It does
    /// not restore or write unauthenticated historical bypass, PAC, WPAD, host,
    /// or port values.
    pub fn disable_legacy_proxy(&self, plan: &LegacyProxyCutoverPlan) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::disable_legacy_proxy(plan)
        }
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy cleanup is only available on macOS")
    }

    pub fn verify_legacy_proxy_still_applied(&self, plan: &LegacyProxyCutoverPlan) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::verify_legacy_applied_proxy(plan)
        }
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy verification is only available on macOS")
    }

    pub fn verify_legacy_proxy_disabled(&self, plan: &LegacyProxyCutoverPlan) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::verify_legacy_proxy_disabled(plan)
        }
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy cleanup verification is only available on macOS")
    }

    /// Idempotent crash recovery: every captured service must be uniformly
    /// still exact-product-applied or already fully cleared. Mixed or changed
    /// states are rejected rather than overwritten.
    pub fn recover_legacy_proxy(&self, plan: &LegacyProxyCutoverPlan) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::recover_legacy_proxy(plan)
        }
        #[cfg(not(target_os = "macos"))]
        bail!("legacy proxy recovery is only available on macOS")
    }

    /// When no live product-owned proxy is expected, require every current
    /// network service to have the relevant proxy modes disabled.
    pub fn verify_all_legacy_proxies_disabled(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::sysproxy_sc::verify_proxies_disabled()
        }
        #[cfg(not(target_os = "macos"))]
        bail!("system proxy verification is only available on macOS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_contains_only_live_service_identity_and_product_port() {
        let plan = LegacyProxyCutoverPlan {
            services: vec![LegacyProxyServiceIdentity {
                service_id: "service-uuid".into(),
                display_name: "Wi-Fi".into(),
            }],
            expected_port: 7890,
        };

        assert_eq!(plan.service_ids().collect::<Vec<_>>(), ["service-uuid"]);
        assert_eq!(plan.expected_port(), 7890);
        // There is deliberately no field capable of carrying attacker-chosen
        // historical hosts, ports, bypass domains, PAC URLs, or WPAD state.
        assert_eq!(std::mem::size_of_val(&plan.expected_port), 2);
    }
}
