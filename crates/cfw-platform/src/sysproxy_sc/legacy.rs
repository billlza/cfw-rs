//! The one-way legacy proxy cutover: capture, verify, disable and recover the
//! services whose live values are the retired installation's endpoint.
//!
//! Each step takes the means to open a preferences session rather than a
//! session, so a step that refuses its input opens none.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFString};
use objc2_system_configuration::{
    kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy,
    kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesSOCKSEnable,
    kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
};

use crate::legacy_proxy::{LegacyProxyCutoverPlan, LegacyProxyServiceIdentity};
use crate::sysproxy_sc::observation::{
    ServiceProxies, observation_is_cleared, observation_matches_product, observe_service,
    protocol_matches_product, read_observation, read_protocol,
};
use crate::sysproxy_sc::store::{
    ProxyConfiguration, ProxyPreferences, ProxyService, current_services, find_service, service_id,
    service_name, validate_identity_text,
};
use crate::sysproxy_sc::values::{as_config_dict, enabled_flag};
use crate::sysproxy_sc::{ConfigDict, MAX_SERVICES, MutableConfigDict};

pub(crate) fn capture_legacy_applied_proxy<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
    expected_port: u16,
) -> Result<LegacyProxyCutoverPlan> {
    let preferences = open()?;
    let services = current_services(&preferences)?;
    let mut owned = Vec::new();
    for service in services {
        // A service without a Proxies protocol carries no proxy to capture.
        let ServiceProxies::Observed(observation) = observe_service(&service)? else {
            continue;
        };
        if observation_matches_product(&observation, expected_port) {
            owned.push(LegacyProxyServiceIdentity {
                service_id: observation.service_id,
                display_name: observation.display_name,
            });
        }
    }
    if owned.is_empty() {
        bail!(
            "no current network service has the exact legacy HTTP/HTTPS/SOCKS value 127.0.0.1:{expected_port} with PAC/WPAD disabled; no proxy field was changed"
        )
    }
    Ok(LegacyProxyCutoverPlan {
        services: owned,
        expected_port,
    })
}

pub(crate) fn validate_plan(plan: &LegacyProxyCutoverPlan) -> Result<()> {
    if plan.expected_port == 0 || plan.services.is_empty() || plan.services.len() > MAX_SERVICES {
        bail!("legacy proxy cutover plan is invalid")
    }
    let mut ids = HashSet::new();
    for service in &plan.services {
        validate_identity_text("service identifier", &service.service_id)?;
        validate_identity_text("service display name", &service.display_name)?;
        if !ids.insert(service.service_id.as_str()) {
            bail!("legacy proxy cutover plan has duplicate service identifiers")
        }
    }
    Ok(())
}

pub(crate) fn verify_legacy_applied_proxy<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
    plan: &LegacyProxyCutoverPlan,
) -> Result<()> {
    validate_plan(plan)?;
    let preferences = open()?;
    let services = current_services(&preferences)?;
    for identity in &plan.services {
        let observation = read_observation(find_service(&services, identity)?)?;
        if !observation_matches_product(&observation, plan.expected_port) {
            bail!(
                "network service {} no longer equals the exact legacy loopback proxy; no proxy field was changed",
                identity.display_name
            )
        }
    }
    Ok(())
}

fn set_number(dict: &MutableConfigDict, key: &CFString, value: i32) {
    let value = CFNumber::new_i32(value);
    dict.set(key, value.as_ref());
}

fn clear_protocol(dict: &MutableConfigDict, enable: &CFString, host: &CFString, port: &CFString) {
    set_number(dict, enable, 0);
    dict.remove(host);
    dict.remove(port);
}

fn stage_clear_product_proxy(service: &impl ProxyService, display_name: &str) -> Result<()> {
    let existing = match service.proxy_configuration() {
        ProxyConfiguration::NoProtocol => {
            bail!("network service {display_name} has no Proxies protocol")
        }
        ProxyConfiguration::Unconfigured => {
            bail!("network service {display_name} has no proxy configuration")
        }
        ProxyConfiguration::Configured(existing) => existing,
    };
    let existing_opaque: &CFDictionary = existing.as_ref();
    // SAFETY: `existing_opaque` is a live CFDictionary and the returned mutable
    // copy retains all existing keys and values. The typed cast matches the
    // documented SC proxy dictionary shape.
    let mutable = unsafe {
        CFMutableDictionary::new_copy(None, existing_opaque.count(), Some(existing_opaque))
            .context("CFDictionaryCreateMutableCopy failed")?
    };
    let mutable = unsafe { CFRetained::cast_unchecked::<MutableConfigDict>(mutable) };
    clear_protocol(
        &mutable,
        unsafe { kSCPropNetProxiesHTTPEnable },
        unsafe { kSCPropNetProxiesHTTPProxy },
        unsafe { kSCPropNetProxiesHTTPPort },
    );
    clear_protocol(
        &mutable,
        unsafe { kSCPropNetProxiesHTTPSEnable },
        unsafe { kSCPropNetProxiesHTTPSProxy },
        unsafe { kSCPropNetProxiesHTTPSPort },
    );
    clear_protocol(
        &mutable,
        unsafe { kSCPropNetProxiesSOCKSEnable },
        unsafe { kSCPropNetProxiesSOCKSProxy },
        unsafe { kSCPropNetProxiesSOCKSPort },
    );

    let mutable_ref: &MutableConfigDict = CFRetained::as_ref(&mutable);
    let typed: &ConfigDict = AsRef::as_ref(mutable_ref);
    let opaque: &CFDictionary = AsRef::as_ref(typed);
    if !service.stage_proxy_configuration(opaque) {
        bail!("SCNetworkProtocolSetConfiguration failed for {display_name}")
    }
    Ok(())
}

pub(crate) fn disable_legacy_proxy<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
    plan: &LegacyProxyCutoverPlan,
) -> Result<()> {
    validate_plan(plan)?;
    let mut preferences = open()?;
    preferences.lock()?;
    let services = current_services(&preferences)?;

    // Ownership revalidation and staging share the same preferences lock.
    for identity in &plan.services {
        let observation = read_observation(find_service(&services, identity)?)?;
        if !observation_matches_product(&observation, plan.expected_port) {
            bail!(
                "network service {} changed after preparation; no proxy field was changed",
                identity.display_name
            )
        }
    }
    for identity in &plan.services {
        stage_clear_product_proxy(find_service(&services, identity)?, &identity.display_name)?;
    }
    preferences.commit_apply()
}

pub(crate) fn verify_legacy_proxy_disabled<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
    plan: &LegacyProxyCutoverPlan,
) -> Result<()> {
    validate_plan(plan)?;
    let preferences = open()?;
    let services = current_services(&preferences)?;
    for identity in &plan.services {
        let observation = read_observation(find_service(&services, identity)?)?;
        if !observation_is_cleared(&observation) {
            bail!(
                "network service {} still contains a legacy product proxy value",
                identity.display_name
            )
        }
    }
    Ok(())
}

pub(crate) fn recover_legacy_proxy<P: ProxyPreferences>(
    open: impl Fn() -> Result<P>,
    plan: &LegacyProxyCutoverPlan,
) -> Result<()> {
    validate_plan(plan)?;
    let preferences = open()?;
    let services = current_services(&preferences)?;
    let states = plan
        .services
        .iter()
        .map(|identity| {
            let observation = read_observation(find_service(&services, identity)?)?;
            if observation_matches_product(&observation, plan.expected_port) {
                Ok(false)
            } else if observation_is_cleared(&observation) {
                Ok(true)
            } else {
                bail!(
                    "network service {} is neither exact-product-applied nor cleared",
                    identity.display_name
                )
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if states.iter().all(|cleared| *cleared) {
        return verify_legacy_proxy_disabled(&open, plan);
    }
    if states.iter().any(|cleared| *cleared) {
        bail!("legacy proxy services are in a non-atomic mixed recovery state")
    }
    disable_legacy_proxy(&open, plan)?;
    verify_legacy_proxy_disabled(&open, plan)
}

fn service_carries_legacy_proxy(
    service: &impl ProxyService,
    owned_ports: &[u16],
    legacy_pac_present: bool,
) -> Result<()> {
    let id = service_id(service)?;
    let name = service_name(service, &id)?;
    // A service with no Proxies protocol or no configuration dictionary carries
    // no proxy at all. This is the same tolerance the previous machine-wide
    // check applied; it is not an ownership claim.
    let ProxyConfiguration::Configured(configuration) = service.proxy_configuration() else {
        return Ok(());
    };
    let configuration = as_config_dict(&configuration);
    // Per protocol, not the all-three conjunction: a partially torn down legacy
    // proxy must still block. Requiring all three would fail open on exactly the
    // residue this check exists to catch.
    for (label, setting_name, enable, host, port) in unsafe {
        [
            (
                "HTTP proxy",
                "Web Proxy (HTTP)",
                kSCPropNetProxiesHTTPEnable,
                kSCPropNetProxiesHTTPProxy,
                kSCPropNetProxiesHTTPPort,
            ),
            (
                "HTTPS proxy",
                "Secure Web Proxy (HTTPS)",
                kSCPropNetProxiesHTTPSEnable,
                kSCPropNetProxiesHTTPSProxy,
                kSCPropNetProxiesHTTPSPort,
            ),
            (
                "SOCKS proxy",
                "SOCKS Proxy",
                kSCPropNetProxiesSOCKSEnable,
                kSCPropNetProxiesSOCKSProxy,
                kSCPropNetProxiesSOCKSPort,
            ),
        ]
    } {
        let state = read_protocol(configuration, enable, host, port, label)?;
        if owned_ports
            .iter()
            .any(|owned| protocol_matches_product(&state, *owned))
        {
            let owned_port = state.port.unwrap_or_default();
            bail!(
                "network service {name} still has {label} enabled on the retired 127.0.0.1:{owned_port} endpoint; turn off \"{setting_name}\" in System Settings > Network > Details > Proxies before confirming legacy cleanup"
            )
        }
    }
    // PAC carries no port, so it is only attributable to this product when the
    // retired installation's own PAC artifact is still on disk.
    if legacy_pac_present
        && enabled_flag(
            configuration,
            unsafe { kSCPropNetProxiesProxyAutoConfigEnable },
            "PAC proxy configuration",
        )?
    {
        bail!(
            "network service {name} still has PAC proxy configuration enabled while the retired installation's proxy.pac remains; turn off \"Automatic Proxy Configuration\" in System Settings > Network > Details > Proxies before confirming legacy cleanup"
        )
    }
    Ok(())
}

pub(crate) fn verify_no_legacy_owned_proxy<P: ProxyPreferences>(
    open: impl FnOnce() -> Result<P>,
    owned_ports: &[u16],
    legacy_pac_present: bool,
) -> Result<()> {
    // Never a vacuous pass: absence is only provable against a known endpoint.
    if owned_ports.is_empty() || owned_ports.contains(&0) {
        bail!(
            "the retired installation's owned proxy port is unknown; legacy proxy absence cannot be proven"
        )
    }
    let preferences = open()?;
    for service in current_services(&preferences)? {
        service_carries_legacy_proxy(&service, owned_ports, legacy_pac_present)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
