//! SystemConfiguration ownership checks and one-way legacy proxy cleanup.
//!
//! Historical proxy snapshots are deliberately not an authority: the legacy
//! app stored them in a user-writable location without an authenticated digest.
//! A cutover may mutate only service IDs captured from live SCPreferences whose
//! HTTP, HTTPS and SOCKS values all exactly equal the product loopback endpoint.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{
    CFArray, CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_system_configuration::{
    SCNetworkService, SCNetworkSet, SCPreferences, kSCNetworkProtocolTypeProxies,
    kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy,
    kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable,
    kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
};

use crate::legacy_proxy::{LegacyProxyCutoverPlan, LegacyProxyServiceIdentity};

const PREFS_NAME: &str = "com.bill.clashformac.legacy-cutover";
const MAX_SERVICES: usize = 64;
const MAX_IDENTITY_BYTES: usize = 1024;

type ConfigDict = CFDictionary<CFString, CFType>;
type MutableConfigDict = CFMutableDictionary<CFString, CFType>;

struct PreferencesSession {
    preferences: CFRetained<SCPreferences>,
    locked: bool,
}

impl PreferencesSession {
    fn open() -> Result<Self> {
        let name = CFString::from_str(PREFS_NAME);
        let preferences =
            SCPreferences::new(None, &name, None).context("SCPreferencesCreate failed")?;
        Ok(Self {
            preferences,
            locked: false,
        })
    }

    fn lock(&mut self) -> Result<()> {
        if !self.preferences.lock(true) {
            bail!("SCPreferencesLock failed")
        }
        self.locked = true;
        Ok(())
    }

    fn commit_apply(&self) -> Result<()> {
        if !self.preferences.commit_changes() {
            bail!("SCPreferencesCommitChanges failed")
        }
        if !self.preferences.apply_changes() {
            bail!("SCPreferencesApplyChanges failed")
        }
        Ok(())
    }
}

impl Drop for PreferencesSession {
    fn drop(&mut self) {
        if self.locked {
            let _unlocked = self.preferences.unlock();
        }
    }
}

fn current_services(prefs: &SCPreferences) -> Result<Vec<CFRetained<SCNetworkService>>> {
    let set = SCNetworkSet::current(prefs).context("SCNetworkSetCopyCurrent failed")?;
    let services = set.services().context("SCNetworkSetCopyServices failed")?;
    // SAFETY: SCNetworkSetCopyServices returns an array of SCNetworkService refs.
    let typed = unsafe { CFRetained::cast_unchecked::<CFArray<SCNetworkService>>(services) };
    if typed.len() > MAX_SERVICES {
        bail!("current network service count exceeds the cutover safety bound")
    }
    let mut result = Vec::with_capacity(typed.len());
    for index in 0..typed.len() {
        if let Some(service) = typed.get(index) {
            result.push(service);
        }
    }
    Ok(result)
}

fn service_id(service: &SCNetworkService) -> Result<String> {
    let value = service
        .service_id()
        .context("SC network service has no stable identifier")?
        .to_string();
    validate_identity_text("service identifier", &value)?;
    Ok(value)
}

fn service_name(service: &SCNetworkService, id: &str) -> Result<String> {
    let value = service
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|| id.to_owned());
    validate_identity_text("service display name", &value)?;
    Ok(value)
}

fn validate_identity_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("SC network {label} is invalid")
    }
    Ok(())
}

fn find_service<'a>(
    services: &'a [CFRetained<SCNetworkService>],
    identity: &LegacyProxyServiceIdentity,
) -> Result<&'a SCNetworkService> {
    let service = services
        .iter()
        .find(|service| {
            service
                .service_id()
                .is_some_and(|id| id.to_string() == identity.service_id)
        })
        .map(AsRef::as_ref)
        .with_context(|| {
            format!(
                "SC network service identity disappeared: {}",
                identity.service_id
            )
        })?;
    if service_name(service, &identity.service_id)? != identity.display_name {
        bail!(
            "SC network service {} changed display identity during cutover",
            identity.service_id
        )
    }
    Ok(service)
}

fn as_config_dict(dict: &CFDictionary) -> &ConfigDict {
    // SAFETY: SystemConfiguration proxy dictionaries use CFString keys and
    // CoreFoundation values.
    unsafe { dict.cast_unchecked::<CFString, CFType>() }
}

fn enabled_flag(dict: &ConfigDict, key: &CFString, label: &str) -> Result<bool> {
    let Some(value) = dict.get(key) else {
        return Ok(false);
    };
    let number = value.downcast::<CFNumber>().map_err(|_| {
        anyhow::anyhow!("{label} enable flag has an unexpected CoreFoundation type")
    })?;
    let value = number
        .as_i32()
        .ok_or_else(|| anyhow::anyhow!("{label} enable flag is not an integer"))?;
    validate_enabled_flag_value(label, value)
}

fn number_value(dict: &ConfigDict, key: &CFString, label: &str) -> Result<Option<i32>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .downcast::<CFNumber>()
        .map_err(|_| anyhow::anyhow!("{label} has an unexpected CoreFoundation type"))?
        .as_i32()
        .ok_or_else(|| anyhow::anyhow!("{label} is not an integer"))
        .map(Some)
}

fn string_value(dict: &ConfigDict, key: &CFString, label: &str) -> Result<Option<String>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .downcast::<CFString>()
        .map_err(|_| anyhow::anyhow!("{label} has an unexpected CoreFoundation type"))
        .map(|value| Some(value.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyProtocolState {
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
}

fn read_protocol(
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
struct ProxyObservation {
    service_id: String,
    display_name: String,
    web: ProxyProtocolState,
    secure_web: ProxyProtocolState,
    socks: ProxyProtocolState,
    pac_enabled: bool,
    wpad_enabled: bool,
}

fn read_observation(service: &SCNetworkService) -> Result<ProxyObservation> {
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

fn protocol_matches_product(protocol: &ProxyProtocolState, expected_port: u16) -> bool {
    protocol.enabled
        && protocol.server.as_deref() == Some("127.0.0.1")
        && protocol.port == Some(expected_port)
}

fn observation_matches_product(observation: &ProxyObservation, expected_port: u16) -> bool {
    !observation.pac_enabled
        && !observation.wpad_enabled
        && protocol_matches_product(&observation.web, expected_port)
        && protocol_matches_product(&observation.secure_web, expected_port)
        && protocol_matches_product(&observation.socks, expected_port)
}

fn protocol_is_cleared(protocol: &ProxyProtocolState) -> bool {
    !protocol.enabled && protocol.server.is_none() && protocol.port.is_none()
}

fn observation_is_cleared(observation: &ProxyObservation) -> bool {
    !observation.pac_enabled
        && !observation.wpad_enabled
        && protocol_is_cleared(&observation.web)
        && protocol_is_cleared(&observation.secure_web)
        && protocol_is_cleared(&observation.socks)
}

pub(crate) fn capture_legacy_applied_proxy(expected_port: u16) -> Result<LegacyProxyCutoverPlan> {
    let session = PreferencesSession::open()?;
    let services = current_services(&session.preferences)?;
    let mut owned = Vec::new();
    for service in services {
        let observation = match read_observation(&service) {
            Ok(observation) => observation,
            Err(error) if error.to_string().contains("has no Proxies protocol") => continue,
            Err(error) => return Err(error),
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

pub(crate) fn verify_legacy_applied_proxy(plan: &LegacyProxyCutoverPlan) -> Result<()> {
    validate_plan(plan)?;
    let session = PreferencesSession::open()?;
    let services = current_services(&session.preferences)?;
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

fn stage_clear_product_proxy(service: &SCNetworkService, display_name: &str) -> Result<()> {
    let protocol = service
        .protocol(unsafe { kSCNetworkProtocolTypeProxies })
        .with_context(|| format!("network service {display_name} has no Proxies protocol"))?;
    let existing = protocol
        .configuration()
        .with_context(|| format!("network service {display_name} has no proxy configuration"))?;
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
    if !unsafe { protocol.set_configuration(Some(opaque)) } {
        bail!("SCNetworkProtocolSetConfiguration failed for {display_name}")
    }
    Ok(())
}

pub(crate) fn disable_legacy_proxy(plan: &LegacyProxyCutoverPlan) -> Result<()> {
    validate_plan(plan)?;
    let mut session = PreferencesSession::open()?;
    session.lock()?;
    let services = current_services(&session.preferences)?;

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
    session.commit_apply()
}

pub(crate) fn verify_legacy_proxy_disabled(plan: &LegacyProxyCutoverPlan) -> Result<()> {
    validate_plan(plan)?;
    let session = PreferencesSession::open()?;
    let services = current_services(&session.preferences)?;
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

pub(crate) fn recover_legacy_proxy(plan: &LegacyProxyCutoverPlan) -> Result<()> {
    validate_plan(plan)?;
    let session = PreferencesSession::open()?;
    let services = current_services(&session.preferences)?;
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
        return verify_legacy_proxy_disabled(plan);
    }
    if states.iter().any(|cleared| *cleared) {
        bail!("legacy proxy services are in a non-atomic mixed recovery state")
    }
    disable_legacy_proxy(plan)?;
    verify_legacy_proxy_disabled(plan)
}

fn validate_enabled_flag_value(label: &str, value: i32) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("{label} enable flag has invalid value {value}; expected 0 or 1"),
    }
}

fn verify_service_disabled(service: &SCNetworkService) -> Result<()> {
    let id = service_id(service)?;
    let name = service_name(service, &id)?;
    let Some(protocol) = service.protocol(unsafe { kSCNetworkProtocolTypeProxies }) else {
        return Ok(());
    };
    let Some(configuration) = protocol.configuration() else {
        return Ok(());
    };
    let configuration = as_config_dict(&configuration);
    for (label, setting_name, key) in unsafe {
        [
            (
                "HTTP proxy",
                "Web Proxy (HTTP)",
                kSCPropNetProxiesHTTPEnable,
            ),
            (
                "HTTPS proxy",
                "Secure Web Proxy (HTTPS)",
                kSCPropNetProxiesHTTPSEnable,
            ),
            ("SOCKS proxy", "SOCKS Proxy", kSCPropNetProxiesSOCKSEnable),
            (
                "PAC proxy configuration",
                "Automatic Proxy Configuration",
                kSCPropNetProxiesProxyAutoConfigEnable,
            ),
            (
                "proxy auto-discovery (WPAD)",
                "Auto Proxy Discovery",
                kSCPropNetProxiesProxyAutoDiscoveryEnable,
            ),
        ]
    } {
        if enabled_flag(configuration, key, label)? {
            bail!(
                "network service {name} still has {label} enabled; turn off \"{setting_name}\" in System Settings > Network > Details > Proxies before confirming legacy cleanup"
            )
        }
    }
    Ok(())
}

pub(crate) fn verify_proxies_disabled() -> Result<()> {
    let session = PreferencesSession::open()?;
    for service in current_services(&session.preferences)? {
        verify_service_disabled(&service)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol(enabled: bool, server: Option<&str>, port: Option<u16>) -> ProxyProtocolState {
        ProxyProtocolState {
            enabled,
            server: server.map(ToOwned::to_owned),
            port,
        }
    }

    fn observation(protocol: ProxyProtocolState) -> ProxyObservation {
        ProxyObservation {
            service_id: "service-id".into(),
            display_name: "Wi-Fi".into(),
            web: protocol.clone(),
            secure_web: protocol.clone(),
            socks: protocol,
            pac_enabled: false,
            wpad_enabled: false,
        }
    }

    #[test]
    fn proxy_enable_flags_accept_only_zero_and_one() {
        assert!(!validate_enabled_flag_value("proxy", 0).expect("zero"));
        assert!(validate_enabled_flag_value("proxy", 1).expect("one"));
        assert!(validate_enabled_flag_value("proxy", -1).is_err());
        assert!(validate_enabled_flag_value("proxy", 2).is_err());
    }

    #[test]
    fn ownership_requires_all_three_exact_live_loopback_protocols() {
        let exact = observation(protocol(true, Some("127.0.0.1"), Some(7890)));
        assert!(observation_matches_product(&exact, 7890));

        let mut malicious_historical_value = exact.clone();
        malicious_historical_value.web.server = Some("attacker.invalid".into());
        assert!(!observation_matches_product(
            &malicious_historical_value,
            7890
        ));

        let mut partial = exact.clone();
        partial.socks.enabled = false;
        assert!(!observation_matches_product(&partial, 7890));

        let mut pac = exact;
        pac.pac_enabled = true;
        assert!(!observation_matches_product(&pac, 7890));
    }

    #[test]
    fn postcondition_requires_owned_values_to_be_cleared() {
        assert!(observation_is_cleared(&observation(protocol(
            false, None, None
        ))));
        assert!(!observation_is_cleared(&observation(protocol(
            false,
            Some("127.0.0.1"),
            Some(7890)
        ))));
    }
}
