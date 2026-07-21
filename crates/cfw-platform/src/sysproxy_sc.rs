//! System proxy via `objc2-system-configuration` (`SCPreferences` +
//! `SCNetworkProtocol` Proxies). Prefer this over `networksetup` CLI parsing;
//! callers should fall back to networksetup when this path returns `Err`.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{
    CFArray, CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_system_configuration::{
    kSCNetworkProtocolTypeDNS, kSCNetworkProtocolTypeProxies, kSCPropNetDNSServerAddresses,
    kSCPropNetProxiesExceptionsList, kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPPort,
    kSCPropNetProxiesHTTPProxy, kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSPort,
    kSCPropNetProxiesHTTPSProxy, kSCPropNetProxiesProxyAutoConfigEnable,
    kSCPropNetProxiesProxyAutoConfigURLString, kSCPropNetProxiesSOCKSEnable,
    kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy, SCNetworkService, SCNetworkSet,
    SCPreferences,
};

use crate::{NetworkServiceProxySnapshot, ProxyProtocolState, PROXY_HOST};

const PREFS_NAME: &str = "com.bill.clashformac.sysproxy";

type ProxyDict = CFDictionary<CFString, CFType>;
type ProxyDictMut = CFMutableDictionary<CFString, CFType>;

struct PrefsSession {
    prefs: CFRetained<SCPreferences>,
    locked: bool,
}

impl PrefsSession {
    fn open() -> Result<Self> {
        let name = CFString::from_str(PREFS_NAME);
        let prefs =
            SCPreferences::new(None, &name, None).context("SCPreferencesCreate failed")?;
        Ok(Self {
            prefs,
            locked: false,
        })
    }

    fn lock(&mut self) -> Result<()> {
        if !self.prefs.lock(true) {
            bail!("SCPreferencesLock failed");
        }
        self.locked = true;
        Ok(())
    }

    fn commit_apply(&self) -> Result<()> {
        if !self.prefs.commit_changes() {
            bail!("SCPreferencesCommitChanges failed");
        }
        if !self.prefs.apply_changes() {
            bail!("SCPreferencesApplyChanges failed");
        }
        Ok(())
    }
}

impl Drop for PrefsSession {
    fn drop(&mut self) {
        if self.locked {
            let _ = self.prefs.unlock();
        }
    }
}

fn current_services(prefs: &SCPreferences) -> Result<Vec<CFRetained<SCNetworkService>>> {
    let set = SCNetworkSet::current(prefs).context("SCNetworkSetCopyCurrent failed")?;
    let services = set.services().context("SCNetworkSetCopyServices failed")?;
    // SAFETY: SCNetworkSetCopyServices returns an array of SCNetworkService refs.
    let typed = unsafe { CFRetained::cast_unchecked::<CFArray<SCNetworkService>>(services) };
    let mut out = Vec::with_capacity(typed.len());
    for index in 0..typed.len() {
        if let Some(service) = typed.get(index) {
            out.push(service);
        }
    }
    Ok(out)
}

fn service_name(service: &SCNetworkService) -> Option<String> {
    service.name().map(|name| name.to_string())
}

fn find_service<'a>(
    services: &'a [CFRetained<SCNetworkService>],
    name: &str,
) -> Result<&'a SCNetworkService> {
    services
        .iter()
        .find(|service| service_name(service).as_deref() == Some(name))
        .map(|service| service.as_ref())
        .with_context(|| format!("SC network service not found: {name}"))
}

fn as_proxy_dict(dict: &CFDictionary) -> &ProxyDict {
    // SAFETY: SystemConfiguration Proxies dictionaries use CFString keys and CFType values.
    unsafe { dict.cast_unchecked::<CFString, CFType>() }
}

fn dict_number(dict: &ProxyDict, key: &CFString) -> Option<i32> {
    let value = dict.get(key)?;
    value.downcast_ref::<CFNumber>().and_then(CFNumber::as_i32)
}

fn dict_string(dict: &ProxyDict, key: &CFString) -> Option<String> {
    let value = dict.get(key)?;
    value
        .downcast_ref::<CFString>()
        .map(|string| string.to_string())
}

fn dict_string_array(dict: &ProxyDict, key: &CFString) -> Vec<String> {
    let Some(value) = dict.get(key) else {
        return Vec::new();
    };
    let Some(array) = value.downcast_ref::<CFArray>() else {
        return Vec::new();
    };
    // SAFETY: ExceptionsList is an array of CFString.
    let typed = unsafe { array.cast_unchecked::<CFString>() };
    let mut out = Vec::with_capacity(typed.len());
    for index in 0..typed.len() {
        if let Some(item) = typed.get(index) {
            let text = item.to_string();
            if !text.is_empty() && text != "Empty" {
                out.push(text);
            }
        }
    }
    out
}

fn read_protocol(
    dict: &ProxyDict,
    enable: &CFString,
    host: &CFString,
    port: &CFString,
) -> ProxyProtocolState {
    let enabled = dict_number(dict, enable).unwrap_or(0) != 0;
    let server = dict_string(dict, host).filter(|value| !value.is_empty());
    let port = dict_number(dict, port).and_then(|value| u16::try_from(value).ok());
    ProxyProtocolState {
        enabled,
        server,
        port,
    }
}

fn proxies_dict(service: &SCNetworkService) -> Result<CFRetained<CFDictionary>> {
    let protocol_type = unsafe { kSCNetworkProtocolTypeProxies };
    let protocol = service
        .protocol(protocol_type)
        .context("SCNetworkServiceCopyProtocol(Proxies) failed")?;
    protocol
        .configuration()
        .context("SCNetworkProtocolGetConfiguration returned null")
}

/// List user-visible network service names from the current SCNetworkSet.
pub(crate) fn list_network_services() -> Result<Vec<String>> {
    let session = PrefsSession::open()?;
    let services = current_services(&session.prefs)?;
    Ok(services
        .iter()
        .filter_map(|service| service_name(service))
        .filter(|name| !name.is_empty())
        .collect())
}

pub(crate) fn read_service_proxy_snapshot(service: &str) -> Result<NetworkServiceProxySnapshot> {
    let session = PrefsSession::open()?;
    let services = current_services(&session.prefs)?;
    let sc_service = find_service(&services, service)?;
    let dict = proxies_dict(sc_service)?;
    let dict = as_proxy_dict(&dict);
    Ok(NetworkServiceProxySnapshot {
        service: service.to_string(),
        web: read_protocol(
            dict,
            unsafe { kSCPropNetProxiesHTTPEnable },
            unsafe { kSCPropNetProxiesHTTPProxy },
            unsafe { kSCPropNetProxiesHTTPPort },
        ),
        secure_web: read_protocol(
            dict,
            unsafe { kSCPropNetProxiesHTTPSEnable },
            unsafe { kSCPropNetProxiesHTTPSProxy },
            unsafe { kSCPropNetProxiesHTTPSPort },
        ),
        socks: read_protocol(
            dict,
            unsafe { kSCPropNetProxiesSOCKSEnable },
            unsafe { kSCPropNetProxiesSOCKSProxy },
            unsafe { kSCPropNetProxiesSOCKSPort },
        ),
        bypass_domains: dict_string_array(dict, unsafe { kSCPropNetProxiesExceptionsList }),
    })
}

fn set_number(dict: &ProxyDictMut, key: &CFString, value: i32) {
    let number = CFNumber::new_i32(value);
    dict.set(key, number.as_ref());
}

fn set_string(dict: &ProxyDictMut, key: &CFString, value: &str) {
    let string = CFString::from_str(value);
    dict.set(key, string.as_ref());
}

fn set_string_array(dict: &ProxyDictMut, key: &CFString, values: &[String]) {
    let retained: Vec<CFRetained<CFString>> =
        values.iter().map(|value| CFString::from_str(value)).collect();
    let refs: Vec<&CFString> = retained.iter().map(|value| value.as_ref()).collect();
    let array = CFArray::<CFString>::from_objects(&refs);
    dict.set(key, array.as_ref());
}

fn apply_protocol_to_dict(
    dict: &ProxyDictMut,
    state: &ProxyProtocolState,
    enable: &CFString,
    host: &CFString,
    port: &CFString,
) {
    set_number(dict, enable, i32::from(state.enabled));
    if let Some(server) = state.server.as_deref() {
        set_string(dict, host, server);
    }
    if let Some(value) = state.port {
        set_number(dict, port, i32::from(value));
    }
}

fn seed_mutable_from_existing(dict: &ProxyDictMut, existing: &ProxyDict) {
    let snapshot_keys: &[&CFString] = unsafe {
        &[
            kSCPropNetProxiesHTTPEnable,
            kSCPropNetProxiesHTTPProxy,
            kSCPropNetProxiesHTTPPort,
            kSCPropNetProxiesHTTPSEnable,
            kSCPropNetProxiesHTTPSProxy,
            kSCPropNetProxiesHTTPSPort,
            kSCPropNetProxiesSOCKSEnable,
            kSCPropNetProxiesSOCKSProxy,
            kSCPropNetProxiesSOCKSPort,
            kSCPropNetProxiesExceptionsList,
            kSCPropNetProxiesProxyAutoConfigEnable,
            kSCPropNetProxiesProxyAutoConfigURLString,
        ]
    };
    for key in snapshot_keys {
        if let Some(value) = existing.get(*key) {
            dict.set(*key, value.as_ref());
        }
    }
}

fn mutate_service_proxies<F>(service_name: &str, mutate: F) -> Result<()>
where
    F: FnOnce(&ProxyDictMut) -> Result<()>,
{
    let mut session = PrefsSession::open()?;
    session.lock()?;
    let services = current_services(&session.prefs)?;
    let sc_service = find_service(&services, service_name)?;
    let protocol_type = unsafe { kSCNetworkProtocolTypeProxies };
    let protocol = sc_service
        .protocol(protocol_type)
        .context("SCNetworkServiceCopyProtocol(Proxies) failed")?;

    let dict = ProxyDictMut::empty();
    if let Some(existing) = protocol.configuration() {
        seed_mutable_from_existing(&dict, as_proxy_dict(&existing));
    }

    mutate(&dict)?;

    // SAFETY: dictionary values are CFType instances matching SC schema.
    let mutable_ref: &ProxyDictMut = CFRetained::as_ref(&dict);
    let typed: &CFDictionary<CFString, CFType> = AsRef::as_ref(mutable_ref);
    let opaque: &CFDictionary = AsRef::as_ref(typed);
    if !unsafe { protocol.set_configuration(Some(opaque)) } {
        bail!("SCNetworkProtocolSetConfiguration failed for {service_name}");
    }
    session.commit_apply()?;
    Ok(())
}

pub(crate) fn apply_service_snapshot(snapshot: &NetworkServiceProxySnapshot) -> Result<()> {
    mutate_service_proxies(&snapshot.service, |dict| {
        apply_protocol_to_dict(
            dict,
            &snapshot.web,
            unsafe { kSCPropNetProxiesHTTPEnable },
            unsafe { kSCPropNetProxiesHTTPProxy },
            unsafe { kSCPropNetProxiesHTTPPort },
        );
        apply_protocol_to_dict(
            dict,
            &snapshot.secure_web,
            unsafe { kSCPropNetProxiesHTTPSEnable },
            unsafe { kSCPropNetProxiesHTTPSProxy },
            unsafe { kSCPropNetProxiesHTTPSPort },
        );
        apply_protocol_to_dict(
            dict,
            &snapshot.socks,
            unsafe { kSCPropNetProxiesSOCKSEnable },
            unsafe { kSCPropNetProxiesSOCKSProxy },
            unsafe { kSCPropNetProxiesSOCKSPort },
        );
        if snapshot.bypass_domains.is_empty() {
            dict.remove(unsafe { kSCPropNetProxiesExceptionsList });
        } else {
            set_string_array(
                dict,
                unsafe { kSCPropNetProxiesExceptionsList },
                &snapshot.bypass_domains,
            );
        }
        set_number(dict, unsafe { kSCPropNetProxiesProxyAutoConfigEnable }, 0);
        Ok(())
    })
}

pub(crate) fn apply_clash_proxy(service: &str, port: u16, bypass: &[String]) -> Result<()> {
    mutate_service_proxies(service, |dict| {
        set_number(dict, unsafe { kSCPropNetProxiesProxyAutoConfigEnable }, 0);
        set_number(dict, unsafe { kSCPropNetProxiesHTTPEnable }, 1);
        set_string(dict, unsafe { kSCPropNetProxiesHTTPProxy }, PROXY_HOST);
        set_number(dict, unsafe { kSCPropNetProxiesHTTPPort }, i32::from(port));
        set_number(dict, unsafe { kSCPropNetProxiesHTTPSEnable }, 1);
        set_string(dict, unsafe { kSCPropNetProxiesHTTPSProxy }, PROXY_HOST);
        set_number(dict, unsafe { kSCPropNetProxiesHTTPSPort }, i32::from(port));
        set_number(dict, unsafe { kSCPropNetProxiesSOCKSEnable }, 1);
        set_string(dict, unsafe { kSCPropNetProxiesSOCKSProxy }, PROXY_HOST);
        set_number(dict, unsafe { kSCPropNetProxiesSOCKSPort }, i32::from(port));
        set_string_array(dict, unsafe { kSCPropNetProxiesExceptionsList }, bypass);
        Ok(())
    })
}

pub(crate) fn apply_clash_pac(service: &str, pac_url: &str) -> Result<()> {
    mutate_service_proxies(service, |dict| {
        set_number(dict, unsafe { kSCPropNetProxiesHTTPEnable }, 0);
        set_number(dict, unsafe { kSCPropNetProxiesHTTPSEnable }, 0);
        set_number(dict, unsafe { kSCPropNetProxiesSOCKSEnable }, 0);
        set_number(dict, unsafe { kSCPropNetProxiesProxyAutoConfigEnable }, 1);
        set_string(
            dict,
            unsafe { kSCPropNetProxiesProxyAutoConfigURLString },
            pac_url,
        );
        Ok(())
    })
}

fn mutate_service_dns<F>(service_name: &str, mutate: F) -> Result<()>
where
    F: FnOnce(&ProxyDictMut) -> Result<()>,
{
    let mut session = PrefsSession::open()?;
    session.lock()?;
    let services = current_services(&session.prefs)?;
    let sc_service = find_service(&services, service_name)?;
    let protocol_type = unsafe { kSCNetworkProtocolTypeDNS };
    let protocol = sc_service
        .protocol(protocol_type)
        .context("SCNetworkServiceCopyProtocol(DNS) failed")?;

    let dict = ProxyDictMut::empty();
    if let Some(existing) = protocol.configuration() {
        let existing = as_proxy_dict(&existing);
        if let Some(value) = existing.get(unsafe { kSCPropNetDNSServerAddresses }) {
            dict.set(unsafe { kSCPropNetDNSServerAddresses }, value.as_ref());
        }
    }

    mutate(&dict)?;

    let mutable_ref: &ProxyDictMut = CFRetained::as_ref(&dict);
    let typed: &CFDictionary<CFString, CFType> = AsRef::as_ref(mutable_ref);
    let opaque: &CFDictionary = AsRef::as_ref(typed);
    if !unsafe { protocol.set_configuration(Some(opaque)) } {
        bail!("SCNetworkProtocolSetConfiguration(DNS) failed for {service_name}");
    }
    session.commit_apply()?;
    Ok(())
}

/// Set DNS nameservers for a service. Empty slice clears custom DNS (DHCP).
pub(crate) fn apply_dns_servers(service: &str, servers: &[String]) -> Result<()> {
    mutate_service_dns(service, |dict| {
        if servers.is_empty() {
            dict.remove(unsafe { kSCPropNetDNSServerAddresses });
        } else {
            set_string_array(dict, unsafe { kSCPropNetDNSServerAddresses }, servers);
        }
        Ok(())
    })
}
