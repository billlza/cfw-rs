//! Read-only physical network identity for explicit application policies. TUN,
//! loopback, bridge and virtual interfaces never become an automation trigger.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Wifi,
    Wired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkContext {
    pub interface: String,
    pub kind: NetworkKind,
    pub ssid: Option<String>,
    /// Addresses participate in edge detection but are not needed by the UI.
    #[serde(skip)]
    pub addresses: Vec<String>,
}

/// Called only by the visible Wi-Fi permission button, on the app main thread.
/// Retain the manager while macOS presents its own permission prompt.
#[cfg(target_os = "macos")]
pub fn request_wifi_name_access() -> anyhow::Result<()> {
    use objc2::{MainThreadMarker, rc::Retained};
    use objc2_core_location::CLLocationManager;
    use std::cell::RefCell;
    thread_local! {static MANAGER:RefCell<Option<Retained<CLLocationManager>>>=const {RefCell::new(None)};}
    let _main = MainThreadMarker::new()
        .ok_or_else(|| anyhow::anyhow!("Wi-Fi permission must be requested on the main thread"))?;
    MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        // SAFETY: manager is created and retained on the macOS main thread.
        let manager = manager.get_or_insert_with(|| unsafe { CLLocationManager::new() });
        unsafe { manager.requestWhenInUseAuthorization() };
    });
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn request_wifi_name_access() -> anyhow::Result<()> {
    anyhow::bail!("Wi-Fi name access is supported only on macOS")
}

#[cfg(target_os = "macos")]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    use anyhow::{Context, bail};
    use objc2_core_foundation::{CFArray, CFDictionary, CFString, CFType};
    use objc2_core_wlan::CWWiFiClient;
    use objc2_foundation::NSString;
    use objc2_system_configuration::{
        SCDynamicStore, SCError, SCNetworkService, SCNetworkSet, SCPreferences, kSCStatusNoKey,
    };
    type Dictionary = CFDictionary<CFString, CFType>;
    fn values(
        key: &str,
    ) -> anyhow::Result<Option<objc2_core_foundation::CFRetained<CFDictionary>>> {
        match SCDynamicStore::value(None, &CFString::from_str(key)) {
            Some(value) => {
                Ok(Some(value.downcast::<CFDictionary>().map_err(|_| {
                    anyhow::anyhow!("network state has an invalid type")
                })?))
            }
            None if SCError() == kSCStatusNoKey as i32 => Ok(None),
            None => bail!("SystemConfiguration network observation failed"),
        }
    }
    fn string(dict: &Dictionary, key: &str) -> anyhow::Result<Option<String>> {
        dict.get(&CFString::from_str(key))
            .map(|value| {
                value
                    .downcast::<CFString>()
                    .map(|v| v.to_string())
                    .map_err(|_| anyhow::anyhow!("network field has an invalid type"))
            })
            .transpose()
    }
    let prefs = SCPreferences::new(
        None,
        &CFString::from_str("com.bill.clashformac.network-observation"),
        None,
    )
    .context("network preferences are unavailable")?;
    let set = SCNetworkSet::current(&prefs).context("current network set is unavailable")?;
    let services = set.services().context("network services are unavailable")?;
    if services.len() > 64 {
        bail!("network service count exceeds its observation bound")
    }
    // SAFETY: SCNetworkSetCopyServices is documented to contain SCNetworkService.
    let services = unsafe { services.cast_unchecked::<SCNetworkService>() };
    let primary = values("State:/Network/Global/IPv4")?.or(values("State:/Network/Global/IPv6")?);
    // SAFETY: SCDynamicStore network dictionaries have CFString keys and CFType values.
    let primary = primary
        .as_ref()
        .map(|v| unsafe { v.cast_unchecked::<CFString, CFType>() })
        .map(|v| string(v, "PrimaryInterface"))
        .transpose()?
        .flatten();
    // SAFETY: retained system CoreWLAN objects; only documented read methods are called.
    let wifi = unsafe { CWWiFiClient::sharedWiFiClient() };
    let mut candidates = Vec::new();
    for index in 0..services.len() {
        let service = services
            .get(index)
            .context("network service entry is missing")?;
        if !service.enabled() {
            continue;
        }
        let Some(interface) = service.interface() else {
            continue;
        };
        let kind = interface
            .interface_type()
            .context("network interface type is unavailable")?
            .to_string();
        if !matches!(kind.as_str(), "Ethernet" | "IEEE80211") {
            continue;
        }
        let name = interface
            .bsd_name()
            .context("physical network interface name is unavailable")?
            .to_string();
        if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            bail!("physical interface name is invalid")
        }
        let id = service
            .service_id()
            .context("network service identity is unavailable")?;
        let mut addresses = Vec::new();
        for family in ["IPv4", "IPv6"] {
            if let Some(value) = values(&format!("State:/Network/Service/{id}/{family}"))? {
                // SAFETY: same documented network dictionary contract as above.
                let dict = unsafe { value.cast_unchecked::<CFString, CFType>() };
                if let Some(values) = dict.get(&CFString::from_str("Addresses")) {
                    let values = values
                        .downcast::<CFArray>()
                        .map_err(|_| anyhow::anyhow!("network addresses have an invalid type"))?;
                    if values.len() > 64 {
                        bail!("network address count exceeds its observation bound")
                    }
                    // SAFETY: Addresses in an SC network dictionary is an array of CFStrings.
                    let values = unsafe { values.cast_unchecked::<CFString>() };
                    for index in 0..values.len() {
                        let value = values
                            .get(index)
                            .context("network address entry is missing")?
                            .to_string();
                        let address = value
                            .parse::<std::net::IpAddr>()
                            .context("network address is invalid")?;
                        if !address.is_loopback() && !address.is_unspecified() {
                            addresses.push(value)
                        }
                    }
                }
            }
        }
        if addresses.is_empty() {
            continue;
        }
        addresses.sort();
        addresses.dedup();
        // SAFETY: the name came from a physical SC interface; CoreWLAN returns
        // None for a non-Wi-Fi interface. No location permission is requested.
        let wifi_interface = unsafe { wifi.interfaceWithName(Some(&NSString::from_str(&name))) };
        let ssid = wifi_interface
            .as_ref()
            .and_then(|v| unsafe { v.ssid() })
            .map(|v| v.to_string());
        if ssid.as_ref().is_some_and(|v| v.len() > 32) {
            bail!("observed Wi-Fi name exceeds 32 bytes")
        }
        candidates.push(NetworkContext {
            interface: name,
            kind: if wifi_interface.is_some() {
                NetworkKind::Wifi
            } else {
                NetworkKind::Wired
            },
            ssid,
            addresses,
        });
    }
    candidates.sort_by_key(|value| {
        (
            Some(&value.interface) != primary.as_ref(),
            value.interface.clone(),
        )
    });
    Ok(candidates.into_iter().next())
}

#[cfg(not(target_os = "macos"))]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    anyhow::bail!("physical network observation is supported only on macOS")
}
