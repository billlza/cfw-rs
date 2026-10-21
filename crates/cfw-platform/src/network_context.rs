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

// Network type comes from SystemConfiguration, not CoreWLAN's optional
// interface or SSID observation (which can be unavailable without permission).
#[cfg(any(target_os = "macos", test))]
fn physical_network_kind(interface_type: &str) -> Option<NetworkKind> {
    match interface_type {
        "IEEE80211" => Some(NetworkKind::Wifi),
        "Ethernet" => Some(NetworkKind::Wired),
        _ => None,
    }
}

// Prefer the IPv4 primary, falling back to IPv6 when that field is absent.
// Failures to observe a network dictionary must not look like missing data.
#[cfg(any(target_os = "macos", test))]
fn primary_interface_from_states(
    mut read: impl FnMut(&str) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<Option<String>> {
    for key in ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] {
        if let Some(primary) = read(key)? {
            return Ok(Some(primary));
        }
    }
    Ok(None)
}

// Do not query CoreWLAN on wired links or mistake an undisclosed SSID for a
// wired network.
#[cfg(any(target_os = "macos", test))]
fn wifi_ssid_if_needed(
    kind: NetworkKind,
    read_ssid: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if kind == NetworkKind::Wifi {
        read_ssid()
    } else {
        None
    }
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
    let primary = primary_interface_from_states(|key| {
        let Some(value) = values(key)? else {
            return Ok(None);
        };
        // SAFETY: SCDynamicStore network dictionaries have CFString keys and CFType values.
        let value = unsafe { value.cast_unchecked::<CFString, CFType>() };
        string(&value, "PrimaryInterface")
    })?;
    // Only create a CoreWLAN client if a Wi-Fi interface needs an SSID read.
    let mut wifi_client = None;
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
        let interface_type = interface
            .interface_type()
            .context("network interface type is unavailable")?
            .to_string();
        let Some(kind) = physical_network_kind(&interface_type) else {
            continue;
        };
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
        // SAFETY: the type is a physical SystemConfiguration interface.
        // CoreWLAN supplies only an optional SSID, without prompting for access.
        let ssid = wifi_ssid_if_needed(kind, || {
            let wifi = wifi_client.get_or_insert_with(|| unsafe { CWWiFiClient::sharedWiFiClient() });
            let interface = unsafe { wifi.interfaceWithName(Some(&NSString::from_str(&name))) };
            interface
                .as_ref()
                .and_then(|value| unsafe { value.ssid() })
                .map(|value| value.to_string())
        });
        if ssid.as_ref().is_some_and(|v| v.len() > 32) {
            bail!("observed Wi-Fi name exceeds 32 bytes")
        }
        candidates.push(NetworkContext {
            interface: name,
            kind,
            ssid,
            addresses,
        });
    }
    candidates.sort_by(|left, right| {
        let left_is_primary = Some(left.interface.as_str()) == primary.as_deref();
        let right_is_primary = Some(right.interface.as_str()) == primary.as_deref();
        right_is_primary
            .cmp(&left_is_primary)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    Ok(candidates.into_iter().next())
}

#[cfg(not(target_os = "macos"))]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    anyhow::bail!("physical network observation is supported only on macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_interface_type_is_independent_of_wifi_name_visibility() {
        assert_eq!(physical_network_kind("IEEE80211"), Some(NetworkKind::Wifi));
        assert_eq!(physical_network_kind("Ethernet"), Some(NetworkKind::Wired));
        for interface_type in ["PPP", "VPN", "Loopback", "Bridge", ""] {
            assert_eq!(physical_network_kind(interface_type), None);
        }

        let mut reads = 0;
        assert_eq!(
            wifi_ssid_if_needed(NetworkKind::Wired, || {
                reads += 1;
                Some("unused".into())
            }),
            None
        );
        assert_eq!(reads, 0, "wired interfaces must not query CoreWLAN");
        assert_eq!(
            wifi_ssid_if_needed(NetworkKind::Wifi, || {
                reads += 1;
                None
            }),
            None
        );
        assert_eq!(reads, 1, "Wi-Fi without an SSID is still Wi-Fi");
    }

    #[test]
    fn primary_interface_falls_back_only_when_ipv4_has_no_primary() {
        let mut keys = Vec::new();
        let primary = primary_interface_from_states(|key| {
            keys.push(key.to_string());
            Ok(key.ends_with("IPv6").then(|| "en6".to_string()))
        })
        .unwrap();
        assert_eq!(primary.as_deref(), Some("en6"));
        assert_eq!(
            keys,
            ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"]
        );

        keys.clear();
        let primary = primary_interface_from_states(|key| {
            keys.push(key.to_string());
            Ok(Some("en0".to_string()))
        })
        .unwrap();
        assert_eq!(primary.as_deref(), Some("en0"));
        assert_eq!(
            keys,
            ["State:/Network/Global/IPv4"],
            "IPv6 must not be queried after an IPv4 primary is found"
        );

        let mut calls = 0;
        let error = primary_interface_from_states(|_| {
            calls += 1;
            anyhow::bail!("observation failed")
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.to_string(), "observation failed");
        assert_eq!(primary_interface_from_states(|_| Ok(None)).unwrap(), None);
    }
}
