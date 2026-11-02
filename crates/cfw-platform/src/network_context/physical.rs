//! Which physical network this Mac is on, from what SystemConfiguration and
//! CoreWLAN report. Only enabled Ethernet and Wi-Fi services with a usable
//! address qualify, and the primary interface wins.
//!
//! `system.rs` implements the reads on the live system; the tests implement
//! them in memory.

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{CFArray, CFDictionary, CFRetained, CFString, CFType};

use super::{NetworkContext, NetworkKind};

/// The most services, and the most addresses of one family, observed.
const MAX_ENTRIES: usize = 64;

/// What the observation reads of the system.
pub(super) trait NetworkSystem {
    type Service: NetworkService;

    /// The services of the current network set, in set order.
    fn services(&self) -> Result<Vec<Self::Service>>;
    /// The dynamic-store value at `key`; None when the key is absent.
    fn state(&self, key: &str) -> Result<Option<CFRetained<CFType>>>;
    /// CoreWLAN's view of an interface: None when it is not Wi-Fi, otherwise
    /// the network name it reports, if it reports one.
    fn wifi_name(&self, interface: &str) -> Option<Option<String>>;
}

/// One service of the current network set.
pub(super) trait NetworkService {
    fn is_enabled(&self) -> bool;
    /// None when the service has no interface.
    fn physical_interface(&self) -> Option<ServiceInterface>;
    fn identifier(&self) -> Option<String>;
}

/// What SystemConfiguration reports of a service's interface.
pub(super) struct ServiceInterface {
    pub(super) kind: Option<String>,
    pub(super) bsd_name: Option<String>,
}

pub(super) fn current_context(system: &impl NetworkSystem) -> Result<Option<NetworkContext>> {
    let services = system.services()?;
    if services.len() > MAX_ENTRIES {
        bail!("network service count exceeds its observation bound")
    }
    let ipv4 = state_dictionary(system, "State:/Network/Global/IPv4")?;
    let ipv6 = state_dictionary(system, "State:/Network/Global/IPv6")?;
    let primary = ipv4
        .or(ipv6)
        .map(|global| string(&global, "PrimaryInterface"))
        .transpose()?
        .flatten();
    let mut candidates = Vec::new();
    for service in services {
        if !service.is_enabled() {
            continue;
        }
        let Some(interface) = service.physical_interface() else {
            continue;
        };
        let kind = interface
            .kind
            .context("network interface type is unavailable")?;
        if !matches!(kind.as_str(), "Ethernet" | "IEEE80211") {
            continue;
        }
        let name = interface
            .bsd_name
            .context("physical network interface name is unavailable")?;
        if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            bail!("physical interface name is invalid")
        }
        let id = service
            .identifier()
            .context("network service identity is unavailable")?;
        let mut addresses = Vec::new();
        for family in ["IPv4", "IPv6"] {
            if let Some(state) =
                state_dictionary(system, &format!("State:/Network/Service/{id}/{family}"))?
            {
                usable_addresses(&state, &mut addresses)?;
            }
        }
        if addresses.is_empty() {
            continue;
        }
        addresses.sort();
        addresses.dedup();
        let wifi = system.wifi_name(&name);
        let ssid = wifi.clone().flatten();
        if ssid.as_ref().is_some_and(|v| v.len() > 32) {
            bail!("observed Wi-Fi name exceeds 32 bytes")
        }
        candidates.push(NetworkContext {
            interface: name,
            kind: if wifi.is_some() {
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

fn state_dictionary(
    system: &impl NetworkSystem,
    key: &str,
) -> Result<Option<CFRetained<CFDictionary>>> {
    system
        .state(key)?
        .map(|value| {
            value
                .downcast::<CFDictionary>()
                .map_err(|_| anyhow::anyhow!("network state has an invalid type"))
        })
        .transpose()
}

fn string(dict: &CFDictionary, key: &str) -> Result<Option<String>> {
    // SAFETY: SCDynamicStore network dictionaries have CFString keys and CFType values.
    let dict = unsafe { dict.cast_unchecked::<CFString, CFType>() };
    dict.get(&CFString::from_str(key))
        .map(|value| {
            value
                .downcast::<CFString>()
                .map(|v| v.to_string())
                .map_err(|_| anyhow::anyhow!("network field has an invalid type"))
        })
        .transpose()
}

/// Appends the addresses of one family's state that are neither loopback nor
/// unspecified.
fn usable_addresses(state: &CFDictionary, addresses: &mut Vec<String>) -> Result<()> {
    // SAFETY: same documented network dictionary contract as above.
    let dict = unsafe { state.cast_unchecked::<CFString, CFType>() };
    let Some(values) = dict.get(&CFString::from_str("Addresses")) else {
        return Ok(());
    };
    let values = values
        .downcast::<CFArray>()
        .map_err(|_| anyhow::anyhow!("network addresses have an invalid type"))?;
    if values.len() > MAX_ENTRIES {
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
            .parse::<IpAddr>()
            .context("network address is invalid")?;
        if !address.is_loopback() && !address.is_unspecified() {
            addresses.push(value)
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
