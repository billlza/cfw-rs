//! The live SystemConfiguration, CoreWLAN and Core Location calls behind the
//! physical network observation. Nothing here decides which network is
//! current; `physical.rs` does, and its tests run it in memory.

use anyhow::{Context, Result, bail};
use objc2::rc::Retained;
use objc2_core_foundation::{CFRetained, CFString, CFType};
use objc2_core_wlan::CWWiFiClient;
use objc2_foundation::NSString;
use objc2_system_configuration::{
    SCDynamicStore, SCError, SCNetworkService, SCNetworkSet, SCPreferences, kSCStatusNoKey,
};

use super::physical::{NetworkService, NetworkSystem, ServiceInterface};

/// Called only by the visible Wi-Fi permission button, on the app main thread.
/// Retain the manager while macOS presents its own permission prompt.
pub(super) fn request_wifi_name_access() -> Result<()> {
    use objc2::MainThreadMarker;
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

/// A read-only session on this Mac's network preferences and Wi-Fi client.
pub(super) struct LiveNetwork {
    preferences: CFRetained<SCPreferences>,
    wifi: Retained<CWWiFiClient>,
}

impl LiveNetwork {
    pub(super) fn open() -> Result<Self> {
        let preferences = SCPreferences::new(
            None,
            &CFString::from_str("com.bill.clashformac.network-observation"),
            None,
        )
        .context("network preferences are unavailable")?;
        // SAFETY: retained system CoreWLAN objects; only documented read methods are called.
        let wifi = unsafe { CWWiFiClient::sharedWiFiClient() };
        Ok(Self { preferences, wifi })
    }
}

impl NetworkSystem for LiveNetwork {
    type Service = CFRetained<SCNetworkService>;

    fn services(&self) -> Result<Vec<Self::Service>> {
        let set = SCNetworkSet::current(&self.preferences)
            .context("current network set is unavailable")?;
        let services = set.services().context("network services are unavailable")?;
        // SAFETY: SCNetworkSetCopyServices is documented to contain SCNetworkService.
        let services = unsafe { services.cast_unchecked::<SCNetworkService>() };
        (0..services.len())
            .map(|index| {
                services
                    .get(index)
                    .context("network service entry is missing")
            })
            .collect()
    }

    fn state(&self, key: &str) -> Result<Option<CFRetained<CFType>>> {
        match SCDynamicStore::value(None, &CFString::from_str(key)) {
            Some(value) => Ok(Some(value)),
            None if SCError() == kSCStatusNoKey as i32 => Ok(None),
            None => bail!("SystemConfiguration network observation failed"),
        }
    }

    fn wifi_name(&self, interface: &str) -> Option<Option<String>> {
        // SAFETY: the name came from a physical SC interface; CoreWLAN returns
        // None for a non-Wi-Fi interface. No location permission is requested.
        let wifi = unsafe {
            self.wifi
                .interfaceWithName(Some(&NSString::from_str(interface)))
        }?;
        Some(unsafe { wifi.ssid() }.map(|v| v.to_string()))
    }
}

impl NetworkService for CFRetained<SCNetworkService> {
    fn is_enabled(&self) -> bool {
        self.enabled()
    }

    fn physical_interface(&self) -> Option<ServiceInterface> {
        let interface = self.interface()?;
        Some(ServiceInterface {
            kind: interface.interface_type().map(|kind| kind.to_string()),
            bsd_name: interface.bsd_name().map(|name| name.to_string()),
        })
    }

    fn identifier(&self) -> Option<String> {
        self.service_id().map(|id| id.to_string())
    }
}
