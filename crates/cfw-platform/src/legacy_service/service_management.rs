//! The SMAppService registration of the historical privileged helper, which
//! this application only observes and unregisters.

use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_service_management::SMAppService;

use crate::{ServiceModeStatus, map_service_status};

use super::LEGACY_HELPER_PLIST_NAME;

fn service() -> Retained<SMAppService> {
    let name = NSString::from_str(LEGACY_HELPER_PLIST_NAME);
    // SAFETY: this creates a descriptor for one compile-time plist name.
    unsafe { SMAppService::daemonServiceWithPlistName(&name) }
}

pub(super) fn status() -> ServiceModeStatus {
    // SAFETY: status is a read-only query.
    map_service_status(unsafe { service().status() })
}

pub(super) fn unregister() -> Result<(), String> {
    // SAFETY: the service descriptor is fixed and this path only unregisters it.
    unsafe { service().unregisterAndReturnError() }
        .map_err(|error| format!("SMAppService legacy helper unregister failed: {error:?}"))
}
