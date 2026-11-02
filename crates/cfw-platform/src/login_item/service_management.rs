//! The SMAppService Login Item registration of the calling application.
//! Tests never run these calls: registering would add the test binary to the
//! user's Login Items.

use objc2::rc::{Retained, autoreleasepool};
use objc2_service_management::SMAppService;

use crate::{ServiceModeStatus, map_service_status};

fn service() -> Retained<SMAppService> {
    // SAFETY: mainAppService returns the calling application's service object.
    unsafe { SMAppService::mainAppService() }
}

pub(super) fn status() -> ServiceModeStatus {
    // SAFETY: status is a read-only query.
    // These queries also run on Rust's blocking pool, outside AppKit's
    // event-loop autorelease pool.
    autoreleasepool(|_| map_service_status(unsafe { service().status() }))
}

pub(super) fn register() -> Result<ServiceModeStatus, String> {
    autoreleasepool(|_| {
        let service = service();
        // SAFETY: registration is scoped by macOS to the signed calling app.
        unsafe { service.registerAndReturnError() }
            .map_err(|error| format!("SMAppService Login Item register failed: {error:?}"))?;
        Ok(map_service_status(unsafe { service.status() }))
    })
}

pub(super) fn unregister() -> Result<(), String> {
    autoreleasepool(|_| {
        if matches!(
            status(),
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
        ) {
            return Ok(());
        }
        // SAFETY: unregistration is scoped by macOS to the signed calling app.
        unsafe { service().unregisterAndReturnError() }
            .map_err(|error| format!("SMAppService Login Item unregister failed: {error:?}"))?;
        match status() {
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => Ok(()),
            other => Err(format!(
                "SMAppService Login Item remains registered: {other:?}"
            )),
        }
    })
}

pub(super) fn open_settings() {
    // SAFETY: this only opens the system-owned Login Items settings pane.
    autoreleasepool(|_| unsafe { SMAppService::openSystemSettingsLoginItems() })
}
