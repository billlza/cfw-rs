use anyhow::{Result, bail};

use crate::login_item::ensure_path_absent;
use crate::{MacOsPlatformService, ServiceModeStatus, launchctl};

const LEGACY_HELPER_LABEL: &str = "com.bill.clashformac.helper";
const LEGACY_HELPER_PLIST_NAME: &str = "com.bill.clashformac.helper.plist";
const LEGACY_HELPER_PLIST_PATH: &str = "/Library/LaunchDaemons/com.bill.clashformac.helper.plist";

/// One-way retirement surface for the historical privileged helper.
pub trait LegacyServiceRetirement {
    fn service_mode_status(&self) -> ServiceModeStatus;
    fn retire_legacy_service(&self) -> Result<()>;
    fn verify_legacy_service_retired(&self) -> Result<()>;
}

impl LegacyServiceRetirement for MacOsPlatformService {
    fn service_mode_status(&self) -> ServiceModeStatus {
        #[cfg(target_os = "macos")]
        {
            sm_legacy_service::status()
        }
        #[cfg(not(target_os = "macos"))]
        {
            ServiceModeStatus::Unknown
        }
    }

    fn retire_legacy_service(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            // The migration release embeds a non-starting tombstone plist with
            // this exact name, so SMAppService can instantiate the supported
            // descriptor for the historical registration. A normal GUI app
            // has no authority to mutate the system launchd domain or unlink
            // /Library/LaunchDaemons directly; those are verification-only
            // boundaries here, not unreliable privileged fallbacks.
            if !matches!(
                sm_legacy_service::status(),
                ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
            ) {
                sm_legacy_service::unregister().map_err(anyhow::Error::msg)?;
            }
            self.verify_legacy_service_retired()
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode retirement is only available on macOS")
        }
    }

    fn verify_legacy_service_retired(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let target = format!("system/{LEGACY_HELPER_LABEL}");
            let plist = std::path::Path::new(LEGACY_HELPER_PLIST_PATH);
            let mut errors = Vec::new();
            collect_error(
                &mut errors,
                "verify fixed launchd job is unloaded",
                launchctl::ensure_unloaded(&target),
            );
            collect_error(
                &mut errors,
                "verify fixed daemon plist is absent",
                ensure_path_absent(plist),
            );
            let final_status = sm_legacy_service::status();
            if !matches!(
                final_status,
                ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
            ) {
                errors.push(format!(
                    "verify SMAppService retirement: legacy Service Mode remains registered: {final_status:?}"
                ));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                bail!("legacy helper retirement incomplete: {}", errors.join("; "))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Service Mode verification is only available on macOS")
        }
    }
}

fn collect_error(errors: &mut Vec<String>, operation: &str, result: Result<()>) {
    if let Err(error) = result {
        errors.push(format!("{operation}: {error}"));
    }
}

#[cfg(target_os = "macos")]
mod sm_legacy_service {
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn privileged_identity_is_compile_time_fixed() {
        assert_eq!(LEGACY_HELPER_LABEL, "com.bill.clashformac.helper");
        assert_eq!(
            PathBuf::from(LEGACY_HELPER_PLIST_PATH),
            PathBuf::from("/Library/LaunchDaemons/com.bill.clashformac.helper.plist")
        );
    }

    #[test]
    fn retirement_error_collection_keeps_every_failure() {
        let mut errors = Vec::new();
        collect_error(&mut errors, "first", Err(anyhow::anyhow!("one")));
        collect_error(&mut errors, "second", Ok(()));
        collect_error(&mut errors, "third", Err(anyhow::anyhow!("three")));
        assert_eq!(errors, ["first: one", "third: three"]);
    }
}
