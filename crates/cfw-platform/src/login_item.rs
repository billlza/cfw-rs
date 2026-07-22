use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::{MacOsPlatformService, ServiceModeStatus, launchctl};

const LEGACY_LOGIN_AGENT_LABEL: &str = "com.bill.clashformac";

impl MacOsPlatformService {
    /// Register the signed main application as its own Login Item.
    pub fn enable_login_item(&self) -> Result<ServiceModeStatus> {
        #[cfg(target_os = "macos")]
        {
            sm_login_item::register().map_err(anyhow::Error::msg)
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Login Item is only available on macOS")
        }
    }

    pub fn disable_login_item(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            sm_login_item::unregister().map_err(anyhow::Error::msg)
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Login Item is only available on macOS")
        }
    }

    pub fn login_item_status(&self) -> ServiceModeStatus {
        #[cfg(target_os = "macos")]
        {
            sm_login_item::status()
        }
        #[cfg(not(target_os = "macos"))]
        {
            ServiceModeStatus::Unknown
        }
    }

    pub fn open_login_items_settings(&self) {
        #[cfg(target_os = "macos")]
        sm_login_item::open_settings();
    }

    /// Remove only the historical fixed-label user LaunchAgent.
    ///
    /// This function has no generic label or program parameter and therefore
    /// cannot be reused to install or start an arbitrary process.
    pub fn retire_legacy_login_agent(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let path = legacy_login_agent_path()?;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Ok(metadata)
                    if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {}
                Ok(_) => bail!(
                    "refusing to retire non-file legacy Login Item path: {}",
                    path.display()
                ),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to inspect {}", path.display()));
                }
            }
            let uid = launchctl::current_uid()?;
            let target = format!("gui/{uid}/{LEGACY_LOGIN_AGENT_LABEL}");
            launchctl::run_allow_absent(&["disable", &target])?;
            launchctl::run_allow_absent(&["bootout", &target])?;

            remove_fixed_file_if_present(&path)?;
            launchctl::ensure_unloaded(&target)?;
            ensure_path_absent(&path)
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("legacy Login Item retirement is only available on macOS")
        }
    }
}

fn legacy_login_agent_path() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").context("HOME is required to retire the legacy Login Item")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LEGACY_LOGIN_AGENT_LABEL}.plist")))
}

pub(crate) fn remove_fixed_file_if_present(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let kind = metadata.file_type();
    if !(kind.is_file() || kind.is_symlink()) {
        bail!(
            "refusing to remove non-file legacy launchd path: {}",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))
}

pub(crate) fn ensure_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!(
            "legacy launchd path remains after retirement: {}",
            path.display()
        ),
        Err(error) => Err(error).with_context(|| format!("failed to verify {}", path.display())),
    }
}

#[cfg(target_os = "macos")]
mod sm_login_item {
    use objc2::rc::Retained;
    use objc2_service_management::SMAppService;

    use crate::{ServiceModeStatus, map_service_status};

    fn service() -> Retained<SMAppService> {
        // SAFETY: mainAppService returns the calling application's service object.
        unsafe { SMAppService::mainAppService() }
    }

    pub(super) fn status() -> ServiceModeStatus {
        // SAFETY: status is a read-only query.
        map_service_status(unsafe { service().status() })
    }

    pub(super) fn register() -> Result<ServiceModeStatus, String> {
        let service = service();
        // SAFETY: registration is scoped by macOS to the signed calling app.
        unsafe { service.registerAndReturnError() }
            .map_err(|error| format!("SMAppService Login Item register failed: {error:?}"))?;
        Ok(map_service_status(unsafe { service.status() }))
    }

    pub(super) fn unregister() -> Result<(), String> {
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
    }

    pub(super) fn open_settings() {
        // SAFETY: this only opens the system-owned Login Items settings pane.
        unsafe { SMAppService::openSystemSettingsLoginItems() }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cfw-platform-login-{name}-{}", std::process::id()))
    }

    #[test]
    fn fixed_file_cleanup_unlinks_symlink_without_following_it() {
        let root = test_root("symlink");
        let target = root.join("target");
        let link = root.join("legacy.plist");
        fs::create_dir_all(&root).expect("create root");
        fs::write(&target, b"keep").expect("write target");
        symlink(&target, &link).expect("create symlink");

        remove_fixed_file_if_present(&link).expect("remove link");

        assert_eq!(fs::read(&target).expect("read target"), b"keep");
        fs::remove_file(target).expect("remove target");
        fs::remove_dir(root).expect("remove root");
    }

    #[test]
    fn fixed_file_cleanup_rejects_directories() {
        let root = test_root("directory");
        fs::create_dir_all(&root).expect("create root");
        let error = remove_fixed_file_if_present(&root).expect_err("directory must be rejected");
        assert!(error.to_string().contains("non-file"));
        fs::remove_dir(root).expect("remove root");
    }
}
