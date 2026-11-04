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
            service_management::register().map_err(anyhow::Error::msg)
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Login Item is only available on macOS")
        }
    }

    pub fn disable_login_item(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            service_management::unregister().map_err(anyhow::Error::msg)
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Login Item is only available on macOS")
        }
    }

    pub fn login_item_status(&self) -> ServiceModeStatus {
        #[cfg(target_os = "macos")]
        {
            service_management::status()
        }
        #[cfg(not(target_os = "macos"))]
        {
            ServiceModeStatus::Unknown
        }
    }

    pub fn open_login_items_settings(&self) {
        #[cfg(target_os = "macos")]
        service_management::open_settings();
    }

    /// Remove only the historical fixed-label user LaunchAgent.
    ///
    /// This function has no generic label or program parameter and therefore
    /// cannot be reused to install or start an arbitrary process.
    pub fn retire_legacy_login_agent(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let path = legacy_login_agent_path()?;
            if !legacy_login_agent_present(&path)? {
                return Ok(());
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

/// Whether a legacy Login Item file is left to retire. Anything but a file or
/// a symlink in its place is refused, not removed.
fn legacy_login_agent_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => bail!(
            "refusing to retire non-file legacy Login Item path: {}",
            path.display()
        ),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
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
mod service_management;

#[cfg(test)]
mod tests;
