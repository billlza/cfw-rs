//! Applicability of historical platform maintenance, separate from the native
//! engine authority which must still admit every Windows networking operation.

pub(crate) fn require_legacy_profile_migration() -> Result<(), String> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err("Historical Mac profile migration does not apply to this platform; import a configuration file or subscription instead".into())
    }
}

#[cfg(target_os = "macos")]
pub use crate::legacy::LegacyRetirementGate as PlatformMaintenanceGate;
#[cfg(target_os = "macos")]
pub(crate) use crate::legacy::legacy_retirement_status;

#[cfg(target_os = "macos")]
pub(crate) fn start_block_reason(gate: &PlatformMaintenanceGate) -> Result<Option<String>, String> {
    Ok(gate.status()?.start_block_reason())
}

#[cfg(target_os = "macos")]
pub(crate) fn require_start_allowed(gate: &PlatformMaintenanceGate) -> Result<(), String> {
    crate::legacy::require_network_start_allowed(gate)
}

/// Refuses a runtime preference change while a historical cutover journal
/// governs startup.
#[cfg(target_os = "macos")]
pub(crate) fn require_runtime_preferences_changeable(
    app_home: &std::path::Path,
) -> Result<(), String> {
    crate::legacy::require_runtime_preferences_changeable(app_home)
        .map_err(|error| error.to_string())
}

/// This release has no predecessor Windows retirement protocol. This is an
/// applicability fact, not evidence of stopped processes or restored proxies.
#[cfg(windows)]
#[derive(Clone, Debug, Default)]
pub enum PlatformMaintenanceGate {
    #[default]
    FirstWindowsRelease,
}

#[cfg(windows)]
#[derive(serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum PlatformMaintenanceStatus {
    NotApplicable,
}

#[cfg(windows)]
#[tauri::command]
pub(crate) fn legacy_retirement_status(
    gate: tauri::State<'_, PlatformMaintenanceGate>,
) -> PlatformMaintenanceStatus {
    match *gate {
        PlatformMaintenanceGate::FirstWindowsRelease => PlatformMaintenanceStatus::NotApplicable,
    }
}

#[cfg(windows)]
pub(crate) fn start_block_reason(gate: &PlatformMaintenanceGate) -> Result<Option<String>, String> {
    match gate {
        PlatformMaintenanceGate::FirstWindowsRelease => Ok(None),
    }
}

#[cfg(windows)]
pub(crate) fn require_start_allowed(gate: &PlatformMaintenanceGate) -> Result<(), String> {
    match gate {
        PlatformMaintenanceGate::FirstWindowsRelease => Ok(()),
    }
}

/// No predecessor's cutover journal can govern startup on Windows, so runtime
/// preferences are always changeable here.
#[cfg(windows)]
pub(crate) fn require_runtime_preferences_changeable(
    _app_home: &std::path::Path,
) -> Result<(), String> {
    Ok(())
}
