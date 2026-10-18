//! Desktop observations and explicitly platform-specific management adapters.
//!
//! Network data-plane activation belongs to the platform's engine authority.
//! On macOS this is the signed ProxyAgent and Packet Tunnel System Extension.
//! This crate deliberately exposes no API that can
//! install a helper, start a core, enable a system proxy, install a PAC file, or
//! modify routes.

#[cfg(target_os = "macos")]
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod app_update;
#[cfg(target_os = "macos")]
mod bounded_command;
mod language;
#[cfg(target_os = "macos")]
mod launchctl;
#[cfg(target_os = "macos")]
mod legacy_observation;
#[cfg(target_os = "macos")]
mod legacy_proxy;
#[cfg(target_os = "macos")]
mod legacy_service;
#[cfg(target_os = "macos")]
mod login_item;
pub use language::preferred_languages;
mod network_context;
#[cfg(target_os = "macos")]
mod network_observation;
pub use network_context::{
    NetworkContext, NetworkKind, current_network_context, request_wifi_name_access,
};
#[cfg(target_os = "macos")]
mod release_security;
mod system_version;
pub use system_version::operating_system_version;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod sysproxy_sc;

#[cfg(target_os = "macos")]
pub use app_update::{
    AppUpdateToolError, InstalledHostOutput, extract_update_archive, open_installed_application,
    run_installed_host, verify_update_application_signature,
};
#[cfg(target_os = "macos")]
pub use legacy_observation::{observe_legacy_process_table, observe_legacy_tcp_listener_table};
#[cfg(target_os = "macos")]
pub use legacy_proxy::{LegacyProxyCutoverPlan, LegacyProxyServiceIdentity};
#[cfg(target_os = "macos")]
pub use legacy_service::{
    LegacyServiceJobObservation, LegacyServiceJobProgram, LegacyServiceRetirement,
};
#[cfg(target_os = "macos")]
pub use network_observation::{
    NetworkProxyProtocolObservation, NetworkRoutingObservation, NetworkServiceObservation,
};
#[cfg(target_os = "macos")]
pub use release_security::{
    ReleaseSecurityCommandOutput, ReleaseSignedComponent, assess_release_application,
    inspect_release_signature, observe_gatekeeper_status, verify_release_signature,
};

/// Registration state reported by `SMAppService`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(target_os = "macos")]
pub enum ServiceModeStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

/// Stateless façade for the small set of macOS operations the shell retains.
#[derive(Debug, Clone, Copy, Default)]
#[cfg(target_os = "macos")]
pub struct MacOsPlatformService;

#[cfg(target_os = "macos")]
pub(crate) fn map_service_status(
    value: objc2_service_management::SMAppServiceStatus,
) -> ServiceModeStatus {
    use objc2_service_management::SMAppServiceStatus;

    if value == SMAppServiceStatus::Enabled {
        ServiceModeStatus::Enabled
    } else if value == SMAppServiceStatus::RequiresApproval {
        ServiceModeStatus::RequiresApproval
    } else if value == SMAppServiceStatus::NotRegistered {
        ServiceModeStatus::NotRegistered
    } else if value == SMAppServiceStatus::NotFound {
        ServiceModeStatus::NotFound
    } else {
        ServiceModeStatus::Unknown
    }
}
