//! Narrow macOS platform adapters used by the migration and application shell.
//!
//! Network data-plane activation belongs to the signed ProxyAgent and Packet
//! Tunnel System Extension. This crate deliberately exposes no API that can
//! install a helper, start a core, enable a system proxy, install a PAC file, or
//! modify routes.

use serde::{Deserialize, Serialize};

mod bounded_command;
mod launchctl;
mod legacy_observation;
mod legacy_proxy;
mod legacy_service;
mod login_item;
mod network_observation;
mod release_security;

#[cfg(target_os = "macos")]
mod sysproxy_sc;

pub use legacy_observation::{observe_legacy_process_table, observe_legacy_tcp_listener_table};
pub use legacy_proxy::{LegacyProxyCutoverPlan, LegacyProxyServiceIdentity};
pub use legacy_service::{
    LegacyServiceJobObservation, LegacyServiceJobProgram, LegacyServiceRetirement,
};
pub use network_observation::{
    NetworkProxyProtocolObservation, NetworkRoutingObservation, NetworkServiceObservation,
};
pub use release_security::{
    ReleaseSecurityCommandOutput, ReleaseSignedComponent, assess_release_application,
    inspect_release_signature, observe_gatekeeper_status, verify_release_signature,
};

/// Registration state reported by `SMAppService`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceModeStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

/// Stateless façade for the small set of macOS operations the shell retains.
#[derive(Debug, Clone, Copy, Default)]
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
