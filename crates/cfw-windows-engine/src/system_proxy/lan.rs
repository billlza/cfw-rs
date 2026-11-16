//! Read-only views of this user's WinINet LAN options, for the interface
//! and for port reservation. Nothing here opens an ownership record.
use super::*;

/// Read-only UI summary of this user's WinINet LAN options. Raw proxy/PAC
/// strings, bypass rules and ownership records never enter this payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LanProxyObservation {
    pub manual_proxy_enabled: bool,
    pub auto_config_enabled: bool,
    pub auto_detect_enabled: bool,
}

pub fn observe_lan_proxy_state() -> Result<LanProxyObservation, ProxyError> {
    cfw_windows_storage::require_process_identity()?;
    user_identity()?;
    Ok(native::observe_read_only()?.public_observation())
}

/// Read this interactive process user's WinINet LAN manual-proxy reservations.
/// This never opens a journal, requests mutation rights, evaluates PAC/WPAD,
/// resolves a hostname, or reports global runtime ownership.
pub fn observe_lan_proxy_ports() -> Result<std::collections::BTreeSet<u16>, ProxyError> {
    cfw_windows_storage::require_process_identity()?;
    user_identity()?;
    let settings = native::observe_read_only()?;
    crate::proxy_endpoints::loopback_ports(settings.flags & PROXY_TYPE_PROXY != 0, &settings.server)
        .map_err(|()| ProxyError::InvalidObservation)
}
