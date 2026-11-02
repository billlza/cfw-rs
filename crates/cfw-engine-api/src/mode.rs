//! Engine modes, the owners that run them and the platform each backend serves.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    #[default]
    Off,
    LocalProxy,
    SystemProxy,
    Tunnel,
    TunnelSystemProxy,
}

impl EngineMode {
    pub const fn system_proxy_enabled(self) -> bool {
        matches!(self, Self::SystemProxy | Self::TunnelSystemProxy)
    }

    pub const fn tunnel_enabled(self) -> bool {
        matches!(self, Self::Tunnel | Self::TunnelSystemProxy)
    }

    pub const fn from_switches(system_proxy: bool, tunnel: bool) -> Self {
        match (system_proxy, tunnel) {
            (false, false) => Self::LocalProxy,
            (true, false) => Self::SystemProxy,
            (false, true) => Self::Tunnel,
            (true, true) => Self::TunnelSystemProxy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineOwner {
    ProxyAgent,
    PacketTunnelSystemExtension,
    WindowsUserAgent,
    WindowsTunnelService,
}

/// Closed platform identity selected by the concrete backend, never inferred
/// from an incoming runtime observation. The Apple wire owner names stay intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineRuntimePlatform {
    MacOs,
    Windows,
}

impl EngineRuntimePlatform {
    /// This affects the canonical configuration before any digest or lease is
    /// prepared. It does not advertise or authorize platform TUN availability.
    pub const fn tunnel_stack(self) -> cfw_singbox_config::TunnelStack {
        match self {
            Self::MacOs => cfw_singbox_config::TunnelStack::System,
            Self::Windows => cfw_singbox_config::TunnelStack::Gvisor,
        }
    }

    pub const fn proxy_owner(self) -> EngineOwner {
        match self {
            Self::MacOs => EngineOwner::ProxyAgent,
            Self::Windows => EngineOwner::WindowsUserAgent,
        }
    }

    pub const fn tunnel_owner(self) -> EngineOwner {
        match self {
            Self::MacOs => EngineOwner::PacketTunnelSystemExtension,
            Self::Windows => EngineOwner::WindowsTunnelService,
        }
    }

    /// Whether authorizing a tunnel configuration waits for a person. macOS
    /// saves the VPN configuration only after the user's consent. On Windows
    /// the SYSTEM service was approved when the MSI was installed, so its
    /// authorization is a configuration check with nothing to approve.
    pub const fn tunnel_authorization_awaits_consent(self) -> bool {
        match self {
            Self::MacOs => true,
            Self::Windows => false,
        }
    }
}

impl EngineOwner {
    pub const fn supports_mode(self, mode: EngineMode) -> bool {
        matches!(
            (self, mode),
            (
                Self::ProxyAgent | Self::WindowsUserAgent,
                EngineMode::LocalProxy | EngineMode::SystemProxy
            ) | (
                Self::PacketTunnelSystemExtension | Self::WindowsTunnelService,
                EngineMode::Tunnel | EngineMode::TunnelSystemProxy
            )
        )
    }
}
