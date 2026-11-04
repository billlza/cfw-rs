//! Read-only physical network identity for explicit application policies. TUN,
//! loopback, bridge and virtual interfaces never become an automation trigger.
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod physical;
#[cfg(target_os = "macos")]
mod system;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Wifi,
    Wired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkContext {
    pub interface: String,
    pub kind: NetworkKind,
    pub ssid: Option<String>,
    /// Addresses participate in edge detection but are not needed by the UI.
    #[serde(skip)]
    pub addresses: Vec<String>,
}

/// Called only by the visible Wi-Fi permission button, on the app main thread.
#[cfg(target_os = "macos")]
pub fn request_wifi_name_access() -> anyhow::Result<()> {
    system::request_wifi_name_access()
}

#[cfg(windows)]
pub fn request_wifi_name_access() -> anyhow::Result<()> {
    crate::windows::network::request_wifi_name_access()
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn request_wifi_name_access() -> anyhow::Result<()> {
    anyhow::bail!("Wi-Fi name access is unsupported on this platform")
}

#[cfg(target_os = "macos")]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    physical::current_context(&system::LiveNetwork::open()?)
}

#[cfg(windows)]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    crate::windows::network::current_network_context()
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn current_network_context() -> anyhow::Result<Option<NetworkContext>> {
    anyhow::bail!("physical network observation is unsupported on this platform")
}
