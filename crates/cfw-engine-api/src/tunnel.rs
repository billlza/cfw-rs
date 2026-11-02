//! Tunnel network options, installation outcomes and the wait for System Extension approval.

use std::pin::Pin;

use cfw_singbox_config::DirectIpv4HostRoutes;
use serde::{Deserialize, Serialize};

use crate::{BackendError, EngineCommandContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelNetworkOptions {
    pub ipv6_enabled: bool,
    pub bypass_private_networks: bool,
    pub direct_ipv4_hosts: DirectIpv4HostRoutes,
    pub mtu: u16,
    /// The tunnel's own loopback mixed listener used by macOS HTTP/HTTPS proxy settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_proxy_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelInstallOutcome {
    Ready,
    AwaitingApproval,
}

/// What a bounded wait for the person's System Extension approval found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelApprovalWait {
    /// The activation request reached its terminal callback. The next
    /// `install_tunnel` of the same context reads its outcome.
    Resolved,
    /// The request was still waiting for the person when the wait ended.
    StillAwaiting,
    /// No activation request of that context is waiting for approval.
    NoPendingRequest,
}

pub type TunnelApprovalFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TunnelApprovalWait, BackendError>> + Send + 'a>>;

/// Waits for the answer to a Tunnel installation that returned
/// `AwaitingApproval`. The wait changes nothing: it neither takes the
/// activation request over nor consumes its outcome, and it holds no native
/// mutation, so a stop never waits behind it.
pub trait TunnelApprovalBackend: Send + Sync + 'static {
    fn await_tunnel_approval(&self, context: EngineCommandContext) -> TunnelApprovalFuture<'_>;
}
