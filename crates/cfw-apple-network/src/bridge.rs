//! The narrow transport the signed Swift Host Bridge implements.

use cfw_engine_api::{
    CutoverPreflightRequest, EngineCommandContext, EngineStartRequest, NativeEngineStatus,
    RuntimeIdentity, TunnelApprovalWait, TunnelInstallOutcome,
};

use crate::NativeBridgeError;

pub type NativeBridgeFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, NativeBridgeError>> + Send + 'a>>;

/// Narrow transport implemented by the generated Swift Host Bridge/XPC shim.
///
/// A successful start must already include native readiness attestation. A
/// successful stop is a barrier and must match the complete command context;
/// stale stop requests must fail instead of terminating a newer runtime.
pub trait NativeBridge: Send + Sync + 'static {
    /// Request macOS network authorization without starting an engine or lease.
    fn authorize_system_proxy(&self, restoration_only: bool) -> NativeBridgeFuture<'_, ()>;
    /// Queries ProxyAgent and Packet Tunnel status as one mutually-exclusive
    /// observation. Simultaneous owners or unverified native state are errors.
    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus>;

    fn check_configuration(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, ()>;

    fn start_local_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity>;

    fn stop_local_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity>;

    fn stop_system_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome>;

    /// Waits for the answer to the approval that the installation of this
    /// exact context asked for; see
    /// [`TunnelApprovalBackend`](cfw_engine_api::TunnelApprovalBackend).
    fn await_tunnel_approval(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelApprovalWait>;

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn authorize_tunnel_configuration(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, ()>;

    fn start_tunnel(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, RuntimeIdentity>;

    fn stop_tunnel(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn preflight_cutover(
        &self,
        request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, cfw_engine_api::CutoverPreflightOutcome>;
}
