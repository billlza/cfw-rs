//! The fail-closed bridge used while the signed Host Bridge is not linked.

use cfw_engine_api::{
    CutoverPreflightRequest, EngineCommandContext, EngineStartRequest, NativeEngineStatus,
    RuntimeIdentity, TunnelApprovalWait, TunnelInstallOutcome,
};

use crate::{NativeBridge, NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture};

/// Explicit fail-closed transport used until the signed Swift C ABI artifact is
/// linked. It never reports a native mode as active.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingNativeBridge;

impl MissingNativeBridge {
    fn unavailable<T>() -> NativeBridgeFuture<'static, T> {
        Box::pin(async {
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Unavailable,
                "signed macOS Host Bridge is not linked",
            ))
        })
    }
}

impl NativeBridge for MissingNativeBridge {
    fn check_configuration(&self, _request: EngineStartRequest) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }
    fn start_local_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Self::unavailable()
    }

    fn stop_local_proxy(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn authorize_system_proxy(&self, _restoration_only: bool) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus> {
        Self::unavailable()
    }

    fn start_system_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Self::unavailable()
    }

    fn stop_system_proxy(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn install_tunnel(
        &self,
        _context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome> {
        Self::unavailable()
    }

    fn await_tunnel_approval(
        &self,
        _context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelApprovalWait> {
        Self::unavailable()
    }

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn authorize_tunnel_configuration(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn start_tunnel(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Self::unavailable()
    }

    fn stop_tunnel(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Self::unavailable()
    }

    fn preflight_cutover(
        &self,
        _request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, cfw_engine_api::CutoverPreflightOutcome> {
        Self::unavailable()
    }
}

#[cfg(test)]
mod tests;
