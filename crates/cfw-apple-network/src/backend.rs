//! The engine backend over a native bridge: each call forwards its exact request
//! and maps a native failure to the backend error of the same kind.

use cfw_engine_api::{
    BackendError, BackendFuture, CutoverPreflightBackend, CutoverPreflightFuture,
    CutoverPreflightRequest, EngineBackend, EngineCommandContext, EngineStartRequest,
    NativeEngineStatus, RuntimeIdentity, SystemProxyAuthorization, TunnelApprovalBackend,
    TunnelApprovalFuture, TunnelInstallOutcome,
};

use crate::{NativeBridge, NativeBridgeError};

pub struct AppleNetworkBackend<B> {
    bridge: B,
}

impl<B> AppleNetworkBackend<B> {
    pub fn new(bridge: B) -> Self {
        Self { bridge }
    }

    pub fn bridge(&self) -> &B {
        &self.bridge
    }
}

impl<B: NativeBridge> EngineBackend for AppleNetworkBackend<B> {
    fn runtime_platform(&self) -> cfw_engine_api::EngineRuntimePlatform {
        cfw_engine_api::EngineRuntimePlatform::MacOs
    }

    fn check_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .check_configuration(request)
                .await
                .map_err(map_bridge_error)
        })
    }
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move { self.bridge.query_status().await.map_err(map_bridge_error) })
    }

    fn start_local_proxy(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.bridge
                .start_local_proxy(request)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .stop_local_proxy(context)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.bridge
                .start_system_proxy(request)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn stop_system_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .stop_system_proxy(context)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(async move {
            self.bridge
                .install_tunnel(context)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .cancel_tunnel_install(context)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn authorize_tunnel_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .authorize_tunnel_configuration(request)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.bridge
                .start_tunnel(request)
                .await
                .map_err(map_bridge_error)
        })
    }

    fn stop_tunnel(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .stop_tunnel(context)
                .await
                .map_err(map_bridge_error)
        })
    }
}

impl<B: NativeBridge> SystemProxyAuthorization for AppleNetworkBackend<B> {
    fn authorize_system_proxy(&self, restoration_only: bool) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.bridge
                .authorize_system_proxy(restoration_only)
                .await
                .map_err(map_bridge_error)
        })
    }
}

impl<B: NativeBridge> CutoverPreflightBackend for AppleNetworkBackend<B> {
    fn preflight_cutover(&self, request: CutoverPreflightRequest) -> CutoverPreflightFuture<'_> {
        Box::pin(async move {
            self.bridge
                .preflight_cutover(request)
                .await
                .map_err(map_bridge_error)
        })
    }
}

impl<B: NativeBridge> TunnelApprovalBackend for AppleNetworkBackend<B> {
    fn await_tunnel_approval(&self, context: EngineCommandContext) -> TunnelApprovalFuture<'_> {
        Box::pin(async move {
            self.bridge
                .await_tunnel_approval(context)
                .await
                .map_err(map_bridge_error)
        })
    }
}

fn map_bridge_error(error: NativeBridgeError) -> BackendError {
    BackendError::new(error.code.into(), error.message)
}

#[cfg(test)]
mod tests;
