//! The engine commands of [`NativeBridge`], each sent as one native request
//! whose result must be of the command's kind.

use cfw_engine_api::{
    CutoverPreflightOutcome, CutoverPreflightRequest, EngineCommandContext, EngineStartRequest,
    NativeBridgeCommand, NativeBridgeResult, NativeEngineStatus, RuntimeIdentity,
    TunnelApprovalWait, TunnelInstallOutcome,
};

use crate::{
    NativeBridge, NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture,
    NativeFrameworkBridge,
};

impl NativeBridge for NativeFrameworkBridge {
    fn check_configuration(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::CheckConfiguration { request })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native configuration check returned the wrong result kind",
                )),
            }
        })
    }
    fn authorize_system_proxy(&self, restoration_only: bool) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(if restoration_only {
                    NativeBridgeCommand::AuthorizeSystemProxyRestoration
                } else {
                    NativeBridgeCommand::AuthorizeSystemProxy
                })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native authorization returned the wrong result kind",
                )),
            }
        })
    }

    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus> {
        Box::pin(async move {
            match self.invoke(NativeBridgeCommand::QueryStatus).await? {
                NativeBridgeResult::Status(status) => Ok(status),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native query returned the wrong result kind",
                )),
            }
        })
    }

    fn start_local_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StartLocalProxy { request })
                .await?
            {
                NativeBridgeResult::Runtime(runtime) => Ok(runtime),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native local proxy start returned the wrong result kind",
                )),
            }
        })
    }

    fn stop_local_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StopLocalProxy { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native local proxy stop returned the wrong result kind",
                )),
            }
        })
    }

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StartSystemProxy { request })
                .await?
            {
                NativeBridgeResult::Runtime(runtime) => Ok(runtime),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native proxy start returned the wrong result kind",
                )),
            }
        })
    }

    fn stop_system_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StopSystemProxy { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native proxy stop returned the wrong result kind",
                )),
            }
        })
    }

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::InstallTunnel { context })
                .await?
            {
                NativeBridgeResult::TunnelInstall(outcome) => Ok(outcome),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel install returned the wrong result kind",
                )),
            }
        })
    }

    fn await_tunnel_approval(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelApprovalWait> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::AwaitTunnelApproval { context })
                .await?
            {
                NativeBridgeResult::TunnelApproval(wait) => Ok(wait),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel approval wait returned the wrong result kind",
                )),
            }
        })
    }

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::CancelTunnelInstall { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel install cancellation returned the wrong result kind",
                )),
            }
        })
    }

    fn authorize_tunnel_configuration(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::AuthorizeTunnelConfiguration { request })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "Tunnel authorization returned an unexpected result",
                )),
            }
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StartTunnel { request })
                .await?
            {
                NativeBridgeResult::Runtime(runtime) => Ok(runtime),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel start returned the wrong result kind",
                )),
            }
        })
    }

    fn stop_tunnel(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StopTunnel { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel stop returned the wrong result kind",
                )),
            }
        })
    }

    fn preflight_cutover(
        &self,
        request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, CutoverPreflightOutcome> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::PreflightCutover {
                    request: Box::new(request),
                })
                .await?
            {
                NativeBridgeResult::CutoverPreflight(outcome) => Ok(outcome),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native cutover preflight returned the wrong result kind",
                )),
            }
        })
    }
}
