//! Rust-side adapter for the signed macOS networking boundary.
//!
//! The product coordinator depends only on `cfw-engine-api`; this crate maps
//! native Host Bridge and ProxyAgent failures into stable domain errors. The
//! eventual C ABI transport must implement [`NativeBridge`] without exposing
//! Swift, XPC, Network Extension, or libbox details to the application layer.

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, CutoverPreflightBackend, CutoverPreflightFuture,
    CutoverPreflightRequest, EngineBackend, EngineCommandContext, EngineStartRequest,
    NativeEngineStatus, RuntimeIdentity, TunnelInstallOutcome,
};

mod generation_store;
mod native_bridge;

pub use generation_store::{GenerationStoreError, KeychainEngineGenerationStore};
pub use native_bridge::NativeFrameworkBridge;

pub type NativeBridgeFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, NativeBridgeError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBridgeErrorCode {
    Busy,
    PermissionDenied,
    ApprovalDenied,
    ConfigurationRejected,
    CredentialsUnavailable,
    CredentialConflict,
    CredentialVaultMissing,
    CredentialGcConflict,
    IdentityRejected,
    Timeout,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBridgeError {
    pub code: NativeBridgeErrorCode,
    pub message: String,
}

impl NativeBridgeError {
    pub fn new(code: NativeBridgeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Narrow transport implemented by the generated Swift Host Bridge/XPC shim.
///
/// A successful start must already include native readiness attestation. A
/// successful stop is a barrier and must match the complete command context;
/// stale stop requests must fail instead of terminating a newer runtime.
pub trait NativeBridge: Send + Sync + 'static {
    /// Queries ProxyAgent and Packet Tunnel status as one mutually-exclusive
    /// observation. Simultaneous owners or unverified native state are errors.
    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus>;

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity>;

    fn stop_system_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome>;

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn start_tunnel(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, RuntimeIdentity>;

    fn stop_tunnel(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()>;

    fn preflight_cutover(
        &self,
        request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, cfw_engine_api::CutoverPreflightOutcome>;
}

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
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move { self.bridge.query_status().await.map_err(map_bridge_error) })
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

fn map_bridge_error(error: NativeBridgeError) -> BackendError {
    let kind = match error.code {
        NativeBridgeErrorCode::Busy => BackendErrorKind::Busy,
        NativeBridgeErrorCode::PermissionDenied => BackendErrorKind::PermissionDenied,
        NativeBridgeErrorCode::ApprovalDenied => BackendErrorKind::ApprovalDenied,
        NativeBridgeErrorCode::ConfigurationRejected => BackendErrorKind::ConfigurationRejected,
        NativeBridgeErrorCode::CredentialsUnavailable => BackendErrorKind::CredentialsUnavailable,
        NativeBridgeErrorCode::CredentialConflict => BackendErrorKind::ConfigurationRejected,
        NativeBridgeErrorCode::CredentialVaultMissing => BackendErrorKind::CredentialsUnavailable,
        NativeBridgeErrorCode::CredentialGcConflict => BackendErrorKind::Busy,
        NativeBridgeErrorCode::IdentityRejected => BackendErrorKind::IdentityRejected,
        NativeBridgeErrorCode::Timeout => BackendErrorKind::Timeout,
        NativeBridgeErrorCode::Unavailable => BackendErrorKind::Unavailable,
        NativeBridgeErrorCode::Internal => BackendErrorKind::Internal,
    };
    BackendError::new(kind, error.message)
}

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

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
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
mod tests {
    use std::sync::Mutex;

    use cfw_engine_api::{EngineOwner, TunnelNetworkOptions};

    use super::*;

    #[derive(Default)]
    struct RecordingBridge {
        calls: Mutex<Vec<EngineCommandContext>>,
    }

    impl NativeBridge for RecordingBridge {
        fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus> {
            Box::pin(async { Ok(NativeEngineStatus::Off) })
        }

        fn start_system_proxy(
            &self,
            request: EngineStartRequest,
        ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .expect("calls lock")
                    .push(request.context.clone());
                Ok(RuntimeIdentity {
                    owner: EngineOwner::ProxyAgent,
                    context: request.context,
                    config_digest: request.config_digest,
                    ready: true,
                })
            })
        }

        fn stop_system_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
            Box::pin(async move {
                self.calls.lock().expect("calls lock").push(context);
                Ok(())
            })
        }

        fn install_tunnel(
            &self,
            context: EngineCommandContext,
        ) -> NativeBridgeFuture<'_, TunnelInstallOutcome> {
            Box::pin(async move {
                self.calls.lock().expect("calls lock").push(context);
                Ok(TunnelInstallOutcome::AwaitingApproval)
            })
        }

        fn cancel_tunnel_install(
            &self,
            context: EngineCommandContext,
        ) -> NativeBridgeFuture<'_, ()> {
            Box::pin(async move {
                self.calls.lock().expect("calls lock").push(context);
                Ok(())
            })
        }

        fn start_tunnel(
            &self,
            request: EngineStartRequest,
        ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .expect("calls lock")
                    .push(request.context.clone());
                Ok(RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    context: request.context,
                    config_digest: request.config_digest,
                    ready: true,
                })
            })
        }

        fn stop_tunnel(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
            Box::pin(async move {
                self.calls.lock().expect("calls lock").push(context);
                Ok(())
            })
        }

        fn preflight_cutover(
            &self,
            request: CutoverPreflightRequest,
        ) -> NativeBridgeFuture<'_, cfw_engine_api::CutoverPreflightOutcome> {
            Box::pin(async move {
                Ok(cfw_engine_api::CutoverPreflightOutcome::AwaitingApproval {
                    target: request.target(),
                    context: request.tunnel_request().context.clone(),
                    system_proxy_config_digest: request
                        .system_proxy_request()
                        .config_digest
                        .clone(),
                    tunnel_config_digest: request.tunnel_request().config_digest.clone(),
                })
            })
        }
    }

    fn context() -> EngineCommandContext {
        EngineCommandContext {
            installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
            config_epoch: 4,
            generation: 9,
        }
    }

    fn tunnel_request() -> EngineStartRequest {
        EngineStartRequest {
            context: context(),
            config_json: "{\"inbounds\":[]}".to_owned(),
            config_content_digest: "b".repeat(64),
            config_digest: "a".repeat(64),
            credential_slots: Vec::new(),
            tunnel_options: Some(TunnelNetworkOptions {
                ipv6_enabled: true,
                bypass_private_networks: true,
                mtu: 1_500,
            }),
        }
    }

    #[tokio::test]
    async fn adapter_preserves_complete_stop_context() {
        let backend = AppleNetworkBackend::new(RecordingBridge::default());
        backend
            .stop_tunnel(context())
            .await
            .expect("native stop barrier");
        assert_eq!(
            backend
                .bridge()
                .calls
                .lock()
                .expect("calls lock")
                .as_slice(),
            &[context()]
        );
    }

    #[tokio::test]
    async fn adapter_preserves_typed_native_status() {
        let backend = AppleNetworkBackend::new(RecordingBridge::default());
        assert_eq!(
            backend.query_status().await.expect("native status"),
            NativeEngineStatus::Off
        );
    }

    #[tokio::test]
    async fn adapter_preserves_tunnel_runtime_attestation() {
        let backend = AppleNetworkBackend::new(RecordingBridge::default());
        let request = tunnel_request();
        let runtime = backend
            .start_tunnel(request.clone())
            .await
            .expect("native runtime");
        assert_eq!(runtime.context, request.context);
        assert_eq!(runtime.config_digest, request.config_digest);
        assert!(runtime.ready);
    }

    #[tokio::test]
    async fn missing_native_bridge_is_never_reported_as_success() {
        let backend = AppleNetworkBackend::new(MissingNativeBridge);
        assert_eq!(
            backend
                .query_status()
                .await
                .expect_err("missing bridge cannot prove native Off")
                .kind,
            BackendErrorKind::Unavailable
        );
        let error = backend
            .start_tunnel(tunnel_request())
            .await
            .expect_err("missing bridge must fail closed");
        assert_eq!(error.kind, BackendErrorKind::Unavailable);
    }
}
