use std::sync::Mutex;

use cfw_engine_api::{
    BackendErrorKind, CutoverPreflightOutcome, EngineMode, EngineOwner, EngineRuntimePlatform,
    TunnelApprovalWait,
};

use super::*;
use crate::test_support::{context, cutover_request, tunnel_request};
use crate::{NativeBridgeErrorCode, NativeBridgeFuture};

#[derive(Default)]
struct RecordingBridge {
    calls: Mutex<Vec<EngineCommandContext>>,
    authorization_requests: Mutex<Vec<bool>>,
    authorization_error: Option<NativeBridgeError>,
}

impl NativeBridge for RecordingBridge {
    fn check_configuration(&self, _request: EngineStartRequest) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn start_local_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        self.start_system_proxy(request)
    }

    fn stop_local_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        self.stop_system_proxy(context)
    }
    fn authorize_tunnel_configuration(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            self.calls.lock().expect("calls lock").push(request.context);
            Ok(())
        })
    }

    fn authorize_system_proxy(&self, restoration_only: bool) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            self.authorization_requests
                .lock()
                .unwrap()
                .push(restoration_only);
            match &self.authorization_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        })
    }

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

    fn await_tunnel_approval(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelApprovalWait> {
        Box::pin(async move {
            self.calls.lock().expect("calls lock").push(context);
            Ok(TunnelApprovalWait::StillAwaiting)
        })
    }

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            self.calls.lock().expect("calls lock").push(context);
            Ok(())
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, RuntimeIdentity> {
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
                system_proxy_config_digest: request.system_proxy_request().config_digest.clone(),
                tunnel_config_digest: request.tunnel_request().config_digest.clone(),
                credential_audience: request.tunnel_request().credential_audience.clone(),
            })
        })
    }
}

#[tokio::test]
async fn authorization_preserves_intent_without_starting_a_runtime() {
    let backend = AppleNetworkBackend::new(RecordingBridge::default());
    let authorization: &dyn SystemProxyAuthorization = &backend;
    authorization.authorize_system_proxy(true).await.unwrap();
    authorization.authorize_system_proxy(false).await.unwrap();
    assert_eq!(
        *backend.bridge().authorization_requests.lock().unwrap(),
        [true, false]
    );
    assert!(backend.bridge().calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn authorization_denials_timeouts_and_transport_errors_remain_errors() {
    for kind in [
        BackendErrorKind::ApprovalDenied,
        BackendErrorKind::PermissionDenied,
        BackendErrorKind::Timeout,
        BackendErrorKind::Unavailable,
    ] {
        let backend = AppleNetworkBackend::new(RecordingBridge {
            authorization_error: Some(NativeBridgeError::new(kind.into(), "native refusal")),
            ..RecordingBridge::default()
        });
        assert_eq!(
            backend.authorize_system_proxy(true).await,
            Err(BackendError::new(kind, "native refusal"))
        );
        assert_eq!(
            *backend.bridge().authorization_requests.lock().unwrap(),
            [true]
        );
        assert!(backend.bridge().calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn the_approval_wait_carries_the_exact_installation_context() {
    let backend = AppleNetworkBackend::new(RecordingBridge::default());
    let approval: &dyn TunnelApprovalBackend = &backend;
    let context = EngineCommandContext {
        installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        config_epoch: 3,
        generation: 9,
    };
    assert_eq!(
        approval.await_tunnel_approval(context.clone()).await,
        Ok(TunnelApprovalWait::StillAwaiting)
    );
    assert_eq!(*backend.bridge().calls.lock().unwrap(), [context]);
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

/// Fails every call with one native error.
struct FailingBridge(NativeBridgeError);

impl FailingBridge {
    fn fail<T>(&self) -> NativeBridgeFuture<'_, T> {
        let error = self.0.clone();
        Box::pin(async move { Err(error) })
    }
}

impl NativeBridge for FailingBridge {
    fn authorize_system_proxy(&self, _restoration_only: bool) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus> {
        self.fail()
    }

    fn check_configuration(&self, _request: EngineStartRequest) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn start_local_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        self.fail()
    }

    fn stop_local_proxy(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn start_system_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        self.fail()
    }

    fn stop_system_proxy(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn install_tunnel(
        &self,
        _context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome> {
        self.fail()
    }

    fn await_tunnel_approval(
        &self,
        _context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelApprovalWait> {
        self.fail()
    }

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn authorize_tunnel_configuration(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn start_tunnel(
        &self,
        _request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        self.fail()
    }

    fn stop_tunnel(&self, _context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        self.fail()
    }

    fn preflight_cutover(
        &self,
        _request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, CutoverPreflightOutcome> {
        self.fail()
    }
}

#[tokio::test]
async fn every_adapter_call_reaches_the_bridge_with_its_exact_request() {
    let backend = AppleNetworkBackend::new(RecordingBridge::default());
    let request = tunnel_request();
    assert_eq!(backend.runtime_platform(), EngineRuntimePlatform::MacOs);
    backend
        .check_configuration(request.clone())
        .await
        .expect("configuration check");
    for runtime in [
        backend.start_local_proxy(request.clone()).await,
        backend.start_system_proxy(request.clone()).await,
    ] {
        let runtime = runtime.expect("proxy runtime");
        assert_eq!(runtime.owner, EngineOwner::ProxyAgent);
        assert_eq!(runtime.context, request.context);
        assert_eq!(runtime.config_digest, request.config_digest);
    }
    backend
        .stop_local_proxy(context())
        .await
        .expect("local proxy stop");
    backend
        .stop_system_proxy(context())
        .await
        .expect("system proxy stop");
    assert_eq!(
        backend.install_tunnel(context()).await,
        Ok(TunnelInstallOutcome::AwaitingApproval)
    );
    backend
        .cancel_tunnel_install(context())
        .await
        .expect("install cancellation");
    backend
        .authorize_tunnel_configuration(request.clone())
        .await
        .expect("tunnel authorization");
    assert!(matches!(
        backend.preflight_cutover(cutover_request()).await,
        Ok(CutoverPreflightOutcome::AwaitingApproval { target: EngineMode::Tunnel, context, .. })
            if context == request.context
    ));
    // Seven of the calls carry the context; each reached the bridge with it.
    assert_eq!(
        *backend.bridge().calls.lock().expect("calls lock"),
        vec![request.context; 7]
    );
}

#[tokio::test]
async fn every_adapter_call_reports_a_native_failure_as_its_kind() {
    let backend = AppleNetworkBackend::new(FailingBridge(NativeBridgeError::new(
        NativeBridgeErrorCode::CredentialConflict,
        "native failure",
    )));
    let request = tunnel_request();
    let outcomes = [
        backend.check_configuration(request.clone()).await,
        backend.query_status().await.map(|_| ()),
        backend.start_local_proxy(request.clone()).await.map(|_| ()),
        backend.stop_local_proxy(context()).await,
        backend
            .start_system_proxy(request.clone())
            .await
            .map(|_| ()),
        backend.stop_system_proxy(context()).await,
        backend.install_tunnel(context()).await.map(|_| ()),
        backend.cancel_tunnel_install(context()).await,
        backend
            .authorize_tunnel_configuration(request.clone())
            .await,
        backend.start_tunnel(request).await.map(|_| ()),
        backend.stop_tunnel(context()).await,
        backend.authorize_system_proxy(false).await,
        backend
            .preflight_cutover(cutover_request())
            .await
            .map(|_| ()),
        backend.await_tunnel_approval(context()).await.map(|_| ()),
    ];
    for outcome in outcomes {
        assert_eq!(
            outcome,
            Err(BackendError::new(
                BackendErrorKind::CredentialConflict,
                "native failure"
            ))
        );
    }
}
