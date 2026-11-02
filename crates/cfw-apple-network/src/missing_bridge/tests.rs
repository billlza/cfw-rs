use cfw_engine_api::{BackendErrorKind, EngineBackend};

use super::*;
use crate::AppleNetworkBackend;
use crate::test_support::{context, cutover_request, tunnel_request};

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

#[tokio::test]
async fn every_call_through_a_missing_bridge_fails_closed() {
    let bridge = MissingNativeBridge;
    let request = tunnel_request();
    let outcomes = [
        bridge.check_configuration(request.clone()).await,
        bridge.start_local_proxy(request.clone()).await.map(|_| ()),
        bridge.stop_local_proxy(context()).await,
        bridge.authorize_system_proxy(false).await,
        bridge.query_status().await.map(|_| ()),
        bridge.start_system_proxy(request.clone()).await.map(|_| ()),
        bridge.stop_system_proxy(context()).await,
        bridge.install_tunnel(context()).await.map(|_| ()),
        bridge.await_tunnel_approval(context()).await.map(|_| ()),
        bridge.cancel_tunnel_install(context()).await,
        bridge.authorize_tunnel_configuration(request.clone()).await,
        bridge.start_tunnel(request).await.map(|_| ()),
        bridge.stop_tunnel(context()).await,
        bridge
            .preflight_cutover(cutover_request())
            .await
            .map(|_| ()),
    ];
    for outcome in outcomes {
        assert_eq!(
            outcome,
            Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Unavailable,
                "signed macOS Host Bridge is not linked"
            ))
        );
    }
}
