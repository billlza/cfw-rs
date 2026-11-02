use cfw_engine_api::{BackendErrorKind, EngineBackend};

use super::*;
use crate::AppleNetworkBackend;
use crate::test_support::tunnel_request;

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
