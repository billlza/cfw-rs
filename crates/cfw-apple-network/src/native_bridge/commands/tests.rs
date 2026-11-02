use cfw_engine_api::{EngineMode, EngineOwner};

use super::*;
use crate::NativeFrameworkBridge;
use crate::native_bridge::fake_native::{
    admitted_requests, answer_fake_native, fake_bridge, ffi_test_serialization, result_for,
};
use crate::test_support::{context, cutover_request, tunnel_request};

/// Answers the next request with `result`; returns the command the fake
/// admitted and what `call` made of the answer.
async fn answered<T>(
    result: NativeBridgeResult,
    call: impl AsyncFnOnce(&NativeFrameworkBridge) -> Result<T, NativeBridgeError>,
) -> (serde_json::Value, Result<T, NativeBridgeError>) {
    answer_fake_native(move |request| result_for(request, result.clone()));
    let outcome = call(&fake_bridge()).await;
    let admitted = admitted_requests();
    assert_eq!(admitted.len(), 1, "one request per command");
    (admitted[0].body["command"].clone(), outcome)
}

/// Requires `call` to refuse an answer of another kind with `message`.
async fn refuses<T>(
    other: NativeBridgeResult,
    message: &str,
    call: impl AsyncFnOnce(&NativeFrameworkBridge) -> Result<T, NativeBridgeError>,
) {
    let (_, outcome) = answered(other, call).await;
    assert_eq!(
        outcome.err(),
        Some(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            message
        ))
    );
}

/// The wire form of a command.
fn sent(command: NativeBridgeCommand) -> serde_json::Value {
    serde_json::to_value(command).expect("command wire form")
}

fn runtime(owner: EngineOwner) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: context(),
        config_digest: "a".repeat(64),
        ready: true,
    }
}

#[tokio::test]
async fn proxy_commands_send_their_request_and_return_their_result() {
    let _serial = ffi_test_serialization().lock().await;
    let request = tunnel_request();
    let proxy = runtime(EngineOwner::ProxyAgent);

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.check_configuration(request.clone()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::CheckConfiguration {
            request: request.clone()
        })
    );
    assert_eq!(outcome, Ok(()));

    for (restoration_only, expected) in [
        (false, NativeBridgeCommand::AuthorizeSystemProxy),
        (true, NativeBridgeCommand::AuthorizeSystemProxyRestoration),
    ] {
        let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
            bridge.authorize_system_proxy(restoration_only).await
        })
        .await;
        assert_eq!(command, sent(expected));
        assert_eq!(outcome, Ok(()));
    }

    let (command, outcome) = answered(
        NativeBridgeResult::Status(NativeEngineStatus::Off),
        async |bridge| bridge.query_status().await,
    )
    .await;
    assert_eq!(command, sent(NativeBridgeCommand::QueryStatus));
    assert_eq!(outcome, Ok(NativeEngineStatus::Off));

    let (command, outcome) = answered(NativeBridgeResult::Runtime(proxy.clone()), async |bridge| {
        bridge.start_local_proxy(request.clone()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StartLocalProxy {
            request: request.clone()
        })
    );
    assert_eq!(outcome, Ok(proxy.clone()));

    let (command, outcome) = answered(NativeBridgeResult::Runtime(proxy.clone()), async |bridge| {
        bridge.start_system_proxy(request.clone()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StartSystemProxy {
            request: request.clone()
        })
    );
    assert_eq!(outcome, Ok(proxy));

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.stop_local_proxy(context()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StopLocalProxy { context: context() })
    );
    assert_eq!(outcome, Ok(()));

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.stop_system_proxy(context()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StopSystemProxy { context: context() })
    );
    assert_eq!(outcome, Ok(()));
}

#[tokio::test]
async fn tunnel_commands_send_their_request_and_return_their_result() {
    let _serial = ffi_test_serialization().lock().await;
    let request = tunnel_request();
    let tunnel = runtime(EngineOwner::PacketTunnelSystemExtension);

    let (command, outcome) = answered(
        NativeBridgeResult::TunnelInstall(TunnelInstallOutcome::AwaitingApproval),
        async |bridge| bridge.install_tunnel(context()).await,
    )
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::InstallTunnel { context: context() })
    );
    assert_eq!(outcome, Ok(TunnelInstallOutcome::AwaitingApproval));

    let (command, outcome) = answered(
        NativeBridgeResult::TunnelApproval(TunnelApprovalWait::StillAwaiting),
        async |bridge| bridge.await_tunnel_approval(context()).await,
    )
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::AwaitTunnelApproval { context: context() })
    );
    assert_eq!(outcome, Ok(TunnelApprovalWait::StillAwaiting));

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.cancel_tunnel_install(context()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::CancelTunnelInstall { context: context() })
    );
    assert_eq!(outcome, Ok(()));

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.authorize_tunnel_configuration(request.clone()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::AuthorizeTunnelConfiguration {
            request: request.clone()
        })
    );
    assert_eq!(outcome, Ok(()));

    let (command, outcome) = answered(
        NativeBridgeResult::Runtime(tunnel.clone()),
        async |bridge| bridge.start_tunnel(request.clone()).await,
    )
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StartTunnel {
            request: request.clone()
        })
    );
    assert_eq!(outcome, Ok(tunnel));

    let (command, outcome) = answered(NativeBridgeResult::Acknowledged, async |bridge| {
        bridge.stop_tunnel(context()).await
    })
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::StopTunnel { context: context() })
    );
    assert_eq!(outcome, Ok(()));

    let awaiting = CutoverPreflightOutcome::AwaitingApproval {
        target: EngineMode::Tunnel,
        context: context(),
        system_proxy_config_digest: request.config_digest.clone(),
        tunnel_config_digest: request.config_digest.clone(),
        credential_audience: request.credential_audience.clone(),
    };
    let (command, outcome) = answered(
        NativeBridgeResult::CutoverPreflight(awaiting.clone()),
        async |bridge| bridge.preflight_cutover(cutover_request()).await,
    )
    .await;
    assert_eq!(
        command,
        sent(NativeBridgeCommand::PreflightCutover {
            request: Box::new(cutover_request())
        })
    );
    assert_eq!(outcome, Ok(awaiting));
}

#[tokio::test]
async fn every_command_refuses_a_result_of_another_kind() {
    let _serial = ffi_test_serialization().lock().await;
    let request = tunnel_request();
    let other = NativeBridgeResult::TunnelApproval(TunnelApprovalWait::StillAwaiting);

    refuses(
        other.clone(),
        "native configuration check returned the wrong result kind",
        async |bridge| bridge.check_configuration(request.clone()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native authorization returned the wrong result kind",
        async |bridge| bridge.authorize_system_proxy(false).await,
    )
    .await;
    refuses(
        other.clone(),
        "native query returned the wrong result kind",
        async |bridge| bridge.query_status().await,
    )
    .await;
    refuses(
        other.clone(),
        "native local proxy start returned the wrong result kind",
        async |bridge| bridge.start_local_proxy(request.clone()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native local proxy stop returned the wrong result kind",
        async |bridge| bridge.stop_local_proxy(context()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native proxy start returned the wrong result kind",
        async |bridge| bridge.start_system_proxy(request.clone()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native proxy stop returned the wrong result kind",
        async |bridge| bridge.stop_system_proxy(context()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native tunnel install returned the wrong result kind",
        async |bridge| bridge.install_tunnel(context()).await,
    )
    .await;
    refuses(
        NativeBridgeResult::Acknowledged,
        "native tunnel approval wait returned the wrong result kind",
        async |bridge| bridge.await_tunnel_approval(context()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native tunnel install cancellation returned the wrong result kind",
        async |bridge| bridge.cancel_tunnel_install(context()).await,
    )
    .await;
    refuses(
        other.clone(),
        "Tunnel authorization returned an unexpected result",
        async |bridge| bridge.authorize_tunnel_configuration(request.clone()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native tunnel start returned the wrong result kind",
        async |bridge| bridge.start_tunnel(request.clone()).await,
    )
    .await;
    refuses(
        other.clone(),
        "native tunnel stop returned the wrong result kind",
        async |bridge| bridge.stop_tunnel(context()).await,
    )
    .await;
    refuses(
        other,
        "native cutover preflight returned the wrong result kind",
        async |bridge| bridge.preflight_cutover(cutover_request()).await,
    )
    .await;
}
