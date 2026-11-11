use cfw_engine_api::{EngineCommandContext, NativeBridgeCommand};

use super::*;

#[test]
fn only_waits_for_a_person_take_the_authorization_budget() {
    let context = EngineCommandContext {
        installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        config_epoch: 1,
        generation: 4,
    };
    assert!(waits_for_person(
        &NativeBridgeCommand::AwaitTunnelApproval {
            context: context.clone()
        }
    ));
    assert!(waits_for_person(&NativeBridgeCommand::AuthorizeSystemProxy));
    assert!(waits_for_person(
        &NativeBridgeCommand::AuthorizeInstallationRecovery
    ));
    assert!(waits_for_person(
        &NativeBridgeCommand::AuthorizeSystemProxyRestoration
    ));
    for command in [
        NativeBridgeCommand::QueryStatus,
        NativeBridgeCommand::InstallTunnel {
            context: context.clone(),
        },
        NativeBridgeCommand::CancelTunnelInstall {
            context: context.clone(),
        },
        NativeBridgeCommand::StopTunnel { context },
    ] {
        assert!(!waits_for_person(&command), "{command:?}");
    }
}

#[test]
fn c_header_and_rust_watchdog_constants_match() {
    let header = include_str!("../../../../../native/macos/Headers/CFWNativeBridge.h");
    assert!(header.contains("CFW_NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS 30000u"));
    assert!(header.contains("CFW_NATIVE_BRIDGE_AUTHORIZATION_BUDGET_MILLISECONDS 300000u"));
    assert_eq!(NATIVE_BRIDGE_AUTHORIZATION_BUDGET_MILLISECONDS, 300_000);
    assert!(header.contains("CFW_NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS 20000u"));
    assert!(header.contains("CFW_NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS 55000u"));
    assert!(
        NATIVE_BRIDGE_OUTER_WATCHDOG > NATIVE_BRIDGE_OPERATION_BUDGET + NATIVE_BRIDGE_CLEANUP_GRACE
    );
}
