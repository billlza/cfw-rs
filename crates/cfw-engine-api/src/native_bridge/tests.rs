use cfw_singbox_config::CredentialKind;

use super::*;
use crate::{NativeServiceOffProofProfile, test_support::PROFILE_ID};

#[test]
fn native_bridge_v10_contract_fixtures_decode_in_rust() {
    let query: NativeRequestEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/query-request.json"
    ))
    .expect("query fixture");
    assert_eq!(query.schema_version, ENGINE_PROTOCOL_VERSION);
    assert!(matches!(query.command, NativeBridgeCommand::QueryStatus));

    let maintenance: NativeRequestEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/maintenance-request.json"
    ))
    .expect("maintenance request fixture");
    assert!(matches!(
        maintenance.command,
        NativeBridgeCommand::MaintainCurrentServices {
            action: NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent
        }
    ));

    let maintenance_response: NativeResponseEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/maintenance-response.json"
    ))
    .expect("maintenance response fixture");
    let Some(NativeBridgeResult::ServiceMaintenance(maintenance_result)) =
        maintenance_response.result
    else {
        panic!("maintenance fixture response kind");
    };
    assert!(maintenance_result.validate());
    assert_eq!(
        maintenance_result.action,
        NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent
    );

    let recovery: NativeRequestEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/recovery-maintenance-request.json"
    ))
    .expect("recovery maintenance request fixture");
    assert!(matches!(
        recovery.command,
        NativeBridgeCommand::MaintainCurrentServices {
            action: NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority
        }
    ));
    let recovery_response: NativeResponseEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/recovery-maintenance-response.json"
    ))
    .expect("recovery maintenance response fixture");
    let Some(NativeBridgeResult::ServiceMaintenance(recovery_result)) = recovery_response.result
    else {
        panic!("recovery maintenance fixture response kind");
    };
    assert!(recovery_result.validate());
    assert_eq!(
        recovery_result.action,
        NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority
    );
    assert_eq!(
        recovery_result.off_proof_profile,
        Some(NativeServiceOffProofProfile::Installed40019RecoveryCurrentAuthorityV1_1)
    );

    let preview: NativeRequestEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/gc-preview-request.json"
    ))
    .expect("GC preview fixture");
    let NativeBridgeCommand::PreviewCredentialGarbageCollection { request } = preview.command
    else {
        panic!("fixture command kind");
    };
    assert_eq!(request.snapshot_digest(), "ab".repeat(32));
    assert_eq!(request.catalog().len(), 1);
    assert_eq!(
        request.catalog()[0]
            .references()
            .iter()
            .map(|reference| reference.kind())
            .collect::<Vec<_>>(),
        [
            CredentialKind::AnyTlsPassword,
            CredentialKind::TuicUuid,
            CredentialKind::TuicPassword,
        ]
    );

    let response: NativeResponseEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/gc-preview-response.json"
    ))
    .expect("GC preview response fixture");
    let Some(NativeBridgeResult::CredentialGarbageCollectionPreview(preview)) = response.result
    else {
        panic!("fixture response kind");
    };
    assert_eq!(preview.orphan_count, 1);
    assert_eq!(
        preview.vault_revision,
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    );

    let conflict: NativeResponseEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/endpoint-conflict-response.json"
    ))
    .expect("endpoint conflict response fixture");
    assert!(conflict.result.is_none());
    assert_eq!(
        conflict.failure.expect("endpoint failure").code,
        BackendErrorKind::ControllerEndpointInUse
    );
}

#[test]
fn system_proxy_authorization_has_no_configuration_payload() {
    for (command, opcode) in [
        (
            NativeBridgeCommand::AuthorizeSystemProxy,
            "authorize_system_proxy",
        ),
        (
            NativeBridgeCommand::AuthorizeSystemProxyRestoration,
            "authorize_system_proxy_restoration",
        ),
    ] {
        let wire = serde_json::json!({"opcode": opcode});
        assert_eq!(
            serde_json::to_value(&command).expect("authorization wire command"),
            wire
        );
        assert_eq!(
            serde_json::from_value::<NativeBridgeCommand>(wire)
                .expect("authorization command decoding"),
            command
        );
    }
}

#[test]
fn the_tunnel_approval_wait_has_one_wire_shape() {
    let context = EngineCommandContext {
        installation_id: PROFILE_ID.into(),
        config_epoch: 2,
        generation: 7,
    };
    let command = NativeBridgeCommand::AwaitTunnelApproval { context };
    let wire = serde_json::json!({
        "opcode": "await_tunnel_approval",
        "payload": {"context": {
            "installation_id": PROFILE_ID, "config_epoch": 2, "generation": 7
        }}
    });
    assert_eq!(serde_json::to_value(&command).expect("encode"), wire);
    assert_eq!(
        serde_json::from_value::<NativeBridgeCommand>(wire).expect("decode"),
        command
    );
    for (wait, value) in [
        (TunnelApprovalWait::Resolved, "resolved"),
        (TunnelApprovalWait::StillAwaiting, "still_awaiting"),
        (TunnelApprovalWait::NoPendingRequest, "no_pending_request"),
    ] {
        let wire = serde_json::json!({"kind": "tunnel_approval", "value": value});
        assert_eq!(
            serde_json::from_value::<NativeBridgeResult>(wire.clone()).expect("decode"),
            NativeBridgeResult::TunnelApproval(wait)
        );
        assert_eq!(
            serde_json::to_value(NativeBridgeResult::TunnelApproval(wait)).expect("encode"),
            wire
        );
    }
}

#[test]
fn native_public_query_json_contract_is_unchanged() {
    let bytes = include_bytes!("../../../../contracts/native-bridge-v10/query-request.json");
    let request: NativeRequestEnvelope =
        serde_json::from_slice(bytes).expect("public query request fixture");
    assert_eq!(
        serde_json::to_value(request).expect("request value"),
        serde_json::from_slice::<serde_json::Value>(bytes).expect("fixture value")
    );
}
