use cfw_singbox_config::CredentialKind;

use super::*;
use crate::{
    CredentialPresenceRequest, EngineMode, NativeServiceOffProofProfile, TunnelNetworkOptions,
    test_support::{CREDENTIAL_ID, PROFILE_ID, VAULT_REVISION, audience, context, trojan_profile},
};

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

fn start_request() -> EngineStartRequest {
    EngineStartRequest {
        mode: cfw_singbox_config::ProjectionMode::SystemProxy,
        context: context(),
        credential_audience: audience(PROFILE_ID),
        config_json: "never-print-this-config".into(),
        config_content_digest: "01".repeat(32),
        config_digest: "02".repeat(32),
        credential_slots: Vec::new(),
        tunnel_options: None,
    }
}

#[test]
fn every_command_debug_names_its_operation_and_never_the_configuration() {
    let profile = trojan_profile(CREDENTIAL_ID, 443);
    let settings = cfw_singbox_config::EngineSettings::default();
    let snapshot =
        CredentialGarbageCollectionRequest::new("ab".repeat(32), Vec::new()).expect("snapshot");
    let preview = CredentialGarbageCollectionPreview {
        snapshot_digest: "ab".repeat(32),
        vault_revision: VAULT_REVISION.into(),
        orphan_bindings: Vec::new(),
        orphan_count: 0,
    };
    let mut tunnel = start_request();
    tunnel.mode = cfw_singbox_config::ProjectionMode::Tunnel;
    tunnel.tunnel_options = Some(TunnelNetworkOptions {
        ipv6_enabled: false,
        bypass_private_networks: true,
        direct_ipv4_hosts: cfw_singbox_config::DirectIpv4HostRoutes::default(),
        mtu: 1_500,
        system_proxy_port: None,
    });
    let commands = [
        (NativeBridgeCommand::QueryStatus, "QueryStatus"),
        (
            NativeBridgeCommand::CheckConfiguration {
                request: start_request(),
            },
            "CheckConfiguration",
        ),
        (
            NativeBridgeCommand::AuthorizeSystemProxy,
            "AuthorizeSystemProxy",
        ),
        (
            NativeBridgeCommand::AuthorizeSystemProxyRestoration,
            "AuthorizeSystemProxyRestoration",
        ),
        (
            NativeBridgeCommand::StartLocalProxy {
                request: start_request(),
            },
            "StartLocalProxy",
        ),
        (
            NativeBridgeCommand::StopLocalProxy { context: context() },
            "StopLocalProxy",
        ),
        (
            NativeBridgeCommand::MaintainCurrentServices {
                action: NativeServiceMaintenanceAction::Status,
            },
            "MaintainCurrentServices",
        ),
        (
            NativeBridgeCommand::StartSystemProxy {
                request: start_request(),
            },
            "StartSystemProxy",
        ),
        (
            NativeBridgeCommand::StopSystemProxy { context: context() },
            "StopSystemProxy",
        ),
        (
            NativeBridgeCommand::InstallTunnel { context: context() },
            "InstallTunnel",
        ),
        (
            NativeBridgeCommand::AwaitTunnelApproval { context: context() },
            "AwaitTunnelApproval",
        ),
        (
            NativeBridgeCommand::CancelTunnelInstall { context: context() },
            "CancelTunnelInstall",
        ),
        (
            NativeBridgeCommand::AuthorizeTunnelConfiguration {
                request: tunnel.clone(),
            },
            "AuthorizeTunnelConfiguration",
        ),
        (
            NativeBridgeCommand::StartTunnel {
                request: tunnel.clone(),
            },
            "StartTunnel",
        ),
        (
            NativeBridgeCommand::StopTunnel { context: context() },
            "StopTunnel",
        ),
        (
            NativeBridgeCommand::QueryCredentialPresence {
                request: CredentialPresenceRequest::new(PROFILE_ID, &profile)
                    .expect("query")
                    .into(),
            },
            "QueryCredentialPresence",
        ),
        (
            NativeBridgeCommand::RebindProfileCredentials {
                request: CredentialRebindRequest::new(PROFILE_ID, &profile, &profile, &settings)
                    .expect("rebind"),
            },
            "RebindProfileCredentials",
        ),
        (
            NativeBridgeCommand::PreflightCutover {
                request: Box::new(
                    CutoverPreflightRequest::new(EngineMode::Tunnel, start_request(), tunnel)
                        .expect("preflight"),
                ),
            },
            "PreflightCutover",
        ),
        (
            NativeBridgeCommand::TestProfileDelays {
                request: ProfileDelayTestRequest {
                    audience: audience(PROFILE_ID),
                    config_json: "never-print-this-config".into(),
                    credential_slots: Vec::new(),
                    proxies: vec!["proxy".into()],
                    timeout_ms: 5_000,
                    target_url: None,
                    expected_status: None,
                },
            },
            "TestProfileDelays",
        ),
        (
            NativeBridgeCommand::PreviewCredentialGarbageCollection {
                request: snapshot.clone(),
            },
            "PreviewCredentialGarbageCollection",
        ),
        (
            NativeBridgeCommand::CommitCredentialGarbageCollection {
                request: CredentialGarbageCollectionCommitRequest::new(snapshot, &preview)
                    .expect("commit"),
            },
            "CommitCredentialGarbageCollection",
        ),
    ];
    for (command, name) in commands {
        let debug = format!("{command:?}");
        assert!(
            debug == name || debug.starts_with(&format!("{name} {{")),
            "{debug}"
        );
        assert!(!debug.contains("never-print-this-config"), "{debug}");
    }
}

#[test]
fn each_request_envelope_carries_the_protocol_version_and_a_fresh_id() {
    let first = NativeRequestEnvelope::new(NativeBridgeCommand::QueryStatus);
    let second = NativeRequestEnvelope::new(NativeBridgeCommand::QueryStatus);
    assert_eq!(first.schema_version, ENGINE_PROTOCOL_VERSION);
    assert_eq!(first.request_id.get_version_num(), 4);
    assert_ne!(first.request_id, second.request_id);
    assert_eq!(first.command, NativeBridgeCommand::QueryStatus);
}

#[test]
fn installation_recovery_contract_matches_native_request_and_response_shapes() {
    let request: NativeRequestEnvelope = serde_json::from_str(include_str!(
        "../../../../contracts/native-bridge-v10/installation-recovery-request.json"
    ))
    .unwrap();
    assert_eq!(
        request.command,
        NativeBridgeCommand::AuthorizeInstallationRecovery
    );
    for (bytes, enrolled) in [
        (
            include_str!(
                "../../../../contracts/native-bridge-v10/installation-recovery-response.json"
            ),
            true,
        ),
        (
            include_str!(
                "../../../../contracts/native-bridge-v10/installation-unenrolled-response.json"
            ),
            false,
        ),
    ] {
        let response: NativeResponseEnvelope = serde_json::from_str(bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::from_str::<serde_json::Value>(bytes).unwrap()
        );
        let Some(NativeBridgeResult::InstallationRecovery(state)) = response.result else {
            panic!("recovery result")
        };
        assert_eq!(state.identity.is_some(), enrolled);
        if let Some(identity) = state.identity {
            assert_eq!(identity.accepted_epoch, 7);
            assert_eq!(identity.revision, 12);
            assert_eq!(identity.console_uid, 501);
        }
    }
}
