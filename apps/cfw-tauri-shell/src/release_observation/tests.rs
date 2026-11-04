use super::*;
use cfw_engine_api::{EngineCommandContext, EngineMode, EngineOwner, RuntimeIdentity};

fn candidate() -> CandidateObservation {
    CandidateObservation {
        version: "0.4.0".to_owned(),
        build_number: "40005".to_owned(),
        #[cfg(windows)]
        msi_product_code: "{11111111-1111-4111-8111-111111111111}".to_owned(),
        #[cfg(windows)]
        msi_package_code: "{22222222-2222-4222-8222-222222222222}".to_owned(),
    }
}

fn process() -> ProcessObservation {
    ProcessObservation {
        pid: 123,
        #[cfg(target_os = "macos")]
        start_unix_ms: 1_700_000_000_000,
        #[cfg(windows)]
        creation_filetime: 133_444_736_000_001_234,
        #[cfg(windows)]
        session_id: 2,
    }
}

#[test]
fn active_snapshot_is_a_canonical_closed_public_event() {
    let snapshot = EngineSnapshot {
        desired_mode: EngineMode::Tunnel,
        state: EngineState::TunnelActive {
            runtime: RuntimeIdentity {
                owner: TUNNEL_OWNER,
                context: EngineCommandContext {
                    installation_id: "must-not-be-logged".to_owned(),
                    config_epoch: 7,
                    generation: 11,
                },
                config_digest: "a".repeat(64),
                ready: true,
            },
        },
        generation: 11,
        config_digest: Some("a".repeat(64)),
    };
    let message = build_engine_snapshot_message(
        &snapshot,
        true,
        &candidate(),
        process(),
        9,
        1_700_000_001_000,
    )
    .expect("closed observation");
    assert!(message.starts_with(MESSAGE_PREFIX));
    assert!(!message.contains("must-not-be-logged"));
    let json = &message[MESSAGE_PREFIX.len()..];
    let value: Value = serde_json::from_str(json).expect("strict event JSON");
    assert_eq!(
        serde_json::to_string(&canonicalize(value.clone())).unwrap(),
        json
    );
    assert_eq!(value["document"], DOCUMENT);
    assert_eq!(value["component"], "host");
    assert_eq!(value["payload"]["state"]["phase"], "tunnel_active");
    assert_eq!(
        value["payload"]["state"]["owner"],
        serde_json::to_value(TUNNEL_OWNER).unwrap()
    );
    assert_eq!(value["payload"]["state"]["ready"], true);
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            "candidate",
            "component",
            "document",
            "event",
            "payload",
            "process",
            "recorded_unix_ms",
            "schema_version",
            "sequence",
        ]
    );
}

#[test]
fn failed_snapshot_does_not_log_native_error_text() {
    let snapshot = EngineSnapshot {
        desired_mode: cfw_engine_api::EngineMode::SystemProxy,
        state: EngineState::Failed {
            generation: 4,
            target: cfw_engine_api::EngineMode::SystemProxy,
            error: "secret-bearing injected failure".to_owned(),
            recheck_pending: false,
        },
        generation: 4,
        config_digest: None,
    };
    let message = build_engine_snapshot_message(&snapshot, false, &candidate(), process(), 1, 1)
        .expect("failed observation");
    assert!(!message.contains("secret-bearing"));
    assert!(message.contains("\"phase\":\"failed\""));
}

#[test]
fn zero_sequence_is_rejected() {
    let error = build_engine_snapshot_message(
        &EngineSnapshot::default(),
        true,
        &candidate(),
        process(),
        0,
        1,
    )
    .expect_err("zero sequence");
    assert_eq!(error, "release observation sequence must be positive");
}

#[test]
fn dns_snapshot_rejects_a_foreign_platform_owner() {
    let mut snapshot = tunnel_snapshot(7, 'a');
    let EngineState::TunnelActive { runtime } = &mut snapshot.state else {
        panic!("test requires a tunnel snapshot");
    };
    runtime.owner = if TUNNEL_OWNER == EngineOwner::WindowsTunnelService {
        EngineOwner::PacketTunnelSystemExtension
    } else {
        EngineOwner::WindowsTunnelService
    };
    assert!(DnsEvidenceSnapshotReceipt::from_ready_tunnel(&snapshot).is_err());
}

#[test]
#[cfg(windows)]
fn windows_event_preserves_filetime_and_closed_installer_identity() {
    let message = build_engine_snapshot_message(
        &EngineSnapshot::default(),
        false,
        &candidate(),
        process(),
        1,
        1,
    )
    .expect("Windows observation");
    let event: Value = serde_json::from_str(message.strip_prefix(MESSAGE_PREFIX).unwrap()).unwrap();
    assert_eq!(
        event["process"],
        json!({"pid":123,
        "creation_filetime":133_444_736_000_001_234_u64,"session_id":2})
    );
    assert_eq!(
        event["candidate"],
        json!({"version":"0.4.0","build_number":"40005",
        "msi_product_code":"{11111111-1111-4111-8111-111111111111}",
        "msi_package_code":"{22222222-2222-4222-8222-222222222222}"})
    );
    assert_ne!(DOCUMENT, "cfw-product-observation-event-v1");
}

fn tunnel_snapshot(generation: u64, digest: char) -> EngineSnapshot {
    let config_digest = digest.to_string().repeat(64);
    EngineSnapshot {
        desired_mode: EngineMode::Tunnel,
        state: EngineState::TunnelActive {
            runtime: RuntimeIdentity {
                owner: TUNNEL_OWNER,
                context: EngineCommandContext {
                    installation_id: "not-in-receipt".to_owned(),
                    config_epoch: 7,
                    generation,
                },
                config_digest: config_digest.clone(),
                ready: true,
            },
        },
        generation,
        config_digest: Some(config_digest),
    }
}

#[test]
fn dns_transaction_receipt_is_closed_canonical_and_strictly_ordered() {
    let baseline = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(7, 'a'))
        .expect("baseline receipt");
    let test = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'b'))
        .expect("test receipt");
    let restore = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(9, 'a'))
        .expect("restore receipt");
    let message = build_dns_evidence_transaction_message(
        ReleaseDnsEvidenceCase::PrimaryIpv4,
        &baseline,
        &test,
        &restore,
        ObservationMetadata {
            candidate: &candidate(),
            process: process(),
            sequence: 12,
            recorded_unix_ms: 1_700_000_001_000,
        },
    )
    .expect("closed receipt");
    assert!(message.starts_with(MESSAGE_PREFIX));
    assert!(!message.contains("not-in-receipt"));
    assert!(!message.contains("dns-query"));
    assert!(!message.contains("controller"));
    let json = &message[MESSAGE_PREFIX.len()..];
    let value: Value = serde_json::from_str(json).expect("strict event JSON");
    assert_eq!(
        serde_json::to_string(&canonicalize(value.clone())).unwrap(),
        json
    );
    assert_eq!(value["event"], "dns_evidence_transaction");
    assert_eq!(value["payload"]["receipt"]["role"], "primary_ipv4");
    assert_eq!(
        value["payload"]["receipt"]["candidate_observation_sequence"],
        12
    );
    assert_eq!(value["payload"]["receipt"]["baseline"]["generation"], 7);
    assert_eq!(value["payload"]["receipt"]["test"]["generation"], 8);
    assert_eq!(value["payload"]["receipt"]["restore"]["generation"], 9);
}

#[test]
fn dns_transaction_receipt_rejects_digest_or_generation_drift() {
    let baseline = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(7, 'a'))
        .expect("baseline receipt");
    let test = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'b'))
        .expect("test receipt");
    let wrong_restore = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'c'))
        .expect("restore receipt shape");
    assert!(
        build_dns_evidence_transaction_message(
            ReleaseDnsEvidenceCase::SecondaryIpv6,
            &baseline,
            &test,
            &wrong_restore,
            ObservationMetadata {
                candidate: &candidate(),
                process: process(),
                sequence: 1,
                recorded_unix_ms: 1,
            },
        )
        .is_err()
    );
}
