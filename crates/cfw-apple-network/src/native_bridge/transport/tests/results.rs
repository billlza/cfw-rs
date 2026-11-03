//! The results a response may carry: bounded profile delays, a runtime that is
//! ready, attested and owned by its mode, bounded vault and service results,
//! and cutovers that await approval or carry a valid attestation.

use super::*;

#[test]
fn profile_delays_are_bounded_named_and_either_measured_or_failed() {
    let delay = |name: &str, delay: Option<u32>, error_kind: Option<ProfileProbeFailure>| {
        ProfileProxyDelay {
            name: name.to_owned(),
            delay,
            error_kind,
        }
    };
    let accepted = vec![
        delay("Tokyo", Some(1), None),
        delay("Osaka", None, Some(ProfileProbeFailure::NotFound)),
    ];
    assert_eq!(
        answered(NativeBridgeResult::ProfileDelays(accepted.clone())),
        Ok(NativeBridgeResult::ProfileDelays(accepted))
    );
    assert!(
        answered(NativeBridgeResult::ProfileDelays(vec![
            delay(
                "Tokyo",
                Some(1),
                None
            );
            32
        ]))
        .is_ok()
    );
    for refused in [
        vec![delay("Tokyo", Some(1), None); 33],
        vec![delay("", Some(1), None)],
        vec![delay(&"n".repeat(513), Some(1), None)],
        vec![delay("Tokyo", Some(0), None)],
        vec![delay("Tokyo", Some(1), Some(ProfileProbeFailure::Timeout))],
        vec![delay("Tokyo", None, None)],
    ] {
        assert_eq!(
            answered(NativeBridgeResult::ProfileDelays(refused)),
            non_canonical()
        );
    }
    assert!(
        answered(NativeBridgeResult::ProfileDelays(vec![delay(
            &"n".repeat(512),
            Some(1),
            None
        )]))
        .is_ok()
    );
}

#[test]
fn a_runtime_must_be_ready_attested_and_owned_by_its_mode() {
    for (status, owner) in [
        (
            NativeEngineStatus::LocalProxy {
                runtime: runtime(EngineOwner::ProxyAgent),
            },
            EngineOwner::ProxyAgent,
        ),
        (
            NativeEngineStatus::SystemProxy {
                runtime: runtime(EngineOwner::ProxyAgent),
            },
            EngineOwner::ProxyAgent,
        ),
        (
            NativeEngineStatus::Tunnel {
                runtime: runtime(EngineOwner::PacketTunnelSystemExtension),
            },
            EngineOwner::PacketTunnelSystemExtension,
        ),
    ] {
        assert_eq!(
            answered(NativeBridgeResult::Status(status.clone())),
            Ok(NativeBridgeResult::Status(status)),
            "{owner:?}"
        );
    }
    for misowned in [
        NativeEngineStatus::SystemProxy {
            runtime: runtime(EngineOwner::PacketTunnelSystemExtension),
        },
        NativeEngineStatus::Tunnel {
            runtime: runtime(EngineOwner::ProxyAgent),
        },
    ] {
        assert_eq!(
            answered(NativeBridgeResult::Status(misowned)),
            incomplete_runtime()
        );
    }

    let attested = runtime(EngineOwner::PacketTunnelSystemExtension);
    assert!(answered(NativeBridgeResult::Runtime(attested.clone())).is_ok());
    let broken: [fn(&mut RuntimeIdentity); 6] = [
        |runtime| runtime.context.installation_id = "60FB4B30-53DA-47CA-A933-E98268CE5703".into(),
        |runtime| runtime.context.config_epoch = 0,
        |runtime| runtime.context.generation = 0,
        |runtime| runtime.config_digest = "A".repeat(64),
        |runtime| runtime.config_digest = "a".repeat(63),
        |runtime| runtime.ready = false,
    ];
    for break_it in broken {
        let mut runtime = attested.clone();
        break_it(&mut runtime);
        assert_eq!(
            answered(NativeBridgeResult::Runtime(runtime)),
            incomplete_runtime()
        );
    }
}

#[test]
fn vault_and_service_results_are_bounded_and_canonical() {
    let reference = CredentialRef::new(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::TrojanPassword,
    )
    .expect("credential reference");
    let presence = CredentialPresence {
        reference,
        present: true,
    };
    assert!(
        answered(NativeBridgeResult::CredentialPresence(vec![
            presence.clone();
            MAX_CREDENTIAL_SLOTS
        ]))
        .is_ok()
    );
    assert_eq!(
        answered(NativeBridgeResult::CredentialPresence(vec![
            presence;
            MAX_CREDENTIAL_SLOTS
                + 1
        ])),
        non_canonical()
    );

    let mut preview = match parse_response(
        request_id(),
        include_bytes!("../../../../../../contracts/native-bridge-v10/gc-preview-response.json"),
    ) {
        Ok(NativeBridgeResult::CredentialGarbageCollectionPreview(preview)) => preview,
        other => panic!("unexpected contract result {other:?}"),
    };
    preview.vault_revision = "not-a-revision".into();
    assert_eq!(
        answered(NativeBridgeResult::CredentialGarbageCollectionPreview(
            preview
        )),
        non_canonical()
    );
    for (vault_revision, accepted) in [
        ("cccccccc-cccc-4ccc-8ccc-cccccccccccc", true),
        ("CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", false),
    ] {
        let receipt = NativeBridgeResult::CredentialGarbageCollectionReceipt(
            CredentialGarbageCollectionReceipt {
                vault_revision: vault_revision.into(),
                deleted_count: 1,
            },
        );
        assert_eq!(answered(receipt).is_ok(), accepted, "{vault_revision}");
    }

    let status = NativeServiceMaintenanceResult {
        action: NativeServiceMaintenanceAction::Status,
        engine_status: None,
        global_authority: NativeServiceRegistrationStatus::Enabled,
        off_proof_profile: None,
        proxy_agent: NativeServiceRegistrationStatus::Enabled,
    };
    assert!(answered(NativeBridgeResult::ServiceMaintenance(status.clone())).is_ok());
    let unproven_off = NativeServiceMaintenanceResult {
        action: NativeServiceMaintenanceAction::ProveOff,
        ..status
    };
    assert_eq!(
        answered(NativeBridgeResult::ServiceMaintenance(unproven_off)),
        non_canonical()
    );
    assert!(
        answered(NativeBridgeResult::TunnelApproval(
            TunnelApprovalWait::StillAwaiting
        ))
        .is_ok()
    );
}

#[test]
fn a_cutover_awaiting_approval_names_a_real_target_and_context() {
    let awaiting = |target: EngineMode, context: EngineCommandContext, digest: String| {
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::AwaitingApproval {
            target,
            context,
            system_proxy_config_digest: digest.clone(),
            tunnel_config_digest: digest,
            credential_audience: CredentialAudience::new(REQUEST, "c".repeat(64))
                .expect("audience"),
        })
    };
    assert!(answered(awaiting(EngineMode::Tunnel, context(), "a".repeat(64))).is_ok());
    let mut uppercase = context();
    uppercase.installation_id = uppercase.installation_id.to_uppercase();
    let mut first_epoch = context();
    first_epoch.config_epoch = 0;
    let mut first_generation = context();
    first_generation.generation = 0;
    for refused in [
        awaiting(EngineMode::Off, context(), "a".repeat(64)),
        awaiting(EngineMode::Tunnel, uppercase, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, first_epoch, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, first_generation, "a".repeat(64)),
        awaiting(EngineMode::Tunnel, context(), "not-a-digest".into()),
    ] {
        assert_eq!(answered(refused), non_canonical());
    }
}

#[test]
fn a_ready_cutover_carries_an_attestation_that_is_still_valid() {
    let ready = |valid_for_millis: u32| {
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::Ready {
            attestation: CutoverPreflightAttestation {
                attestation_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(),
                target: EngineMode::Tunnel,
                context: context(),
                system_proxy_config_digest: "a".repeat(64),
                tunnel_config_digest: "b".repeat(64),
                credential_audience: CredentialAudience::new(REQUEST, "c".repeat(64))
                    .expect("audience"),
                credential_references: Vec::new(),
                valid_for_millis,
            },
        })
    };
    assert!(answered(ready(1_000)).is_ok());
    assert_eq!(answered(ready(0)), non_canonical());
}
