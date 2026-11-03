//! The staged transaction's cases and stages: a distinct profile for every
//! case, the strict stage order, and the restore after a failed stage.

use super::*;

#[tokio::test]
async fn every_case_has_a_distinct_source_owned_profile_identity() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    establish_baseline(&coordinator).await;
    let baseline = coordinator
        .restart_spec()
        .await
        .expect("restart spec request")
        .expect("accepted baseline spec");
    let mut ids = std::collections::BTreeSet::new();
    for case in ReleasePacketEvidenceCase::ALL {
        let plan = test_plan(case, &baseline).expect("closed test plan");
        assert!(ids.insert(plan.profile_id));
        if case == ReleasePacketEvidenceCase::StopCleanup {
            assert_eq!(plan.mode, EngineMode::Off);
            assert_eq!(plan.expected_digest, None);
        } else {
            assert_eq!(plan.mode, EngineMode::Tunnel);
            assert!(plan.expected_digest.is_some());
        }
        assert_eq!(
            plan.settings.enable_ipv6,
            !matches!(
                case,
                ReleasePacketEvidenceCase::StopCleanup
                    | ReleasePacketEvidenceCase::Ipv6DisabledAbsence
            )
        );
    }
    assert_eq!(ids.len(), ReleasePacketEvidenceCase::ALL.len());
}

#[tokio::test]
async fn all_thirteen_cases_apply_observe_and_restore_in_strict_stage_order() {
    for case in ReleasePacketEvidenceCase::ALL {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, baseline_digest) = establish_baseline(&coordinator).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let (observe_snapshot, observe_transaction) = observers();
        let outcome = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            case,
            successful_stages(order.clone()),
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect("Packet transaction");
        assert_eq!(
            *order.lock().expect("order lock"),
            vec!["begin", "test", "finish"]
        );
        assert_eq!(
            outcome.baseline.config_digest(),
            Some(baseline_digest.as_str())
        );
        assert_eq!(
            outcome.restore.config_digest(),
            Some(baseline_digest.as_str())
        );
        assert!(outcome.baseline.generation() < outcome.test.generation());
        assert!(outcome.test.generation() < outcome.restore.generation());
        assert!(outcome.candidate_observation_sequence > 0);
        match case {
            ReleasePacketEvidenceCase::StopCleanup => {
                assert_eq!(outcome.test.phase(), PacketEvidencePhase::Off);
                assert!(!outcome.test.ipv6_enabled());
            }
            ReleasePacketEvidenceCase::Ipv6DisabledAbsence => {
                assert_eq!(outcome.test.phase(), PacketEvidencePhase::TunnelActive);
                assert!(!outcome.test.ipv6_enabled());
            }
            _ => assert!(outcome.test.ipv6_enabled()),
        }
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    }
}

#[tokio::test]
async fn failed_test_stage_still_restores_and_runs_capture_finalization() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    let (baseline, digest) = establish_baseline(&coordinator).await;
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| async { Err(PacketEvidenceCaptureFailure::CommandFailed) },
        move |terminal| async move {
            let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                panic!("test-stage failure did not restore before finalization");
            };
            assert!(restored.test.is_some());
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let (observe_snapshot, observe_transaction) = observers();
    let error = execute_packet_evidence_transaction_with(
        coordinator.clone(),
        ReleasePacketEvidenceCase::TcpIpv4,
        stages,
        Duration::from_secs(1),
        observe_snapshot,
        observe_transaction,
    )
    .await
    .expect_err("test command failure");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::CommandFailed)
    ));
    assert_eq!(finalized.load(Ordering::Acquire), 1);
    assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
    assert_eq!(
        coordinator.snapshot().config_digest.as_deref(),
        Some(digest.as_str())
    );
}

#[tokio::test]
async fn failed_apply_restores_before_finalization_without_claiming_a_test_receipt() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let (_baseline, digest) = establish_baseline(&coordinator).await;
    backend.fail_start_on(2);
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| async { panic!("test stage must not run after failed apply") },
        move |terminal| async move {
            let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                panic!("apply failure did not restore before finalization");
            };
            assert!(restored.test.is_none());
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let (observe_snapshot, observe_transaction) = observers();
    let error = execute_packet_evidence_transaction_with(
        coordinator.clone(),
        ReleasePacketEvidenceCase::TcpIpv4,
        stages,
        Duration::from_secs(1),
        observe_snapshot,
        observe_transaction,
    )
    .await
    .expect_err("apply failure");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::TestApply(_)
    ));
    assert_eq!(finalized.load(Ordering::Acquire), 1);
    assert_eq!(
        coordinator.snapshot().config_digest.as_deref(),
        Some(digest.as_str())
    );
}
