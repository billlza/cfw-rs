//! The end of the transaction: the finish callback after a proven restore, a
//! dropped caller, failed observations, and the sticky quarantine after a
//! failed restore.

use super::*;

#[tokio::test]
async fn finish_callback_panic_is_attempted_once_after_proven_restore() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempted = attempts.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |_terminal| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
                attempted.fetch_add(1, Ordering::AcqRel);
                panic!("injected finish callback panic")
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("finish callback panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(attempts.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("finish callback panic hard timeout");
}

#[tokio::test]
async fn finish_callback_timeout_is_attempted_once_after_proven_restore() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempted = attempts.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |_terminal| async move {
                attempted.fetch_add(1, Ordering::AcqRel);
                std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>().await
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_millis(10),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("finish callback timeout");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CaptureTimeout
        ));
        assert_eq!(attempts.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("finish callback timeout hard timeout");
}

#[tokio::test]
async fn dropped_post_begin_caller_cannot_cancel_restore_or_terminal_cleanup() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let gate = EngineMaintenanceGate::default();
        let maintenance = gate.reserve_if_idle().expect("maintenance admission");
        let exercise_started = Arc::new(tokio::sync::Notify::new());
        let exercise_release = Arc::new(tokio::sync::Notify::new());
        let started = exercise_started.clone();
        let release = exercise_release.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            move |_test| async move {
                started.notify_one();
                release.notified().await;
                Ok(())
            },
            move |terminal| async move {
                assert!(matches!(
                    terminal,
                    PacketEvidenceCaptureTerminal::Restored(_)
                ));
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let operation_coordinator = coordinator.clone();
        let sequence = Arc::new(AtomicU64::new(0));
        let snapshot_sequence = sequence.clone();
        let response = maintenance.run_to_completion(async move {
            execute_packet_evidence_transaction_with(
                operation_coordinator,
                ReleasePacketEvidenceCase::TcpIpv6,
                stages,
                Duration::from_secs(1),
                move |_snapshot, _ipv6| Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1),
                move |dns, _baseline, _test, _restore| {
                    Ok(if dns.is_some() {
                        sequence.fetch_add(1, Ordering::AcqRel) + 1
                    } else {
                        0
                    })
                },
            )
            .await
        });
        exercise_started.notified().await;
        drop(response);
        assert!(matches!(
            gate.reserve_if_idle(),
            Err(EngineMaintenanceError::AlreadyActive)
        ));
        exercise_release.notify_one();
        loop {
            match gate.reserve_if_idle() {
                Ok(released) => {
                    drop(released);
                    break;
                }
                Err(EngineMaintenanceError::AlreadyActive) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected maintenance state: {error}"),
            }
        }
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("caller cancellation recovery hard timeout");
}

#[tokio::test]
async fn restore_observation_failure_uses_aborted_terminal_cleanup() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    establish_baseline(&coordinator).await;
    let observation_calls = Arc::new(AtomicUsize::new(0));
    let observed = observation_calls.clone();
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| async { Ok(()) },
        move |terminal| async move {
            let PacketEvidenceCaptureTerminal::Aborted(aborted) = terminal else {
                panic!("unpublished restore cannot be reported as restored");
            };
            assert_eq!(aborted.reason, PacketEvidenceAbortReason::ObservationFailed);
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let error = execute_packet_evidence_transaction_with(
        coordinator,
        ReleasePacketEvidenceCase::Udp,
        stages,
        Duration::from_secs(1),
        move |_snapshot, _ipv6| {
            let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
            if call == 3 {
                Err(PacketEvidenceTransactionError::Observation(
                    "injected restore observation failure".to_owned(),
                ))
            } else {
                Ok(call as u64)
            }
        },
        |_dns, _baseline, _test, _restore| Ok(0),
    )
    .await
    .expect_err("restore observation failure");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::Observation(_)
    ));
    assert_eq!(observation_calls.load(Ordering::Acquire), 3);
    assert_eq!(finalized.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn transaction_observation_failure_finalizes_after_proven_restore() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    establish_baseline(&coordinator).await;
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| async { Ok(()) },
        move |terminal| async move {
            assert!(matches!(
                terminal,
                PacketEvidenceCaptureTerminal::Restored(_)
            ));
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let sequence = AtomicU64::new(0);
    let error = execute_packet_evidence_transaction_with(
        coordinator,
        ReleasePacketEvidenceCase::DnsAPrimary,
        stages,
        Duration::from_secs(1),
        |_snapshot, _ipv6| Ok(sequence.fetch_add(1, Ordering::AcqRel) + 1),
        |_dns, _baseline, _test, _restore| {
            Err(PacketEvidenceTransactionError::Observation(
                "injected transaction observation failure".to_owned(),
            ))
        },
    )
    .await
    .expect_err("transaction observation failure");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::Observation(_)
    ));
    assert_eq!(finalized.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn failed_restore_enters_sticky_quarantine() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    establish_baseline(&coordinator).await;
    backend.fail_start_on(3);
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| async { Ok(()) },
        move |terminal| async move {
            let PacketEvidenceCaptureTerminal::Aborted(aborted) = terminal else {
                panic!("failed restore cannot claim a restored terminal state");
            };
            assert_eq!(aborted.reason, PacketEvidenceAbortReason::RestoreUnproven);
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let (observe_snapshot, observe_transaction) = observers();
    let error = execute_packet_evidence_transaction_with(
        coordinator.clone(),
        ReleasePacketEvidenceCase::Quic,
        stages,
        Duration::from_secs(1),
        observe_snapshot,
        observe_transaction,
    )
    .await
    .expect_err("restore failure");
    assert!(matches!(error, PacketEvidenceTransactionError::Restore(_)));
    assert_eq!(finalized.load(Ordering::Acquire), 1);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
    let retry = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("quarantine blocks restart");
    assert_eq!(
        retry,
        EngineCoordinatorError::ReleaseEvidenceRestoreUnproven
    );
}
