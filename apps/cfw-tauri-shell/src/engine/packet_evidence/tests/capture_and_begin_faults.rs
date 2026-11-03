//! Faults in the capture and in an ambiguous begin: panics and timeouts that
//! still restore the baseline and reach exactly one terminal finalizer.

use super::*;

#[tokio::test]
async fn capture_panic_is_typed_and_exact_baseline_is_restored() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    let (baseline, _) = establish_baseline(&coordinator).await;
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
            panic!("injected stage panic")
        },
        |_restored| async { Ok(()) },
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
    .expect_err("stage panic");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::CapturePanicked
    ));
    assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
}

#[tokio::test]
async fn capture_timeout_restores_and_reaches_one_terminal_finalizer() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    let (baseline, _) = establish_baseline(&coordinator).await;
    let finalized = Arc::new(AtomicUsize::new(0));
    let finalized_stage = finalized.clone();
    let stages = PacketEvidenceStages::new(
        |_baseline| async { Ok(()) },
        |_test| std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>(),
        move |terminal| async move {
            assert!(matches!(
                terminal,
                PacketEvidenceCaptureTerminal::Restored(_)
            ));
            finalized_stage.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    );
    let (observe_snapshot, observe_transaction) = observers();
    let error = execute_packet_evidence_transaction_with(
        coordinator.clone(),
        ReleasePacketEvidenceCase::TcpIpv4,
        stages,
        Duration::from_millis(10),
        observe_snapshot,
        observe_transaction,
    )
    .await
    .expect_err("capture timeout");
    assert!(matches!(
        error,
        PacketEvidenceTransactionError::CaptureTimeout
    ));
    assert_eq!(finalized.load(Ordering::Acquire), 1);
    assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
}

#[tokio::test]
async fn ambiguous_begin_timeout_restores_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let begin_side_effects = Arc::new(AtomicUsize::new(0));
        let began = begin_side_effects.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            move |_baseline| async move {
                began.fetch_add(1, Ordering::AcqRel);
                std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>().await
            },
            |_test| async { panic!("test cannot run after ambiguous begin") },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("unchanged actor baseline must be restored explicitly");
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
            Duration::from_millis(10),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("ambiguous begin timeout");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CaptureTimeout
        ));
        assert_eq!(begin_side_effects.load(Ordering::Acquire), 1);
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        assert!(coordinator.snapshot().generation >= baseline.generation);
    })
    .await
    .expect("ambiguous begin cleanup hard timeout");
}

#[tokio::test]
async fn ambiguous_begin_sync_panic_restores_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
                panic!("injected synchronous begin panic")
            },
            |_test| async { panic!("test cannot run after begin panic") },
            move |_terminal| async move {
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
        .expect_err("synchronous begin panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("synchronous begin panic hard timeout");
}

#[tokio::test]
async fn ambiguous_begin_future_panic_restores_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { panic!("injected asynchronous begin panic") },
            |_test| async { panic!("test cannot run after begin panic") },
            move |_terminal| async move {
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
        .expect_err("asynchronous begin panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("asynchronous begin panic hard timeout");
}
