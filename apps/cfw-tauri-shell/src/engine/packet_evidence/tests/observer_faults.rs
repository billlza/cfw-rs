//! Panics in the snapshot, transaction and restore observers: the baseline is
//! still restored and the terminal is taken once.

use super::*;

#[tokio::test]
async fn post_begin_snapshot_observer_panic_restores_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed = observation_calls.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { panic!("panicking observation must precede test callback") },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("successful panic recovery must report restored state");
                };
                assert!(restored.test.is_none());
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_secs(1),
            move |_snapshot, _ipv6| {
                let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
                if call == 2 {
                    panic!("injected post-begin snapshot observation panic");
                }
                Ok(call as u64)
            },
            |_dns, _baseline, _test, _restore| Ok(0),
        )
        .await
        .expect_err("snapshot observer panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(observation_calls.load(Ordering::Acquire), 3);
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("snapshot panic recovery hard timeout");
}

#[tokio::test]
async fn post_begin_transaction_observer_panic_restores_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let sequence = Arc::new(AtomicU64::new(0));
        let snapshot_sequence = sequence.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("transaction observer panic must restore");
                };
                assert!(restored.test.is_some());
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::DnsAPrimary,
            stages,
            Duration::from_secs(1),
            move |_snapshot, _ipv6| Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1),
            |_dns, _baseline, _test, _restore| panic!("injected transaction observer panic"),
        )
        .await
        .expect_err("transaction observer panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("transaction panic recovery hard timeout");
}

#[tokio::test]
async fn restore_observer_panic_recovers_again_and_takes_terminal_once() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed = observation_calls.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("second restore observation must prove the baseline");
                };
                assert!(restored.test.is_some());
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_secs(1),
            move |_snapshot, _ipv6| {
                let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
                if call == 3 {
                    panic!("injected restore observation panic");
                }
                Ok(call as u64)
            },
            |_dns, _baseline, _test, _restore| Ok(0),
        )
        .await
        .expect_err("restore observer panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(observation_calls.load(Ordering::Acquire), 4);
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    })
    .await
    .expect("restore observer panic hard timeout");
}
