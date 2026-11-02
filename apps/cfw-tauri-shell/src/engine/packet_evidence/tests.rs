use super::*;
use crate::engine::maintenance::{EngineMaintenanceError, EngineMaintenanceGate};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext,
    EngineSessionIdentity, EngineStartRequest, NativeEngineStatus, RuntimeIdentity,
    TunnelInstallOutcome,
};

#[derive(Default)]
struct FakeBackend {
    operations: Mutex<Vec<&'static str>>,
    status: Mutex<NativeEngineStatus>,
    start_count: AtomicUsize,
    fail_start_on: Mutex<Option<usize>>,
}

impl FakeBackend {
    fn fail_start_on(&self, attempt: usize) {
        *self.fail_start_on.lock().expect("failure lock") = Some(attempt);
    }
}

impl EngineBackend for FakeBackend {
    fn runtime_platform(&self) -> cfw_engine_api::EngineRuntimePlatform {
        cfw_engine_api::EngineRuntimePlatform::MacOs
    }

    fn check_configuration(&self, _request: EngineStartRequest) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_local_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        panic!("Local proxy is outside the packet evidence fixture")
    }

    fn stop_local_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        panic!("Local proxy is outside the packet evidence fixture")
    }

    fn authorize_tunnel_configuration(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move { Ok(self.status.lock().expect("status lock").clone()) })
    }

    fn start_system_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async {
            Err(BackendError::new(
                BackendErrorKind::Internal,
                "proxy is outside the Packet transaction fixture",
            ))
        })
    }

    fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async {
            Err(BackendError::new(
                BackendErrorKind::Internal,
                "proxy is outside the Packet transaction fixture",
            ))
        })
    }

    fn install_tunnel(
        &self,
        _context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("install_tunnel");
            Ok(TunnelInstallOutcome::Ready)
        })
    }

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
            Ok(())
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("start_tunnel");
            let attempt = self.start_count.fetch_add(1, Ordering::AcqRel) + 1;
            if *self.fail_start_on.lock().expect("failure lock") == Some(attempt) {
                return Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "injected tunnel start failure",
                ));
            }
            let runtime = RuntimeIdentity {
                owner: EngineOwner::PacketTunnelSystemExtension,
                context: request.context,
                config_digest: request.config_digest,
                ready: true,
            };
            *self.status.lock().expect("status lock") = NativeEngineStatus::Tunnel {
                runtime: runtime.clone(),
            };
            Ok(runtime)
        })
    }

    fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("stop_tunnel");
            *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
            Ok(())
        })
    }
}

fn coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn(
        backend,
        EngineSessionIdentity {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            config_epoch: 1,
        },
    )
}

async fn establish_baseline(coordinator: &EngineModeCoordinator) -> (EngineSnapshot, String) {
    let snapshot = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("baseline tunnel");
    let digest = snapshot
        .config_digest
        .clone()
        .expect("baseline configuration digest");
    (snapshot, digest)
}

fn successful_stages(order: Arc<Mutex<Vec<&'static str>>>) -> PacketEvidenceStages {
    let begin_order = order.clone();
    let test_order = order.clone();
    PacketEvidenceStages::new(
        move |baseline| async move {
            assert_eq!(baseline.baseline.phase(), PacketEvidencePhase::TunnelActive);
            begin_order.lock().expect("order lock").push("begin");
            Ok(())
        },
        move |test| async move {
            assert!(test.test.generation() > test.baseline.generation());
            test_order.lock().expect("order lock").push("test");
            Ok(())
        },
        move |terminal| async move {
            let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                panic!("successful transaction unexpectedly aborted capture");
            };
            assert_eq!(
                restored.baseline.config_digest(),
                restored.restore.config_digest()
            );
            order.lock().expect("order lock").push("finish");
            Ok(())
        },
    )
}

type TestSnapshotObserver =
    Box<dyn FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>>;
type TestTransactionObserver = Box<
    dyn FnOnce(
        Option<ReleaseDnsEvidenceCase>,
        &EngineSnapshot,
        &EngineSnapshot,
        &EngineSnapshot,
    ) -> Result<u64, PacketEvidenceTransactionError>,
>;

fn observers() -> (TestSnapshotObserver, TestTransactionObserver) {
    let sequence = Arc::new(AtomicU64::new(0));
    let snapshot_sequence = sequence.clone();
    (
        Box::new(move |_snapshot, _ipv6| Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1)),
        Box::new(move |dns, _baseline, _test, _restore| {
            Ok(if dns.is_some() {
                sequence.fetch_add(1, Ordering::AcqRel) + 1
            } else {
                0
            })
        }),
    )
}

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
