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

mod capture_and_begin_faults;
mod finish_and_restore;
mod observer_faults;
mod stage_order;
