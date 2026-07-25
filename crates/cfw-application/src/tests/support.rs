use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext,
    EngineGenerationStore, EngineLineage, EngineOwner, EngineSessionIdentity, EngineStartRequest,
    NativeEngineStatus, RuntimeIdentity, TunnelInstallOutcome,
};
use tokio::sync::Notify;

use crate::{CoordinatorOptions, EngineModeCoordinator};

#[derive(Default)]
pub(super) struct FakeBackend {
    operations: Mutex<Vec<&'static str>>,
    proxy_requests: Mutex<Vec<EngineStartRequest>>,
    proxy_stop_contexts: Mutex<Vec<EngineCommandContext>>,
    tunnel_install_contexts: Mutex<Vec<EngineCommandContext>>,
    tunnel_cancel_contexts: Mutex<Vec<EngineCommandContext>>,
    tunnel_requests: Mutex<Vec<EngineStartRequest>>,
    tunnel_stop_contexts: Mutex<Vec<EngineCommandContext>>,
    native_status: Mutex<NativeEngineStatus>,
    query_count: AtomicUsize,
    pub(super) wrong_proxy_digest: Mutex<bool>,
    pub(super) wrong_proxy_owner: Mutex<bool>,
    pub(super) awaiting_approval: Mutex<bool>,
    pub(super) fail_proxy_start: Mutex<bool>,
    pub(super) fail_proxy_stop: Mutex<bool>,
    pub(super) fail_query: Mutex<bool>,
    /// When true, a successful stop attests the owner stopped (returns `Ok`) but
    /// does not clear the native observation, so a subsequent independent
    /// OS-state query still reports the prior owner. Models a stop whose owner
    /// stopped attestation succeeds while the Global Off barrier stays unproven.
    pub(super) stop_leaves_owner_present: Mutex<bool>,
    pub(super) proxy_start_error: Mutex<Option<BackendErrorKind>>,
    pub(super) tunnel_install_error: Mutex<Option<BackendErrorKind>>,
    pub(super) tunnel_start_error: Mutex<Option<BackendErrorKind>>,
    pub(super) hang_proxy_start: Mutex<bool>,
    pub(super) proxy_start_delay: Mutex<Duration>,
    pub(super) proxy_start_gate: Mutex<Option<Arc<Notify>>>,
}

impl FakeBackend {
    pub(super) fn operations(&self) -> Vec<&'static str> {
        self.operations.lock().expect("operations lock").clone()
    }

    pub(super) fn proxy_stop_contexts(&self) -> Vec<EngineCommandContext> {
        self.proxy_stop_contexts
            .lock()
            .expect("proxy stop contexts lock")
            .clone()
    }

    pub(super) fn proxy_requests(&self) -> Vec<EngineStartRequest> {
        self.proxy_requests
            .lock()
            .expect("proxy requests lock")
            .clone()
    }

    pub(super) fn tunnel_requests(&self) -> Vec<EngineStartRequest> {
        self.tunnel_requests
            .lock()
            .expect("tunnel requests lock")
            .clone()
    }

    pub(super) fn tunnel_install_contexts(&self) -> Vec<EngineCommandContext> {
        self.tunnel_install_contexts
            .lock()
            .expect("tunnel install contexts lock")
            .clone()
    }

    pub(super) fn tunnel_cancel_contexts(&self) -> Vec<EngineCommandContext> {
        self.tunnel_cancel_contexts
            .lock()
            .expect("tunnel cancel contexts lock")
            .clone()
    }

    pub(super) fn tunnel_stop_contexts(&self) -> Vec<EngineCommandContext> {
        self.tunnel_stop_contexts
            .lock()
            .expect("tunnel stop contexts lock")
            .clone()
    }

    pub(super) fn set_native_status(&self, status: NativeEngineStatus) {
        *self.native_status.lock().expect("native status lock") = status;
    }

    pub(super) fn query_count(&self) -> usize {
        self.query_count.load(Ordering::Acquire)
    }
}

pub(super) struct MemoryGenerationStore {
    lineage: Mutex<EngineLineage>,
    fail_reserve: Mutex<bool>,
}

impl MemoryGenerationStore {
    pub(super) fn new(generation: u64) -> Self {
        Self {
            lineage: Mutex::new(EngineLineage {
                session: test_session(),
                generation,
            }),
            fail_reserve: Mutex::new(false),
        }
    }

    pub(super) fn set_fail_reserve(&self, fail: bool) {
        *self.fail_reserve.lock().expect("reserve failure lock") = fail;
    }
}

impl EngineGenerationStore for MemoryGenerationStore {
    fn load(&self) -> Result<EngineLineage, String> {
        Ok(self
            .lineage
            .lock()
            .map_err(|error| error.to_string())?
            .clone())
    }

    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String> {
        if *self
            .fail_reserve
            .lock()
            .map_err(|error| error.to_string())?
        {
            return Err("injected authoritative generation failure".into());
        }
        let mut lineage = self.lineage.lock().map_err(|error| error.to_string())?;
        if lineage.generation != expected_generation {
            return Err(format!(
                "expected generation {expected_generation}, found {}",
                lineage.generation
            ));
        }
        lineage.generation = lineage
            .generation
            .checked_add(1)
            .ok_or_else(|| "generation exhausted".to_owned())?;
        Ok(lineage.generation)
    }
}

impl EngineBackend for FakeBackend {
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move {
            self.query_count.fetch_add(1, Ordering::AcqRel);
            if *self.fail_query.lock().expect("query failure lock") {
                return Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "native status unavailable",
                ));
            }
            Ok(self
                .native_status
                .lock()
                .expect("native status lock")
                .clone())
        })
    }

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("start_proxy");
            self.proxy_requests
                .lock()
                .expect("proxy requests lock")
                .push(request.clone());
            if *self.hang_proxy_start.lock().expect("hang start lock") {
                std::future::pending::<()>().await;
            }
            let start_gate = self
                .proxy_start_gate
                .lock()
                .expect("start gate lock")
                .clone();
            if let Some(start_gate) = start_gate {
                start_gate.notified().await;
            }
            let delay = *self.proxy_start_delay.lock().expect("start delay lock");
            tokio::time::sleep(delay).await;
            if let Some(kind) = *self
                .proxy_start_error
                .lock()
                .expect("proxy start error lock")
            {
                return Err(BackendError::new(
                    kind,
                    "proxy start reported a typed backend error",
                ));
            }
            if *self.fail_proxy_start.lock().expect("fail start lock") {
                return Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "proxy agent unavailable",
                ));
            }
            let wrong_digest = *self.wrong_proxy_digest.lock().expect("wrong digest lock");
            let wrong_owner = *self.wrong_proxy_owner.lock().expect("wrong owner lock");
            let runtime = RuntimeIdentity {
                owner: if wrong_owner {
                    EngineOwner::PacketTunnelSystemExtension
                } else {
                    EngineOwner::ProxyAgent
                },
                context: request.context,
                config_digest: if wrong_digest {
                    "wrong".to_owned()
                } else {
                    request.config_digest
                },
                ready: true,
            };
            *self.native_status.lock().expect("native status lock") =
                NativeEngineStatus::SystemProxy {
                    runtime: runtime.clone(),
                };
            Ok(runtime)
        })
    }

    fn stop_system_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("stop_proxy");
            self.proxy_stop_contexts
                .lock()
                .expect("proxy stop contexts lock")
                .push(context);
            if *self.fail_proxy_stop.lock().expect("fail stop lock") {
                return Err(BackendError::new(
                    BackendErrorKind::Internal,
                    "proxy stop barrier failed",
                ));
            }
            if !*self
                .stop_leaves_owner_present
                .lock()
                .expect("stop leaves owner lock")
            {
                *self.native_status.lock().expect("native status lock") = NativeEngineStatus::Off;
            }
            Ok(())
        })
    }

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("install_tunnel");
            self.tunnel_install_contexts
                .lock()
                .expect("tunnel install contexts lock")
                .push(context);
            if let Some(kind) = *self
                .tunnel_install_error
                .lock()
                .expect("tunnel install error lock")
            {
                return Err(BackendError::new(
                    kind,
                    "tunnel install reported a typed backend error",
                ));
            }
            if *self.awaiting_approval.lock().expect("approval lock") {
                Ok(TunnelInstallOutcome::AwaitingApproval)
            } else {
                Ok(TunnelInstallOutcome::Ready)
            }
        })
    }

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("cancel_tunnel_install");
            self.tunnel_cancel_contexts
                .lock()
                .expect("tunnel cancel contexts lock")
                .push(context);
            *self.native_status.lock().expect("native status lock") = NativeEngineStatus::Off;
            Ok(())
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("start_tunnel");
            self.tunnel_requests
                .lock()
                .expect("tunnel requests lock")
                .push(request.clone());
            tokio::time::sleep(Duration::from_millis(5)).await;
            if let Some(kind) = *self
                .tunnel_start_error
                .lock()
                .expect("tunnel start error lock")
            {
                return Err(BackendError::new(
                    kind,
                    "tunnel start reported a typed backend error",
                ));
            }
            let runtime = RuntimeIdentity {
                owner: EngineOwner::PacketTunnelSystemExtension,
                context: request.context,
                config_digest: request.config_digest,
                ready: true,
            };
            *self.native_status.lock().expect("native status lock") = NativeEngineStatus::Tunnel {
                runtime: runtime.clone(),
            };
            Ok(runtime)
        })
    }

    fn stop_tunnel(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operations lock")
                .push("stop_tunnel");
            self.tunnel_stop_contexts
                .lock()
                .expect("tunnel stop contexts lock")
                .push(context);
            if !*self
                .stop_leaves_owner_present
                .lock()
                .expect("stop leaves owner lock")
            {
                *self.native_status.lock().expect("native status lock") = NativeEngineStatus::Off;
            }
            Ok(())
        })
    }
}

pub(super) fn test_session() -> EngineSessionIdentity {
    EngineSessionIdentity {
        installation_id: "test-installation".to_owned(),
        config_epoch: 7,
    }
}

pub(super) fn coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_millis(20),
            initial_generation: 0,
        },
    )
}
