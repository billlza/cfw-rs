use std::fs;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext, EngineMode,
    EngineOwner, EngineRuntimePlatform, EngineSessionIdentity, EngineSnapshot, EngineStartRequest,
    EngineState, NativeEngineStatus, RuntimeIdentity, TunnelInstallOutcome,
};
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::maintenance::{
    EngineMaintenanceError, EngineMaintenanceGate, EngineModeChangeIntent, MAX_PENDING_MODE_CHANGES,
};
use super::mode_switch::set_mode_with_endpoint_rebind;
use super::{
    ActiveControllerBinding, EngineEndpointBinding, StagedEndpointRebind, commit_endpoint_rebind,
    engine_snapshot_is_off, read_active_controller_access, record_endpoint_runtime,
    selected_profile_for_mode,
};
use crate::engine::endpoints::{CANDIDATE_COUNT, EndpointCandidateCursor};
use cfw_application::{EngineControllerAccess, EngineModeCoordinator};

struct EndpointRetryBackend {
    conflicts_before_success: usize,
    tunnel_failures_before_success: usize,
    tunnel_failure: BackendErrorKind,
    tunnel_cleanup_error: Option<BackendErrorKind>,
    tunnel_off_proof_error: bool,
    /// Fails a System Proxy start whose configuration downloads rule sets,
    /// as libbox does when they cannot be fetched before readiness.
    rule_set_start_failure: Option<BackendErrorKind>,
    starts: Mutex<Vec<(u64, u16)>>,
    stops: AtomicUsize,
    status: Mutex<NativeEngineStatus>,
}

impl EndpointRetryBackend {
    fn new(conflicts_before_success: usize) -> Self {
        Self {
            conflicts_before_success,
            tunnel_failures_before_success: 0,
            tunnel_failure: BackendErrorKind::TicketExpired,
            tunnel_cleanup_error: None,
            tunnel_off_proof_error: false,
            rule_set_start_failure: None,
            starts: Mutex::new(Vec::new()),
            stops: AtomicUsize::new(0),
            status: Mutex::new(NativeEngineStatus::Off),
        }
    }

    fn starts(&self) -> Vec<(u64, u16)> {
        self.starts.lock().expect("starts lock").clone()
    }
}

impl EngineBackend for EndpointRetryBackend {
    fn runtime_platform(&self) -> cfw_engine_api::EngineRuntimePlatform {
        cfw_engine_api::EngineRuntimePlatform::MacOs
    }

    fn check_configuration(&self, _request: EngineStartRequest) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_local_proxy(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            let result = self.start_system_proxy(request).await;
            let mut status = self.status.lock().expect("status lock");
            if let NativeEngineStatus::SystemProxy { runtime } = &*status {
                *status = NativeEngineStatus::LocalProxy {
                    runtime: runtime.clone(),
                };
            }
            result
        })
    }

    fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        self.stop_system_proxy(context)
    }

    fn authorize_tunnel_configuration(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move {
            if self.tunnel_off_proof_error && self.stops.load(Ordering::Acquire) > 0 {
                return Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "Off cannot be observed",
                ));
            }
            Ok(self.status.lock().expect("status lock").clone())
        })
    }

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            let configuration: serde_json::Value = serde_json::from_str(&request.config_json)
                .map_err(|error| {
                    BackendError::new(BackendErrorKind::Internal, error.to_string())
                })?;
            let mixed_port = configuration["inbounds"]
                .as_array()
                .and_then(|inbounds| inbounds.iter().find(|inbound| inbound["type"] == "mixed"))
                .and_then(|inbound| inbound["listen_port"].as_u64())
                .and_then(|port| u16::try_from(port).ok())
                .ok_or_else(|| {
                    BackendError::new(
                        BackendErrorKind::Internal,
                        "projected mixed endpoint is missing",
                    )
                })?;
            let attempt = {
                let mut starts = self.starts.lock().expect("starts lock");
                starts.push((request.context.generation, mixed_port));
                starts.len()
            };
            if attempt <= self.conflicts_before_success {
                return Err(BackendError::new(
                    BackendErrorKind::MixedEndpointInUse,
                    "injected mixed endpoint conflict",
                ));
            }
            if let Some(kind) = self.rule_set_start_failure
                && configuration["route"]["rule_set"]
                    .as_array()
                    .is_some_and(|rule_sets| !rule_sets.is_empty())
            {
                return Err(BackendError::new(
                    kind,
                    "initialize rule-set[cfw-geosite-cn]: download failed",
                ));
            }
            let runtime = RuntimeIdentity {
                owner: EngineOwner::ProxyAgent,
                context: request.context,
                config_digest: request.config_digest,
                ready: true,
            };
            *self.status.lock().expect("status lock") = NativeEngineStatus::SystemProxy {
                runtime: runtime.clone(),
            };
            Ok(runtime)
        })
    }

    fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async move {
            self.stops.fetch_add(1, Ordering::AcqRel);
            *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
            Ok(())
        })
    }

    fn install_tunnel(
        &self,
        _context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(async { Ok(TunnelInstallOutcome::Ready) })
    }

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            let attempt = {
                let mut starts = self.starts.lock().expect("starts lock");
                starts.push((request.context.generation, 0));
                starts.len()
            };
            if attempt <= self.tunnel_failures_before_success {
                return Err(BackendError::new(
                    self.tunnel_failure,
                    "injected Tunnel start failure",
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
            self.stops.fetch_add(1, Ordering::AcqRel);
            if let Some(error) = self.tunnel_cleanup_error {
                return Err(BackendError::new(error, "injected cleanup failure"));
            }
            *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
            Ok(())
        })
    }
}

fn endpoint_retry_coordinator(backend: Arc<EndpointRetryBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn(
        backend,
        EngineSessionIdentity {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
        },
    )
}

fn endpoint_binding(settings: EngineSettings) -> EngineEndpointBinding {
    EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(settings.clone()).expect("controller"),
        cursor: EndpointCandidateCursor::from_persisted(settings).expect("cursor"),
        active: None,
    }
}

#[path = "tests/runtime_settings.rs"]
mod runtime_settings;

#[path = "tests/ticket_retry.rs"]
mod ticket_retry;

#[path = "tests/controller_binding.rs"]
mod controller_binding;

#[path = "tests/endpoint_retry.rs"]
mod endpoint_retry;

#[path = "tests/mode_profile.rs"]
mod mode_profile;

#[path = "tests/mode_queue.rs"]
mod mode_queue;

#[path = "tests/restoration.rs"]
mod restoration;
