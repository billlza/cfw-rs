use std::fs;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext, EngineMode,
    EngineOwner, EngineSessionIdentity, EngineSnapshot, EngineStartRequest, EngineState,
    NativeEngineStatus, RuntimeIdentity, TunnelInstallOutcome,
};
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::maintenance::{
    EngineMaintenanceError, EngineMaintenanceGate, EngineModeChangeIntent, MAX_PENDING_MODE_CHANGES,
};
use super::{
    ActiveControllerBinding, EngineEndpointBinding, StagedEndpointRebind, commit_endpoint_rebind,
    read_active_controller_access, record_endpoint_runtime, selected_profile_for_mode,
    set_mode_with_endpoint_rebind,
};
use crate::engine::endpoints::{CANDIDATE_COUNT, EndpointCandidateCursor};
use cfw_application::{EngineControllerAccess, EngineModeCoordinator};

#[tokio::test]
async fn maintenance_rejects_queued_off_change_and_blocks_every_renderer_mode() {
    let gate = EngineMaintenanceGate::default();
    let prior_change = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
        .await
        .expect("initial admission");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(prior_change);
    let maintenance = gate
        .reserve_if_idle()
        .expect("idle maintenance reservation");

    for mode in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert!(matches!(
            gate.begin_mode_change(EngineModeChangeIntent::Set(mode))
                .await,
            Err(EngineMaintenanceError::AlreadyActive)
        ));
    }
    drop(maintenance);
    gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("released");
}

#[tokio::test]
async fn queued_mode_changes_are_serial_and_visible_to_maintenance() {
    let gate = EngineMaintenanceGate::default();
    let first_change = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("mode change admission");
    let second_change = gate.begin_mode_change(EngineModeChangeIntent::ReapplyCurrent);
    tokio::pin!(second_change);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut second_change)
            .await
            .is_err(),
        "a second mutation must wait for the first response"
    );
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(first_change);
    let second_change = tokio::time::timeout(Duration::from_secs(1), &mut second_change)
        .await
        .expect("queued mutation must resume")
        .expect("queued mutation admission");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(second_change);
    let maintenance = gate.reserve_if_idle().expect("idle admission");
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::SystemProxy))
            .await,
        Err(EngineMaintenanceError::AlreadyActive)
    ));
    drop(maintenance);
}

#[tokio::test]
async fn queued_current_reapply_reads_off_only_after_prior_off_releases() {
    let gate = EngineMaintenanceGate::default();
    let desired_mode = Arc::new(std::sync::Mutex::new(EngineMode::Tunnel));
    let off = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
        .await
        .expect("Off admission");
    let current_mode = desired_mode.clone();
    let queued_reapply = async {
        let lease = gate
            .begin_mode_change(EngineModeChangeIntent::ReapplyCurrent)
            .await
            .expect("current-mode admission");
        let observed = *current_mode.lock().expect("desired mode lock");
        (observed, lease)
    };
    tokio::pin!(queued_reapply);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut queued_reapply)
            .await
            .is_err(),
        "reapply must wait behind the prior Off intent"
    );

    *desired_mode.lock().expect("desired mode lock") = EngineMode::Off;
    drop(off);
    let (observed, reapply) = tokio::time::timeout(Duration::from_secs(1), &mut queued_reapply)
        .await
        .expect("queued reapply resumes");
    assert_eq!(observed, EngineMode::Off);
    drop(reapply);
}

#[tokio::test]
async fn mode_change_queue_is_bounded_and_cancelled_waiters_release_capacity() {
    let gate = EngineMaintenanceGate::default();
    let first = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("first mode mutation");
    let mut queued = Vec::new();
    for _ in 1..MAX_PENDING_MODE_CHANGES {
        let mut pending =
            Box::pin(gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel)));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), pending.as_mut())
                .await
                .is_err(),
            "a queued mutation cannot bypass the held serial permit"
        );
        queued.push(pending);
    }
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
            .await,
        Err(EngineMaintenanceError::QueueFull)
    ));

    drop(queued);
    drop(first);
    let maintenance = gate
        .reserve_if_idle()
        .expect("cancelled waiters release their registrations");
    drop(maintenance);
}

#[tokio::test]
async fn caller_cancellation_cannot_release_an_accepted_mode_operation() {
    let gate = EngineMaintenanceGate::default();
    let lease = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("mode mutation");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let operation_started = started.clone();
    let operation_release = release.clone();
    let response = lease.run_to_completion(async move {
        operation_started.notify_one();
        operation_release.notified().await;
    });
    started.notified().await;
    drop(response);

    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    release.notify_one();
    let maintenance = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match gate.reserve_if_idle() {
                Ok(lease) => break lease,
                Err(EngineMaintenanceError::ModeChangeActive) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected maintenance error: {error}"),
            }
        }
    })
    .await
    .expect("accepted operation must eventually release its lease");
    drop(maintenance);
}

#[tokio::test]
async fn shutdown_maintenance_survives_caller_cancellation_and_blocks_all_modes() {
    let gate = EngineMaintenanceGate::default();
    let shutdown = gate
        .reserve_if_idle()
        .expect("exclusive shutdown admission");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let operation_started = started.clone();
    let operation_release = release.clone();
    let response = shutdown.run_to_completion(async move {
        operation_started.notify_one();
        operation_release.notified().await;
    });
    started.notified().await;
    drop(response);

    for mode in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert!(matches!(
            gate.begin_mode_change(EngineModeChangeIntent::Set(mode))
                .await,
            Err(EngineMaintenanceError::AlreadyActive)
        ));
    }
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::AlreadyActive)
    ));

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match gate
                .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
                .await
            {
                Ok(lease) => break lease,
                Err(EngineMaintenanceError::AlreadyActive) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected mode admission error: {error}"),
            }
        }
    })
    .await
    .expect("completed shutdown task releases its dropped response guard");
}

#[test]
fn non_off_mode_uses_the_digest_bound_selected_profile() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    let expected = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"shadowsocks","tag":"selected","server":"proxy.example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","credential_ref":{"id":"34db18b6-9903-4e9f-8854-15648e19e4f3","kind":"shadowsocks_password"}}],"route":{"final":"selected"}}"#,
    )
    .expect("typed profile");
    let imported = repository
        .import(Some("Selected"), &expected)
        .expect("import");
    repository.select(&imported.id).expect("select");
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy).expect("selected"),
        (imported.id.clone(), expected)
    );
}

#[test]
fn non_off_mode_rejects_absent_or_stale_selection_but_off_remains_available() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::Tunnel),
        Err(ProfileError::NoSelectedProfile)
    ));
    let imported = repository
        .import(Some("Selected"), &ValidatedSingBoxProfile::direct())
        .expect("import");
    repository.select(&imported.id).expect("select");
    fs::remove_file(
        root.path()
            .join("profiles")
            .join(format!("{}.profile.json", imported.id)),
    )
    .expect("remove selected profile");
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::Off).expect("Off profile"),
        (
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
        )
    );
}

#[test]
fn controller_access_is_bound_to_the_exact_active_generation_and_digest() {
    let settings = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(settings.clone()).expect("controller"),
        cursor: EndpointCandidateCursor::from_persisted(settings).expect("cursor"),
        active: None,
    });
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_err());

    let active = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::ProxyAgent,
                context: EngineCommandContext {
                    installation_id: "installation".into(),
                    config_epoch: 1,
                    generation: 7,
                },
                config_digest: "digest-a".into(),
                ready: true,
            },
        },
        generation: 7,
        config_digest: Some("digest-a".into()),
    };
    record_endpoint_runtime(&endpoints, &active).expect("bind active controller");
    assert!(read_active_controller_access(&endpoints, 7, "digest-a").is_ok());
    assert!(read_active_controller_access(&endpoints, 8, "digest-a").is_err());
    assert!(read_active_controller_access(&endpoints, 7, "digest-b").is_err());

    let expected = endpoints.read().expect("endpoint lock").clone();
    let mut replacement_settings = expected.controller.settings().clone();
    replacement_settings.controller_port += 1;
    let replacement = EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(replacement_settings.clone())
            .expect("replacement controller"),
        cursor: EndpointCandidateCursor::from_persisted(replacement_settings)
            .expect("replacement cursor"),
        active: None,
    };
    let staged = StagedEndpointRebind {
        expected: expected.clone(),
        replacement: replacement.clone(),
    };
    commit_endpoint_rebind(&endpoints, staged).expect("commit endpoint CAS");
    assert!(
        read_active_controller_access(&endpoints, 7, "digest-a").is_err(),
        "an endpoint rebind invalidates the prior active identity"
    );
    assert!(
        commit_endpoint_rebind(
            &endpoints,
            StagedEndpointRebind {
                expected,
                replacement,
            },
        )
        .is_err(),
        "a stale staged endpoint binding cannot overwrite current state"
    );
}

#[test]
fn invalid_active_snapshot_cannot_bind_controller_access() {
    let settings = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(settings.clone()).expect("controller"),
        cursor: EndpointCandidateCursor::from_persisted(settings).expect("cursor"),
        active: Some(ActiveControllerBinding {
            generation: 1,
            config_digest: "prior".into(),
        }),
    });
    let invalid = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::PacketTunnelSystemExtension,
                context: EngineCommandContext {
                    installation_id: "installation".into(),
                    config_epoch: 1,
                    generation: 2,
                },
                config_digest: "digest".into(),
                ready: true,
            },
        },
        generation: 2,
        config_digest: Some("digest".into()),
    };
    assert!(record_endpoint_runtime(&endpoints, &invalid).is_err());
    assert!(read_active_controller_access(&endpoints, 1, "prior").is_ok());
}

struct EndpointRetryBackend {
    conflicts_before_success: usize,
    starts: Mutex<Vec<(u64, u16)>>,
    stops: AtomicUsize,
    status: Mutex<NativeEngineStatus>,
}

impl EndpointRetryBackend {
    fn new(conflicts_before_success: usize) -> Self {
        Self {
            conflicts_before_success,
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
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async move { Ok(self.status.lock().expect("status lock").clone()) })
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
        Box::pin(async {
            Err(BackendError::new(
                BackendErrorKind::Internal,
                "tunnel is outside the endpoint retry fixture",
            ))
        })
    }

    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_tunnel(&self, _request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        Box::pin(async {
            Err(BackendError::new(
                BackendErrorKind::Internal,
                "tunnel is outside the endpoint retry fixture",
            ))
        })
    }

    fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
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

fn advance_test_mixed_endpoint(
    endpoints: &std::sync::RwLock<EngineEndpointBinding>,
    conflict: BackendErrorKind,
) -> Result<(), String> {
    if conflict != BackendErrorKind::MixedEndpointInUse {
        return Err("unexpected endpoint conflict role".into());
    }
    let mut current = endpoints
        .write()
        .map_err(|_| "endpoint test lock is poisoned".to_owned())?;
    let mut settings = current.controller.settings().clone();
    let maximum = EngineSettings::default().mixed_port + (CANDIDATE_COUNT as u16 - 1);
    if settings.mixed_port >= maximum {
        return Err("mixed endpoint candidates are exhausted".into());
    }
    settings.mixed_port += 1;
    *current = endpoint_binding(settings);
    Ok(())
}

#[tokio::test]
async fn mode_retry_loop_advances_endpoints_and_generation_after_exact_off() {
    let backend = Arc::new(EndpointRetryBackend::new(2));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));

    let snapshot = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::SystemProxy,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        &ValidatedSingBoxProfile::direct(),
        |conflict| advance_test_mixed_endpoint(&endpoints, conflict),
    )
    .await
    .expect("third bounded endpoint starts");

    let base_port = EngineSettings::default().mixed_port;
    assert_eq!(
        backend.starts(),
        vec![(1, base_port), (2, base_port + 1), (3, base_port + 2)]
    );
    assert_eq!(backend.stops.load(Ordering::Acquire), 2);
    assert_eq!(snapshot.generation, 3);
    assert!(matches!(snapshot.state, EngineState::ProxyActive { .. }));
    assert!(
        read_active_controller_access(
            &endpoints,
            3,
            snapshot.config_digest.as_deref().expect("digest")
        )
        .is_ok()
    );
}

#[tokio::test]
async fn mode_retry_loop_stops_after_the_last_bounded_endpoint() {
    let backend = Arc::new(EndpointRetryBackend::new(CANDIDATE_COUNT + 1));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));

    let error = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::SystemProxy,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        &ValidatedSingBoxProfile::direct(),
        |conflict| advance_test_mixed_endpoint(&endpoints, conflict),
    )
    .await
    .expect_err("the ninth endpoint attempt is forbidden");

    assert_eq!(error, "mixed endpoint candidates are exhausted");
    let starts = backend.starts();
    assert_eq!(starts.len(), CANDIDATE_COUNT);
    assert_eq!(backend.stops.load(Ordering::Acquire), CANDIDATE_COUNT);
    assert_eq!(
        starts
            .iter()
            .map(|(generation, _)| *generation)
            .collect::<Vec<_>>(),
        (1..=CANDIDATE_COUNT as u64).collect::<Vec<_>>()
    );
    assert!(starts.windows(2).all(|pair| pair[1].1 == pair[0].1 + 1));
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
}
