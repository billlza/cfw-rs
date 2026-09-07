use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineEvent;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::LiveStreams;
use crate::engine::{EngineMaintenanceLease, ManagedEngine};
use crate::window_state::WindowBoundsManager;

#[derive(Default)]
pub(crate) struct AppLifecycle {
    shared: Arc<LifecycleShared>,
    shutdown_maintenance: Mutex<Option<EngineMaintenanceLease>>,
}

#[derive(Default)]
struct LifecycleShared {
    owner: AtomicU8,
    handoff_status: Mutex<MigrationHandoffStatus>,
}

const LIFECYCLE_IDLE: u8 = 0;
const LIFECYCLE_SHUTDOWN: u8 = 1;
const LIFECYCLE_HANDOFF: u8 = 2;
const LIFECYCLE_EXIT_READY: u8 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum MigrationHandoffStatus {
    #[default]
    Idle,
    InProgress,
    Failed {
        code: &'static str,
        message: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationHandoffFailure {
    Admission,
    Operation,
    UnexpectedTaskEnd,
}

impl MigrationHandoffFailure {
    fn status(self) -> MigrationHandoffStatus {
        match self {
            Self::Admission => MigrationHandoffStatus::Failed {
                code: "migration_handoff_admission_failed",
                message: "The signed migration session could not be admitted. Review the migration log and retry.",
            },
            Self::Operation => MigrationHandoffStatus::Failed {
                code: "migration_handoff_failed",
                message: "The migration session did not complete. No legacy cutover was authorized; review the migration log and retry.",
            },
            Self::UnexpectedTaskEnd => MigrationHandoffStatus::Failed {
                code: "migration_handoff_task_failed",
                message: "Migration orchestration ended unexpectedly. No legacy cutover was authorized; review the application log before retrying.",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownAdmission {
    Started,
    AlreadyInProgress,
    ExitReady,
}

pub(crate) struct HandoffLifecycleLease {
    shared: Arc<LifecycleShared>,
    active: bool,
}

impl AppLifecycle {
    pub(crate) fn exit_ready(&self) -> bool {
        self.shared.owner.load(Ordering::Acquire) == LIFECYCLE_EXIT_READY
    }

    pub(crate) fn migration_handoff_status(&self) -> Result<MigrationHandoffStatus, String> {
        self.shared
            .handoff_status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "migration handoff lifecycle status lock failed".to_owned())
    }

    fn begin_shutdown(&self) -> Result<ShutdownAdmission, String> {
        match self.shared.owner.compare_exchange(
            LIFECYCLE_IDLE,
            LIFECYCLE_SHUTDOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(ShutdownAdmission::Started),
            Err(LIFECYCLE_SHUTDOWN) => Ok(ShutdownAdmission::AlreadyInProgress),
            Err(LIFECYCLE_EXIT_READY) => Ok(ShutdownAdmission::ExitReady),
            Err(owner) => Err(format!(
                "application shutdown cannot start while lifecycle is owned by {}",
                lifecycle_owner_name(owner)
            )),
        }
    }

    fn begin_handoff_lease(&self) -> Result<HandoffLifecycleLease, String> {
        self.shared.begin_handoff()?;
        Ok(HandoffLifecycleLease {
            shared: self.shared.clone(),
            active: true,
        })
    }

    fn reset_owner_after_failure(&self, expected: u8) -> Result<(), String> {
        self.shared.reset_owner_after_failure(expected)
    }

    fn mark_exit_ready(
        &self,
        expected_owner: u8,
        maintenance: EngineMaintenanceLease,
    ) -> Result<(), String> {
        let mut held = self
            .shutdown_maintenance
            .lock()
            .map_err(|_| "application shutdown maintenance lock failed".to_owned())?;
        if held.is_some() {
            return Err("application shutdown maintenance was already retained".into());
        }
        *held = Some(maintenance);
        match self.shared.owner.compare_exchange(
            expected_owner,
            LIFECYCLE_EXIT_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(owner) => {
                *held = None;
                Err(format!(
                    "application exit readiness expected {} but found {}",
                    lifecycle_owner_name(expected_owner),
                    lifecycle_owner_name(owner)
                ))
            }
        }
    }
}

impl LifecycleShared {
    fn begin_handoff(&self) -> Result<(), String> {
        let mut status = self
            .handoff_status
            .lock()
            .map_err(|_| "migration handoff lifecycle status lock failed".to_owned())?;
        self.owner
            .compare_exchange(
                LIFECYCLE_IDLE,
                LIFECYCLE_HANDOFF,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|owner| {
                format!(
                    "migration handoff cannot start while application lifecycle is owned by {}",
                    lifecycle_owner_name(owner)
                )
            })?;
        *status = MigrationHandoffStatus::InProgress;
        Ok(())
    }

    fn reset_owner_after_failure(&self, expected: u8) -> Result<(), String> {
        self.owner
            .compare_exchange(
                expected,
                LIFECYCLE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|owner| {
                format!(
                    "application lifecycle reset expected {} but found {}",
                    lifecycle_owner_name(expected),
                    lifecycle_owner_name(owner)
                )
            })
    }

    fn fail_handoff(&self, failure: MigrationHandoffFailure) -> Result<(), String> {
        let mut status = self
            .handoff_status
            .lock()
            .map_err(|_| "migration handoff lifecycle status lock failed".to_owned())?;
        self.reset_owner_after_failure(LIFECYCLE_HANDOFF)?;
        *status = failure.status();
        Ok(())
    }
}

fn lifecycle_owner_name(owner: u8) -> &'static str {
    match owner {
        LIFECYCLE_IDLE => "idle",
        LIFECYCLE_SHUTDOWN => "shutdown",
        LIFECYCLE_HANDOFF => "migration handoff",
        LIFECYCLE_EXIT_READY => "exit readiness",
        _ => "an invalid lifecycle state",
    }
}

pub(crate) fn begin_handoff_lifecycle(app: &AppHandle) -> Result<HandoffLifecycleLease, String> {
    app.state::<AppLifecycle>().begin_handoff_lease()
}

pub(crate) async fn prepare_handoff_exit(
    app: AppHandle,
    lifecycle_lease: &mut HandoffLifecycleLease,
) -> Result<(), String> {
    flush_window_bounds_for_exit(&app);
    let lifecycle = app.state::<AppLifecycle>();
    let outcome = match app.state::<ManagedEngine>().shutdown_to_completion().await {
        Ok(outcome) => outcome,
        Err(error) => {
            return Err(format!(
                "dashboard shutdown admission failed; migration handoff was cancelled: {error}"
            ));
        }
    };
    let (result, maintenance) = outcome.into_parts();
    match result {
        Ok(_) => {
            if let Err(error) = lifecycle.mark_exit_ready(LIFECYCLE_HANDOFF, maintenance) {
                return Err(format!(
                    "dashboard shutdown finalization failed; migration handoff was cancelled: {error}"
                ));
            }
            lifecycle_lease.active = false;
            app.state::<LiveStreams>().stop_all();
            Ok(())
        }
        Err(error) => Err(format!(
            "dashboard shutdown failed; migration handoff was cancelled: {error}"
        )),
    }
}

fn finish_exit(
    app: &AppHandle,
    maintenance: EngineMaintenanceLease,
    exit_code: i32,
) -> Result<(), String> {
    app.state::<AppLifecycle>()
        .mark_exit_ready(LIFECYCLE_SHUTDOWN, maintenance)?;
    app.state::<LiveStreams>().stop_all();
    app.exit(exit_code);
    Ok(())
}

fn reset_shutdown_after_failure(app: &AppHandle) {
    if let Err(error) = app
        .state::<AppLifecycle>()
        .reset_owner_after_failure(LIFECYCLE_SHUTDOWN)
    {
        emit_shutdown_error(app, "shutdown_lifecycle_reset_failed", error);
    }
}

fn emit_shutdown_error(app: &AppHandle, code: &str, message: String) {
    if let Err(emit_error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(code, message),
    ) {
        eprintln!("failed to publish shutdown error: {emit_error}");
    }
}

fn start_shutdown(app: AppHandle, exit_code: i32) -> Result<(), String> {
    let lifecycle = app.state::<AppLifecycle>();
    match lifecycle.begin_shutdown() {
        Ok(ShutdownAdmission::Started) => {}
        Ok(ShutdownAdmission::AlreadyInProgress) => return Ok(()),
        Ok(ShutdownAdmission::ExitReady) => {
            app.exit(exit_code);
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    flush_window_bounds_for_exit(&app);

    tauri::async_runtime::spawn(async move {
        let coordinator = app.state::<ManagedEngine>().coordinator.clone();
        let shutdown = app.state::<ManagedEngine>().shutdown_to_completion().await;
        match shutdown {
            Ok(outcome) => {
                let (result, maintenance) = outcome.into_parts();
                if let Err(error) = result {
                    let safely_off =
                        coordinator.snapshot().state == cfw_engine_api::EngineState::Off;
                    emit_shutdown_error(&app, "shutdown_failed", error);
                    if !safely_off {
                        reset_shutdown_after_failure(&app);
                        return;
                    }
                }
                if let Err(error) = finish_exit(&app, maintenance, exit_code) {
                    emit_shutdown_error(&app, "shutdown_finalization_failed", error);
                    reset_shutdown_after_failure(&app);
                }
            }
            Err(error) => {
                let safely_off = coordinator.snapshot().state == cfw_engine_api::EngineState::Off;
                emit_shutdown_error(
                    &app,
                    "shutdown_admission_failed",
                    format!("{error}; engine currently Off: {safely_off}"),
                );
                reset_shutdown_after_failure(&app);
            }
        }
    });
    Ok(())
}

fn flush_window_bounds_for_exit(app: &AppHandle) {
    if let Err(error) = app.state::<WindowBoundsManager>().flush(app) {
        emit_shutdown_error(app, "window_bounds_flush_failed", error);
    }
}

pub(crate) fn request_shutdown(app: AppHandle, exit_code: i32) -> Result<(), String> {
    // Repeated requests for the same shutdown are idempotent. A migration
    // handoff is a different lifecycle owner and remains an explicit rejection.
    start_shutdown(app, exit_code)
}

#[tauri::command]
pub(crate) fn quit_app(app: AppHandle) -> Result<(), String> {
    request_shutdown(app, 0)
}

impl HandoffLifecycleLease {
    pub(crate) fn fail(&mut self, failure: MigrationHandoffFailure) -> Result<(), String> {
        self.shared.fail_handoff(failure)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for HandoffLifecycleLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(error) = self
            .shared
            .fail_handoff(MigrationHandoffFailure::UnexpectedTaskEnd)
        {
            eprintln!("failed to publish unexpected migration handoff termination: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shutdown_path_uses_the_admitted_completion_boundary() {
        let source = include_str!("lifecycle.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production lifecycle source");
        assert_eq!(source.matches("shutdown_to_completion().await").count(), 2);
        assert!(!source.contains("coordinator.shutdown().await"));
        let quit = source
            .split("pub(crate) fn quit_app")
            .nth(1)
            .expect("quit command")
            .split('}')
            .next()
            .expect("quit command body");
        assert!(quit.contains("request_shutdown(app, 0)"));
        assert!(!quit.contains(".await"));
    }

    #[test]
    fn handoff_failure_is_queryable_and_retry_replaces_it_with_in_progress() {
        let lifecycle = AppLifecycle::default();
        let mut lease = lifecycle.begin_handoff_lease().expect("handoff admission");
        assert_eq!(
            lifecycle.migration_handoff_status().expect("status"),
            MigrationHandoffStatus::InProgress
        );
        assert!(lifecycle.begin_shutdown().is_err());
        assert!(lifecycle.begin_handoff_lease().is_err());
        lease
            .fail(MigrationHandoffFailure::Operation)
            .expect("handoff failure");

        let failure = lifecycle
            .migration_handoff_status()
            .expect("failure status");
        assert_eq!(failure, MigrationHandoffFailure::Operation.status());
        let encoded = serde_json::to_string(&failure).expect("serialize failure");
        assert!(encoded.len() < 512, "handoff status must remain bounded");
        assert!(!encoded.contains("/Users/"));

        let retry = lifecycle.begin_handoff_lease().expect("handoff retry");
        assert_eq!(
            lifecycle.migration_handoff_status().expect("retry status"),
            MigrationHandoffStatus::InProgress
        );
        drop(retry);
    }

    #[test]
    fn dropped_handoff_lease_records_unexpected_failure_and_restores_admission() {
        let lifecycle = AppLifecycle::default();
        drop(lifecycle.begin_handoff_lease().expect("handoff admission"));
        assert_eq!(
            lifecycle
                .migration_handoff_status()
                .expect("failure status"),
            MigrationHandoffFailure::UnexpectedTaskEnd.status()
        );
        let retry = lifecycle
            .begin_handoff_lease()
            .expect("retry after task end");
        drop(retry);
    }

    #[test]
    fn shutdown_is_idempotent_but_remains_mutually_exclusive_with_handoff() {
        let lifecycle = AppLifecycle::default();
        assert_eq!(
            lifecycle.begin_shutdown().expect("shutdown admission"),
            ShutdownAdmission::Started
        );
        assert_eq!(
            lifecycle.begin_shutdown().expect("idempotent shutdown"),
            ShutdownAdmission::AlreadyInProgress
        );
        assert!(lifecycle.begin_handoff_lease().is_err());
        lifecycle
            .reset_owner_after_failure(LIFECYCLE_SHUTDOWN)
            .expect("shutdown rollback");
        let handoff = lifecycle
            .begin_handoff_lease()
            .expect("handoff after rollback");
        assert!(lifecycle.begin_shutdown().is_err());
        drop(handoff);
    }

    #[test]
    fn simultaneous_handoff_and_shutdown_admit_exactly_one_owner() {
        for _ in 0..64 {
            let lifecycle = Arc::new(AppLifecycle::default());
            let start = Arc::new(std::sync::Barrier::new(3));
            let finish = Arc::new(std::sync::Barrier::new(3));

            let handoff_lifecycle = lifecycle.clone();
            let handoff_start = start.clone();
            let handoff_finish = finish.clone();
            let handoff = std::thread::spawn(move || {
                handoff_start.wait();
                let lease = handoff_lifecycle.begin_handoff_lease().ok();
                handoff_finish.wait();
                let admitted = lease.is_some();
                drop(lease);
                admitted
            });

            let shutdown_lifecycle = lifecycle.clone();
            let shutdown_start = start.clone();
            let shutdown_finish = finish.clone();
            let shutdown = std::thread::spawn(move || {
                shutdown_start.wait();
                let admitted = matches!(
                    shutdown_lifecycle.begin_shutdown(),
                    Ok(ShutdownAdmission::Started)
                );
                shutdown_finish.wait();
                admitted
            });

            start.wait();
            finish.wait();
            let admitted = [
                handoff.join().expect("handoff racer"),
                shutdown.join().expect("shutdown racer"),
            ];
            assert_eq!(admitted.into_iter().filter(|admitted| *admitted).count(), 1);
        }
    }
}
