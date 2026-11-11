use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
    identity_recovery_exit: AtomicBool,
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
const LIFECYCLE_UPDATE: u8 = 4;
const LIFECYCLE_IDENTITY_RECOVERY: u8 = 5;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum MigrationHandoffStatus {
    #[default]
    Idle,
    #[cfg(target_os = "macos")]
    InProgress,
    #[cfg(target_os = "macos")]
    Failed {
        code: &'static str,
        message: &'static str,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationHandoffFailure {
    Admission,
    Operation,
    UnexpectedTaskEnd,
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
pub(crate) struct HandoffLifecycleLease {
    shared: Arc<LifecycleShared>,
    active: bool,
}

/// Exclusive ownership during a maintenance operation that requires process
/// exit. Dropping it before exit is prepared restores normal operation.
pub(crate) struct MaintenanceLifecycleLease {
    shared: Arc<LifecycleShared>,
    owner: u8,
    active: bool,
}

impl AppLifecycle {
    pub(crate) fn startup_work_allowed(&self) -> bool {
        self.shared.owner.load(Ordering::Acquire) == LIFECYCLE_IDLE
    }

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

    fn mark_uninitialized_exit_ready(&self) -> Result<(), String> {
        self.shared
            .owner
            .compare_exchange(
                LIFECYCLE_SHUTDOWN,
                LIFECYCLE_EXIT_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| "startup shutdown lost lifecycle ownership".into())
    }

    #[cfg(target_os = "macos")]
    fn begin_handoff_lease(&self) -> Result<HandoffLifecycleLease, String> {
        self.shared.begin_handoff()?;
        Ok(HandoffLifecycleLease {
            shared: self.shared.clone(),
            active: true,
        })
    }

    fn begin_maintenance_lease(&self, owner: u8) -> Result<MaintenanceLifecycleLease, String> {
        self.shared
            .owner
            .compare_exchange(LIFECYCLE_IDLE, owner, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|current| {
                format!(
                    "{} cannot start while application lifecycle is owned by {}",
                    lifecycle_owner_name(owner),
                    lifecycle_owner_name(current)
                )
            })?;
        Ok(MaintenanceLifecycleLease {
            shared: self.shared.clone(),
            owner,
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
    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
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
        LIFECYCLE_UPDATE => "update installation",
        LIFECYCLE_IDENTITY_RECOVERY => "installation identity recovery",
        _ => "an invalid lifecycle state",
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn begin_handoff_lifecycle(app: &AppHandle) -> Result<HandoffLifecycleLease, String> {
    app.state::<AppLifecycle>().begin_handoff_lease()
}

#[cfg(target_os = "macos")]
pub(crate) async fn prepare_handoff_exit(
    app: AppHandle,
    lifecycle_lease: &mut HandoffLifecycleLease,
) -> Result<(), String> {
    let shutdown_warning = prepare_owned_exit(&app, LIFECYCLE_HANDOFF)
        .await
        .map_err(|error| match error {
            OwnedExitError::Admission(error) => format!(
                "dashboard shutdown admission failed; migration handoff was cancelled: {error}"
            ),
            OwnedExitError::Shutdown(error) => {
                format!("dashboard shutdown failed; migration handoff was cancelled: {error}")
            }
            OwnedExitError::Finalization(error) => format!(
                "dashboard shutdown finalization failed; migration handoff was cancelled: {error}"
            ),
        })?;
    if let Some(warning) = shutdown_warning {
        eprintln!("dashboard shutdown reported an error with the engine Off: {warning}");
    }
    lifecycle_lease.active = false;
    Ok(())
}

pub(crate) fn begin_update_lifecycle(app: &AppHandle) -> Result<MaintenanceLifecycleLease, String> {
    app.state::<AppLifecycle>()
        .begin_maintenance_lease(LIFECYCLE_UPDATE)
}

/// Stops networking for an update hand-off. On success the engine is Off, no
/// mode change can queue behind it, and the process may only exit. A shutdown
/// error reported with the engine Off is returned for the caller's record.
pub(crate) async fn prepare_update_exit(
    app: &AppHandle,
    lifecycle_lease: &mut MaintenanceLifecycleLease,
) -> Result<Option<String>, String> {
    let shutdown_warning = prepare_owned_exit(app, LIFECYCLE_UPDATE)
        .await
        .map_err(|error| match error {
            OwnedExitError::Admission(error)
            | OwnedExitError::Shutdown(error)
            | OwnedExitError::Finalization(error) => error,
        })?;
    lifecycle_lease.active = false;
    Ok(shutdown_warning)
}

#[cfg(target_os = "macos")]
pub(crate) fn begin_identity_recovery(
    app: &AppHandle,
) -> Result<MaintenanceLifecycleLease, String> {
    app.state::<AppLifecycle>()
        .begin_maintenance_lease(LIFECYCLE_IDENTITY_RECOVERY)
}

/// Called after authentication, before any Keychain mutation. The already-held
/// Off maintenance reservation remains in AppLifecycle even if the write fails
/// or its caller disappears. This process can never start with a stale session.
#[cfg(target_os = "macos")]
pub(crate) async fn prepare_identity_recovery_exit(
    app: &AppHandle,
    lease: &mut MaintenanceLifecycleLease,
    maintenance: EngineMaintenanceLease,
) -> Result<(), String> {
    if lease.owner != LIFECYCLE_IDENTITY_RECOVERY || !lease.active {
        return Err("installation recovery lost its lifecycle reservation".into());
    }
    if !app.state::<ManagedEngine>().is_off_under(&maintenance) {
        return Err("stop the engine before recovering its installation identity".into());
    }
    flush_window_bounds_for_exit(app).await;
    let lifecycle = app.state::<AppLifecycle>();
    lifecycle.mark_exit_ready(LIFECYCLE_IDENTITY_RECOVERY, maintenance)?;
    lease.active = false;
    lifecycle
        .identity_recovery_exit
        .store(true, Ordering::Release);
    app.state::<LiveStreams>().stop_all();
    if let Err(error) = app
        .state::<crate::commands::ManagedProviders>()
        .stop_refresh()
    {
        eprintln!("provider refresh shutdown failed during identity recovery: {error}");
    }
    Ok(())
}

pub(crate) fn identity_recovery_requires_restart(app: &AppHandle) -> bool {
    let lifecycle = app.state::<AppLifecycle>();
    lifecycle.exit_ready() && lifecycle.identity_recovery_exit.load(Ordering::Acquire)
}

enum OwnedExitError {
    Admission(String),
    Shutdown(String),
    Finalization(String),
}

/// Converges the engine to Off for a lifecycle owner other than ordinary
/// shutdown and marks the process ready to exit under that owner.
///
/// As for an ordinary quit, a shutdown that reports an error although the
/// engine is Off has reached its goal: the exit goes ahead and the error is
/// returned for the owner's record, instead of leaving the application
/// running with its networking stopped.
async fn prepare_owned_exit(app: &AppHandle, owner: u8) -> Result<Option<String>, OwnedExitError> {
    flush_window_bounds_for_exit(app).await;
    let lifecycle = app.state::<AppLifecycle>();
    let coordinator = app.state::<ManagedEngine>().coordinator.clone();
    let shutdown = app.state::<ManagedEngine>().shutdown_to_completion().await;
    let (result, maintenance) = shutdown.map_err(OwnedExitError::Admission)?.into_parts();
    let shutdown_warning = match result {
        Ok(_) => None,
        Err(error) => {
            let safely_off = coordinator.snapshot().state == cfw_engine_api::EngineState::Off;
            if !safely_off {
                return Err(OwnedExitError::Shutdown(error));
            }
            Some(error)
        }
    };
    lifecycle
        .mark_exit_ready(owner, maintenance)
        .map_err(OwnedExitError::Finalization)?;
    app.state::<LiveStreams>().stop_all();
    if let Err(error) = app
        .state::<crate::commands::ManagedProviders>()
        .stop_refresh()
    {
        eprintln!("provider refresh shutdown failed: {error}");
    }
    Ok(shutdown_warning)
}

fn finish_exit(
    app: &AppHandle,
    maintenance: EngineMaintenanceLease,
    exit_code: i32,
) -> Result<(), String> {
    app.state::<AppLifecycle>()
        .mark_exit_ready(LIFECYCLE_SHUTDOWN, maintenance)?;
    app.state::<LiveStreams>().stop_all();
    if let Err(error) = app
        .state::<crate::commands::ManagedProviders>()
        .stop_refresh()
    {
        eprintln!("provider refresh shutdown failed: {error}");
    }
    crate::diagnostics::record(
        app,
        cfw_core::DiagnosticTopic::Startup,
        "shutdown_dispatch_exit",
        "",
    );
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
    crate::diagnostics::record(app, cfw_core::DiagnosticTopic::Network, code, &message);
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
        Ok(ShutdownAdmission::Started) => {
            crate::diagnostics::record(
                &app,
                cfw_core::DiagnosticTopic::Startup,
                "shutdown_started",
                "",
            );
        }
        Ok(ShutdownAdmission::AlreadyInProgress) => return Ok(()),
        Ok(ShutdownAdmission::ExitReady) => {
            app.exit(exit_code);
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    if app
        .state::<crate::startup_state::NativeStartup>()
        .cancel_uninstalled()?
    {
        lifecycle.mark_uninitialized_exit_ready()?;
        app.exit(exit_code);
        return Ok(());
    }

    tauri::async_runtime::spawn(async move {
        crate::diagnostics::record(
            &app,
            cfw_core::DiagnosticTopic::Startup,
            "shutdown_task_started",
            "",
        );
        flush_window_bounds_for_exit(&app).await;
        crate::diagnostics::record(
            &app,
            cfw_core::DiagnosticTopic::Startup,
            "shutdown_window_bounds_finished",
            "",
        );
        let coordinator = app.state::<ManagedEngine>().coordinator.clone();
        let shutdown = app.state::<ManagedEngine>().shutdown_to_completion().await;
        crate::diagnostics::record(
            &app,
            cfw_core::DiagnosticTopic::Startup,
            "shutdown_engine_request_finished",
            "",
        );
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

async fn flush_window_bounds_for_exit(app: &AppHandle) {
    if let Err(error) = app.state::<WindowBoundsManager>().flush(app).await {
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

#[cfg(target_os = "macos")]
impl HandoffLifecycleLease {
    pub(crate) fn fail(&mut self, failure: MigrationHandoffFailure) -> Result<(), String> {
        self.shared.fail_handoff(failure)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for MaintenanceLifecycleLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(error) = self.shared.reset_owner_after_failure(self.owner) {
            eprintln!("failed to release the maintenance lifecycle: {error}");
        }
    }
}

#[cfg(target_os = "macos")]
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
mod tests;
