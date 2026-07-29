use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use cfw_engine_api::EngineEvent;
use tauri::{AppHandle, Emitter, Manager};

use crate::commands::LiveStreams;
use crate::engine::{EngineMaintenanceLease, ManagedEngine};

#[derive(Default)]
pub(crate) struct AppLifecycle {
    shutdown_in_progress: AtomicBool,
    exit_ready: AtomicBool,
    shutdown_maintenance: Mutex<Option<EngineMaintenanceLease>>,
}

impl AppLifecycle {
    pub(crate) fn exit_ready(&self) -> bool {
        self.exit_ready.load(Ordering::Acquire)
    }

    fn begin_shutdown(&self) -> bool {
        self.shutdown_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn reset_after_failure(&self) {
        self.shutdown_in_progress.store(false, Ordering::Release);
    }

    fn mark_exit_ready(&self, maintenance: EngineMaintenanceLease) -> Result<(), String> {
        let mut held = self
            .shutdown_maintenance
            .lock()
            .map_err(|_| "application shutdown maintenance lock failed".to_owned())?;
        if held.is_some() {
            return Err("application shutdown maintenance was already retained".into());
        }
        *held = Some(maintenance);
        self.exit_ready.store(true, Ordering::Release);
        Ok(())
    }
}

pub(crate) async fn prepare_handoff_exit(app: AppHandle) -> Result<(), String> {
    let lifecycle = app.state::<AppLifecycle>();
    if !lifecycle.begin_shutdown() {
        return Err("application shutdown is already in progress".into());
    }
    let outcome = match app.state::<ManagedEngine>().shutdown_to_completion().await {
        Ok(outcome) => outcome,
        Err(error) => {
            lifecycle.reset_after_failure();
            return Err(format!(
                "dashboard shutdown admission failed; migration handoff was cancelled: {error}"
            ));
        }
    };
    let (result, maintenance) = outcome.into_parts();
    match result {
        Ok(_) => {
            if let Err(error) = lifecycle.mark_exit_ready(maintenance) {
                lifecycle.reset_after_failure();
                return Err(format!(
                    "dashboard shutdown finalization failed; migration handoff was cancelled: {error}"
                ));
            }
            app.state::<LiveStreams>().stop_all();
            Ok(())
        }
        Err(error) => {
            lifecycle.reset_after_failure();
            Err(format!(
                "dashboard shutdown failed; migration handoff was cancelled: {error}"
            ))
        }
    }
}

fn finish_exit(
    app: &AppHandle,
    maintenance: EngineMaintenanceLease,
    exit_code: i32,
) -> Result<(), String> {
    app.state::<AppLifecycle>().mark_exit_ready(maintenance)?;
    app.state::<LiveStreams>().stop_all();
    app.exit(exit_code);
    Ok(())
}

fn emit_shutdown_error(app: &AppHandle, code: &str, message: String) {
    if let Err(emit_error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(code, message),
    ) {
        eprintln!("failed to publish shutdown error: {emit_error}");
    }
}

fn start_shutdown(app: AppHandle, exit_code: i32) -> bool {
    let lifecycle = app.state::<AppLifecycle>();
    if lifecycle.exit_ready() {
        app.exit(exit_code);
        return true;
    }
    if !lifecycle.begin_shutdown() {
        return false;
    }

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
                        app.state::<AppLifecycle>().reset_after_failure();
                        return;
                    }
                }
                if let Err(error) = finish_exit(&app, maintenance, exit_code) {
                    emit_shutdown_error(&app, "shutdown_finalization_failed", error);
                    app.state::<AppLifecycle>().reset_after_failure();
                }
            }
            Err(error) => {
                let safely_off = coordinator.snapshot().state == cfw_engine_api::EngineState::Off;
                emit_shutdown_error(
                    &app,
                    "shutdown_admission_failed",
                    format!("{error}; engine currently Off: {safely_off}"),
                );
                app.state::<AppLifecycle>().reset_after_failure();
            }
        }
    });
    true
}

pub(crate) fn request_shutdown(app: AppHandle, exit_code: i32) {
    // An app-owned task may already own lifecycle finalization. Repeated menu,
    // tray, and RunEvent requests are intentionally idempotent and must not
    // create a second actor command.
    let _shutdown_started_or_already_owned = start_shutdown(app, exit_code);
}

#[tauri::command]
pub(crate) fn quit_app(app: AppHandle) -> Result<(), String> {
    if start_shutdown(app, 0) {
        Ok(())
    } else {
        Err("application shutdown is already in progress".into())
    }
}

#[cfg(test)]
mod tests {
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
        assert!(quit.contains("start_shutdown(app, 0)"));
        assert!(!quit.contains(".await"));
    }
}
