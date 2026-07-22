use std::sync::atomic::{AtomicBool, Ordering};

use cfw_engine_api::EngineEvent;
use tauri::{AppHandle, Emitter, Manager};

use crate::engine::ManagedEngine;

#[derive(Default)]
pub(crate) struct AppLifecycle {
    shutdown_in_progress: AtomicBool,
    exit_ready: AtomicBool,
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

    fn mark_exit_ready(&self) {
        self.exit_ready.store(true, Ordering::Release);
    }
}

pub(crate) fn request_shutdown(app: AppHandle, exit_code: i32) {
    let lifecycle = app.state::<AppLifecycle>();
    if lifecycle.exit_ready() {
        app.exit(exit_code);
        return;
    }
    if !lifecycle.begin_shutdown() {
        return;
    }

    tauri::async_runtime::spawn(async move {
        let coordinator = app.state::<ManagedEngine>().coordinator.clone();
        match coordinator.shutdown().await {
            Ok(_) => {
                app.state::<AppLifecycle>().mark_exit_ready();
                app.exit(exit_code);
            }
            Err(error) => {
                let safely_off = coordinator.snapshot().state == cfw_engine_api::EngineState::Off;
                if let Err(emit_error) = app.emit(
                    "cfw://engine-event",
                    EngineEvent::boundary_failure("shutdown_failed", error.to_string()),
                ) {
                    eprintln!("failed to publish shutdown error: {emit_error}");
                }
                if safely_off {
                    app.state::<AppLifecycle>().mark_exit_ready();
                    app.exit(exit_code);
                } else {
                    app.state::<AppLifecycle>().reset_after_failure();
                }
            }
        }
    });
}

#[tauri::command]
pub(crate) async fn quit_app(app: AppHandle) -> Result<(), String> {
    let lifecycle = app.state::<AppLifecycle>();
    if !lifecycle.begin_shutdown() {
        return Err("application shutdown is already in progress".into());
    }
    let coordinator = app.state::<ManagedEngine>().coordinator.clone();
    match coordinator.shutdown().await {
        Ok(_) => {
            lifecycle.mark_exit_ready();
            app.exit(0);
            Ok(())
        }
        Err(error) => {
            if coordinator.snapshot().state == cfw_engine_api::EngineState::Off {
                if let Err(emit_error) = app.emit(
                    "cfw://engine-event",
                    EngineEvent::boundary_failure("shutdown_failed", error.to_string()),
                ) {
                    eprintln!("failed to publish shutdown error: {emit_error}");
                }
                lifecycle.mark_exit_ready();
                app.exit(0);
                Ok(())
            } else {
                lifecycle.reset_after_failure();
                Err(format!("engine shutdown failed: {error}"))
            }
        }
    }
}
