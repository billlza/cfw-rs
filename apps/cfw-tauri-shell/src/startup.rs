//! Construct the native shell immediately; initialize I/O on background workers.
use tauri::{AppHandle, Manager};

use crate::diagnostics::Diagnostics;
use crate::startup_state::{NativeStartup, prepare_off_main};

pub(crate) fn start(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let result = initialize(app.clone()).await;
        if let Err(error) = &result {
            crate::emit_startup_error(&app, "native_initialization_failed", error.clone());
        }
        if let Err(error) = app.state::<NativeStartup>().finish(result) {
            // Cancellation is terminal. It never admits a late coordinator.
            crate::diagnostics::record(
                &app,
                cfw_core::DiagnosticTopic::Startup,
                "native_initialization_ended",
                &error,
            );
        }
    });
}

async fn initialize(app: AppHandle) -> Result<(), String> {
    let worker = app.clone();
    let (profiles, prepared) = prepare_off_main(move || {
        let diagnostics = worker.state::<Diagnostics>();
        let bridge = diagnostics
            .startup_step("native_bridge", || {
                Ok::<_, std::convert::Infallible>(cfw_apple_network::NativeFrameworkBridge::load())
            })
            .map_err(|error| error.to_string())?;
        if let Some(error) = bridge.unavailable_reason() {
            diagnostics.record(
                cfw_core::DiagnosticTopic::Startup,
                "native_bridge_unavailable",
                error,
            );
        }
        let profiles = diagnostics.startup_step("profile_store", || {
            crate::commands::build_managed_profiles(bridge.clone())
        })?;
        let engine = diagnostics.startup_step("engine_manager", || {
            crate::engine::prepare_managed_engine(bridge)
        })?;
        Ok((profiles, engine))
    })
    .await?;

    on_main(&app, move |app| {
        app.state::<NativeStartup>().install(|| {
            if !app.manage(profiles) {
                return Err("managed profiles were registered twice".into());
            }
            if !app.manage(prepared.engine) {
                return Err("managed engine was registered twice".into());
            }
            std::mem::drop(tauri::async_runtime::spawn(prepared.task));
            Ok(())
        })
    })
    .await?;

    let worker = app.clone();
    prepare_off_main(move || {
        crate::engine::start_engine_event_forwarder(worker.clone());
        worker
            .state::<Diagnostics>()
            .startup_step("launch_preflight", || {
                crate::legacy::run_launch_preflight(&worker)
            })
    })
    .await?;

    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        app.state::<crate::LaunchContext>()
            .mark_renderer_native_ready()?;
    } else {
        on_main(&app, |app| {
            if !app
                .state::<crate::lifecycle::AppLifecycle>()
                .startup_work_allowed()
            {
                return Err("application exited before tray initialization".into());
            }
            app.state::<Diagnostics>()
                .startup_step("tray", || crate::shell::build_tray(&app))
                .map_err(|error| error.to_string())?;
            crate::commands::start_provider_refresh(app.clone())
        })
        .await?;
        // Optional startup controls may complete after the dashboard is ready.
        // They must not hold the shell hostage to a filesystem or OS service.
        let optional = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = crate::automation::initialize(optional.clone()).await {
                crate::emit_startup_error(&optional, "automation_initialization_failed", error);
            }
            #[cfg(feature = "physical-release-evidence")]
            {
                let worker = optional.clone();
                if let Err(error) = prepare_off_main(move || {
                    if !worker
                        .state::<crate::lifecycle::AppLifecycle>()
                        .startup_work_allowed()
                    {
                        return Err("application is exiting".into());
                    }
                    crate::packet_evidence_transport::run_packet_evidence_transaction(worker)
                        .map_err(|error| error.to_string())
                })
                .await
                {
                    crate::emit_startup_error(&optional, "evidence_control_unavailable", error);
                }
            }
        });
    }
    crate::diagnostics::record(
        &app,
        cfw_core::DiagnosticTopic::Startup,
        "native_setup_ready",
        "",
    );
    Ok(())
}

/// Only short AppKit work belongs here. The caller awaits the main queue from
/// an async task; the main thread never waits for the caller or for I/O.
pub(crate) async fn on_main<T: Send + 'static>(
    app: &AppHandle,
    operation: impl FnOnce(AppHandle) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let handle = app.clone();
    app.run_on_main_thread(move || {
        let result = operation(handle);
        if send.send(result).is_err() {
            eprintln!("native UI completion receiver closed");
        }
    })
    .map_err(|error| error.to_string())?;
    receive
        .await
        .map_err(|error| format!("native UI task did not complete: {error}"))?
}

pub(crate) fn command_available_before_ready(command: &str) -> bool {
    matches!(
        command,
        "boot_payload"
            | "report_dashboard_startup"
            | "reveal_logs_directory"
            | "reload_dashboard"
            | "quit_app"
            | "force_quit_app"
            | "open_page"
    )
}

#[cfg(test)]
mod tests;
