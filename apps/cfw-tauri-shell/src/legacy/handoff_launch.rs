//! Launching the migration hand-off instance: the renderer's entry point and
//! the app-owned task that waits until the instance is ready, then exits the
//! dashboard.

use super::*;

/// Launches the controlled `--migration-handoff` instance that owns the
/// prepare/confirm/recover cutover path.
///
/// The default dashboard cannot drive the destructive cutover (every cutover
/// command rejects a non-handoff launch). This is the one renderer entry point
/// that starts the handoff: it refuses to run inside a handoff instance, proves
/// the running app is the installed, signed, notarized release before spawning,
/// and starts a sibling process that acquires the exclusive handoff lease. The
/// dashboard exits only after that child completes setup and publishes a
/// ticket-bound readiness acknowledgement. Once admitted, the orchestration is
/// owned by the application lifecycle; renderer reload or cancellation can
/// discard only the response, never the child cleanup or shutdown boundary.
/// This command never mutates proxy, DNS, route, or legacy process state.
#[tauri::command]
pub(crate) async fn begin_migration_handoff(
    app: AppHandle,
    launch: State<'_, crate::LaunchContext>,
) -> Result<(), String> {
    if launch.is_migration_handoff() {
        return Err("this instance is already the migration handoff".into());
    }
    let mut lifecycle_lease = crate::lifecycle::begin_handoff_lifecycle(&app)?;
    let setup = (|| {
        admission::require_canonical_handoff_candidate()?;
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve the running executable: {error}"))?;
        let store = crate::settings_store()?;
        store.ensure_layout().map_err(|error| error.to_string())?;
        handoff_ticket::PendingHandoff::create(&store.paths().app_home, &executable)
    })();
    let pending = match setup {
        Ok(pending) => pending,
        Err(error) => {
            let error = fail_handoff_lifecycle(
                &mut lifecycle_lease,
                MigrationHandoffFailure::Admission,
                error,
            );
            emit_cutover_failure(&app, "migration_handoff_admission_failed", &error);
            return Err(error);
        }
    };
    let exit_app = app.clone();
    let operation_app = app.clone();
    let receiver = spawn_supervised_app_result(
        async move {
            let outcome = run_migration_handoff(operation_app, pending, &mut lifecycle_lease).await;
            (outcome, lifecycle_lease)
        },
        move |task| match task {
            Ok((outcome, mut lifecycle_lease)) => match outcome {
                Ok(()) => Ok(()),
                Err(error) => {
                    let error = fail_handoff_lifecycle(
                        &mut lifecycle_lease,
                        MigrationHandoffFailure::Operation,
                        error,
                    );
                    emit_cutover_failure(&exit_app, "migration_handoff_failed", &error);
                    Err(error)
                }
            },
            Err(error) => {
                emit_cutover_failure(&exit_app, "migration_handoff_task_failed", &error);
                Err(error)
            }
        },
        move || app_exit_after_handoff(&app),
    );
    receiver
        .await
        .map_err(|_| "migration handoff task ended without a terminal result".to_owned())?
}

fn fail_handoff_lifecycle(
    lifecycle_lease: &mut crate::lifecycle::HandoffLifecycleLease,
    failure: MigrationHandoffFailure,
    operation: String,
) -> String {
    match lifecycle_lease.fail(failure) {
        Ok(()) => operation,
        Err(lifecycle) => {
            format!("{operation}; migration handoff lifecycle finalization failed: {lifecycle}")
        }
    }
}

fn app_exit_after_handoff(app: &AppHandle) {
    app.exit(0);
}

/// Supervises the app-owned worker independently of the renderer response. The
/// finalizer observes worker panic/cancellation, publishes terminal state, and
/// sends the optional IPC response before the successful exit callback runs.
pub(super) fn spawn_supervised_app_result<F, O, C, A>(
    operation: F,
    finalize: C,
    after_successful_response: A,
) -> oneshot::Receiver<Result<(), String>>
where
    F: Future<Output = O> + Send + 'static,
    O: Send + 'static,
    C: FnOnce(Result<O, String>) -> Result<(), String> + Send + 'static,
    A: FnOnce() + Send + 'static,
{
    let operation = tauri::async_runtime::spawn(operation);
    let (sender, receiver) = oneshot::channel();
    std::mem::drop(tauri::async_runtime::spawn(async move {
        let operation = operation.await.map_err(|error| {
            let reason = match error {
                tauri::Error::JoinError(error) if error.is_panic() => "panicked",
                tauri::Error::JoinError(error) if error.is_cancelled() => "was cancelled",
                _ => "ended without a result",
            };
            format!("migration handoff application task {reason}")
        });
        let outcome = finalize(operation);
        let should_exit = outcome.is_ok();
        let _renderer_was_cancelled = sender.send(outcome);
        if should_exit {
            after_successful_response();
        }
    }));
    receiver
}

async fn run_migration_handoff(
    app: AppHandle,
    pending: handoff_ticket::PendingHandoff,
    lifecycle_lease: &mut crate::lifecycle::HandoffLifecycleLease,
) -> Result<(), String> {
    let child = pending.child_guard();
    let readiness = tauri::async_runtime::spawn_blocking(move || child.launch_until_ready()).await;
    let child = match readiness {
        Ok(result) => result?,
        Err(error) => {
            return Err(format!("migration handoff readiness task failed: {error}"));
        }
    };
    if let Err(error) = crate::lifecycle::prepare_handoff_exit(app, lifecycle_lease).await {
        return child.fail(error);
    }
    child.disarm();
    Ok(())
}
