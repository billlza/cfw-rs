#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use cfw_apple_network::NATIVE_BRIDGE_OUTER_WATCHDOG;
use cfw_apple_network::NativeFrameworkBridge;
use cfw_engine_api::{
    NativeServiceEngineStatus, NativeServiceMaintenanceAction, NativeServiceMaintenanceResult,
    NativeServiceOffProofProfile, NativeServiceRegistrationStatus,
};
use serde::Serialize;

use crate::launch::ServiceMaintenanceAction;
#[cfg(target_os = "macos")]
use crate::main_run_loop_driver::pump_until_deadline;

const DOCUMENT: &str = "cfw-current-service-maintenance-v2";
#[cfg(target_os = "macos")]
const MAIN_RUN_LOOP_OUTER_SLACK: Duration = Duration::from_secs(1);
#[cfg(target_os = "macos")]
const MAIN_RUN_LOOP_ABORT_GRACE: Duration = Duration::from_secs(2);

#[cfg(target_os = "macos")]
#[derive(Debug, Eq, PartialEq)]
enum WorkerWaitOutcome {
    Completed,
    Aborted,
    AbortDidNotSettle,
}

#[derive(Serialize)]
struct MaintenanceReceipt {
    action: NativeServiceMaintenanceAction,
    document: &'static str,
    engine_status: Option<NativeServiceEngineStatus>,
    global_authority: NativeServiceRegistrationStatus,
    off_proof_profile: Option<NativeServiceOffProofProfile>,
    proxy_agent: NativeServiceRegistrationStatus,
}

pub(crate) fn run(action: ServiceMaintenanceAction) -> Result<(), String> {
    let bridge = NativeFrameworkBridge::load();
    if !bridge.is_available() {
        return Err(bridge
            .unavailable_reason()
            .unwrap_or("native bridge unavailable")
            .to_owned());
    }
    let action = native_action(action);
    let result = run_native_maintenance(bridge, action)?;
    let receipt = MaintenanceReceipt {
        action: result.action,
        document: DOCUMENT,
        engine_status: result.engine_status,
        global_authority: result.global_authority,
        off_proof_profile: result.off_proof_profile,
        proxy_agent: result.proxy_agent,
    };
    println!(
        "{}",
        serde_json::to_string(&receipt)
            .map_err(|_| "service maintenance receipt encoding failed".to_owned())?
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_native_maintenance(
    bridge: NativeFrameworkBridge,
    action: NativeServiceMaintenanceAction,
) -> Result<NativeServiceMaintenanceResult, String> {
    // NetworkExtension preference completion handlers are delivered on the
    // application main thread. This CLI branch runs before Tauri creates its
    // event loop, so blocking that thread would starve the callback while the
    // native deadline continued to advance on a utility queue.
    // SAFETY: pthread_main_np only observes the calling thread identity.
    if unsafe { libc::pthread_main_np() } != 1 {
        return Err("service maintenance must run on the macOS main thread".to_owned());
    }

    let worker = tauri::async_runtime::spawn(async move {
        tokio::time::timeout(
            NATIVE_BRIDGE_OUTER_WATCHDOG,
            bridge.maintain_current_services(action),
        )
        .await
    });
    let deadline = Instant::now() + NATIVE_BRIDGE_OUTER_WATCHDOG + MAIN_RUN_LOOP_OUTER_SLACK;
    match wait_for_worker(
        || worker.inner().is_finished(),
        || worker.abort(),
        deadline,
        || Instant::now() + MAIN_RUN_LOOP_ABORT_GRACE,
        |is_finished, wait_deadline| pump_until_deadline(is_finished, wait_deadline),
    ) {
        WorkerWaitOutcome::Completed => {}
        WorkerWaitOutcome::Aborted => {
            let _ = tauri::async_runtime::block_on(worker);
            return Err("service maintenance main-run-loop watchdog expired".to_owned());
        }
        WorkerWaitOutcome::AbortDidNotSettle => {
            drop(worker);
            return Err(
                "service maintenance main-run-loop watchdog expired and worker cancellation did not settle"
                    .to_owned(),
            );
        }
    }
    let result = tauri::async_runtime::block_on(worker)
        .map_err(|_| "service maintenance worker terminated unexpectedly".to_owned())?;
    let result =
        result.map_err(|_| "native service maintenance exceeded its outer watchdog".to_owned())?;
    result.map_err(|error| format!("native service maintenance failed: {}", error.message))
}

#[cfg(target_os = "macos")]
fn wait_for_worker(
    mut is_finished: impl FnMut() -> bool,
    mut abort: impl FnMut(),
    operation_deadline: Instant,
    cleanup_deadline: impl FnOnce() -> Instant,
    mut wait_until: impl FnMut(&mut dyn FnMut() -> bool, Instant) -> bool,
) -> WorkerWaitOutcome {
    if wait_until(&mut is_finished, operation_deadline) {
        return WorkerWaitOutcome::Completed;
    }
    abort();
    if wait_until(&mut is_finished, cleanup_deadline()) {
        WorkerWaitOutcome::Aborted
    } else {
        WorkerWaitOutcome::AbortDidNotSettle
    }
}

#[cfg(not(target_os = "macos"))]
fn run_native_maintenance(
    _bridge: NativeFrameworkBridge,
    _action: NativeServiceMaintenanceAction,
) -> Result<NativeServiceMaintenanceResult, String> {
    Err("service maintenance is supported only on macOS".to_owned())
}

const fn native_action(action: ServiceMaintenanceAction) -> NativeServiceMaintenanceAction {
    match action {
        ServiceMaintenanceAction::ProveOff => NativeServiceMaintenanceAction::ProveOff,
        ServiceMaintenanceAction::ProveInstalled40019Off => {
            NativeServiceMaintenanceAction::ProveInstalled40019Off
        }
        ServiceMaintenanceAction::Status => NativeServiceMaintenanceAction::Status,
        ServiceMaintenanceAction::UnregisterProxyAgent => {
            NativeServiceMaintenanceAction::UnregisterProxyAgent
        }
        ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent => {
            NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent
        }
        ServiceMaintenanceAction::UnregisterGlobalAuthority => {
            NativeServiceMaintenanceAction::UnregisterGlobalAuthority
        }
        ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority => {
            NativeServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority
        }
        ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority => {
            NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority
        }
        ServiceMaintenanceAction::RegisterGlobalAuthority => {
            NativeServiceMaintenanceAction::RegisterGlobalAuthority
        }
        ServiceMaintenanceAction::RegisterProxyAgent => {
            NativeServiceMaintenanceAction::RegisterProxyAgent
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[cfg(target_os = "macos")]
    use core_foundation::runloop::CFRunLoopRunResult;

    use super::*;
    #[cfg(target_os = "macos")]
    use crate::main_run_loop_driver::{
        MAIN_RUN_LOOP_SLICE, idle_for_empty_slice, pump_until_finished,
    };

    #[cfg(target_os = "macos")]
    #[test]
    fn completed_worker_never_pumps_or_reads_a_deadline() {
        assert!(pump_until_finished(
            || true,
            || panic!("completed worker must not read another deadline"),
            |_| panic!("completed worker must not pump the run loop"),
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn main_thread_pump_can_deliver_the_only_completion() {
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let mut slices = 0;

        assert!(pump_until_finished(
            || observed.load(Ordering::Acquire),
            || Some(MAIN_RUN_LOOP_SLICE),
            |_| {
                slices += 1;
                finished.store(true, Ordering::Release);
            },
        ));
        assert_eq!(slices, 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exhausted_main_run_loop_budget_fails_without_an_extra_pump() {
        let mut pumps = 0;
        assert!(!pump_until_finished(|| false, || None, |_| pumps += 1));
        assert_eq!(pumps, 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_empty_run_loop_sleeps_only_for_the_unconsumed_slice() {
        let expected = Duration::from_millis(17);
        let mut observed = None;
        idle_for_empty_slice(CFRunLoopRunResult::Finished, expected, |duration| {
            observed = Some(duration);
        });
        assert_eq!(observed, Some(expected));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_timed_out_run_loop_does_not_add_another_delay() {
        idle_for_empty_slice(
            CFRunLoopRunResult::TimedOut,
            Duration::from_millis(17),
            |_| panic!("a consumed slice must not sleep twice"),
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn watchdog_abort_settlement_is_pumped_before_join() {
        use std::cell::Cell;

        let finished = Cell::new(false);
        let aborted = Cell::new(false);
        let cleanup_deadline_read = Cell::new(false);
        let mut waits = 0;
        let now = Instant::now();
        let outcome = wait_for_worker(
            || finished.get(),
            || {
                aborted.set(true);
                finished.set(true);
            },
            now,
            || {
                cleanup_deadline_read.set(true);
                now + MAIN_RUN_LOOP_ABORT_GRACE
            },
            |is_finished, _| {
                waits += 1;
                if waits == 1 {
                    assert!(!aborted.get());
                    false
                } else {
                    assert!(aborted.get());
                    is_finished()
                }
            },
        );
        assert_eq!(outcome, WorkerWaitOutcome::Aborted);
        assert_eq!(waits, 2);
        assert!(cleanup_deadline_read.get());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn watchdog_never_joins_an_unsettled_abort() {
        use std::cell::Cell;

        let aborted = Cell::new(false);
        let mut waits = 0;
        let now = Instant::now();
        let outcome = wait_for_worker(
            || false,
            || aborted.set(true),
            now,
            || now + MAIN_RUN_LOOP_ABORT_GRACE,
            |_, _| {
                waits += 1;
                if waits == 2 {
                    assert!(aborted.get());
                }
                false
            },
        );
        assert_eq!(outcome, WorkerWaitOutcome::AbortDidNotSettle);
        assert_eq!(waits, 2);
    }

    #[test]
    fn every_cli_action_maps_to_one_closed_native_action() {
        let cases = [
            (
                ServiceMaintenanceAction::ProveOff,
                NativeServiceMaintenanceAction::ProveOff,
            ),
            (
                ServiceMaintenanceAction::ProveInstalled40019Off,
                NativeServiceMaintenanceAction::ProveInstalled40019Off,
            ),
            (
                ServiceMaintenanceAction::Status,
                NativeServiceMaintenanceAction::Status,
            ),
            (
                ServiceMaintenanceAction::UnregisterProxyAgent,
                NativeServiceMaintenanceAction::UnregisterProxyAgent,
            ),
            (
                ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent,
                NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent,
            ),
            (
                ServiceMaintenanceAction::UnregisterGlobalAuthority,
                NativeServiceMaintenanceAction::UnregisterGlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority,
                NativeServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority,
                NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RegisterGlobalAuthority,
                NativeServiceMaintenanceAction::RegisterGlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RegisterProxyAgent,
                NativeServiceMaintenanceAction::RegisterProxyAgent,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(native_action(input), expected);
        }
    }
}
