use std::time::{Duration, Instant};

use core_foundation::runloop::{CFRunLoop, CFRunLoopRunResult, kCFRunLoopDefaultMode};

pub(crate) const MAIN_RUN_LOOP_SLICE: Duration = Duration::from_millis(20);

pub(crate) fn pump_until_deadline(
    mut is_finished: impl FnMut() -> bool,
    deadline: Instant,
) -> bool {
    pump_until_finished(
        &mut is_finished,
        || {
            deadline
                .checked_duration_since(Instant::now())
                .map(|remaining| remaining.min(MAIN_RUN_LOOP_SLICE))
                .filter(|remaining| !remaining.is_zero())
        },
        pump_main_run_loop,
    )
}

fn pump_main_run_loop(duration: Duration) {
    let started = Instant::now();
    // SAFETY: kCFRunLoopDefaultMode is a process-lifetime CoreFoundation
    // constant. Callers must establish that this is the macOS main thread.
    let mode = unsafe { kCFRunLoopDefaultMode };
    let result = CFRunLoop::run_in_mode(mode, duration, false);
    let remaining = duration.saturating_sub(started.elapsed());
    idle_for_empty_slice(result, remaining, std::thread::sleep);
}

pub(crate) fn idle_for_empty_slice(
    result: CFRunLoopRunResult,
    remaining: Duration,
    mut sleep: impl FnMut(Duration),
) {
    if matches!(
        result,
        CFRunLoopRunResult::Finished | CFRunLoopRunResult::Stopped
    ) && !remaining.is_zero()
    {
        // An empty or stopped run loop may return immediately instead of
        // consuming the requested slice. Preserve the bounded polling cadence
        // so a missing source cannot hot-spin the maintenance process.
        sleep(remaining);
    }
}

pub(crate) fn pump_until_finished(
    mut is_finished: impl FnMut() -> bool,
    mut next_slice: impl FnMut() -> Option<Duration>,
    mut pump: impl FnMut(Duration),
) -> bool {
    while !is_finished() {
        let Some(duration) = next_slice() else {
            return false;
        };
        pump(duration);
    }
    true
}
