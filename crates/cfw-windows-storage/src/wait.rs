//! Win32 timeout indications are quantized by the system clock. Retain one
//! monotonic deadline across early returns; never restart the entire interval.
use std::{io, os::windows::io::AsRawHandle, time::Instant};

use windows_sys::Win32::{
    Foundation::{WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::WaitForSingleObject,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Signaled,
    Abandoned,
    TimedOut,
}

/// Wait on a retained handle until it signals or the monotonic deadline passes.
/// An abandoned mutex transfers ownership just as the native API specifies;
/// callers must still validate the protected state. This does not cancel I/O.
pub fn wait_until(handle: &impl AsRawHandle, deadline: Instant) -> io::Result<WaitOutcome> {
    wait_with(deadline, Instant::now, |milliseconds| {
        // SAFETY: the handle remains borrowed for this entire synchronous wait.
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), milliseconds) } {
            WAIT_OBJECT_0 => Ok(WaitOutcome::Signaled),
            WAIT_ABANDONED => Ok(WaitOutcome::Abandoned),
            WAIT_TIMEOUT => Ok(WaitOutcome::TimedOut),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected native wait result")),
        }
    })
}

fn wait_with(
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut wait: impl FnMut(u32) -> io::Result<WaitOutcome>,
) -> io::Result<WaitOutcome> {
    loop {
        let Some(remaining) = deadline.checked_duration_since(now()) else {
            return Ok(WaitOutcome::TimedOut);
        };
        if remaining.is_zero() {
            return Ok(WaitOutcome::TimedOut);
        }
        // Round up partial milliseconds and never pass INFINITE. Even a
        // rounded-up wait can return early at a system-clock tick boundary.
        let milliseconds = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(u128::from(u32::MAX - 1)) as u32;
        match wait(milliseconds)? {
            WaitOutcome::TimedOut => continue,
            completed => return Ok(completed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn early_timeout_preserves_the_original_deadline_and_rounds_up_the_remainder() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(3);
        let mut clock = [start, deadline - Duration::from_micros(1500), deadline].into_iter();
        let mut waits = Vec::new();
        let result = wait_with(
            deadline,
            || clock.next().expect("wait exceeded its fixed deadline"),
            |milliseconds| {
                waits.push(milliseconds);
                Ok(WaitOutcome::TimedOut)
            },
        )
        .unwrap();
        assert_eq!(result, WaitOutcome::TimedOut);
        assert_eq!(waits, [3000, 2]);
    }

    #[test]
    fn acquisition_after_an_early_timeout_is_preserved_including_abandonment() {
        let start = Instant::now();
        for outcome in [WaitOutcome::Signaled, WaitOutcome::Abandoned] {
            let mut clock = [start, start + Duration::from_millis(5)].into_iter();
            let mut replies = [WaitOutcome::TimedOut, outcome].into_iter();
            assert_eq!(
                wait_with(
                    start + Duration::from_millis(20),
                    || clock.next().unwrap(),
                    |_| Ok(replies.next().unwrap()),
                )
                .unwrap(),
                outcome
            );
        }
    }

    #[test]
    fn expired_deadlines_and_native_failures_do_not_restart_or_hide_errors() {
        let now = Instant::now();
        assert_eq!(
            wait_with(
                now,
                || now,
                |_| panic!("expired deadline entered kernel wait")
            )
            .unwrap(),
            WaitOutcome::TimedOut
        );
        let error = wait_with(
            now + Duration::from_secs(1),
            || now,
            |_| Err(io::Error::from_raw_os_error(6)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(6));
    }
}
