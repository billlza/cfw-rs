use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null;
use std::time::Instant;

use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED};
use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::CreateEventW;

use crate::{Error, LOCK_WAIT, WaitOutcome, wait_until};

/// Submit one kernel wait instead of periodically racing a writer that can
/// release and reacquire between polls. The lock range matches std::fs::File's
/// Windows whole-file lock, preserving interoperability with existing callers.
pub(crate) fn acquire(file: File, exclusive: bool) -> Result<File, Error> {
    // SAFETY: unnamed manual-reset event; no inherited handle or input buffer.
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the successful CreateEventW transferred one owned event handle.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    let flags = if exclusive {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        0
    };
    // SAFETY: file was opened for overlapped I/O. The event and OVERLAPPED stay
    // alive until the operation is completed, including cancellation teardown.
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } != 0
    {
        return Ok(file);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
        return Err(error.into());
    }
    let wait = wait_until(&event, Instant::now() + LOCK_WAIT);
    if matches!(wait, Ok(WaitOutcome::Signaled)) {
        let mut transferred = 0;
        // SAFETY: event completion means the kernel no longer writes to the
        // OVERLAPPED. GetOverlappedResult still checks the operation's outcome.
        if unsafe { GetOverlappedResult(file.as_raw_handle(), &overlapped, &mut transferred, 0) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        return Ok(file);
    }
    let failure = match wait {
        Ok(WaitOutcome::TimedOut) => Error::Busy,
        Err(error) => Error::Io(error),
        Ok(_) => Error::Io(io::Error::other("file lock event reported abandonment")),
    };
    // Target only this lock request. Cancellation can race successful lock
    // acquisition; the file is dropped on both paths so no late lock survives.
    // SAFETY: exact live handle and pending OVERLAPPED from LockFileEx above.
    let cancel_error = if unsafe { CancelIoEx(file.as_raw_handle(), &overlapped) } == 0 {
        let error = io::Error::last_os_error();
        (error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)).then_some(error)
    } else {
        None
    };
    let mut transferred = 0;
    // SAFETY: cancellation itself is not completion. Drain before releasing
    // the stack buffer/event, even when a driver takes time to acknowledge it.
    let completion_error =
        if unsafe { GetOverlappedResult(file.as_raw_handle(), &overlapped, &mut transferred, 1) }
            == 0
        {
            let error = io::Error::last_os_error();
            (error.raw_os_error() != Some(ERROR_OPERATION_ABORTED as i32)).then_some(error)
        } else {
            None
        };
    Err([cancel_error, completion_error]
        .into_iter()
        .flatten()
        .fold(failure, |operation, error| Error::CleanupFailed {
            operation: Box::new(operation),
            cleanup: Box::new(Error::Io(error)),
        }))
}
