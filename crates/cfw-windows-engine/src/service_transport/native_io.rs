//! Exclusive overlapped operations without an IOCP adapter or hidden reads.
//! Cancellation is followed by native completion before buffers are released.
//! Kernel cancellation teardown can exceed the requested deadline; callers run
//! on a dedicated worker and must not report it retired before this returns.
use super::*;
use cfw_windows_storage::{WaitOutcome, wait_until};
use std::{cell::UnsafeCell, ptr::null, sync::atomic::AtomicBool};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NO_DATA,
        ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
    },
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::ConnectNamedPipe,
        Threading::CreateEventW,
    },
};

mod pending_read;
pub(crate) use pending_read::PendingMessageRead;
mod connected_pair;
pub(crate) use connected_pair::connected_pair;

struct Operation {
    event: OwnedHandle,
    state: UnsafeCell<OVERLAPPED>,
}
impl Operation {
    fn new() -> Result<Self, ServiceTransportError> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let state = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        Ok(Self {
            event,
            state: UnsafeCell::new(state),
        })
    }

    // `self` and all input/output buffers remain at their submitted addresses
    // until this completes. No method moves an Operation with pending I/O.
    fn complete(
        &self,
        pipe: &OwnedHandle,
        started: bool,
        start_error: io::Error,
        deadline: Instant,
        cancel: Option<&AtomicBool>,
    ) -> Result<u32, ServiceTransportError> {
        if !started && start_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(classify(start_error));
        }
        if started {
            let mut transferred = 0;
            if unsafe {
                GetOverlappedResult(pipe.as_raw_handle(), self.state.get(), &mut transferred, 0)
            } == 0
            {
                return Err(classify(io::Error::last_os_error()));
            }
            check_deadline(deadline)?;
            check_cancel(cancel)?;
            return Ok(transferred);
        }
        let failure = match self.wait(deadline, cancel) {
            Ok(()) => {
                let mut transferred = 0;
                if unsafe {
                    GetOverlappedResult(pipe.as_raw_handle(), self.state.get(), &mut transferred, 0)
                } == 0
                {
                    return Err(classify(io::Error::last_os_error()));
                }
                check_deadline(deadline)?;
                check_cancel(cancel)?;
                return Ok(transferred);
            }
            Err(error) => error,
        };
        // Cancellation may race ordinary completion. ERROR_NOT_FOUND is only
        // accepted after the exact operation has also been drained below.
        let cancellation = if unsafe { CancelIoEx(pipe.as_raw_handle(), self.state.get()) } == 0 {
            let error = io::Error::last_os_error();
            (error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)).then_some(error)
        } else {
            None
        };
        let mut transferred = 0;
        // Do not free an OVERLAPPED or buffer on cancellation acknowledgement
        // alone. A delayed driver keeps this worker alive, not a false receipt.
        let completion = if unsafe {
            GetOverlappedResult(pipe.as_raw_handle(), self.state.get(), &mut transferred, 1)
        } == 0
        {
            let error = io::Error::last_os_error();
            (error.raw_os_error() != Some(ERROR_OPERATION_ABORTED as i32)).then_some(error)
        } else {
            None
        };
        Err([cancellation, completion]
            .into_iter()
            .flatten()
            .fold(failure, |operation, cleanup| {
                ServiceTransportError::Cleanup {
                    operation: Box::new(operation),
                    cleanup: Box::new(classify(cleanup)),
                }
            }))
    }
    fn wait(
        &self,
        deadline: Instant,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), ServiceTransportError> {
        loop {
            check_cancel(cancel)?;
            let poll = if cancel.is_some() {
                deadline.min(Instant::now() + Duration::from_millis(25))
            } else {
                deadline
            };
            match wait_until(&self.event, poll)? {
                WaitOutcome::Signaled => return Ok(()),
                WaitOutcome::TimedOut if cancel.is_some() && Instant::now() < deadline => {}
                WaitOutcome::TimedOut => return Err(ServiceTransportError::Deadline),
                _ => return Err(io::Error::other("pipe event reported abandonment").into()),
            }
        }
    }
}

fn check_cancel(cancel: Option<&AtomicBool>) -> Result<(), ServiceTransportError> {
    if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
        Err(ServiceTransportError::Cancelled)
    } else {
        Ok(())
    }
}

fn classify(error: io::Error) -> ServiceTransportError {
    if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
        ServiceTransportError::MessageLength
    } else {
        error.into()
    }
}

/// A listener poll deadline ends only the wait. The exact operation and pipe
/// remain owned until admitted, explicitly closed, or dropped. Cancelling and
/// replacing the instance on every poll can discard a client that connected at
/// the deadline before the server thread observed completion.
pub(crate) struct PendingAccept {
    pipe: Option<OwnedHandle>,
    // Allocated before ConnectNamedPipe. Its OVERLAPPED address is never moved
    // while pending, including when the enclosing listener itself is moved.
    operation: Box<Operation>,
    started: bool,
    pending: bool,
    connected: bool,
}
// SAFETY: this is an exclusively owned connect operation with no borrowed data
// buffer or thread-affine completion routine. Its OVERLAPPED stays at its boxed
// address, kernel writes use UnsafeCell, and its event/pipe handles remain owned
// until native completion. Event waits/GetOverlappedResult/CancelIoEx may run on
// another thread. This does not grant Sync or make borrowed read/write I/O Send.
unsafe impl Send for PendingAccept {}
impl PendingAccept {
    pub(crate) fn new(pipe: OwnedHandle) -> Result<Self, ServiceTransportError> {
        Ok(Self {
            pipe: Some(pipe),
            operation: Box::new(Operation::new()?),
            started: false,
            pending: false,
            connected: false,
        })
    }

    pub(crate) fn wait(&mut self, deadline: Instant) -> Result<(), ServiceTransportError> {
        check_deadline(deadline)?;
        let pipe = self.pipe.as_ref().ok_or(ServiceTransportError::Closed)?;
        if !self.started {
            self.started = true;
            if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), self.operation.state.get()) } != 0 {
                self.connected = true;
            } else {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(value) if value == ERROR_PIPE_CONNECTED as i32 => self.connected = true,
                    Some(value) if value == ERROR_IO_PENDING as i32 => self.pending = true,
                    _ => return Err(classify(error)),
                }
            }
        }
        if !self.connected {
            match wait_until(&self.operation.event, deadline)? {
                WaitOutcome::TimedOut => return Err(ServiceTransportError::Deadline),
                WaitOutcome::Signaled => {}
                _ => return Err(io::Error::other("pipe accept event reported abandonment").into()),
            }
            let mut transferred = 0;
            if unsafe {
                GetOverlappedResult(
                    pipe.as_raw_handle(),
                    self.operation.state.get(),
                    &mut transferred,
                    0,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
                    self.pending = false;
                }
                return Err(classify(error));
            }
            self.pending = false;
            self.connected = true;
        }
        // A late observation still fails this poll, but retains the completed
        // connection for the next poll instead of closing its client's handle.
        check_deadline(deadline)
    }

    pub(crate) fn into_pipe(mut self) -> Result<OwnedHandle, ServiceTransportError> {
        if self.pending || !self.connected {
            return Err(ServiceTransportError::RequestOrder);
        }
        self.pipe.take().ok_or(ServiceTransportError::Closed)
    }

    pub(crate) fn retire(&mut self) -> Result<(), ServiceTransportError> {
        if !self.pending {
            return Ok(());
        }
        let pipe = self.pipe.as_ref().ok_or(ServiceTransportError::Closed)?;
        let cancellation =
            if unsafe { CancelIoEx(pipe.as_raw_handle(), self.operation.state.get()) } == 0 {
                let error = io::Error::last_os_error();
                (error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)).then_some(error)
            } else {
                None
            };
        let mut transferred = 0;
        let completion = if unsafe {
            GetOverlappedResult(
                pipe.as_raw_handle(),
                self.operation.state.get(),
                &mut transferred,
                1,
            )
        } != 0
        {
            self.pending = false;
            None
        } else {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(value)
                    if [
                        ERROR_OPERATION_ABORTED,
                        ERROR_BROKEN_PIPE,
                        ERROR_NO_DATA,
                        ERROR_PIPE_NOT_CONNECTED,
                    ]
                    .contains(&(value as u32)) =>
                {
                    // These are completed cancellation/peer-disconnect results
                    // for an unadmitted connection, never a successful command.
                    self.pending = false;
                    None
                }
                _ => Some(error),
            }
        };
        match (cancellation, completion) {
            (None, None) => Ok(()),
            (Some(error), None) | (None, Some(error)) => Err(classify(error)),
            (Some(operation), Some(cleanup)) => Err(ServiceTransportError::Cleanup {
                operation: Box::new(classify(operation)),
                cleanup: Box::new(classify(cleanup)),
            }),
        }
    }
}
impl Drop for PendingAccept {
    fn drop(&mut self) {
        // Normal listener shutdown calls retire explicitly and reports errors.
        // An unverified emergency retirement cannot release a live OVERLAPPED.
        if self.retire().is_err() {
            std::process::abort();
        }
    }
}

pub(super) fn read(
    pipe: &OwnedHandle,
    deadline: Instant,
) -> Result<ServicePayload, ServiceTransportError> {
    read_bounded(pipe, deadline, MAX_MESSAGE, None)
}

// Shared overlapped I/O; protocol callers retain their smaller message limits.
// Only internal launch framing can request a larger buffer than service RPC.
pub(crate) fn read_bounded(
    pipe: &OwnedHandle,
    deadline: Instant,
    maximum: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ServicePayload, ServiceTransportError> {
    check_deadline(deadline)?;
    check_cancel(cancel)?;
    if maximum == 0 || maximum > 4 * MAX_MESSAGE {
        return Err(ServiceTransportError::MessageLength);
    }
    let mut bytes = Zeroizing::new(vec![0; maximum]);
    let operation = Operation::new()?;
    let started = unsafe {
        ReadFile(
            pipe.as_raw_handle(),
            bytes.as_mut_ptr(),
            maximum as u32,
            null_mut(),
            operation.state.get(),
        )
    } != 0;
    let error = io::Error::last_os_error();
    let length = operation.complete(pipe, started, error, deadline, cancel)? as usize;
    if length == 0 || length > bytes.len() {
        return Err(ServiceTransportError::MessageLength);
    }
    Ok(ServicePayload { bytes, length })
}

pub(super) fn write(
    pipe: &OwnedHandle,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ServiceTransportError> {
    write_bounded(pipe, bytes, deadline, MAX_MESSAGE, None)
}

pub(crate) fn write_bounded(
    pipe: &OwnedHandle,
    bytes: &[u8],
    deadline: Instant,
    maximum: usize,
    cancel: Option<&AtomicBool>,
) -> Result<(), ServiceTransportError> {
    check_deadline(deadline)?;
    check_cancel(cancel)?;
    if maximum == 0 || maximum > 4 * MAX_MESSAGE || bytes.is_empty() || bytes.len() > maximum {
        return Err(ServiceTransportError::MessageLength);
    }
    let operation = Operation::new()?;
    let started = unsafe {
        WriteFile(
            pipe.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            null_mut(),
            operation.state.get(),
        )
    } != 0;
    let error = io::Error::last_os_error();
    let length = operation.complete(pipe, started, error, deadline, cancel)? as usize;
    if length != bytes.len() {
        return Err(ServiceTransportError::MessageLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
