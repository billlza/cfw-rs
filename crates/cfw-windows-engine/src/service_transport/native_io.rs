//! Exclusive overlapped operations without an IOCP adapter or hidden reads.
//! Cancellation is followed by native completion before buffers are released.
//! Kernel cancellation teardown can exceed the requested deadline; callers run
//! on a dedicated worker and must not report it retired before this returns.
use super::*;
use cfw_windows_storage::{WaitOutcome, wait_until};
use std::ptr::null;
use windows_sys::Win32::{
    Foundation::{
        ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED,
        ERROR_PIPE_CONNECTED,
    },
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::ConnectNamedPipe,
        Threading::CreateEventW,
    },
};

struct Operation {
    event: OwnedHandle,
    state: OVERLAPPED,
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
        Ok(Self { event, state })
    }

    // `self` and all input/output buffers remain at their submitted addresses
    // until this completes. No method moves an Operation with pending I/O.
    fn complete(
        &self,
        pipe: &OwnedHandle,
        started: bool,
        start_error: io::Error,
        deadline: Instant,
    ) -> Result<u32, ServiceTransportError> {
        if !started && start_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(classify(start_error));
        }
        if started {
            let mut transferred = 0;
            if unsafe {
                GetOverlappedResult(pipe.as_raw_handle(), &self.state, &mut transferred, 0)
            } == 0
            {
                return Err(classify(io::Error::last_os_error()));
            }
            check_deadline(deadline)?;
            return Ok(transferred);
        }
        let wait = wait_until(&self.event, deadline);
        if matches!(wait, Ok(WaitOutcome::Signaled)) {
            let mut transferred = 0;
            if unsafe {
                GetOverlappedResult(pipe.as_raw_handle(), &self.state, &mut transferred, 0)
            } == 0
            {
                return Err(classify(io::Error::last_os_error()));
            }
            check_deadline(deadline)?;
            return Ok(transferred);
        }
        let failure = match wait {
            Ok(WaitOutcome::TimedOut) => ServiceTransportError::Deadline,
            Err(error) => error.into(),
            Ok(_) => io::Error::other("pipe event reported abandonment").into(),
        };
        // Cancellation may race ordinary completion. ERROR_NOT_FOUND is only
        // accepted after the exact operation has also been drained below.
        let cancellation = if unsafe { CancelIoEx(pipe.as_raw_handle(), &self.state) } == 0 {
            let error = io::Error::last_os_error();
            (error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)).then_some(error)
        } else {
            None
        };
        let mut transferred = 0;
        // Do not free an OVERLAPPED or buffer on cancellation acknowledgement
        // alone. A delayed driver keeps this worker alive, not a false receipt.
        let completion = if unsafe {
            GetOverlappedResult(pipe.as_raw_handle(), &self.state, &mut transferred, 1)
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
}

fn classify(error: io::Error) -> ServiceTransportError {
    if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
        ServiceTransportError::MessageLength
    } else {
        error.into()
    }
}

pub(super) fn connect(pipe: &OwnedHandle, deadline: Instant) -> Result<(), ServiceTransportError> {
    check_deadline(deadline)?;
    let mut operation = Operation::new()?;
    let started = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), &mut operation.state) } != 0;
    let error = io::Error::last_os_error();
    if !started && error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
        return check_deadline(deadline);
    }
    operation.complete(pipe, started, error, deadline)?;
    Ok(())
}

pub(super) fn read(
    pipe: &OwnedHandle,
    deadline: Instant,
) -> Result<ServicePayload, ServiceTransportError> {
    check_deadline(deadline)?;
    let mut bytes = Zeroizing::new(vec![0; MAX_MESSAGE]);
    let mut operation = Operation::new()?;
    let started = unsafe {
        ReadFile(
            pipe.as_raw_handle(),
            bytes.as_mut_ptr(),
            MAX_MESSAGE as u32,
            null_mut(),
            &mut operation.state,
        )
    } != 0;
    let error = io::Error::last_os_error();
    let length = operation.complete(pipe, started, error, deadline)? as usize;
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
    check_deadline(deadline)?;
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return Err(ServiceTransportError::MessageLength);
    }
    let mut operation = Operation::new()?;
    let started = unsafe {
        WriteFile(
            pipe.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            null_mut(),
            &mut operation.state,
        )
    } != 0;
    let error = io::Error::last_os_error();
    let length = operation.complete(pipe, started, error, deadline)? as usize;
    if length != bytes.len() {
        return Err(ServiceTransportError::MessageLength);
    }
    Ok(())
}
