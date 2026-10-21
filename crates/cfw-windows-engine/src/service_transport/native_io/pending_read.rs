//! One owned message read whose poll timeout does not cancel kernel I/O.
//! Packet pumps can check their driver and lifecycle between polls without
//! discarding a message that completed at the polling deadline.
use super::*;
use std::sync::Arc;
use windows_sys::Win32::Foundation::ERROR_HANDLE_EOF;

pub(crate) struct PendingMessageRead {
    pipe: Arc<OwnedHandle>,
    operation: Box<Operation>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    pending: bool,
    completed: Option<Result<u32, ServiceTransportError>>,
}

// SAFETY: the unique operation owns its initialized buffer, event and retained
// pipe. Buffer storage and boxed OVERLAPPED addresses stay fixed while pending.
// Only the kernel writes them until completion; moving this owner to a worker
// does not access the buffer or transfer a thread-affine completion callback.
// Poll/retire require exclusive access. This does not grant Sync.
unsafe impl Send for PendingMessageRead {}

fn expected_teardown(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if [
        ERROR_OPERATION_ABORTED, ERROR_BROKEN_PIPE, ERROR_NO_DATA,
        ERROR_PIPE_NOT_CONNECTED, ERROR_HANDLE_EOF,
    ].contains(&(code as u32)))
}

impl PendingMessageRead {
    pub(crate) fn new(
        pipe: Arc<OwnedHandle>,
        maximum: usize,
    ) -> Result<Self, ServiceTransportError> {
        if maximum == 0 || maximum > 4 * MAX_MESSAGE {
            return Err(ServiceTransportError::MessageLength);
        }
        let mut value = Self {
            pipe,
            operation: Box::new(Operation::new()?),
            bytes: Some(Zeroizing::new(vec![0; maximum])),
            pending: false,
            completed: None,
        };
        // The owner exists before submission: no error path may release a
        // buffer/OVERLAPPED while its exact operation is still in flight.
        let bytes = value.bytes.as_mut().ok_or(ServiceTransportError::Closed)?;
        let started = unsafe {
            ReadFile(
                value.pipe.as_raw_handle(),
                bytes.as_mut_ptr(),
                maximum as u32,
                null_mut(),
                value.operation.state.get(),
            )
        } != 0;
        if started {
            value.pending = true;
            value.observe_completion();
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
                value.pending = true;
            } else {
                value.completed = Some(Err(classify(error)));
            }
        }
        Ok(value)
    }

    fn observe_completion(&mut self) {
        let mut transferred = 0;
        if unsafe {
            GetOverlappedResult(
                self.pipe.as_raw_handle(),
                self.operation.state.get(),
                &mut transferred,
                0,
            )
        } != 0
        {
            self.pending = false;
            self.completed = Some(Ok(transferred));
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
                self.pending = false;
                self.completed = Some(Err(classify(error)));
            }
        }
    }

    pub(crate) fn poll(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<ServicePayload>, ServiceTransportError> {
        // An elapsed poll deadline means a nonblocking observation, not a
        // failed RPC. Scheduling delay must not poison an idle packet pump.
        if deadline
            .checked_duration_since(Instant::now())
            .is_some_and(|remaining| remaining > MAX_IO_TIME)
        {
            return Err(ServiceTransportError::Deadline);
        }
        if self.bytes.is_none() {
            return Err(ServiceTransportError::Closed);
        }
        loop {
            if cancel.load(Ordering::Acquire) {
                return match self.retire() {
                    Ok(()) => Err(ServiceTransportError::Cancelled),
                    Err(cleanup) => Err(ServiceTransportError::Cleanup {
                        operation: Box::new(ServiceTransportError::Cancelled),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
            if self.pending {
                self.observe_completion();
            }
            if !self.pending {
                let result = self.completed.take().ok_or(ServiceTransportError::Closed)?;
                let bytes = self.bytes.take().ok_or(ServiceTransportError::Closed)?;
                let length = result? as usize;
                if length == 0 || length > bytes.len() {
                    return Err(ServiceTransportError::MessageLength);
                }
                return Ok(Some(ServicePayload { bytes, length }));
            }
            let poll = deadline.min(Instant::now() + Duration::from_millis(25));
            match wait_until(&self.operation.event, poll)? {
                WaitOutcome::Signaled => {
                    self.observe_completion();
                    if self.pending {
                        return Err(io::Error::other(
                            "packet read event signaled without native completion",
                        )
                        .into());
                    }
                }
                WaitOutcome::TimedOut if Instant::now() < deadline => {}
                WaitOutcome::TimedOut => return Ok(None),
                _ => return Err(io::Error::other("packet read event was abandoned").into()),
            }
        }
    }

    /// Explicit teardown. Completion, including a peer closing during
    /// cancellation, is required before the buffer can be released.
    pub(crate) fn retire(&mut self) -> Result<(), ServiceTransportError> {
        if !self.pending {
            self.bytes.take();
            return match self.completed.take() {
                Some(Err(ServiceTransportError::Io(error))) if expected_teardown(&error) => Ok(()),
                Some(Err(error)) => Err(error),
                _ => Ok(()),
            };
        }
        let cancellation =
            if unsafe { CancelIoEx(self.pipe.as_raw_handle(), self.operation.state.get()) } == 0 {
                let error = io::Error::last_os_error();
                (error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)).then_some(error)
            } else {
                None
            };
        let mut transferred = 0;
        let completion = if unsafe {
            GetOverlappedResult(
                self.pipe.as_raw_handle(),
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
            if error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
                self.pending = false;
            }
            // These are terminal results of deliberate teardown, never
            // successful packet reads. Other native failures are preserved.
            (!expected_teardown(&error)).then_some(error)
        };
        if !self.pending {
            self.bytes.take();
            self.completed.take();
        }
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

impl Drop for PendingMessageRead {
    fn drop(&mut self) {
        // An emergency Drop proves no lifecycle success. A still-live kernel
        // write cannot be left pointing at a freed packet buffer.
        if self.retire().is_err() && self.pending {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Arc<OwnedHandle>, OwnedHandle) {
        let owner = NativePeerProcess::open(std::process::id()).unwrap();
        let (server, client) = connected_pair(&owner, "packets", 65536).unwrap();
        (Arc::new(server), client)
    }

    #[test]
    fn packet_poll_timeout_retains_operation_across_worker_transfer() {
        let (server, client) = pair();
        let mut read = PendingMessageRead::new(server, 128).unwrap();
        assert!(read.pending);
        assert!(
            read.poll(Instant::now(), &AtomicBool::new(false))
                .unwrap()
                .is_none()
        );
        assert!(
            read.poll(
                Instant::now() + Duration::from_millis(20),
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_none()
        );
        assert!(read.pending);
        let buffer = read.bytes.as_ref().unwrap().as_ptr() as usize;
        let state = read.operation.state.get() as usize;
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            assert_eq!(read.bytes.as_ref().unwrap().as_ptr() as usize, buffer);
            assert_eq!(read.operation.state.get() as usize, state);
            ready.send(()).unwrap();
            let result = read
                .poll(
                    Instant::now() + Duration::from_secs(5),
                    &AtomicBool::new(false),
                )
                .unwrap()
                .unwrap();
            assert_eq!(result.as_bytes(), b"retained-packet");
            assert!(!read.pending);
            assert!(
                read.poll(
                    Instant::now() + Duration::from_secs(1),
                    &AtomicBool::new(false)
                )
                .is_err()
            );
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        write_bounded(
            &client,
            b"retained-packet",
            Instant::now() + Duration::from_secs(5),
            128,
            None,
        )
        .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn packet_cancellation_drains_before_the_buffer_is_released() {
        let (server, client) = pair();
        let mut read = PendingMessageRead::new(Arc::clone(&server), 128).unwrap();
        assert!(read.pending);
        assert!(matches!(
            read.poll(
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(true)
            ),
            Err(ServiceTransportError::Cancelled)
        ));
        assert!(!read.pending && read.bytes.is_none());
        drop(read);
        write_bounded(
            &client,
            b"after-retirement",
            Instant::now() + Duration::from_secs(5),
            128,
            None,
        )
        .unwrap();
        let mut next = PendingMessageRead::new(server, 128).unwrap();
        let result = next
            .poll(
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        assert_eq!(result.as_bytes(), b"after-retirement");
    }

    #[test]
    fn packet_oversized_message_fails_without_returning_a_prefix() {
        let (server, client) = pair();
        write_bounded(
            &client,
            b"long",
            Instant::now() + Duration::from_secs(5),
            128,
            None,
        )
        .unwrap();
        let mut read = PendingMessageRead::new(server, 3).unwrap();
        assert!(matches!(
            read.poll(
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false)
            ),
            Err(ServiceTransportError::MessageLength)
        ));
        assert!(!read.pending && read.bytes.is_none());
    }

    #[test]
    fn packet_cancellation_keeps_an_already_completed_protocol_failure() {
        let (server, client) = pair();
        write_bounded(
            &client,
            b"long",
            Instant::now() + Duration::from_secs(5),
            128,
            None,
        )
        .unwrap();
        let mut read = PendingMessageRead::new(server, 3).unwrap();
        if read.pending {
            assert!(matches!(
                wait_until(
                    &read.operation.event,
                    Instant::now() + Duration::from_secs(5)
                )
                .unwrap(),
                WaitOutcome::Signaled
            ));
            read.observe_completion();
        }
        assert!(matches!(
            &read.completed,
            Some(Err(ServiceTransportError::MessageLength))
        ));
        assert!(
            matches!(read.poll(Instant::now() + Duration::from_secs(5), &AtomicBool::new(true)),
            Err(ServiceTransportError::Cleanup { operation, cleanup })
                if matches!(*operation, ServiceTransportError::Cancelled)
                    && matches!(*cleanup, ServiceTransportError::MessageLength))
        );
        assert!(!read.pending && read.bytes.is_none());
    }
}
