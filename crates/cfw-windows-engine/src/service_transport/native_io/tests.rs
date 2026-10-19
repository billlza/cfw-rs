use super::*;

fn pending_listener() -> (String, PendingAccept) {
    // This is an ordinary-user I/O test, not service/role admission. The raw
    // endpoint is unique and restricted to the current user; no SYSTEM trust
    // check or product listener construction is bypassed by shipped code.
    let name = format!("CFW-accept-{}", uuid::Uuid::new_v4());
    let peer = NativePeerProcess::open(std::process::id()).unwrap();
    let sddl: Vec<_> = format!("D:P(A;;GA;;;{})", peer.identity().user_sid())
        .encode_utf16()
        .chain([0])
        .collect();
    let mut raw_descriptor = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw_descriptor,
                null_mut(),
            )
        },
        0
    );
    let descriptor = Descriptor(raw_descriptor);
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path: Vec<_> = service_pipe_name(&name, ServiceClientRole::Desktop)
        .unwrap()
        .encode_utf16()
        .chain([0])
        .collect();
    let raw = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            16384,
            16384,
            0,
            &security,
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
    let server = unsafe { OwnedHandle::from_raw_handle(raw) };
    (name, PendingAccept::new(server).unwrap())
}

#[test]
fn accept_poll_expiry_keeps_a_completed_client_for_the_next_poll() {
    let (name, mut pending) = pending_listener();
    assert!(matches!(
        pending.wait(Instant::now() + Duration::from_millis(20)),
        Err(ServiceTransportError::Deadline)
    ));
    let mut client = LocalServicePipe::open(&name, ServiceClientRole::Desktop).unwrap();
    assert!(matches!(
        wait_until(
            &pending.operation.event,
            Instant::now() + Duration::from_secs(5)
        )
        .unwrap(),
        WaitOutcome::Signaled
    ));
    // The kernel has completed the connection, but the server only observes it
    // after its poll budget. Expiry must not discard this client's next write.
    assert!(matches!(
        pending.wait(Instant::now()),
        Err(ServiceTransportError::Deadline)
    ));
    pending
        .wait(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let server = pending.into_pipe().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    client.write_message(b"pending-client", deadline).unwrap();
    assert_eq!(
        read(&server, deadline).unwrap().as_bytes(),
        b"pending-client"
    );
    write(&server, b"admitted", deadline).unwrap();
    assert_eq!(
        client.read_message(deadline).unwrap().as_bytes(),
        b"admitted"
    );
}

#[test]
fn pending_accept_is_cancelled_and_drained_after_worker_transfer() {
    let (name, mut pending) = pending_listener();
    assert!(matches!(
        pending.wait(Instant::now() + Duration::from_millis(20)),
        Err(ServiceTransportError::Deadline)
    ));
    std::thread::spawn(move || {
        pending.retire().unwrap();
        drop(pending);
    })
    .join()
    .unwrap();
    assert!(
        matches!(LocalServicePipe::open(&name, ServiceClientRole::Desktop), Err(ServicePeerError::Native { source, .. }) if source.raw_os_error() == Some(2))
    );
}

#[test]
fn explicit_cancellation_drains_an_already_pending_native_read() {
    let (name, mut pending) = pending_listener();
    let _client = LocalServicePipe::open(&name, ServiceClientRole::Desktop).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    pending.wait(deadline).unwrap();
    let server = pending.into_pipe().unwrap();
    let mut bytes = Zeroizing::new(vec![0; 128]);
    let operation = Operation::new().unwrap();
    let started = unsafe {
        ReadFile(
            server.as_raw_handle(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            null_mut(),
            operation.state.get(),
        )
    } != 0;
    let error = io::Error::last_os_error();
    assert!(!started);
    assert_eq!(error.raw_os_error(), Some(ERROR_IO_PENDING as i32));
    assert!(matches!(
        operation.complete(
            &server,
            started,
            error,
            deadline,
            Some(&AtomicBool::new(true))
        ),
        Err(ServiceTransportError::Cancelled)
    ));
    let mut transferred = 0;
    assert_eq!(
        unsafe {
            GetOverlappedResult(
                server.as_raw_handle(),
                operation.state.get(),
                &mut transferred,
                0,
            )
        },
        0
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_OPERATION_ABORTED as i32)
    );
}

#[test]
fn explicit_cancellation_drains_an_already_pending_full_pipe_write() {
    let (name, mut pending) = pending_listener();
    let _client = LocalServicePipe::open(&name, ServiceClientRole::Desktop).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    pending.wait(deadline).unwrap();
    let server = pending.into_pipe().unwrap();
    let bytes = Zeroizing::new(vec![7; MAX_MESSAGE]);
    let operation = Operation::new().unwrap();
    let started = unsafe {
        WriteFile(
            server.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            null_mut(),
            operation.state.get(),
        )
    } != 0;
    let error = io::Error::last_os_error();
    assert!(!started);
    assert_eq!(error.raw_os_error(), Some(ERROR_IO_PENDING as i32));
    assert!(matches!(
        operation.complete(
            &server,
            started,
            error,
            deadline,
            Some(&AtomicBool::new(true))
        ),
        Err(ServiceTransportError::Cancelled)
    ));
    let mut transferred = 0;
    assert_eq!(
        unsafe {
            GetOverlappedResult(
                server.as_raw_handle(),
                operation.state.get(),
                &mut transferred,
                0,
            )
        },
        0
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_OPERATION_ABORTED as i32)
    );
}
