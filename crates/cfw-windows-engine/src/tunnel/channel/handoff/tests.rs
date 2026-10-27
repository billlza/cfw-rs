use super::*;
use std::ptr::null;
use windows_sys::Win32::{
    Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        SetNamedPipeHandleState,
    },
};

#[test]
fn ordinary_user_cannot_create_packet_handoff_probes() {
    let peer = NativePeerProcess::open(std::process::id()).unwrap();
    assert!(!peer.identity().is_local_system());
    assert!(matches!(
        EndpointHandoff::create_for(uuid::Uuid::new_v4(), 1500, &peer),
        Err(HandoffError::Service(_))
    ));
}

#[test]
fn packet_handoff_access_matches_the_engine_host_contract() {
    const ENGINE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../native/windows/engine-host/packet_windows_test.go"
    ));
    let declarations: Vec<_> = ENGINE
        .lines()
        .filter_map(|line| line.strip_prefix("const handoffEndpointAccess = "))
        .collect();
    assert_eq!(declarations, [format!("{ENDPOINT_ACCESS:#010x}")]);
    assert_eq!(ENDPOINT_ACCESS, 0x0010_0083);
}

/// A pipe pair with the given server mode, instance limit and buffers; the
/// client end optionally switched to `client_mode`.
fn pair(
    mode: u32,
    instances: u32,
    buffer: u32,
    client_mode: Option<u32>,
) -> (OwnedHandle, OwnedHandle) {
    let name: Vec<u16> = format!(r"\\.\pipe\cfw-handoff-test-{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain([0])
        .collect();
    let server = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            mode | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            instances,
            buffer,
            buffer,
            0,
            null(),
        )
    };
    assert_ne!(
        server,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    let server = unsafe { OwnedHandle::from_raw_handle(server) };
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | SYNCHRONIZE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    assert_ne!(
        client,
        INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    if let Some(mode) = client_mode {
        assert_ne!(
            unsafe { SetNamedPipeHandleState(client.as_raw_handle(), &mode, null(), null()) },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }
    (server, client)
}

#[test]
fn packet_handoff_accepts_only_a_message_pipe_client_end() {
    let message = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE;
    let (_server, client) = pair(message, 1, 64 * 1024, Some(PIPE_READMODE_MESSAGE));
    require_endpoint_pipe(client.as_raw_handle(), 1500).unwrap();
    require_endpoint_pipe(client.as_raw_handle(), 9000).unwrap();
    let refused = [
        // A byte pipe, and a message pipe read in byte or nonblocking mode.
        pair(PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 64 * 1024, None),
        pair(message, 1, 64 * 1024, None),
        pair(
            message,
            1,
            64 * 1024,
            Some(PIPE_READMODE_MESSAGE | PIPE_NOWAIT),
        ),
        // A second instance could be opened by another process.
        pair(message, 2, 64 * 1024, Some(PIPE_READMODE_MESSAGE)),
        // Buffers larger than the engine host accepts.
        pair(message, 1, 256 * 1024, Some(PIPE_READMODE_MESSAGE)),
    ];
    for (index, (_server, client)) in refused.iter().enumerate() {
        assert!(
            matches!(
                require_endpoint_pipe(client.as_raw_handle(), 1500),
                Err(HandoffError::Substituted)
            ),
            "case {index}"
        );
    }
    // Buffers smaller than the packet MTU cannot carry a full packet.
    let (_server, small) = pair(message, 1, 8 * 1024, Some(PIPE_READMODE_MESSAGE));
    require_endpoint_pipe(small.as_raw_handle(), 1500).unwrap();
    assert!(matches!(
        require_endpoint_pipe(small.as_raw_handle(), 9000),
        Err(HandoffError::Substituted)
    ));
    // The server end reports PIPE_SERVER_END, which no client end carries.
    let (server, _client) = pair(message, 1, 64 * 1024, Some(PIPE_READMODE_MESSAGE));
    assert!(matches!(
        require_endpoint_pipe(server.as_raw_handle(), 1500),
        Err(HandoffError::Substituted)
    ));
    let event =
        unsafe { windows_sys::Win32::System::Threading::CreateEventW(null(), 0, 0, null()) };
    assert!(!event.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    assert!(matches!(
        require_endpoint_pipe(event.as_raw_handle(), 1500),
        Err(HandoffError::Native { .. })
    ));
}

#[test]
fn packet_handoff_local_copy_keeps_the_object_and_its_access() {
    let (_server, client) = PacketServer::create(uuid::Uuid::new_v4(), 1500).unwrap();
    require_endpoint_pipe(client.handle.as_raw_handle(), 1500).unwrap();
    let copy = duplicate_local(client.handle.as_raw_handle()).unwrap();
    assert_ne!(copy.as_raw_handle(), client.handle.as_raw_handle());
    assert_ne!(
        unsafe { CompareObjectHandles(copy.as_raw_handle(), client.handle.as_raw_handle()) },
        0
    );
    let mut flags = 0;
    assert_ne!(
        unsafe { GetHandleInformation(copy.as_raw_handle(), &mut flags) },
        0
    );
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    require_endpoint_pipe(copy.as_raw_handle(), 1500).unwrap();
}
