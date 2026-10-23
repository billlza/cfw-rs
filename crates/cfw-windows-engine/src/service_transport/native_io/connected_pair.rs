//! Private endpoints connected by their creating process before inheritance.
//! This establishes native object ownership, not a runtime/privileged lease.
use super::*;
use windows_sys::Win32::{
    Storage::FileSystem::{
        CreateFileW, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::Pipes::SetNamedPipeHandleState,
};

pub(crate) fn connected_pair(
    owner: &NativePeerProcess,
    purpose: &'static str,
    capacity: u32,
) -> Result<(OwnedHandle, OwnedHandle), ServiceTransportError> {
    if owner.process_id() != std::process::id() {
        return Err(ServiceTransportError::ClientIdentity);
    }
    if !matches!(purpose, "launch" | "packets") {
        return Err(ServiceTransportError::RequestOrder);
    }
    if !(8192..=128 * 1024).contains(&capacity) {
        return Err(ServiceTransportError::MessageLength);
    }
    owner.revalidate()?;
    let sid = owner.identity().user_sid();
    let sddl: Vec<_> = format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut raw_descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut raw_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = Descriptor(raw_descriptor);
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name: Vec<_> = format!(r"\\.\pipe\cfw-{purpose}-{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain([0])
        .collect();
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            capacity,
            capacity,
            0,
            &security,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    let mut pending = PendingAccept::new(unsafe { OwnedHandle::from_raw_handle(raw) })?;
    let raw = unsafe {
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
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    let client = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mode = PIPE_READMODE_MESSAGE;
    if unsafe { SetNamedPipeHandleState(client.as_raw_handle(), &mode, null(), null()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    pending.wait(Instant::now() + Duration::from_secs(5))?;
    let server = pending.into_pipe()?;
    owner.verify_pipe_server(&client)?;
    owner.verify_pipe_client(&server)?;
    Ok((server, client))
}
