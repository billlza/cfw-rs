//! Deliberately bypasses the product client writer to exercise hostile wire
//! sizes and per-message thread identity. Disposable fixture data only.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, READ_CONTROL,
        SECURITY_CONTEXT_TRACKING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::Pipes::{GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, SetNamedPipeHandleState},
};

fn connection(name: &str, pid: u32) -> Result<File> {
    let deadline = Instant::now() + LIMIT;
    let pipe = loop {
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
            )
            .security_qos_flags(
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_CONTEXT_TRACKING,
            )
            .open(format!(r"\\.\pipe\{name}.desktop"));
        match opened {
            Ok(pipe) => break pipe,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(format!("open adversarial fixture pipe: {error}")),
        }
    };
    let mut actual = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut actual) } == 0 {
        return Err(error("query adversarial fixture server"));
    }
    if actual != pid {
        return Err("adversarial fixture reached a different process".into());
    }
    if unsafe {
        SetNamedPipeHandleState(pipe.as_raw_handle(), &PIPE_READMODE_MESSAGE, null(), null())
    } == 0
    {
        return Err(error("select adversarial fixture message mode"));
    }
    Ok(pipe)
}

fn write_one(pipe: &mut File, body: &[u8]) -> Result<()> {
    let length = pipe.write(body).map_err(|e| e.to_string())?;
    if length != body.len() {
        return Err("fixture message was written only in part".into());
    }
    Ok(())
}

fn require_closed(pipe: &mut File) -> Result<()> {
    let mut reply = [0; 16];
    match pipe.read(&mut reply) {
        Ok(0) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => Ok(()),
        Err(error) => Err(format!(
            "rejected fixture pipe returned a different error: {error}"
        )),
        Ok(_) => Err("rejected fixture message received a response".into()),
    }
}

pub(super) fn queued_identity(root: &Path, name: &str, pid: u32) -> Result<()> {
    let mut pipe = connection(name, pid)?;
    write_one(&mut pipe, b"identity-probe")?;
    let mut reply = [0; 5];
    pipe.read_exact(&mut reply).map_err(|e| e.to_string())?;
    if reply != *b"ready" {
        return Err("queued identity fixture was not ready".into());
    }
    // Both messages are queued before the server reads. A prefetched second
    // message must not substitute its primary identity for the first one.
    restricted::with_medium_impersonation(|| write_one(&mut pipe, b"ping"))?;
    write_one(&mut pipe, b"ping")?;
    let ready = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("identity-probe.ready"))
        .map_err(|e| e.to_string())?;
    ready.sync_all().map_err(|e| e.to_string())?;
    require_closed(&mut pipe)?;
    transport::require_rejection(
        root,
        name,
        ServiceClientRole::Desktop,
        "message_identity_changed",
    )
}

pub(super) fn oversized(root: &Path, name: &str, pid: u32) -> Result<()> {
    let mut pipe = connection(name, pid)?;
    let message = vec![b'x'; cfw_engine_api::authority_v1::MAX_ENVELOPE_BYTES + 1];
    match pipe.write(&message) {
        Ok(length) if length == message.len() => {}
        Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => {}
        Err(error) => {
            return Err(format!(
                "oversized fixture write failed unexpectedly: {error}"
            ));
        }
        Ok(_) => return Err("oversized fixture message was written only in part".into()),
    }
    require_closed(&mut pipe)?;
    transport::require_rejection(root, name, ServiceClientRole::Desktop, "message_length")
}

pub(super) fn server_deadline(root: &Path, name: &str, pid: u32) -> Result<()> {
    let mut pipe = connection(name, pid)?;
    require_closed(&mut pipe)?;
    transport::require_rejection(root, name, ServiceClientRole::Desktop, "message_deadline")
}

pub(super) fn client_deadline(name: &str, image: &Path, expected: [u8; 32]) -> Result<()> {
    let mut pipe =
        LocalServicePipe::open(name, ServiceClientRole::Desktop).map_err(|e| e.to_string())?;
    let peer = WindowsServicePeer::from_pipe_server(name, verified(image, expected)?, &pipe)
        .map_err(|e| e.to_string())?;
    match pipe.read_message(Instant::now() + Duration::from_millis(100)) {
        Err(ServiceTransportError::Deadline) => {}
        Err(error) => {
            return Err(format!(
                "client deadline returned a different failure: {error}"
            ));
        }
        Ok(_) => return Err("client received an unsolicited fixture message".into()),
    }
    assert!(matches!(
        peer.verify_pipe_server(&pipe),
        Err(ServicePeerError::ConnectionClosed)
    ));
    assert!(matches!(
        pipe.read_message(Instant::now() + LIMIT),
        Err(ServiceTransportError::Closed)
    ));
    Ok(())
}
