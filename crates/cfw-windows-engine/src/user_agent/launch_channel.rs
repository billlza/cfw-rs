//! One inherited launch frame and its decode acknowledgement. This channel
//! grants no Authority lease and does not report that an engine is running.
//! Both endpoints run on native workers; cancellation drains kernel I/O before
//! releasing buffers, so a delayed driver can outlive the requested deadline.
use super::handoff::{HandoffError, LaunchMessage, MAX_FRAME_BYTES, UserAgentLaunch};
use crate::{
    NativePeerProcess, PeerIdentityError, ServiceTransportError, VerifiedExecutable,
    service_transport::{check_deadline, native_io},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::Pipes::{
        CreateNamedPipeW, GetNamedPipeHandleStateW, GetNamedPipeInfo, PIPE_READMODE_MESSAGE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_SERVER_END, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        SetNamedPipeHandleState,
    },
};

const ACK_PREFIX: &[u8] = b"cfw.launch.received.v1\0";
const ACK_BYTES: usize = ACK_PREFIX.len() + 32;

#[derive(Debug, thiserror::Error)]
pub enum LaunchChannelError {
    #[error("Windows launch channel I/O: {0}")]
    Io(#[from] io::Error),
    #[error("Windows launch channel transport: {0}")]
    Transport(#[from] ServiceTransportError),
    #[error("Windows launch channel peer: {0}")]
    Peer(#[from] PeerIdentityError),
    #[error("Windows launch channel frame: {0}")]
    Frame(#[from] HandoffError),
    #[error("Windows launch channel identity or inherited endpoint is invalid")]
    Identity,
    #[error("Windows launch acknowledgement does not match the sent frame")]
    Acknowledgement,
}
pub type Result<T> = std::result::Result<T, LaunchChannelError>;

/// Sender is consumed even on failure. Its acknowledgement proves only that
/// the receiving endpoint decoded this frame. The caller must retain and
/// supervise its launched process, and resolve uncertain outcomes through
/// Authority rather than retrying the ticket or assuming no engine was started.
pub struct LaunchSender {
    pipe: OwnedHandle,
}

impl LaunchSender {
    /// Create both connected endpoints in the trusted launcher. Neither is
    /// inheritable yet. The caller inherits only the returned receiver through
    /// an explicit process handle list and drops its local copy after spawn.
    /// No pipe name, configuration, key or ticket enters the command line.
    pub fn create() -> Result<(Self, OwnedHandle)> {
        let current = user()?;
        let name = format!(r"\\.\pipe\cfw-launch-{}", uuid::Uuid::new_v4());
        let server = create_server(&name, current.identity().user_sid())?;
        let mut pending = native_io::PendingAccept::new(server)?;
        let name: Vec<_> = name.encode_utf16().chain([0]).collect();
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
        let receiver = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mode = PIPE_READMODE_MESSAGE;
        if unsafe { SetNamedPipeHandleState(receiver.as_raw_handle(), &mode, null(), null()) } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        pending.wait(Instant::now() + Duration::from_secs(5))?;
        let pipe = pending.into_pipe()?;
        current.verify_pipe_server(&receiver)?;
        Ok((Self { pipe }, receiver))
    }
    pub fn send(
        self,
        message: LaunchMessage,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<()> {
        user()?;
        check_deadline(deadline)?;
        let expected = acknowledgement(message.as_bytes());
        native_io::write_bounded(
            &self.pipe,
            message.as_bytes(),
            deadline,
            MAX_FRAME_BYTES,
            Some(cancel),
        )?;
        let received = native_io::read_bounded(&self.pipe, deadline, ACK_BYTES, Some(cancel))?;
        if received.as_bytes() != expected {
            return Err(LaunchChannelError::Acknowledgement);
        }
        Ok(())
    }
}

pub struct LaunchReceiver {
    pipe: OwnedHandle,
    parent: NativePeerProcess,
    expected_parent: Arc<VerifiedExecutable>,
}
impl LaunchReceiver {
    /// The expected Desktop image comes from trusted installation state, never
    /// the launch frame. Take a separately owned duplicate of inherited stdin
    /// if another runtime component also owns the process's standard handle.
    pub fn from_inherited(
        pipe: OwnedHandle,
        expected_parent: Arc<VerifiedExecutable>,
    ) -> Result<Self> {
        let current = user()?;
        let mut flags = 0;
        if unsafe {
            GetNamedPipeInfo(
                pipe.as_raw_handle(),
                &mut flags,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let mut state = 0;
        if unsafe {
            GetNamedPipeHandleStateW(
                pipe.as_raw_handle(),
                &mut state,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if flags & PIPE_SERVER_END != 0
            || flags & PIPE_TYPE_MESSAGE == 0
            || state & PIPE_READMODE_MESSAGE == 0
        {
            return Err(LaunchChannelError::Identity);
        }
        let parent = NativePeerProcess::from_pipe_server(&pipe)?;
        if parent.identity().user_session() != current.identity().user_session()
            || parent.identity().integrity_rid() < 0x2000
            || parent.identity().is_app_container()
            || parent.identity().is_restricted()
        {
            return Err(LaunchChannelError::Identity);
        }
        parent.verify_executable(&expected_parent)?;
        Ok(Self {
            pipe,
            parent,
            expected_parent,
        })
    }
    pub fn receive(self, deadline: Instant, cancel: &AtomicBool) -> Result<UserAgentLaunch> {
        user()?;
        check_deadline(deadline)?;
        self.parent.verify_pipe_server(&self.pipe)?;
        self.parent.verify_executable(&self.expected_parent)?;
        let frame = native_io::read_bounded(&self.pipe, deadline, MAX_FRAME_BYTES, Some(cancel))?;
        let launch = UserAgentLaunch::decode(frame.as_bytes())?;
        self.parent.verify_pipe_server(&self.pipe)?;
        self.parent.verify_executable(&self.expected_parent)?;
        native_io::write_bounded(
            &self.pipe,
            &acknowledgement(frame.as_bytes()),
            deadline,
            ACK_BYTES,
            Some(cancel),
        )?;
        Ok(launch)
    }
}

fn acknowledgement(frame: &[u8]) -> [u8; ACK_BYTES] {
    let mut value = [0; ACK_BYTES];
    value[..ACK_PREFIX.len()].copy_from_slice(ACK_PREFIX);
    value[ACK_PREFIX.len()..].copy_from_slice(&Sha256::digest(frame));
    value
}
fn user() -> Result<NativePeerProcess> {
    let current = NativePeerProcess::open(std::process::id())?;
    let identity = current.identity();
    if identity.session_id() == 0
        || identity.integrity_rid() < 0x2000
        || identity.is_app_container()
        || identity.is_restricted()
        || matches!(identity.user_sid(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
    {
        return Err(LaunchChannelError::Identity);
    }
    Ok(current)
}
struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn create_server(name: &str, sid: &str) -> Result<OwnedHandle> {
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
    let name: Vec<_> = name.encode_utf16().chain([0]).collect();
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            8192,
            8192,
            0,
            &security,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

#[cfg(test)]
mod tests;
