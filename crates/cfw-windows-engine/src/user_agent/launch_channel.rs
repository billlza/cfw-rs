//! An inherited launch frame and its decode acknowledgement. Installed owners
//! retain the same private channel for fresh, correlated runtime observations.
//! The launch acknowledgement alone never attests an engine or grants a lease.
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
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr::null_mut,
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeHandleStateW, GetNamedPipeInfo, PIPE_READMODE_MESSAGE, PIPE_SERVER_END,
    PIPE_TYPE_MESSAGE,
};

const ACK_PREFIX: &[u8] = b"cfw.launch.received.v1\0";
const ACK_BYTES: usize = ACK_PREFIX.len() + 32;
/// Sent by the launched Agent once its own installed images and private
/// storage are admitted. The launcher prepares the lease only after reading
/// it, so the Authority's fixed preparation lifetime covers the launch
/// handoff and Bind alone, never the Agent's cold admission.
const ADMITTED: &[u8] = b"cfw.launch.admitted.v1\0";
mod observation;
pub(crate) use observation::{ObservationClient, ObservationServer};

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
    #[error("Windows launch admission announcement is invalid")]
    Admission,
    #[error("Windows runtime observation is malformed, stale or unrelated")]
    Observation,
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
        let (pipe, receiver) = native_io::connected_pair(&current, "launch", 8192)?;
        Ok((Self { pipe }, receiver))
    }
    /// Wait for the launched Agent's admission announcement. Nothing has been
    /// sent yet: a timeout or a foreign message leaves no ticket with the Agent.
    pub fn await_admission(&self, deadline: Instant, cancel: &AtomicBool) -> Result<()> {
        user()?;
        check_deadline(deadline)?;
        let received = native_io::read_bounded(&self.pipe, deadline, ADMITTED.len(), Some(cancel))?;
        if received.as_bytes() != ADMITTED {
            return Err(LaunchChannelError::Admission);
        }
        Ok(())
    }
    pub fn send(
        self,
        message: LaunchMessage,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<()> {
        self.send_observed(message, deadline, cancel).map(|_| ())
    }
    pub(crate) fn send_observed(
        self,
        message: LaunchMessage,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<ObservationClient> {
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
        Ok(ObservationClient::new(self.pipe))
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
    /// Announce that this Agent finished admitting its installed images and
    /// private storage. The launcher prepares the lease only after this.
    pub fn announce_admitted(&self, deadline: Instant, cancel: &AtomicBool) -> Result<()> {
        user()?;
        check_deadline(deadline)?;
        self.parent.verify_pipe_server(&self.pipe)?;
        self.parent.verify_executable(&self.expected_parent)?;
        native_io::write_bounded(&self.pipe, ADMITTED, deadline, ADMITTED.len(), Some(cancel))?;
        Ok(())
    }
    pub fn receive(self, deadline: Instant, cancel: &AtomicBool) -> Result<UserAgentLaunch> {
        self.receive_observed(deadline, cancel)
            .map(|(launch, _)| launch)
    }
    pub(crate) fn receive_observed(
        self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(UserAgentLaunch, ObservationServer)> {
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
        Ok((launch, ObservationServer::new(self)))
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

#[cfg(test)]
mod tests;
