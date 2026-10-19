//! Role-scoped control transport on a dedicated native worker. It performs no
//! read-ahead: one ReadFile consumes one whole message, then native identity is
//! captured before another read. Runtime authorization is a separate layer.
use crate::connection_binding::ConnectionBinding;
use crate::service_peer::{
    SERVICE_PIPE_CLIENT_ACCESS, require_system_service_identity, service_pipe_name,
};
use crate::{
    LocalServicePipe, NativePeerIdentity, NativePeerProcess, PeerIdentityError, ServiceClientRole,
    ServicePeerError, VerifiedExecutable, WindowsServicePeer,
};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
        PIPE_WAIT,
    },
};
use zeroize::Zeroizing;

pub(crate) mod native_io;
const MAX_CONNECTIONS: usize = 15;
const MAX_MESSAGE: usize = cfw_engine_api::authority_v1::MAX_ENVELOPE_BYTES;
const MAX_IO_TIME: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum ServiceTransportError {
    #[error("Windows service transport native endpoint: {0}")]
    Endpoint(#[from] ServicePeerError),
    #[error("Windows service transport client identity: {0}")]
    Client(#[from] PeerIdentityError),
    #[error("Windows service transport I/O: {0}")]
    Io(#[from] io::Error),
    #[error("Windows service transport client is not an admissible desktop/user-agent identity")]
    ClientIdentity,
    #[error("Windows service transport message length is invalid")]
    MessageLength,
    #[error(
        "Windows service transport deadline expired or exceeds the allowed interval; delivery may be uncertain"
    )]
    Deadline,
    #[error("Windows local transport was cancelled; delivery may be uncertain")]
    Cancelled,
    #[error("Windows service transport connection is closed")]
    Closed,
    #[error("Windows service transport connection limit reached")]
    Capacity,
    #[error("Windows service transport request/reply order or connection does not match")]
    RequestOrder,
    #[error("Windows service transport operation failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}

/// Can contain credentials; no Debug, Clone or serde implementation. Keep the
/// full native read buffer initialized so every byte is zeroized on drop.
pub struct ServicePayload {
    bytes: Zeroizing<Vec<u8>>,
    length: usize,
}
impl ServicePayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    fn erase(&mut self) {
        use zeroize::Zeroize;
        self.bytes.as_mut_slice().zeroize();
        self.length = 0;
    }
}

pub struct AuthenticatedServiceRequest {
    body: ServicePayload,
    identity: NativePeerIdentity,
    role: ServiceClientRole,
    connection: ConnectionBinding,
    sequence: u64,
}
impl AuthenticatedServiceRequest {
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }
    /// After typed decoding, preserve native request/connection identity while
    /// erasing the raw secret-bearing copy before dispatch or journal mutation.
    pub(crate) fn erase_body(&mut self) {
        self.body.erase();
    }
    pub fn identity(&self) -> &NativePeerIdentity {
        &self.identity
    }
    pub fn role(&self) -> ServiceClientRole {
        self.role
    }
    pub(crate) fn binding(&self) -> ConnectionBinding {
        self.connection.clone()
    }
    pub(crate) fn is_pending(&self) -> bool {
        self.connection.has_pending(self.sequence)
    }
}

struct Slot(Arc<AtomicUsize>);
impl Slot {
    fn reserve(count: &Arc<AtomicUsize>) -> Result<Self, ServiceTransportError> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CONNECTIONS).then_some(current + 1)
            })
            .map_err(|_| ServiceTransportError::Capacity)?;
        Ok(Self(count.clone()))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Fixed role plus expected client image from the trusted installation. A
/// message cannot choose either. Configure service process observation first.
/// This is a blocking native-worker API, not an async UI-thread API.
pub struct LocalServiceListener {
    name: String,
    role: ServiceClientRole,
    expected_client: Arc<VerifiedExecutable>,
    waiting: Option<native_io::PendingAccept>,
    slots: Arc<AtomicUsize>,
}
impl LocalServiceListener {
    pub fn bind(
        service_name: &str,
        role: ServiceClientRole,
        expected_client: VerifiedExecutable,
    ) -> Result<Self, ServiceTransportError> {
        let name = service_pipe_name(service_name, role)?;
        require_system_service_identity()?;
        let waiting = native_io::PendingAccept::new(create_server(&name, true)?)?;
        Ok(Self {
            name,
            role,
            expected_client: Arc::new(expected_client),
            waiting: Some(waiting),
            slots: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn accept(
        &mut self,
        deadline: Instant,
    ) -> Result<LocalServiceConnection, ServiceTransportError> {
        check_deadline(deadline)?;
        require_system_service_identity()?;
        let slot = Slot::reserve(&self.slots)?;
        let connected = self
            .waiting
            .as_mut()
            .ok_or(ServiceTransportError::Closed)?
            .wait(deadline);
        if matches!(connected, Err(ServiceTransportError::Deadline)) {
            return Err(ServiceTransportError::Deadline);
        }
        let mut waiting = self.waiting.take().ok_or(ServiceTransportError::Closed)?;
        let retired = waiting.retire();
        let connected = match (connected, retired) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(ServiceTransportError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        };
        // Keep the previous name owner until a fresh listening instance exists.
        // Only an accepted or failed instance is replaced; a wait timeout keeps
        // the exact pending/completed native connect operation alive.
        let replacement = create_server(&self.name, false).and_then(native_io::PendingAccept::new);
        match (connected, replacement) {
            (Ok(()), Ok(next)) => {
                self.waiting = Some(next);
                Ok(LocalServiceConnection {
                    pipe: Some(waiting.into_pipe()?),
                    role: self.role,
                    expected_client: self.expected_client.clone(),
                    peer: None,
                    slot: Some(slot),
                    identity: ConnectionBinding::new(),
                    next_sequence: 1,
                    pending: None,
                })
            }
            (Err(error), Ok(next)) => {
                self.waiting = Some(next);
                Err(error)
            }
            (Ok(()), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(ServiceTransportError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }

    /// Cancels and drains the listener's pending connect before closing it.
    /// As with other native cancellation, teardown may exceed a poll deadline.
    pub fn close(&mut self) -> Result<(), ServiceTransportError> {
        match self.waiting.take() {
            Some(mut waiting) => waiting.retire(),
            None => Ok(()),
        }
    }
}

struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn create_server(name: &str, first: bool) -> Result<OwnedHandle, ServiceTransportError> {
    let sddl: Vec<_> = format!("O:SYD:P(A;;GA;;;SY)(A;;{SERVICE_PIPE_CLIENT_ACCESS:#x};;;AU)")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = Descriptor(descriptor);
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name: Vec<_> = name.encode_utf16().chain([0]).collect();
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX
                | FILE_FLAG_OVERLAPPED
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            (MAX_CONNECTIONS + 1) as u32,
            16384,
            16384,
            0,
            &security,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

pub struct LocalServiceConnection {
    pipe: Option<OwnedHandle>,
    role: ServiceClientRole,
    expected_client: Arc<VerifiedExecutable>,
    peer: Option<NativePeerProcess>,
    slot: Option<Slot>,
    identity: ConnectionBinding,
    next_sequence: u64,
    pending: Option<u64>,
}
impl LocalServiceConnection {
    pub(crate) fn close(&mut self) {
        self.identity.close();
        self.pipe = None;
        self.slot = None;
        self.peer = None;
        self.pending = None;
    }

    fn request_peer(
        &self,
        request: &AuthenticatedServiceRequest,
        pipe: &OwnedHandle,
    ) -> Result<&NativePeerProcess, ServiceTransportError> {
        if request.connection != self.identity || self.pending != Some(request.sequence) {
            return Err(ServiceTransportError::RequestOrder);
        }
        let peer = self.peer.as_ref().ok_or(ServiceTransportError::Closed)?;
        peer.verify_pipe_client(pipe)?;
        peer.verify_executable(&self.expected_client)?;
        Ok(peer)
    }

    pub(crate) fn retain_request_peer(
        &mut self,
        request: &AuthenticatedServiceRequest,
        deadline: Instant,
    ) -> Result<NativePeerProcess, ServiceTransportError> {
        let result = (|| {
            check_deadline(deadline)?;
            let pipe = self.pipe.as_ref().ok_or(ServiceTransportError::Closed)?;
            let peer = self.request_peer(request, pipe)?.retain()?;
            check_deadline(deadline)?;
            Ok(peer)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// A full native message is immediately bound to its last-message token,
    /// primary process and expected image. No prefetch/read occurs in between.
    /// Live session/lease authorization must still precede runtime commands.
    pub fn receive(
        &mut self,
        deadline: Instant,
    ) -> Result<AuthenticatedServiceRequest, ServiceTransportError> {
        let pipe = self.pipe.take().ok_or(ServiceTransportError::Closed)?;
        let slot = self.slot.take().ok_or(ServiceTransportError::Closed)?;
        let result = (|| {
            check_deadline(deadline)?;
            if self.pending.is_some() {
                return Err(ServiceTransportError::RequestOrder);
            }
            let sequence = self.next_sequence;
            let next = sequence
                .checked_add(1)
                .ok_or(ServiceTransportError::RequestOrder)?;
            let body = native_io::read(&pipe, deadline)?;
            if self.peer.is_none() {
                let peer = NativePeerProcess::from_pipe_client(&pipe)?;
                let identity = peer.identity();
                if identity.is_local_system()
                    || identity.is_app_container()
                    || identity.is_restricted()
                    || !(0x2000..=0x3000).contains(&identity.integrity_rid())
                    || identity.authentication_id() == 0
                    || identity.authentication_id() == u64::MAX
                {
                    return Err(ServiceTransportError::ClientIdentity);
                }
                peer.verify_executable(&self.expected_client)?;
                self.peer = Some(peer);
            }
            let peer = self.peer.as_ref().ok_or(ServiceTransportError::Closed)?;
            peer.verify_pipe_client(&pipe)?;
            peer.verify_executable(&self.expected_client)?;
            check_deadline(deadline)?;
            let request = AuthenticatedServiceRequest {
                body,
                identity: peer.identity().clone(),
                role: self.role,
                connection: self.identity.clone(),
                sequence,
            };
            self.next_sequence = next;
            self.pending = Some(sequence);
            self.identity.received(sequence);
            Ok(request)
        })();
        if result.is_ok() {
            self.pipe = Some(pipe);
            self.slot = Some(slot);
        } else {
            self.close();
        }
        result
    }

    pub fn reply(
        &mut self,
        request: &AuthenticatedServiceRequest,
        body: &[u8],
        deadline: Instant,
    ) -> Result<(), ServiceTransportError> {
        let pipe = self.pipe.take().ok_or(ServiceTransportError::Closed)?;
        let slot = self.slot.take().ok_or(ServiceTransportError::Closed)?;
        let result = (|| {
            check_deadline(deadline)?;
            self.request_peer(request, &pipe)?;
            native_io::write(&pipe, body, deadline)?;
            self.pending = None;
            self.identity.replied();
            Ok(())
        })();
        if result.is_ok() {
            self.pipe = Some(pipe);
            self.slot = Some(slot);
        } else {
            self.close();
        }
        result
    }
}

impl Drop for LocalServiceConnection {
    fn drop(&mut self) {
        self.close();
    }
}

impl LocalServicePipe {
    /// Low-level complete-message I/O. Authenticate the server before sending
    /// anything; normal product callers use ServiceChannel. An I/O failure
    /// poisons this pipe; its owner must drop it and reconcile uncertain calls.
    pub fn write_message(
        &mut self,
        body: &[u8],
        deadline: Instant,
    ) -> Result<(), ServiceTransportError> {
        if self.poisoned {
            return Err(ServiceTransportError::Closed);
        }
        let result = native_io::write(&self.client, body, deadline);
        self.poisoned = result.is_err();
        result
    }
    pub fn read_message(
        &mut self,
        deadline: Instant,
    ) -> Result<ServicePayload, ServiceTransportError> {
        if self.poisoned {
            return Err(ServiceTransportError::Closed);
        }
        let result = native_io::read(&self.client, deadline);
        self.poisoned = result.is_err();
        result
    }
}

struct ClientConnection {
    pipe: LocalServicePipe,
    peer: WindowsServicePeer,
}
/// Sequential native-worker channel. It authenticates SCM before sending and
/// after receiving. Timeout is delivery-uncertain and never retries a request.
pub struct ServiceChannel {
    connection: Option<ClientConnection>,
}
impl ServiceChannel {
    pub fn connect(
        service_name: &str,
        role: ServiceClientRole,
        expected_service: impl Into<Arc<VerifiedExecutable>>,
    ) -> Result<Self, ServiceTransportError> {
        let pipe = LocalServicePipe::open(service_name, role)?;
        let peer = WindowsServicePeer::from_pipe_server(service_name, expected_service, &pipe)?;
        Ok(Self {
            connection: Some(ClientConnection { pipe, peer }),
        })
    }
    pub fn process_id(&self) -> Result<u32, ServiceTransportError> {
        Ok(self
            .connection
            .as_ref()
            .ok_or(ServiceTransportError::Closed)?
            .peer
            .process_id())
    }
    pub fn request(
        &mut self,
        body: &[u8],
        deadline: Instant,
    ) -> Result<ServicePayload, ServiceTransportError> {
        let mut connection = self
            .connection
            .take()
            .ok_or(ServiceTransportError::Closed)?;
        check_deadline(deadline)?;
        connection.peer.verify_pipe_server(&connection.pipe)?;
        connection.pipe.write_message(body, deadline)?;
        let response = connection.pipe.read_message(deadline)?;
        connection.peer.verify_pipe_server(&connection.pipe)?;
        check_deadline(deadline)?;
        self.connection = Some(connection);
        Ok(response)
    }
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<(), ServiceTransportError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(left) if !left.is_zero() && left <= MAX_IO_TIME => Ok(()),
        _ => Err(ServiceTransportError::Deadline),
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    #[test]
    fn erasing_a_decoded_request_wipes_the_entire_initialized_read_buffer() {
        let mut payload = ServicePayload {
            bytes: Zeroizing::new(vec![0x5a; 8192]),
            length: 32,
        };
        payload.erase();
        assert!(payload.as_bytes().is_empty());
        assert_eq!(payload.bytes.len(), 8192);
        assert!(payload.bytes.iter().all(|byte| *byte == 0));
    }
}
