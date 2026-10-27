//! Handing a SYSTEM-created packet endpoint to one ordinary-user process.
//!
//! SYSTEM creates the pipe pair, keeps the server end and places the client
//! end in the recipient's handle table with only the access a packet endpoint
//! uses. The recipient adopts it only when the handle is a non-inheritable,
//! one-instance message pipe client served by the pinned service process, and
//! after SYSTEM confirms that the recipient's own copy is the same pipe
//! object. Then SYSTEM drops its retained client reference, so the recipient
//! holds the only client end. There is one transfer per endpoint, and SYSTEM
//! never closes a handle value in another process: an endpoint that is never
//! confirmed is retired by dropping the server end, which leaves any
//! delivered copy dead. No lease, engine, adapter, route or DNS is involved.
use super::{EndpointCreator, PacketClient, PacketServer};
use crate::{
    NativePeerIdentity, NativePeerProcess, PacketAuthority, PeerIdentityError, ServiceClientRole,
    ServicePeerAuthorization, ServicePeerError, ServiceTransportError,
    tunnel::{
        Error as TunnelError,
        endpoint::{EndpointOffer, HANDOFF_MTU, admits_recipient, handle_value_is_well_formed},
    },
};
use std::{
    io,
    os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetHandleInformation, HANDLE,
    },
    Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE},
    System::{
        Pipes::{
            GetNamedPipeHandleStateW, GetNamedPipeInfo, PIPE_READMODE_MESSAGE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
        },
        Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
    },
};

/// The access the recipient needs to move packets and inspect the pipe, as
/// the engine host does. Without DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
/// attribute or extended-attribute writes, or FILE_CREATE_PIPE_INSTANCE.
pub const ENDPOINT_ACCESS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// Pipe buffers never exceed what the engine host accepts.
const MAXIMUM_PIPE_BUFFER: u32 = 128 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("packet endpoint handoff requires the SYSTEM service: {0}")]
    Service(#[from] ServicePeerError),
    #[error("packet endpoint handoff peer: {0}")]
    Peer(#[from] PeerIdentityError),
    #[error(
        "packet endpoint recipient is not an ordinary user process (system={local_system}, session={session_id}, integrity={integrity_rid:#x}, app_container={app_container}, restricted={restricted})"
    )]
    Recipient {
        local_system: bool,
        session_id: u32,
        integrity_rid: u32,
        app_container: bool,
        restricted: bool,
    },
    #[error("packet endpoint request did not come from its UserAgent recipient")]
    WrongRecipient,
    #[error("packet endpoint offer is malformed")]
    Offer,
    #[error("packet endpoint handle value {0:#x} is not a handle value")]
    HandleValue(u64),
    #[error("packet endpoint handle is not the transferred pipe")]
    Substituted,
    #[error("packet endpoint handoff is not {0}")]
    Phase(&'static str),
    #[error("Windows packet endpoint handoff {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    #[error(transparent)]
    Transport(#[from] ServiceTransportError),
    #[error(transparent)]
    Engine(#[from] crate::Error),
}

fn native(operation: &'static str) -> HandoffError {
    HandoffError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

fn require_recipient(identity: &NativePeerIdentity) -> Result<(), HandoffError> {
    let (local_system, session_id, integrity_rid, app_container, restricted) = (
        identity.is_local_system(),
        identity.session_id(),
        identity.integrity_rid(),
        identity.is_app_container(),
        identity.is_restricted(),
    );
    if admits_recipient(
        local_system,
        session_id,
        integrity_rid,
        app_container,
        restricted,
    ) {
        Ok(())
    } else {
        Err(HandoffError::Recipient {
            local_system,
            session_id,
            integrity_rid,
            app_container,
            restricted,
        })
    }
}

/// SYSTEM's side of one transfer to the authorized UserAgent, which hosts the
/// Tunnel engine. Not Clone or serializable. Confirmation consumes it, so a
/// refused confirmation or any other failure retires the endpoint.
pub struct EndpointHandoff {
    server: PacketServer,
    /// SYSTEM's own client end, kept only to compare the recipient's copy.
    retained: OwnedHandle,
    recipient: NativePeerProcess,
    offer: EndpointOffer,
}

impl EndpointHandoff {
    /// Create an endpoint for `adapter` and place its client end in the
    /// handle table of the UserAgent that sent `request`. Only the SYSTEM
    /// service may do this, and only for an ordinary user process.
    pub fn create(
        adapter: uuid::Uuid,
        mtu: u16,
        request: &ServicePeerAuthorization,
    ) -> Result<Self, HandoffError> {
        require_user_agent(request)?;
        Self::create_for(adapter, mtu, request.process())
    }

    fn create_for(
        adapter: uuid::Uuid,
        mtu: u16,
        recipient: &NativePeerProcess,
    ) -> Result<Self, HandoffError> {
        crate::service_peer::require_system_service_identity()?;
        if !HANDOFF_MTU.contains(&mtu) {
            return Err(HandoffError::Offer);
        }
        let recipient = recipient.retain()?;
        require_recipient(recipient.identity())?;
        let (server, client) = PacketServer::create(adapter, mtu)?;
        let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, recipient.process_id()) };
        if raw.is_null() {
            return Err(native("open the packet endpoint recipient"));
        }
        let target = unsafe { OwnedHandle::from_raw_handle(raw) };
        recipient.revalidate()?;
        let mut delivered: HANDLE = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                client.handle.as_raw_handle(),
                target.as_raw_handle(),
                &mut delivered,
                ENDPOINT_ACCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(native("place the packet endpoint in the recipient"));
        }
        // After an uncertain delivery the recipient may already own, close or
        // reuse the value, so it is never closed from here. Dropping the
        // server end retires an unconfirmed endpoint instead.
        recipient.revalidate()?;
        let handle = delivered as usize as u64;
        if !handle_value_is_well_formed(handle) {
            return Err(HandoffError::HandleValue(handle));
        }
        Ok(Self {
            server,
            retained: client.handle,
            recipient,
            offer: EndpointOffer {
                handle,
                adapter,
                mtu,
            },
        })
    }

    pub fn offer(&self) -> EndpointOffer {
        self.offer
    }

    /// `value` names the recipient's own copy. It must be the very endpoint
    /// SYSTEM created; then SYSTEM drops its retained client reference and
    /// keeps the server end. Any failure, a substituted object included,
    /// consumes the handoff and so retires the endpoint.
    pub fn confirm(
        self,
        request: &ServicePeerAuthorization,
        value: u64,
    ) -> Result<PacketServer, HandoffError> {
        require_user_agent(request)?;
        self.confirm_for(request.process(), value)
    }

    fn confirm_for(
        self,
        peer: &NativePeerProcess,
        value: u64,
    ) -> Result<PacketServer, HandoffError> {
        check_recipient(&self.recipient, peer)?;
        if !handle_value_is_well_formed(value) {
            return Err(HandoffError::HandleValue(value));
        }
        let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, peer.process_id()) };
        if raw.is_null() {
            return Err(native(
                "open the packet endpoint recipient for confirmation",
            ));
        }
        let source = unsafe { OwnedHandle::from_raw_handle(raw) };
        peer.revalidate()?;
        let mut copied: HANDLE = null_mut();
        if unsafe {
            DuplicateHandle(
                source.as_raw_handle(),
                value as usize as HANDLE,
                GetCurrentProcess(),
                &mut copied,
                0,
                0,
                0,
            )
        } == 0
        {
            return Err(native(
                "copy the recipient's packet endpoint for comparison",
            ));
        }
        let copied = unsafe { OwnedHandle::from_raw_handle(copied) };
        peer.revalidate()?;
        if unsafe { CompareObjectHandles(self.retained.as_raw_handle(), copied.as_raw_handle()) }
            == 0
        {
            return Err(HandoffError::Substituted);
        }
        Ok(self.server)
    }
}

/// The handoff serves only the UserAgent role, which hosts the engine.
fn require_user_agent(request: &ServicePeerAuthorization) -> Result<(), HandoffError> {
    if request.request().role() != ServiceClientRole::UserAgent {
        return Err(HandoffError::WrongRecipient);
    }
    Ok(())
}

fn check_recipient(
    recipient: &NativePeerProcess,
    peer: &NativePeerProcess,
) -> Result<(), HandoffError> {
    crate::service_peer::require_system_service_identity()?;
    recipient.revalidate()?;
    peer.revalidate()?;
    if peer.process_id() != recipient.process_id() || peer.identity() != recipient.identity() {
        return Err(HandoffError::WrongRecipient);
    }
    Ok(())
}

impl PacketClient {
    /// Adopt the client end SYSTEM placed in this process. `confirm` asks
    /// SYSTEM to compare this process's own copy, whose value it receives,
    /// with the endpoint SYSTEM created. Only then does the transferred value
    /// close. A refused or substituted value is never closed: it may name
    /// another object this process owns.
    pub fn adopt<E: From<HandoffError>>(
        offer: &EndpointOffer,
        authority: &PacketAuthority,
        confirm: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<Self, E> {
        let candidate = Candidate::receive(offer, authority)?;
        confirm(candidate.copy.as_raw_handle() as usize as u64)?;
        Ok(candidate.finish(offer, authority)?)
    }
}

struct Candidate {
    original: usize,
    copy: OwnedHandle,
}

impl Candidate {
    fn receive(offer: &EndpointOffer, authority: &PacketAuthority) -> Result<Self, HandoffError> {
        let own = NativePeerProcess::open(std::process::id())?;
        require_recipient(own.identity())?;
        if !offer.is_well_formed() {
            return Err(HandoffError::Offer);
        }
        let raw = offer.handle as usize as HANDLE;
        let mut flags = 0;
        if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
            return Err(native("inspect the transferred packet endpoint"));
        }
        // Neither inheritable nor protected from close: the transferred value
        // must be closable once the copy is verified.
        if flags != 0 {
            return Err(HandoffError::Substituted);
        }
        require_endpoint_pipe(raw, offer.mtu)?;
        // SAFETY: GetHandleInformation proved `raw` is an open handle in this
        // process; it is only borrowed for this query.
        authority.verify_pipe_server(&unsafe { BorrowedHandle::borrow_raw(raw) })?;
        Ok(Self {
            original: offer.handle as usize,
            copy: duplicate_local(raw)?,
        })
    }

    fn finish(
        self,
        offer: &EndpointOffer,
        authority: &PacketAuthority,
    ) -> Result<PacketClient, HandoffError> {
        let raw = self.original as HANDLE;
        if raw == self.copy.as_raw_handle()
            || unsafe { CompareObjectHandles(raw, self.copy.as_raw_handle()) } == 0
        {
            return Err(HandoffError::Substituted);
        }
        require_endpoint_pipe(self.copy.as_raw_handle(), offer.mtu)?;
        authority.verify_pipe_server(&self.copy)?;
        // SYSTEM verified the retained copy against its endpoint, and the
        // transferred value names the same object: only now retire it.
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        Ok(PacketClient {
            handle: self.copy,
            creator: EndpointCreator::Authority(authority.clone()),
            name: format!("CFW-TUN-{}", offer.adapter),
            mtu: offer.mtu,
        })
    }
}

/// A message-mode, one-instance, local-only pipe client end in message read
/// mode whose buffers hold a full packet: what the engine host requires.
fn require_endpoint_pipe(raw: HANDLE, mtu: u16) -> Result<(), HandoffError> {
    let (mut flags, mut output, mut input, mut instances) = (0, 0, 0, 0);
    if unsafe { GetNamedPipeInfo(raw, &mut flags, &mut output, &mut input, &mut instances) } == 0 {
        return Err(native("inspect the packet endpoint pipe"));
    }
    let mut state = 0;
    if unsafe {
        GetNamedPipeHandleStateW(
            raw,
            &mut state,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
        )
    } == 0
    {
        return Err(native("inspect the packet endpoint read mode"));
    }
    let allowed = PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS;
    let buffers = u32::from(mtu)..=MAXIMUM_PIPE_BUFFER;
    if flags & PIPE_TYPE_MESSAGE == 0
        || flags & !allowed != 0
        || state != PIPE_READMODE_MESSAGE
        || instances != 1
        || !buffers.contains(&output)
        || !buffers.contains(&input)
    {
        return Err(HandoffError::Substituted);
    }
    Ok(())
}

fn duplicate_local(raw: HANDLE) -> Result<OwnedHandle, HandoffError> {
    let mut copy: HANDLE = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(native("copy the transferred packet endpoint"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}

#[cfg(feature = "native-service-validation")]
mod validation;
#[cfg(feature = "native-service-validation")]
pub use validation::{AdoptedEndpointProbe, PacketHandoffProbe};

#[cfg(test)]
mod tests;
