//! Native validation of the packet endpoint handoff in the SCM fixture: a
//! disposable SYSTEM service hands endpoints to its medium-integrity UserAgent
//! client. The client proves substitutes are refused, which retires the first
//! endpoint; it then adopts a fresh one, echoes one full-MTU packet and closes
//! it. No lease, engine or adapter is involved.
use super::{
    super::{PacketClient, PumpParts},
    ENDPOINT_ACCESS, EndpointHandoff, HandoffError, check_recipient, require_user_agent,
};
use crate::{
    NativePeerProcess, PacketAuthority, ServicePeerAuthorization, ServicePeerError,
    ServiceTransportError,
    service_transport::native_io::{self, PendingMessageRead},
    tunnel::{EndpointOffer, Error as TunnelError, packet, peer_close_code},
};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, ERROR_ACCESS_DENIED, GetHandleInformation, HANDLE_FLAG_INHERIT,
        SetHandleInformation,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, READ_CONTROL,
        WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{CreateEventW, GetCurrentProcess},
};

const MTU: u16 = 1500;
const LIMIT: Duration = Duration::from_secs(5);

/// A full-MTU IPv4 UDP packet between documentation addresses whose payload
/// carries the nonce. The recipient answers with every payload byte inverted.
fn probe_packet(nonce: &[u8; 16]) -> Vec<u8> {
    let mut packet = vec![0u8; usize::from(MTU)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&MTU.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 0, 2, 123]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
    for (index, byte) in packet[20..].iter_mut().enumerate() {
        *byte = nonce[index % nonce.len()] ^ (index as u8);
    }
    packet
}

fn echo(packet: &[u8]) -> Vec<u8> {
    let mut reply = packet.to_vec();
    for byte in &mut reply[20..] {
        *byte = !*byte;
    }
    reply
}

fn contract(detail: &str) -> HandoffError {
    HandoffError::Tunnel(TunnelError::from(detail))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbePhase {
    Offered,
    Renewable,
    Confirmed,
    Sent,
    Echoed,
    Released,
}

/// SYSTEM's side of the native handoff validation.
pub struct PacketHandoffProbe {
    recipient: NativePeerProcess,
    handoff: Option<EndpointHandoff>,
    parts: Option<PumpParts>,
    sent: Option<Vec<u8>>,
    substitutes_refused: u32,
    phase: ProbePhase,
}

impl PacketHandoffProbe {
    pub fn new(request: &ServicePeerAuthorization) -> Result<Self, HandoffError> {
        let handoff = EndpointHandoff::create(uuid::Uuid::new_v4(), MTU, request)?;
        Ok(Self {
            recipient: request.process().retain()?,
            handoff: Some(handoff),
            parts: None,
            sent: None,
            substitutes_refused: 0,
            phase: ProbePhase::Offered,
        })
    }

    fn check(
        &self,
        request: &ServicePeerAuthorization,
        phase: ProbePhase,
    ) -> Result<(), HandoffError> {
        require_user_agent(request)?;
        check_recipient(&self.recipient, request.process())?;
        if self.phase != phase {
            return Err(HandoffError::Phase("in the step this request needs"));
        }
        Ok(())
    }

    pub fn offer(&self) -> Result<EndpointOffer, HandoffError> {
        self.handoff
            .as_ref()
            .map(EndpointHandoff::offer)
            .ok_or(HandoffError::Phase("offered"))
    }

    /// True once `value` named the endpoint. A substitute is refused and
    /// retires the offered endpoint; the client must ask for a fresh one.
    pub fn verify(
        &mut self,
        request: &ServicePeerAuthorization,
        value: u64,
    ) -> Result<bool, HandoffError> {
        self.check(request, ProbePhase::Offered)?;
        let handoff = self.handoff.take().ok_or(HandoffError::Phase("offered"))?;
        match handoff.confirm(request, value) {
            Ok(server) => {
                self.parts = Some(server.into_pump_parts()?);
                self.phase = ProbePhase::Confirmed;
                Ok(true)
            }
            Err(HandoffError::Substituted) => {
                self.substitutes_refused += 1;
                self.phase = ProbePhase::Renewable;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// One fresh endpoint after the refused substitute retired the first.
    pub fn renew(
        &mut self,
        request: &ServicePeerAuthorization,
    ) -> Result<EndpointOffer, HandoffError> {
        self.check(request, ProbePhase::Renewable)?;
        if self.substitutes_refused != 1 {
            return Err(HandoffError::Phase("renewable once"));
        }
        let handoff = EndpointHandoff::create(uuid::Uuid::new_v4(), MTU, request)?;
        let offer = handoff.offer();
        self.handoff = Some(handoff);
        self.phase = ProbePhase::Offered;
        Ok(offer)
    }

    pub fn send(&mut self, request: &ServicePeerAuthorization) -> Result<(), HandoffError> {
        self.check(request, ProbePhase::Confirmed)?;
        if self.substitutes_refused != 1 {
            return Err(HandoffError::Phase("confirmed after a refused substitute"));
        }
        let parts = self
            .parts
            .as_mut()
            .ok_or(HandoffError::Phase("confirmed"))?;
        let packet = probe_packet(uuid::Uuid::new_v4().as_bytes());
        parts
            .sender
            .send(&packet, Instant::now() + LIMIT, &parts.cancel)?;
        self.sent = Some(packet);
        self.phase = ProbePhase::Sent;
        Ok(())
    }

    pub fn receive(&mut self, request: &ServicePeerAuthorization) -> Result<(), HandoffError> {
        self.check(request, ProbePhase::Sent)?;
        let parts = self.parts.as_mut().ok_or(HandoffError::Phase("sent"))?;
        let sent = self.sent.as_ref().ok_or(HandoffError::Phase("sent"))?;
        let received = parts
            .receiver
            .receive(Instant::now() + LIMIT, &parts.cancel)?
            .ok_or_else(|| contract("the recipient sent no echo before the deadline"))?;
        if received.payload.as_bytes() != echo(sent) {
            return Err(contract(
                "the recipient's echo differs from the packet SYSTEM sent",
            ));
        }
        self.phase = ProbePhase::Echoed;
        Ok(())
    }

    /// After the recipient closed its only client end, the server end
    /// observes its peer closing; the endpoint then retires.
    pub fn observe_release(
        &mut self,
        request: &ServicePeerAuthorization,
    ) -> Result<i32, HandoffError> {
        self.check(request, ProbePhase::Echoed)?;
        let mut parts = self.parts.take().ok_or(HandoffError::Phase("echoed"))?;
        let code = match parts
            .receiver
            .receive(Instant::now() + LIMIT, &parts.cancel)
        {
            Err(TunnelError::Transport(ServiceTransportError::Io(error))) => {
                peer_close_code(&error)
                    .ok_or_else(|| contract("the endpoint failed without its peer closing"))?
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(contract("the recipient's endpoint stayed open")),
        };
        parts.receiver.retire()?;
        drop(parts);
        self.phase = ProbePhase::Released;
        Ok(code)
    }

    pub fn substitutes_refused(&self) -> u32 {
        self.substitutes_refused
    }

    pub fn released(&self) -> bool {
        self.phase == ProbePhase::Released
    }
}

/// The recipient's side of the native handoff validation.
pub struct AdoptedEndpointProbe {
    pipe: Arc<OwnedHandle>,
    mtu: u16,
}

impl AdoptedEndpointProbe {
    /// An unrelated object and a pipe this process serves are refused before
    /// SYSTEM is asked and stay open; SYSTEM's own object comparison then
    /// refuses an unrelated copy, which retires the offered endpoint.
    pub fn refuse_substitutes(
        offer: &EndpointOffer,
        authority: &PacketAuthority,
        confirm: impl FnOnce(u64) -> Result<(), HandoffError>,
    ) -> Result<(), HandoffError> {
        let event = unrelated_event()?;
        let unrelated = EndpointOffer {
            handle: event.as_raw_handle() as usize as u64,
            ..*offer
        };
        match PacketClient::adopt(&unrelated, authority, never_confirm) {
            Err(HandoffError::Native { .. }) => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(contract(
                    "an unrelated object was adopted as a packet endpoint",
                ));
            }
        }
        require_open(&event)?;
        let own = NativePeerProcess::open(std::process::id())?;
        let (server, client) = native_io::connected_pair(&own, "packets", 64 * 1024)?;
        let served = EndpointOffer {
            handle: client.as_raw_handle() as usize as u64,
            ..*offer
        };
        match PacketClient::adopt(&served, authority, never_confirm) {
            Err(HandoffError::Service(ServicePeerError::WrongProcess)) => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(contract("a pipe this process serves was adopted")),
        }
        require_open(&client)?;
        drop((server, client));
        match confirm(event.as_raw_handle() as usize as u64) {
            Err(HandoffError::Substituted) => {}
            Err(error) => return Err(error),
            Ok(()) => return Err(contract("SYSTEM confirmed an unrelated object")),
        }
        require_open(&event)
    }

    /// Adopt a fresh endpoint and take the copy a child engine would inherit,
    /// then keep it non-inheritable, as the engine host does.
    pub fn adopt(
        offer: &EndpointOffer,
        authority: &PacketAuthority,
        confirm: impl FnOnce(u64) -> Result<(), HandoffError>,
    ) -> Result<Self, HandoffError> {
        let client = PacketClient::adopt(offer, authority, confirm)?;
        let (handle, _attachment) = client.into_child()?;
        if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(super::native("keep the adopted endpoint non-inheritable"));
        }
        Ok(Self {
            pipe: Arc::new(handle),
            mtu: offer.mtu,
        })
    }

    /// The endpoint cannot gain any right beyond `ENDPOINT_ACCESS`.
    pub fn require_reduced_access(&self) -> Result<(), HandoffError> {
        for access in [
            DELETE,
            READ_CONTROL,
            WRITE_DAC,
            WRITE_OWNER,
            FILE_WRITE_ATTRIBUTES,
            FILE_APPEND_DATA,
            FILE_READ_EA,
            FILE_WRITE_EA,
        ] {
            match duplicate(&self.pipe, access) {
                Ok(_) => {
                    return Err(contract(
                        "the adopted endpoint gained a right it was not given",
                    ));
                }
                Err(HandoffError::Native { source, .. })
                    if source.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
                Err(error) => return Err(error),
            }
        }
        duplicate(&self.pipe, ENDPOINT_ACCESS).map(drop)
    }

    /// Read SYSTEM's packet and write back its echo.
    pub fn echo(&self) -> Result<usize, HandoffError> {
        let mut read = PendingMessageRead::new(Arc::clone(&self.pipe), usize::from(self.mtu))?;
        let packet = read
            .poll(Instant::now() + LIMIT, &AtomicBool::new(false))?
            .ok_or_else(|| contract("SYSTEM sent no packet before the deadline"))?;
        packet::validate(packet.as_bytes(), self.mtu)?;
        let reply = echo(packet.as_bytes());
        native_io::write_bounded(
            &self.pipe,
            &reply,
            Instant::now() + LIMIT,
            usize::from(self.mtu),
            None,
        )?;
        Ok(reply.len())
    }

    /// Closing the only client end lets SYSTEM observe its peer closing.
    pub fn close(self) -> Result<(), HandoffError> {
        drop(Arc::into_inner(self.pipe).ok_or_else(|| contract("the endpoint is still shared"))?);
        Ok(())
    }
}

fn never_confirm(_: u64) -> Result<(), HandoffError> {
    Err(contract("SYSTEM was asked about a locally refused handle"))
}

fn unrelated_event() -> Result<OwnedHandle, HandoffError> {
    let raw = unsafe { CreateEventW(null(), 0, 0, null()) };
    if raw.is_null() {
        return Err(super::native("create an unrelated fixture object"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn require_open(handle: &OwnedHandle) -> Result<(), HandoffError> {
    let mut flags = 0;
    if unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) } == 0 {
        return Err(super::native("a refused handle was closed"));
    }
    Ok(())
}

fn duplicate(handle: &OwnedHandle, access: u32) -> Result<OwnedHandle, HandoffError> {
    let mut raw = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle(),
            GetCurrentProcess(),
            &mut raw,
            access,
            0,
            0,
        )
    } == 0
    {
        return Err(super::native("duplicate the adopted endpoint"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
