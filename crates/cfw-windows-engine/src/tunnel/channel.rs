//! Complete IP messages over a private native pipe. This data-plane primitive
//! grants no Authority lease and never changes adapters, DNS, routes or proxy.
use super::{Error, Result, packet};
use crate::{
    NativePeerProcess, ServicePayload, ServiceTransportError,
    protocol::PacketAttachment,
    service_transport::native_io::{self, PendingMessageRead},
};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
    System::Threading::GetCurrentProcess,
};

const PIPE_CAPACITY: u32 = 64 * 1024;

#[derive(Clone)]
pub struct PacketCancellation(Arc<AtomicBool>);
impl PacketCancellation {
    /// Irreversible for this channel. Its owner must still close/join native
    /// I/O before claiming retirement; setting a flag is not that evidence.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// One packet endpoint owner. `receive` serves a single thread; a pump takes
/// both directions through `into_pump_parts`. Any error closes the endpoint.
pub struct PacketServer {
    receiver: Option<PacketReceiver>,
    sender: Option<PacketSender>,
    cancel: Arc<AtomicBool>,
}

/// Receiver-owned endpoint prepared by the current process. No raw-handle
/// constructor/Clone exists. Remote Authority transfer needs its own verified
/// adoption path; this local constructor must not be mistaken for that path.
pub struct PacketClient {
    handle: OwnedHandle,
    creator: NativePeerProcess,
    name: String,
    mtu: u16,
}

/// Reading direction of one endpoint. Exactly one owner polls it; the caller
/// supplies the cancellation flag, so a half never cancels its sibling itself.
pub(crate) struct PacketReceiver {
    pipe: Arc<OwnedHandle>,
    read: Option<PendingMessageRead>,
    mtu: u16,
}

/// One engine packet whose framing was validated, with its fixed header.
pub(crate) struct Received {
    pub(crate) payload: ServicePayload,
    pub(crate) header: packet::Header,
}

/// Writing direction of one endpoint. One writer keeps packet order.
pub(crate) struct PacketSender {
    pipe: Arc<OwnedHandle>,
    mtu: u16,
}

/// Both directions of one endpoint for a pump. `pipe` is an extra reference:
/// holding the only one after both workers retire proves the server end closes.
pub(crate) struct PumpParts {
    pub(crate) receiver: PacketReceiver,
    pub(crate) sender: PacketSender,
    pub(crate) cancel: Arc<AtomicBool>,
    pub(crate) pipe: Arc<OwnedHandle>,
    pub(crate) mtu: u16,
}

impl PacketServer {
    pub fn create(adapter: uuid::Uuid, mtu: u16) -> Result<(Self, PacketClient)> {
        packet::validate_mtu(mtu)?;
        if adapter.is_nil() {
            return Err("packet adapter identity is nil".into());
        }
        let creator =
            NativePeerProcess::open(std::process::id()).map_err(ServiceTransportError::from)?;
        let (server, client) = native_io::connected_pair(&creator, "packets", PIPE_CAPACITY)?;
        let pipe = Arc::new(server);
        Ok((
            Self {
                receiver: Some(PacketReceiver {
                    pipe: Arc::clone(&pipe),
                    read: None,
                    mtu,
                }),
                sender: Some(PacketSender { pipe, mtu }),
                cancel: Arc::new(AtomicBool::new(false)),
            },
            PacketClient {
                handle: client,
                creator,
                name: format!("CFW-TUN-{adapter}"),
                mtu,
            },
        ))
    }

    pub fn cancellation(&self) -> PacketCancellation {
        PacketCancellation(Arc::clone(&self.cancel))
    }

    /// None is only a polling timeout. The same buffer/OVERLAPPED remains
    /// owned, including a packet that completes just after this poll returns.
    pub fn receive(&mut self, deadline: Instant) -> Result<Option<ServicePayload>> {
        let operation = match self.receiver.as_mut() {
            Some(receiver) => receiver.receive(deadline, &self.cancel),
            None => Err(ServiceTransportError::Closed.into()),
        };
        self.finish(operation)
            .map(|received| received.map(|packet| packet.payload))
    }

    fn finish<T>(&mut self, operation: Result<T>) -> Result<T> {
        match operation {
            Ok(value) => Ok(value),
            Err(operation) => match self.close() {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(Error::Cleanup {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                }),
            },
        }
    }

    pub fn close(&mut self) -> Result<()> {
        self.cancel.store(true, Ordering::Release);
        if let Some(receiver) = &mut self.receiver {
            receiver.retire()?;
        }
        self.receiver = None;
        self.sender = None;
        Ok(())
    }

    /// Hand both directions to one pump. A closed or cancelled endpoint cannot
    /// start one; cancellation handles issued earlier keep applying to it.
    pub(crate) fn into_pump_parts(mut self) -> Result<PumpParts> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(ServiceTransportError::Cancelled.into());
        }
        let (Some(receiver), Some(sender)) = (self.receiver.take(), self.sender.take()) else {
            return Err(ServiceTransportError::Closed.into());
        };
        let pipe = Arc::clone(&sender.pipe);
        let mtu = sender.mtu;
        Ok(PumpParts {
            receiver,
            sender,
            cancel: Arc::clone(&self.cancel),
            pipe,
            mtu,
        })
    }
}

#[cfg(test)]
impl PacketServer {
    /// The test process acts as the engine through the raw client end.
    pub(crate) fn pair_for_test(mtu: u16) -> (Self, OwnedHandle) {
        let (server, client) =
            Self::create(uuid::Uuid::new_v4(), mtu).expect("test packet endpoint");
        (server, client.handle)
    }
}

impl Drop for PacketServer {
    fn drop(&mut self) {
        // Explicit close reports failures. Emergency drop is never a global
        // Off receipt; PendingMessageRead retains native memory until drained.
        // Directions already handed to a pump are not cancelled from here.
        if self.receiver.is_some() || self.sender.is_some() {
            let _ = self.close();
        }
    }
}

impl PacketReceiver {
    /// None is only a polling timeout; the outstanding read stays owned.
    pub(crate) fn receive(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<Received>> {
        if self.read.is_none() {
            self.read = Some(PendingMessageRead::new(
                Arc::clone(&self.pipe),
                usize::from(self.mtu),
            )?);
        }
        let read = self.read.as_mut().ok_or(ServiceTransportError::Closed)?;
        let Some(payload) = read.poll(deadline, cancel)? else {
            return Ok(None);
        };
        self.read = None;
        let header = packet::validate(payload.as_bytes(), self.mtu)?;
        Ok(Some(Received { payload, header }))
    }

    /// Cancel and drain an outstanding read before its buffer is released.
    pub(crate) fn retire(&mut self) -> Result<()> {
        if let Some(read) = &mut self.read {
            read.retire()?;
        }
        self.read = None;
        Ok(())
    }
}

impl PacketSender {
    pub(crate) fn send(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<()> {
        packet::validate(bytes, self.mtu)?;
        native_io::write_bounded(
            &self.pipe,
            bytes,
            deadline,
            usize::from(self.mtu),
            Some(cancel),
        )?;
        Ok(())
    }
}

impl PacketClient {
    pub(crate) fn mtu(&self) -> u16 {
        self.mtu
    }

    pub(crate) fn into_child(
        self,
    ) -> std::result::Result<(OwnedHandle, PacketAttachment), crate::Error> {
        let inherit =
            || -> std::result::Result<OwnedHandle, Box<dyn std::error::Error + Send + Sync>> {
                self.creator.revalidate()?;
                if self.creator.process_id() != std::process::id() {
                    return Err("packet endpoint belongs to another creator".into());
                }
                self.creator.verify_pipe_server(&self.handle)?;
                let mut raw = null_mut();
                if unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        self.handle.as_raw_handle(),
                        GetCurrentProcess(),
                        &mut raw,
                        0,
                        1,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
            };
        let handle = inherit().map_err(|source| crate::Error::Operation {
            operation: "inherit owned packet endpoint",
            source: std::io::Error::other(source),
        })?;
        let metadata = PacketAttachment::for_endpoint(
            handle.as_raw_handle() as usize as u64,
            self.name,
            self.mtu,
        )?;
        // The original local copy closes here. The selected inheritable copy
        // is retained only through CreateProcess, then the child owns it.
        Ok((handle, metadata))
    }
}
