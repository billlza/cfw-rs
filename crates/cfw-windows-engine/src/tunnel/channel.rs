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

pub struct PacketServer {
    pipe: Option<Arc<OwnedHandle>>,
    read: Option<PendingMessageRead>,
    cancel: Arc<AtomicBool>,
    mtu: u16,
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

impl PacketServer {
    pub fn create(adapter: uuid::Uuid, mtu: u16) -> Result<(Self, PacketClient)> {
        packet::validate_mtu(mtu)?;
        if adapter.is_nil() {
            return Err("packet adapter identity is nil".into());
        }
        let creator =
            NativePeerProcess::open(std::process::id()).map_err(ServiceTransportError::from)?;
        let (server, client) = native_io::connected_pair(&creator, "packets", PIPE_CAPACITY)?;
        Ok((
            Self {
                pipe: Some(Arc::new(server)),
                read: None,
                cancel: Arc::new(AtomicBool::new(false)),
                mtu,
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

    pub fn send(&mut self, bytes: &[u8], deadline: Instant) -> Result<()> {
        let operation = (|| {
            packet::validate(bytes, self.mtu)?;
            let pipe = self.pipe.as_ref().ok_or(ServiceTransportError::Closed)?;
            native_io::write_bounded(
                pipe,
                bytes,
                deadline,
                usize::from(self.mtu),
                Some(&self.cancel),
            )?;
            Ok(())
        })();
        self.finish(operation)
    }

    /// None is only a polling timeout. The same buffer/OVERLAPPED remains
    /// owned, including a packet that completes just after this poll returns.
    pub fn receive(&mut self, deadline: Instant) -> Result<Option<ServicePayload>> {
        let operation = (|| {
            let pipe = self.pipe.as_ref().ok_or(ServiceTransportError::Closed)?;
            if self.read.is_none() {
                self.read = Some(PendingMessageRead::new(
                    Arc::clone(pipe),
                    usize::from(self.mtu),
                )?);
            }
            let read = self.read.as_mut().ok_or(ServiceTransportError::Closed)?;
            let received = read.poll(deadline, &self.cancel)?;
            if let Some(bytes) = &received {
                packet::validate(bytes.as_bytes(), self.mtu)?;
                self.read.take();
            }
            Ok(received)
        })();
        self.finish(operation)
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
        if let Some(read) = &mut self.read {
            read.retire()?;
        }
        self.read.take();
        self.pipe.take();
        Ok(())
    }
}

impl Drop for PacketServer {
    fn drop(&mut self) {
        // Explicit close reports failures. Emergency drop is never a global
        // Off receipt; PendingMessageRead retains native memory until drained.
        let _ = self.close();
    }
}

impl PacketClient {
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
