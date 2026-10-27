//! Packet I/O on one owned Wintun session. A pump splits the session into one
//! receiving and one sending half; both borrow it exclusively, so EndSession,
//! CloseAdapter and FreeLibrary cannot run while a worker still holds a half.
use super::{
    Error, Result, Session,
    driver::{AllocatePacket, ReceivePacket, ReleasePacket, SendPacket},
    native_error, packet,
};
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, time::Duration};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::WaitForSingleObject,
};

struct Received {
    release: ReleasePacket,
    session: NonNull<c_void>,
    pointer: NonNull<u8>,
}
impl Drop for Received {
    fn drop(&mut self) {
        // Exactly the pointer returned by ReceivePacket, released once even
        // when header/size admission fails. It never escapes the call below.
        unsafe { (self.release)(self.session.as_ptr(), self.pointer.as_ptr()) };
    }
}

/// A bounded wait, so a worker can observe cancellation between calls.
/// False means the native wait timed out; termination and corruption fail.
fn wait(event: NonNull<c_void>, timeout: Duration) -> Result<bool> {
    let millis = u32::try_from(timeout.as_millis())
        .map_err(|_| Error::Contract("receive wait is too long".into()))?;
    if millis == 0 || millis > 1000 {
        return Err("receive wait must be 1..=1000 ms".into());
    }
    // Borrowed session event; the session owns its lifetime.
    match unsafe { WaitForSingleObject(event.as_ptr(), millis) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(native_error("wait for a packet")),
        _ => Err("unexpected packet receive-event state".into()),
    }
}

/// Copy one complete kernel packet into an MTU-sized caller buffer. None
/// is only Wintun's documented empty-ring status, never another OS error.
fn receive(
    session: NonNull<c_void>,
    receive: ReceivePacket,
    release: ReleasePacket,
    mtu: u16,
    output: &mut [u8],
) -> Result<Option<usize>> {
    if output.len() < usize::from(mtu) {
        return Err("receive buffer is smaller than the negotiated MTU".into());
    }
    let mut length = 0u32;
    let pointer = unsafe { receive(session.as_ptr(), &mut length) };
    let Some(pointer) = NonNull::new(pointer) else {
        let source = std::io::Error::last_os_error();
        return if source.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
            Ok(None)
        } else {
            Err(Error::Native {
                operation: "receive a packet",
                source,
            })
        };
    };
    let received = Received {
        release,
        session,
        pointer,
    };
    if length == 0 || length > u32::from(mtu) {
        return Err(Error::Packet);
    }
    // The pinned Wintun ABI grants exactly `length` initialized bytes
    // until ReleaseReceivePacket. The guard keeps that loan alive.
    let bytes = unsafe { std::slice::from_raw_parts(received.pointer.as_ptr(), length as usize) };
    packet::validate(bytes, mtu)?;
    output[..bytes.len()].copy_from_slice(bytes);
    Ok(Some(bytes.len()))
}

/// Queue one complete packet for the Windows IP stack. RingFull leaves
/// ownership with the caller; it is not a successful or dropped send.
fn send(
    session: NonNull<c_void>,
    allocate: AllocatePacket,
    submit: SendPacket,
    mtu: u16,
    bytes: &[u8],
) -> Result<()> {
    packet::validate(bytes, mtu)?;
    let pointer = unsafe { allocate(session.as_ptr(), bytes.len() as u32) };
    let Some(pointer) = NonNull::new(pointer) else {
        let source = std::io::Error::last_os_error();
        return if source.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) {
            Err(Error::RingFull)
        } else {
            Err(Error::Native {
                operation: "allocate a send packet",
                source,
            })
        };
    };
    // The length was admitted before allocation. No fallible operation,
    // callback or cancellation point can abandon this allocated slot.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len());
        submit(session.as_ptr(), pointer.as_ptr());
    }
    Ok(())
}

impl Session<'_> {
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    // Direct session I/O exists only for the validation probes. Product
    // packets move through `PacketPump`, whose delivery policy guards every
    // packet written to Windows.
    #[cfg(feature = "native-service-validation")]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        wait(self.read_event, timeout)
    }

    #[cfg(feature = "native-service-validation")]
    pub(crate) fn receive(&self, output: &mut [u8]) -> Result<Option<usize>> {
        let library = self.adapter.library;
        receive(
            self.handle,
            library.receive,
            library.release,
            self.mtu,
            output,
        )
    }

    #[cfg(feature = "native-service-validation")]
    pub(crate) fn send(&self, bytes: &[u8]) -> Result<()> {
        let library = self.adapter.library;
        send(self.handle, library.allocate, library.send, self.mtu, bytes)
    }

    /// One receiving and one sending half for two concurrent workers. The
    /// exclusive borrow keeps the owner from using the session meanwhile.
    pub(super) fn split(&mut self) -> (SessionReceiver<'_>, SessionSender<'_>) {
        let library = self.adapter.library;
        (
            SessionReceiver {
                session: self.handle,
                receive: library.receive,
                release: library.release,
                read_event: self.read_event,
                mtu: self.mtu,
                _session: PhantomData,
            },
            SessionSender {
                session: self.handle,
                allocate: library.allocate,
                submit: library.send,
                mtu: self.mtu,
                _session: PhantomData,
            },
        )
    }
}

/// Receiving half of one exclusively borrowed session.
pub(crate) struct SessionReceiver<'s> {
    session: NonNull<c_void>,
    receive: ReceivePacket,
    release: ReleasePacket,
    read_event: NonNull<c_void>,
    mtu: u16,
    _session: PhantomData<&'s mut ()>,
}
// SAFETY: the pinned wintun.h documents WintunReceivePacket and
// WintunReleaseReceivePacket as thread-safe. The read-wait event belongs to
// the session and is only waited on. The exclusive borrow keeps the session,
// adapter and library alive until this half is dropped. Not Sync: one thread.
unsafe impl Send for SessionReceiver<'_> {}
impl SessionReceiver<'_> {
    pub(crate) fn mtu(&self) -> u16 {
        self.mtu
    }
    pub(crate) fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        wait(self.read_event, timeout)
    }
    pub(crate) fn receive(&self, output: &mut [u8]) -> Result<Option<usize>> {
        receive(self.session, self.receive, self.release, self.mtu, output)
    }
    /// Test-only native seam for driving a pump without the driver.
    ///
    /// # Safety
    /// `session` and `read_event` must stay valid for `'s`, and both
    /// functions must be safe to call concurrently for that session.
    #[cfg(test)]
    pub(crate) unsafe fn from_parts(
        session: NonNull<c_void>,
        receive: ReceivePacket,
        release: ReleasePacket,
        read_event: NonNull<c_void>,
        mtu: u16,
    ) -> Self {
        Self {
            session,
            receive,
            release,
            read_event,
            mtu,
            _session: PhantomData,
        }
    }
}

/// Sending half of one exclusively borrowed session.
pub(crate) struct SessionSender<'s> {
    session: NonNull<c_void>,
    allocate: AllocatePacket,
    submit: SendPacket,
    mtu: u16,
    _session: PhantomData<&'s mut ()>,
}
// SAFETY: the pinned wintun.h documents WintunAllocateSendPacket and
// WintunSendPacket as thread-safe; one sender keeps their packet order. The
// exclusive borrow keeps the session alive until this half is dropped.
unsafe impl Send for SessionSender<'_> {}
impl SessionSender<'_> {
    pub(crate) fn send(&self, bytes: &[u8]) -> Result<()> {
        send(self.session, self.allocate, self.submit, self.mtu, bytes)
    }
    /// Test-only native seam for driving a pump without the driver.
    ///
    /// # Safety
    /// `session` must stay valid for `'s`, and both functions must be safe
    /// to call concurrently for that session.
    #[cfg(test)]
    pub(crate) unsafe fn from_parts(
        session: NonNull<c_void>,
        allocate: AllocatePacket,
        submit: SendPacket,
        mtu: u16,
    ) -> Self {
        Self {
            session,
            allocate,
            submit,
            mtu,
            _session: PhantomData,
        }
    }
}
