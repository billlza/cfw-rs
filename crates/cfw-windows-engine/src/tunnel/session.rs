use super::{Error, Result, Session, native_error, packet};
use std::{ptr::NonNull, time::Duration};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::WaitForSingleObject,
};

struct Received<'a> {
    session: &'a Session<'a>,
    pointer: NonNull<u8>,
}
impl Drop for Received<'_> {
    fn drop(&mut self) {
        // Exactly the pointer returned by ReceivePacket, released once even
        // when header/size admission fails. It never escapes the call below.
        unsafe {
            (self.session.adapter.library.release)(
                self.session.handle.as_ptr(),
                self.pointer.as_ptr(),
            )
        };
    }
}

impl Session<'_> {
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// A bounded wait, so a worker can observe cancellation between calls.
    /// False means the native wait timed out; termination and corruption fail.
    pub fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        let millis = u32::try_from(timeout.as_millis())
            .map_err(|_| Error::Contract("receive wait is too long".into()))?;
        if millis == 0 || millis > 1000 {
            return Err("receive wait must be 1..=1000 ms".into());
        }
        let event = unsafe { (self.adapter.library.event)(self.handle.as_ptr()) };
        if event.is_null() {
            return Err(native_error("obtain packet receive event"));
        }
        // Borrowed session event; the session owns its lifetime.
        match unsafe { WaitForSingleObject(event, millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(native_error("wait for a packet")),
            _ => Err("unexpected packet receive-event state".into()),
        }
    }

    /// Copy one complete kernel packet into an MTU-sized caller buffer. None
    /// is only Wintun's documented empty-ring status, never another OS error.
    pub fn receive(&self, output: &mut [u8]) -> Result<Option<usize>> {
        if output.len() < usize::from(self.mtu) {
            return Err("receive buffer is smaller than the negotiated MTU".into());
        }
        let mut length = 0u32;
        let pointer = unsafe { (self.adapter.library.receive)(self.handle.as_ptr(), &mut length) };
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
            session: self,
            pointer,
        };
        if length == 0 || length > u32::from(self.mtu) {
            return Err(Error::Packet);
        }
        // The pinned Wintun ABI grants exactly `length` initialized bytes
        // until ReleaseReceivePacket. The guard keeps that loan alive.
        let bytes =
            unsafe { std::slice::from_raw_parts(received.pointer.as_ptr(), length as usize) };
        packet::validate(bytes, self.mtu)?;
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(bytes.len()))
    }

    /// Queue one complete packet for the Windows IP stack. RingFull leaves
    /// ownership with the caller; it is not a successful or dropped send.
    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        packet::validate(bytes, self.mtu)?;
        let pointer =
            unsafe { (self.adapter.library.allocate)(self.handle.as_ptr(), bytes.len() as u32) };
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
            (self.adapter.library.send)(self.handle.as_ptr(), pointer.as_ptr());
        }
        Ok(())
    }
}
