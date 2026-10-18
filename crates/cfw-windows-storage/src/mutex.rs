use std::{
    io,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    rc::Rc,
    time::Duration,
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::SECURITY_ATTRIBUTES,
    System::Threading::{CreateMutexExW, MUTEX_ALL_ACCESS, ReleaseMutex, WaitForSingleObject},
};

use crate::{Error, security::Security};

/// Serializes one current-user authority across processes and Windows sessions.
/// The global kernel name contains the effective SID hash; the owner and DACL
/// are checked on the opened object before waiting. Not an application identity
/// barrier against other code running as this same user.
pub struct PrivateUserMutex {
    handle: OwnedHandle,
    acquired: bool,
    abandoned: bool,
    // Windows mutex ownership belongs to the acquiring thread.
    _thread: PhantomData<Rc<()>>,
}

impl PrivateUserMutex {
    pub fn acquire(purpose: &str, timeout: Duration) -> Result<Self, Error> {
        if purpose.is_empty()
            || purpose.len() > 96
            || !purpose
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
        {
            return Err(Error::InvalidMutexParameters);
        }
        let security = Security::for_mutex()?;
        let identity = format!("{:x}", Sha256::digest(security.principal()?.as_bytes()));
        let name: Vec<u16> = format!("Global\\CFW.{purpose}.{identity}\0")
            .encode_utf16()
            .collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.descriptor().cast_mut().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: descriptor and NUL-terminated name remain borrowed through
        // creation. The returned non-inheritable kernel handle is owned here.
        let raw = unsafe { CreateMutexExW(&attributes, name.as_ptr(), 0, MUTEX_ALL_ACCESS) };
        if raw.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        security.verify_mutex(&handle)?;
        let result = unsafe {
            WaitForSingleObject(handle.as_raw_handle(), timeout.as_millis().max(1) as u32)
        };
        match result {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self {
                handle,
                acquired: true,
                abandoned: result == WAIT_ABANDONED,
                _thread: PhantomData,
            }),
            WAIT_TIMEOUT => Err(Error::MutexBusy),
            _ => Err(io::Error::last_os_error().into()),
        }
    }

    /// An abandoned predecessor does not certify consistency. The caller must
    /// reload and validate its durable authority before any subsequent mutation.
    pub fn was_abandoned(&self) -> bool {
        self.abandoned
    }

    pub fn release(mut self) -> Result<(), Error> {
        self.unlock()
    }

    fn unlock(&mut self) -> Result<(), Error> {
        if self.acquired {
            if unsafe { ReleaseMutex(self.handle.as_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            self.acquired = false;
        }
        Ok(())
    }
}

impl Drop for PrivateUserMutex {
    fn drop(&mut self) {
        // Explicit release lets an authority report errors. Unwinding still
        // attempts cleanup; Drop cannot turn an operation into success.
        let _ = self.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn purpose() -> String {
        format!(
            "test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn another_thread_cannot_enter_until_the_owner_explicitly_releases() {
        let name = purpose();
        let held = PrivateUserMutex::acquire(&name, Duration::from_secs(3)).unwrap();
        assert!(!held.was_abandoned());
        let contender = name.clone();
        assert!(
            std::thread::spawn(move || matches!(
                PrivateUserMutex::acquire(&contender, Duration::from_millis(20)),
                Err(Error::MutexBusy)
            ))
            .join()
            .unwrap()
        );
        held.release().unwrap();
        std::thread::spawn(move || {
            let acquired = PrivateUserMutex::acquire(&name, Duration::from_secs(3)).unwrap();
            acquired.release().unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn unrelated_purposes_are_independent_and_invalid_names_do_not_create_objects() {
        let held = PrivateUserMutex::acquire(&purpose(), Duration::from_secs(3)).unwrap();
        let other = purpose();
        std::thread::spawn(move || {
            PrivateUserMutex::acquire(&other, Duration::from_millis(20))
                .unwrap()
                .release()
                .unwrap()
        })
        .join()
        .unwrap();
        for invalid in ["", "Uppercase", "a\\b", "a/b", "a\0b"] {
            assert!(matches!(
                PrivateUserMutex::acquire(invalid, Duration::from_secs(1)),
                Err(Error::InvalidMutexParameters)
            ));
        }
        assert!(matches!(
            PrivateUserMutex::acquire("valid", Duration::ZERO),
            Err(Error::InvalidMutexParameters)
        ));
        held.release().unwrap();
    }
}
