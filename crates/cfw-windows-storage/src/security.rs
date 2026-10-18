//! Owner and DACL checks operate on opened handles, never on a second pathname.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, GENERIC_EXECUTE, GENERIC_READ, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_EXECUTE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::{Error, ReadPolicy};

const MAX_SECURITY_BYTES: usize = 16 * 1024;

/// Current-user native authorities must not accidentally read or create state
/// for an impersonated caller. A failed token query never falls back to process.
pub fn require_process_identity() -> Result<(), Error> {
    let mut token = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        let _token = unsafe { OwnedHandle::from_raw_handle(token) };
        return Err(Error::ImpersonatedIdentity);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
        Ok(())
    } else {
        Err(error.into())
    }
}

// These allocations come exclusively from APIs documented to use LocalAlloc.
// They stay local to one call and are released exactly once, including errors.
struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the non-null allocation is owned and came from the matching
        // Win32 allocator. No borrowed pointer outlives this guard.
        unsafe { LocalFree(self.0) };
    }
}

struct Sid(Vec<u32>);

impl Sid {
    fn as_ptr(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    fn current() -> Result<Self, Error> {
        let mut token = null_mut();
        // SAFETY: out points to a live handle slot; the returned handle is owned.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        if opened == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(error.into());
            }
            // There is no impersonation token: the process token is the
            // effective identity. Other thread-token failures never fall back.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        // SAFETY: a successful token open returned one valid owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut required = 0;
        let first = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                null_mut(),
                0,
                &mut required,
            )
        };
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || !(size_of::<TOKEN_USER>()..=MAX_SECURITY_BYTES).contains(&(required as usize))
        {
            return Err(Error::InvalidSecurityDescriptor);
        }
        let mut buffer = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
        let capacity = required;
        // SAFETY: the buffer is pointer-aligned, bounded and at least capacity
        // bytes; the token and returned SID remain live while they are copied.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if required > capacity || (required as usize) < size_of::<TOKEN_USER>() {
            return Err(Error::InvalidSecurityDescriptor);
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        Self::copy_from(user.User.Sid)
    }

    fn system() -> Result<Self, Error> {
        Self::well_known(WinLocalSystemSid)
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, Error> {
        let mut buffer = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut length = SECURITY_MAX_SID_SIZE;
        if unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(buffer))
    }

    fn copy_from(source: PSID) -> Result<Self, Error> {
        if source.is_null() || unsafe { IsValidSid(source) } == 0 {
            return Err(Error::InvalidSecurityDescriptor);
        }
        let length = unsafe { GetLengthSid(source) };
        if length == 0 || length > SECURITY_MAX_SID_SIZE {
            return Err(Error::InvalidSecurityDescriptor);
        }
        let mut buffer = vec![0u32; (length as usize).div_ceil(4)];
        if unsafe { CopySid(length, buffer.as_mut_ptr().cast(), source) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(buffer))
    }

    fn text(&self) -> Result<String, Error> {
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_ptr(), &mut text) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let allocation = LocalAllocation(text.cast());
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(Error::InvalidSecurityDescriptor);
        }
        // SAFETY: the API returned a NUL-terminated SID string; its documented
        // maximum is below this bound, and the allocation remains owned here.
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| Error::InvalidSecurityDescriptor)?;
        drop(allocation);
        Ok(value)
    }
}

pub(crate) struct Security {
    owner: Sid,
    system: Sid,
    // Self-relative security descriptors contain offsets, not borrowed pointers.
    // DWORD storage preserves their required alignment and normal Send/Sync.
    descriptor: Vec<u32>,
}

impl Security {
    pub(crate) fn current() -> Result<Self, Error> {
        Self::for_object(false)
    }

    pub(crate) fn for_mutex() -> Result<Self, Error> {
        Self::for_object(true)
    }

    fn for_object(mutex: bool) -> Result<Self, Error> {
        let owner = Sid::current()?;
        let sid = owner.text()?;
        let acl = if mutex {
            format!("(A;;GA;;;{sid})(A;;GA;;;SY)")
        } else {
            format!("(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
        };
        let sddl: Vec<u16> = format!("O:{sid}D:P{acl}\0").encode_utf16().collect();
        let mut descriptor = null_mut();
        let mut length = 0;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let allocation = LocalAllocation(descriptor);
        if length == 0 || length as usize > MAX_SECURITY_BYTES {
            return Err(Error::InvalidSecurityDescriptor);
        }
        let mut owned = vec![0u32; (length as usize).div_ceil(4)];
        // SAFETY: the converter reports the allocation length; the destination
        // has that capacity and neither range overlaps the other.
        unsafe {
            std::ptr::copy_nonoverlapping(
                descriptor.cast::<u8>(),
                owned.as_mut_ptr().cast(),
                length as usize,
            )
        };
        drop(allocation);
        Ok(Self {
            owner,
            system: Sid::system()?,
            descriptor: owned,
        })
    }

    pub(crate) fn descriptor(&self) -> *const SECURITY_DESCRIPTOR {
        self.descriptor.as_ptr().cast()
    }

    pub(crate) fn principal(&self) -> Result<String, Error> {
        self.owner.text()
    }

    pub(crate) fn verify_mutex(&self, handle: &OwnedHandle) -> Result<(), Error> {
        self.verify_handle(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            ReadPolicy::Private,
            false,
        )
        .map_err(|error| match error {
            Error::UnsafeFile => Error::UnsafeMutex,
            other => other,
        })
    }

    pub(crate) fn verify(
        &self,
        file: &File,
        policy: ReadPolicy,
        directory: bool,
    ) -> Result<(), Error> {
        self.verify_handle(file.as_raw_handle(), SE_FILE_OBJECT, policy, directory)
    }

    fn verify_handle(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        object_type: SE_OBJECT_TYPE,
        policy: ReadPolicy,
        directory: bool,
    ) -> Result<(), Error> {
        let unsafe_object = || {
            if directory {
                Error::UnsafeDirectory
            } else {
                Error::UnsafeFile
            }
        };
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: outputs borrow the returned LocalAlloc descriptor, retained
        // until the owner and every applicable ACE have been checked.
        let result = unsafe {
            GetSecurityInfo(
                handle,
                object_type,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32).into());
        }
        let _allocation = LocalAllocation(descriptor);
        if owner.is_null()
            || acl.is_null()
            || unsafe { IsValidSid(owner) } == 0
            || unsafe { EqualSid(owner, self.owner.as_ptr()) } == 0
            || unsafe { IsValidAcl(acl) } == 0
        {
            return Err(unsafe_object());
        }
        if directory {
            let mut control = 0;
            let mut revision = 0;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            if control & SE_DACL_PROTECTED == 0 {
                return Err(unsafe_object());
            }
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let read_rights = GENERIC_READ
            | GENERIC_EXECUTE
            | READ_CONTROL
            | SYNCHRONIZE
            | FILE_READ_DATA
            | FILE_READ_EA
            | FILE_READ_ATTRIBUTES
            | FILE_EXECUTE;
        for index in 0..info.AceCount {
            let mut pointer = null_mut();
            if unsafe { GetAce(acl, index, &mut pointer) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            // IsValidAcl and GetAce establish a bounded, DWORD-aligned ACE.
            let header = unsafe { &*pointer.cast::<ACE_HEADER>() };
            if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
                continue;
            }
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
                || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
            {
                return Err(unsafe_object());
            }
            let ace = unsafe { &*pointer.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
            if unsafe { IsValidSid(sid) } == 0 {
                return Err(unsafe_object());
            }
            let length = unsafe { GetLengthSid(sid) } as usize;
            if length > usize::from(header.AceSize) - offset_of!(ACCESS_ALLOWED_ACE, SidStart) {
                return Err(unsafe_object());
            }
            if unsafe { EqualSid(sid, self.owner.as_ptr()) } != 0
                || unsafe { EqualSid(sid, self.system.as_ptr()) } != 0
            {
                continue;
            }
            if policy != ReadPolicy::LegacyReadOnly || ace.Mask & !read_rights != 0 {
                return Err(unsafe_object());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_directory_owner_must_match_the_captured_principal() {
        let root = tempfile::tempdir().unwrap();
        let directory =
            crate::PrivateDirectory::open_or_create(&root.path().join("private")).unwrap();
        let mut expected = Security::current().unwrap();
        expected
            .verify(&directory.inner.file, ReadPolicy::Private, true)
            .unwrap();
        // Everyone is a group SID, never this effective user's token-user SID.
        // The same actual filesystem descriptor must fail for another owner.
        expected.owner = Sid::well_known(WinWorldSid).unwrap();
        assert!(matches!(
            expected.verify(&directory.inner.file, ReadPolicy::Private, true),
            Err(Error::UnsafeDirectory)
        ));
    }
}
