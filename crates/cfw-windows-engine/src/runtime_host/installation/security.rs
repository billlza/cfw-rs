use super::*;
use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        *,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    },
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
};

/// Only SYSTEM/Administrators may own or mutate an installed package. Read and
/// execute access for other accounts is permitted. Unknown ACE types fail
/// explicitly; an inherited-only ACE cannot authorize the opened object.
pub(super) fn verify(file: &File) -> Result<()> {
    let mut descriptor = null_mut();
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }
    let _owned = Descriptor(descriptor);
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    if descriptor.is_null()
        || unsafe { IsValidSecurityDescriptor(descriptor) } == 0
        || owner.is_null()
        || !privileged(owner)
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(HostError::InstallationSecurity);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.AceCount > 128 || info.AclBytesInUse > 16384 {
        return Err(HostError::InstallationSecurity);
    }
    let mut writer = false;
    for index in 0..info.AceCount {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(HostError::InstallationSecurity);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if !matches!(
            u32::from(header.AceType),
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
        {
            return Err(HostError::InstallationSecurity);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid: PSID = unsafe {
            ace.cast::<u8>()
                .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                .cast()
        };
        let remaining = usize::from(header.AceSize) - offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let subauthorities = unsafe { *sid.cast::<u8>().add(1) };
        if subauthorities > 15 || 8 + 4 * usize::from(subauthorities) > remaining {
            return Err(HostError::InstallationSecurity);
        }
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize > remaining {
            return Err(HostError::InstallationSecurity);
        }
        if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        const WRITE: u32 = GENERIC_ALL
            | GENERIC_WRITE
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD;
        if allowed.Mask & WRITE != 0 {
            if !privileged(sid) {
                return Err(HostError::InstallationSecurity);
            }
            writer = true;
        }
    }
    if !writer {
        return Err(HostError::InstallationSecurity);
    }
    Ok(())
}
fn privileged(sid: PSID) -> bool {
    unsafe {
        IsValidSid(sid) != 0
            && (IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
    }
}
