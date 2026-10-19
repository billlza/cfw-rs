use super::*;
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl,
        IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED, WinLocalSystemSid,
    },
    Storage::FileSystem::{STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE},
    System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
};

// winnt.h macro omitted by windows-sys 0.61.2 metadata:
// microsoft/win32metadata generation/WinSDK/RecompiledIdlHeaders/um/winnt.h.
const JOB_OBJECT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3f;

pub(super) struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
impl Descriptor {
    pub(super) fn system_only() -> Result<Self> {
        Self::from_sddl(&format!("O:SYD:P(A;;{JOB_OBJECT_ALL_ACCESS:#x};;;SY)"))
    }
    pub(super) fn from_sddl(sddl: &str) -> Result<Self> {
        let wide: Vec<_> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(native("build runtime job descriptor"));
        }
        Ok(Self(descriptor))
    }
    pub(super) fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
    fn validate(&self) -> Result<()> {
        if self.0.is_null() || unsafe { IsValidSecurityDescriptor(self.0) } == 0 {
            return Err(RuntimeJobError::Security);
        }
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) }
                == 0
            || unsafe { GetSecurityDescriptorControl(self.0, &mut control, &mut revision) } == 0
        {
            return Err(native("inspect runtime job descriptor"));
        }
        if owner.is_null()
            || unsafe { IsValidSid(owner) } == 0
            || unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } == 0
            || present == 0
            || acl.is_null()
            || unsafe { IsValidAcl(acl) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(RuntimeJobError::Security);
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
            return Err(native("inspect runtime job ACL"));
        }
        if info.AceCount != 1 {
            return Err(RuntimeJobError::Security);
        }
        let mut raw = null_mut();
        if unsafe { GetAce(acl, 0, &mut raw) } == 0 {
            return Err(native("inspect runtime job ACE"));
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        // SYSTEM SID is 12 bytes, following the 8-byte ACE header and mask.
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || header.AceFlags != 0
            || header.AceSize != 20
        {
            return Err(RuntimeJobError::Security);
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        if ace.Mask != JOB_OBJECT_ALL_ACCESS
            || unsafe { IsValidSid(sid) } == 0
            || unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } == 0
        {
            return Err(RuntimeJobError::Security);
        }
        Ok(())
    }
}

pub(super) fn verify(job: &OwnedHandle) -> Result<()> {
    let mut descriptor = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            job.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(RuntimeJobError::Native {
            operation: "read runtime job security",
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    Descriptor(descriptor).validate()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_job_requires_exact_system_owner_and_protected_single_ace() {
        Descriptor::system_only().unwrap().validate().unwrap();
        for sddl in [
            format!("O:BAD:P(A;;{JOB_OBJECT_ALL_ACCESS:#x};;;SY)"),
            format!("O:SYD:(A;;{JOB_OBJECT_ALL_ACCESS:#x};;;SY)"),
            format!("O:SYD:P(A;;{JOB_OBJECT_ALL_ACCESS:#x};;;AU)"),
            format!("O:SYD:P(A;;{JOB_OBJECT_ALL_ACCESS:#x};;;SY)(A;;1;;;AU)"),
            "O:SYD:P(A;;1;;;SY)".into(),
            "O:SYD:P".into(),
        ] {
            assert!(
                matches!(
                    Descriptor::from_sddl(&sddl).unwrap().validate(),
                    Err(RuntimeJobError::Security)
                ),
                "{sddl}"
            );
        }
    }
}
