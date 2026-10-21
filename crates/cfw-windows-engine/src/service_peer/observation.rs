//! Service-owned process access needed by the query-only client admission.
use super::*;
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    Security::{
        ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            SE_KERNEL_OBJECT, SetSecurityInfo,
        },
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, IsValidSecurityDescriptor,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    },
    Storage::FileSystem::WRITE_DAC,
    System::Threading::PROCESS_ALL_ACCESS,
};

struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

/// Called by the dedicated SYSTEM service before it publishes its pipe.
///
/// Only this process's DACL is replaced. SYSTEM/Administrators retain control;
/// authenticated users may query limited process information and wait for exit.
/// No memory, mutation, handle-duplication or token rights are granted. Failure
/// leaves endpoint publication forbidden; this does not authenticate an install
/// or establish service/runtime readiness. Ordinary UI processes are rejected
/// before any mutation, and token/default/other-process ACLs are unchanged.
pub fn configure_service_process_observation() -> Result<(), ServicePeerError> {
    let _own = require_system_service_identity()?;
    configure_observation_acl()
}

pub(crate) fn require_system_service_identity() -> Result<crate::NativePeerProcess, ServicePeerError>
{
    cfw_windows_storage::require_process_identity()?;
    let own = crate::NativePeerProcess::open(std::process::id())?;
    let identity = own.identity();
    if !identity.is_local_system()
        || identity.session_id() != 0
        || identity.integrity_rid() != 0x4000
        || identity.is_app_container()
        || identity.is_restricted()
    {
        return Err(ServicePeerError::InvalidServiceProcessIdentity {
            local_system: identity.is_local_system(),
            session_id: identity.session_id(),
            integrity_rid: identity.integrity_rid(),
            app_container: identity.is_app_container(),
            restricted: identity.is_restricted(),
        });
    }
    Ok(own)
}

fn configure_observation_acl() -> Result<(), ServicePeerError> {
    let observer = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let sddl: Vec<_> = format!(
        "D:P(A;;{PROCESS_ALL_ACCESS:#x};;;SY)(A;;{PROCESS_ALL_ACCESS:#x};;;BA)(A;;{observer:#x};;;AU)"
    ).encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(native("build service process observation ACL"));
    }
    let descriptor = Descriptor(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut expected = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut expected, &mut defaulted)
    } == 0
    {
        return Err(native("read service process observation ACL"));
    }
    if present == 0 || defaulted != 0 || expected.is_null() {
        return Err(ServicePeerError::ObservationSecurityMismatch {
            detail: "constructed DACL is missing or defaulted".into(),
        });
    }
    let raw = unsafe { OpenProcess(READ_CONTROL | WRITE_DAC, 0, std::process::id()) };
    if raw.is_null() {
        return Err(native("open own service process security"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let code = unsafe {
        SetSecurityInfo(
            process.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            expected,
            null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(ServicePeerError::Native {
            operation: "set service process observation ACL",
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    let mut actual = null_mut();
    let mut owner = null_mut();
    let mut readback = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            process.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut actual,
            null_mut(),
            &mut readback,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(ServicePeerError::Native {
            operation: "read back service process observation ACL",
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    let readback = Descriptor(readback);
    let mut control = 0;
    let mut revision = 0;
    if readback.0.is_null()
        || owner.is_null()
        || unsafe { IsValidSecurityDescriptor(readback.0) } == 0
    {
        return Err(ServicePeerError::ObservationSecurityMismatch {
            detail: "invalid native descriptor or absent owner".into(),
        });
    }
    if unsafe { GetSecurityDescriptorControl(readback.0, &mut control, &mut revision) } == 0 {
        return Err(native("inspect service process observation control"));
    }
    let owner_system = unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0;
    let owner_admin = unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } != 0;
    let aces_match = same_aces(expected, actual)?;
    // Object ownership is distinct from the primary token user. SCM-created
    // SYSTEM processes may have Administrators as their object owner; that
    // principal already has full control in the explicit service ACL.
    if (!owner_system && !owner_admin) || control & SE_DACL_PROTECTED == 0 || !aces_match {
        return Err(ServicePeerError::ObservationSecurityMismatch {
            detail: format!(
                "owner_system={owner_system}, owner_admin={owner_admin}, control={control:#x}, exact_aces={aces_match}"
            ),
        });
    }
    Ok(())
}

// Both ACLs are owned native security descriptors kept alive by the caller.
// Compare every ACE, allowing only allocation-size differences in ACL headers.
fn same_aces(expected: *mut ACL, actual: *mut ACL) -> Result<bool, ServicePeerError> {
    let mut counts = [0; 2];
    for (index, acl) in [expected, actual].into_iter().enumerate() {
        if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return Ok(false);
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
            return Err(native("inspect service process observation ACL"));
        }
        counts[index] = info.AceCount;
    }
    if counts != [3, 3] {
        return Ok(false);
    }
    for index in 0..3 {
        let mut left = null_mut();
        let mut right = null_mut();
        if unsafe { GetAce(expected, index, &mut left) } == 0
            || unsafe { GetAce(actual, index, &mut right) } == 0
        {
            return Err(native("inspect service process observation ACE"));
        }
        let left_len = unsafe { (*left.cast::<ACE_HEADER>()).AceSize } as usize;
        let right_len = unsafe { (*right.cast::<ACE_HEADER>()).AceSize } as usize;
        if left_len < size_of::<ACCESS_ALLOWED_ACE>() || left_len > 256 || left_len != right_len {
            return Ok(false);
        }
        if unsafe { std::slice::from_raw_parts(left.cast::<u8>(), left_len) }
            != unsafe { std::slice::from_raw_parts(right.cast::<u8>(), right_len) }
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_user_cannot_configure_service_observation() {
        let own = crate::NativePeerProcess::open(std::process::id()).unwrap();
        assert!(
            !own.identity().is_local_system(),
            "test requires an ordinary CI user"
        );
        assert!(matches!(
            configure_service_process_observation(),
            Err(ServicePeerError::InvalidServiceProcessIdentity {
                local_system: false,
                ..
            })
        ));
    }
}
