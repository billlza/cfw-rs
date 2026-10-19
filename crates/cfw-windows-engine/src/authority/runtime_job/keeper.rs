use super::*;
use windows_sys::Win32::{
    Foundation::{CompareObjectHandles, GetHandleInformation, HANDLE_FLAG_INHERIT},
    System::Threading::PROCESS_DUP_HANDLE,
};

/// Only the authenticated v3 response may adopt a transferred reference. It
/// retains lifetime, never query/assignment/termination authority. No Clone,
/// serializer or raw-handle constructor is exposed outside this module.
pub(crate) struct RuntimeKeeper {
    handle: OwnedHandle,
    root: RootContext,
    owner: NativePeerProcess,
}
pub(super) fn transfer(job: &OwnedHandle, peer: &NativePeerProcess) -> Result<u64> {
    crate::service_peer::require_system_service_identity()?;
    peer.revalidate()?;
    let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, peer.process_id()) };
    if raw.is_null() {
        return Err(native("open runtime keeper target"));
    }
    let target = unsafe { OwnedHandle::from_raw_handle(raw) };
    peer.revalidate()?;
    let mut received = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            job.as_raw_handle(),
            target.as_raw_handle(),
            &mut received,
            0,
            0,
            0,
        )
    } == 0
    {
        return Err(native("transfer zero-access runtime keeper"));
    }
    // Never close a remote numeric handle after uncertain delivery; the peer
    // may already have adopted/closed/reused it. Its dedicated process bounds
    // any unclaimed reference, and the Authority retains recovery ownership.
    peer.revalidate()?;
    let value = received as usize as u64;
    if value == 0 || value > isize::MAX as u64 || value & 3 != 0 {
        return Err(RuntimeJobError::Security);
    }
    Ok(value)
}
impl RuntimeKeeper {
    pub(in crate::authority) fn adopt(
        value: u64,
        root: &RootContext,
        owner: &NativePeerProcess,
    ) -> Result<Self> {
        owner.revalidate()?;
        if owner.process_id() != std::process::id()
            || owner.identity().is_local_system()
            || owner.identity().integrity_rid() != 0x2000
            || value == 0
            || value > isize::MAX as u64
            || value & 3 != 0
        {
            return Err(RuntimeJobError::Security);
        }
        let raw = value as usize as *mut std::ffi::c_void;
        let mut flags = 0;
        if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
            return Err(native("inspect transferred runtime keeper"));
        }
        let name: Vec<_> = job_name(root)?.encode_utf16().chain([0]).collect();
        let opened = unsafe { OpenJobObjectW(0, 0, name.as_ptr()) };
        if opened.is_null() {
            return Err(native("open zero-access runtime reference"));
        }
        let opened = unsafe { OwnedHandle::from_raw_handle(opened) };
        if raw == opened.as_raw_handle()
            || unsafe { CompareObjectHandles(raw, opened.as_raw_handle()) } == 0
        {
            // Do not close an uncorrelated numeric handle: it could identify
            // another caller-owned object. No runtime is authorized by it.
            return Err(RuntimeJobError::Security);
        }
        // The correlated, authenticated transfer is valid and identifies this
        // operation's Job. Replace it with our own exact zero-access reference.
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        if flags & HANDLE_FLAG_INHERIT != 0 {
            return Err(RuntimeJobError::Security);
        }
        let owner = owner.retain()?;
        Ok(Self {
            handle: opened,
            root: root.clone(),
            owner,
        })
    }
    pub(crate) fn root(&self) -> &RootContext {
        &self.root
    }
    pub(crate) fn inherit_for_engine(&self) -> Result<OwnedHandle> {
        self.owner.revalidate()?;
        if self.owner.process_id() != std::process::id() {
            return Err(RuntimeJobError::Security);
        }
        let mut inherited = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle.as_raw_handle(),
                GetCurrentProcess(),
                &mut inherited,
                0,
                1,
                0,
            )
        } == 0
        {
            return Err(native("inherit zero-access runtime keeper"));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(inherited) })
    }
}

#[cfg(feature = "native-service-validation")]
pub fn validate_runtime_keeper_adoption(value: u64, root: &RootContext) -> Result<OwnedHandle> {
    use windows_sys::Win32::System::Threading::CreateEventW;
    let owner = NativePeerProcess::open(std::process::id())?;
    let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if raw.is_null() {
        return Err(native("create unrelated keeper fixture object"));
    }
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !matches!(
        RuntimeKeeper::adopt(event.as_raw_handle() as usize as u64, root, &owner),
        Err(RuntimeJobError::Security)
    ) {
        return Err(RuntimeJobError::Observation);
    }
    let mut flags = 0;
    if unsafe { GetHandleInformation(event.as_raw_handle(), &mut flags) } == 0 {
        return Err(native("unrelated keeper fixture object was closed"));
    }
    let accepted = RuntimeKeeper::adopt(value, root, &owner)?;
    Ok(accepted.handle)
}
