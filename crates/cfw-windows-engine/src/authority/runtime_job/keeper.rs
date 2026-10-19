use super::*;
use windows_sys::Win32::{
    Foundation::{CompareObjectHandles, GetHandleInformation, HANDLE_FLAG_INHERIT},
    System::Threading::PROCESS_DUP_HANDLE,
};

/// Only an authenticated keeper-transfer response may adopt a reference. It
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
    // may already have adopted/closed/reused it. One transfer is allowed per
    // role/lease; an unclaimed reference closes when its recipient exits. The
    // Authority retains recovery ownership and never retries uncertain delivery.
    peer.revalidate()?;
    let value = received as usize as u64;
    if value == 0 || value > isize::MAX as u64 || value & 3 != 0 {
        return Err(RuntimeJobError::Security);
    }
    Ok(value)
}

/// Verify a receiver-owned reference without granting the receiver permission
/// to open the SYSTEM-only Job by name. Never close a handle in the peer.
pub(super) fn verify(job: &OwnedHandle, peer: &NativePeerProcess, value: u64) -> Result<()> {
    crate::service_peer::require_system_service_identity()?;
    if value == 0 || value > isize::MAX as u64 || value & 3 != 0 {
        return Err(RuntimeJobError::Security);
    }
    peer.revalidate()?;
    let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, peer.process_id()) };
    if raw.is_null() {
        return Err(native("open runtime keeper verifier peer"));
    }
    let source = unsafe { OwnedHandle::from_raw_handle(raw) };
    peer.revalidate()?;
    let mut received = null_mut();
    if unsafe {
        DuplicateHandle(
            source.as_raw_handle(),
            value as usize as *mut std::ffi::c_void,
            GetCurrentProcess(),
            &mut received,
            0,
            0,
            0,
        )
    } == 0
    {
        return Err(native("copy runtime keeper for object verification"));
    }
    let received = unsafe { OwnedHandle::from_raw_handle(received) };
    peer.revalidate()?;
    if unsafe { CompareObjectHandles(job.as_raw_handle(), received.as_raw_handle()) } == 0 {
        return Err(RuntimeJobError::Security);
    }
    Ok(())
}

impl RuntimeKeeper {
    pub(in crate::authority) fn adopt<E: From<RuntimeJobError>>(
        value: u64,
        root: &RootContext,
        owner: &NativePeerProcess,
        verify: impl FnOnce(u64) -> std::result::Result<(), E>,
    ) -> std::result::Result<Self, E> {
        let candidate = Candidate::receive(value, owner)?;
        verify(candidate.copy.as_raw_handle() as usize as u64)?;
        Ok(candidate.finish(root, owner)?)
    }
    pub(crate) fn root(&self) -> &RootContext {
        &self.root
    }
    pub(crate) fn inherit_for_engine(&self) -> Result<OwnedHandle> {
        self.owner.revalidate()?;
        if self.owner.process_id() != std::process::id() {
            return Err(RuntimeJobError::Security);
        }
        duplicate_local(self.handle.as_raw_handle(), true)
    }
}

struct Candidate {
    original: usize,
    copy: OwnedHandle,
}
impl Candidate {
    fn receive(value: u64, owner: &NativePeerProcess) -> Result<Self> {
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
        if flags & HANDLE_FLAG_INHERIT != 0 {
            return Err(RuntimeJobError::Security);
        }
        // Own only this freshly duplicated reference while its object identity
        // is checked by SYSTEM over the same authenticated Authority channel.
        // A rejected/uncertain verification drops our copy, never the original.
        Ok(Self {
            original: value as usize,
            copy: duplicate_local(raw, false)?,
        })
    }
    fn finish(self, root: &RootContext, owner: &NativePeerProcess) -> Result<RuntimeKeeper> {
        owner.revalidate()?;
        let raw = self.original as *mut std::ffi::c_void;
        if raw == self.copy.as_raw_handle()
            || unsafe { CompareObjectHandles(raw, self.copy.as_raw_handle()) } == 0
        {
            // Do not close an uncorrelated numeric handle: it could identify
            // another caller-owned object. No runtime is authorized by it.
            return Err(RuntimeJobError::Security);
        }
        // SYSTEM verified our retained copy against the exact bound runtime
        // Job. Only now retire the matching transferred reference.
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        let owner = owner.retain()?;
        Ok(RuntimeKeeper {
            handle: self.copy,
            root: root.clone(),
            owner,
        })
    }
}
fn duplicate_local(raw: *mut std::ffi::c_void, inheritable: bool) -> Result<OwnedHandle> {
    let mut inherited = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut inherited,
            0,
            i32::from(inheritable),
            0,
        )
    } == 0
    {
        return Err(native("copy zero-access runtime keeper"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(inherited) })
}

#[cfg(feature = "native-service-validation")]
pub fn validate_runtime_keeper_adoption(
    value: u64,
    root: &RootContext,
    mut verify: impl FnMut(u64) -> Result<()>,
) -> Result<OwnedHandle> {
    use windows_sys::Win32::System::Threading::CreateEventW;
    let owner = NativePeerProcess::open(std::process::id())?;
    let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if raw.is_null() {
        return Err(native("create unrelated keeper fixture object"));
    }
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !matches!(
        RuntimeKeeper::adopt(
            event.as_raw_handle() as usize as u64,
            root,
            &owner,
            &mut verify
        ),
        Err(RuntimeJobError::Security)
    ) {
        return Err(RuntimeJobError::Observation);
    }
    let mut flags = 0;
    if unsafe { GetHandleInformation(event.as_raw_handle(), &mut flags) } == 0 {
        return Err(native("unrelated keeper fixture object was closed"));
    }
    let accepted = RuntimeKeeper::adopt(value, root, &owner, verify)?;
    Ok(accepted.handle)
}
