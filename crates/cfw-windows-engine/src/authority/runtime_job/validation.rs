//! Opt-in disposable SYSTEM fixture only. No process is assigned or terminated.
use super::*;
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE},
    System::{
        JobObjects::{JOB_OBJECT_LIMIT_BREAKAWAY_OK, SetInformationJobObject},
        Threading::CreateEventW,
    },
};

pub fn validate_runtime_job_failures_for_validation() -> Result<()> {
    let own = crate::service_peer::require_system_service_identity()?;
    verify_last_handle_loss_with_live_peer()?;
    let root = RootContext {
        installation_id: uuid::Uuid::new_v4(),
        epoch: 1,
        generation: 1,
    };
    let descriptor = security::Descriptor::system_only()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name: Vec<_> = job_name(&root)?.encode_utf16().chain([0]).collect();
    let raw = unsafe { CreateJobObjectW(&attributes, name.as_ptr()) };
    if raw.is_null() {
        return Err(native("create job failure fixture"));
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !matches!(
        RuntimeJob::assign(&root, &own),
        Err(RuntimeJobError::AlreadyExists)
    ) {
        return Err(RuntimeJobError::Observation);
    }
    let raw = unsafe { OpenJobObjectW(OBSERVER_ACCESS, 0, name.as_ptr()) };
    if raw.is_null() {
        return Err(native("open job failure fixture observer"));
    }
    let observer = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let pointer = (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast();
    if unsafe {
        SetInformationJobObject(
            observer.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            pointer,
            size_of_val(&limits) as u32,
        )
    } != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32)
    {
        return Err(RuntimeJobError::Observation);
    }
    drop(observer);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            pointer,
            size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(native("set unsafe job fixture limits"));
    }
    if !matches!(observe(&root), Err(RuntimeJobError::Observation)) {
        return Err(RuntimeJobError::Observation);
    }
    drop(job);
    if !matches!(observe(&root), Err(RuntimeJobError::Unavailable)) {
        return Err(RuntimeJobError::Observation);
    }

    let raw = unsafe { CreateEventW(&attributes, 0, 0, name.as_ptr()) };
    if raw.is_null() {
        return Err(native("create wrong-type job fixture"));
    }
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    match observe(&root) {
        Err(RuntimeJobError::Native { source, .. })
            if source.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) => {}
        _ => return Err(RuntimeJobError::Observation),
    }
    drop(event);

    let unsafe_descriptor = security::Descriptor::from_sddl("O:SYD:P(A;;GA;;;SY)(A;;GR;;;AU)")?;
    let unsafe_attributes = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: unsafe_descriptor.as_ptr(),
        ..attributes
    };
    let raw = unsafe { CreateJobObjectW(&unsafe_attributes, name.as_ptr()) };
    if raw.is_null() {
        return Err(native("create unsafe job ACL fixture"));
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !matches!(observe(&root), Err(RuntimeJobError::Security)) {
        return Err(RuntimeJobError::Observation);
    }
    drop(job);
    if !matches!(observe(&root), Err(RuntimeJobError::Unavailable)) {
        return Err(RuntimeJobError::Observation);
    }
    Ok(())
}

fn verify_last_handle_loss_with_live_peer() -> Result<()> {
    use std::process::{Command, Stdio};
    let image = std::env::current_exe().map_err(|source| RuntimeJobError::Native {
        operation: "locate idle process fixture",
        source,
    })?;
    // This copied fixture has a bounded, idle-only child mode. It never starts
    // an engine or edits proxy state. The parent always retires the held child.
    let mut child = Command::new(image)
        .arg("--runtime-job-idle-probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| RuntimeJobError::Native {
            operation: "spawn idle process fixture",
            source,
        })?;
    let checked = (|| {
        let peer = NativePeerProcess::open(child.id())?;
        let root = RootContext {
            installation_id: uuid::Uuid::new_v4(),
            epoch: 1,
            generation: 1,
        };
        let job = RuntimeJob::assign(&root, &peer)?;
        let before = observe(&root)?;
        if before.state()
            != (RuntimeProcessState::Accounting {
                active: 1,
                total: 1,
            })
        {
            return Err(RuntimeJobError::Observation);
        }
        drop(job);
        // The retained process, creation time and primary token still match.
        // A missing native name during that interval must remain an error.
        peer.revalidate()?;
        if !matches!(observe(&root), Err(RuntimeJobError::Unavailable)) {
            return Err(RuntimeJobError::Observation);
        }
        peer.revalidate()?;
        Ok(())
    })();
    let killed = child.kill();
    let waited = child.wait();
    match (checked, killed, waited) {
        (Ok(()), Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(()), Ok(_)) => Err(error),
        (checked, killed, waited) => Err(RuntimeJobError::Native {
            operation: "retire idle process fixture",
            source: io::Error::other(format!(
                "test={checked:?}; kill={killed:?}; wait={waited:?}"
            )),
        }),
    }
}
