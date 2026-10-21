use super::*;
use std::{
    io,
    mem::size_of,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, GetHandleInformation, HANDLE_FLAG_INHERIT},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::SYNCHRONIZE,
    System::{
        JobObjects::*,
        Threading::{CREATE_NO_WINDOW, CreateEventW, OpenEventW},
    },
};

#[test]
fn owned_packet_endpoint_is_inherited_by_the_real_engine_and_retires() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut server, client) =
        cfw_windows_engine::tunnel::PacketServer::create(uuid::Uuid::new_v4(), 9000).unwrap();
    let (ambient, name) = event();
    let mut owner = EngineProcess::spawn_with_packet_endpoint(
        executable(),
        &temporary.path().join("packet engine 空格"),
        TIMEOUT,
        None,
        client,
    )
    .unwrap();
    let retained = process_handle(owner.process_id());
    drop(ambient);
    assert!(
        !exists(&name).unwrap(),
        "ambient inheritable handle leaked alongside packet capability"
    );
    assert!(
        server
            .receive(Instant::now() + Duration::from_millis(20))
            .unwrap()
            .is_none(),
        "idle packet engine unexpectedly emitted a packet"
    );
    owner.abort().unwrap();
    exited(&retained);
    assert!(
        server
            .receive(Instant::now() + Duration::from_secs(5))
            .is_err(),
        "packet client remained open after the owned engine retired"
    );
    server.close().unwrap();
}

fn event() -> (OwnedHandle, Vec<u16>) {
    let name: Vec<_> = format!("Local\\CFW-engine-inheritance-{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain([0])
        .collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let raw = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
    assert!(!raw.is_null(), "{}", io::Error::last_os_error());
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut flags = 0;
    assert_ne!(
        unsafe { GetHandleInformation(event.as_raw_handle(), &mut flags) },
        0
    );
    assert_ne!(
        flags & HANDLE_FLAG_INHERIT,
        0,
        "the control must actually be inheritable"
    );
    (event, name)
}
fn exists(name: &[u16]) -> io::Result<bool> {
    let raw = unsafe { OpenEventW(SYNCHRONIZE, 0, name.as_ptr()) };
    if !raw.is_null() {
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}
fn cleanup_job() -> OwnedHandle {
    let raw = unsafe { CreateJobObjectW(null(), null()) };
    assert!(!raw.is_null(), "{}", io::Error::last_os_error());
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        },
        0
    );
    job
}
fn count(job: &OwnedHandle) -> io::Result<u32> {
    let mut value = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&mut value as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of_val(&value) as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value.ActiveProcesses)
}

#[test]
fn explicit_inheritance_excludes_ambient_handles_that_the_default_spawn_leaks() {
    let temporary = tempfile::tempdir().unwrap();
    let installation = temporary.path().join("engine with 空格");
    std::fs::create_dir(&installation).unwrap();
    let (source, digest, version) = fixture();
    let image = installation.join("verified worker.exe");
    std::fs::copy(source, &image).unwrap();
    let verified = VerifiedExecutable::open(&image, digest, &version).unwrap();

    // Run the previous default-inheritance behavior against the actual idle
    // worker. No configuration is sent; the owned Job bounds its whole tree.
    let (ambient, name) = event();
    let job = cleanup_job();
    let mut legacy = Command::new(&image)
        .current_dir(&installation)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let assigned = unsafe { AssignProcessToJobObject(job.as_raw_handle(), legacy.as_raw_handle()) };
    let assignment_error = (assigned == 0).then(io::Error::last_os_error);
    drop(ambient);
    let legacy_inherited = exists(&name);
    let terminated = if assigned != 0 {
        if unsafe { TerminateJobObject(job.as_raw_handle(), 2) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    } else {
        legacy.kill()
    };
    let observed = cfw_windows_storage::wait_until(&legacy, Instant::now() + TIMEOUT);
    let retired = legacy.try_wait();
    assert!(
        terminated.is_ok()
            && matches!(observed, Ok(cfw_windows_storage::WaitOutcome::Signaled))
            && retired.as_ref().is_ok_and(Option::is_some),
        "control cleanup: terminate={terminated:?}, wait={observed:?}, exit={retired:?}, inherited={legacy_inherited:?}"
    );
    let deadline = Instant::now() + TIMEOUT;
    while count(&job).unwrap() != 0 {
        assert!(Instant::now() < deadline, "control Job did not retire");
        thread::sleep(Duration::from_millis(1));
    }
    assert_ne!(
        assigned, 0,
        "control Job assignment failed: {assignment_error:?}"
    );
    assert!(
        legacy_inherited.unwrap(),
        "the default-spawn counterexample was not reproduced"
    );
    assert!(
        !exists(&name).unwrap(),
        "control retained its event after retirement"
    );

    let (ambient, name) = event();
    let worker = EngineProcess::spawn(
        verified,
        &temporary.path().join("runtime with 空格"),
        TIMEOUT,
    )
    .unwrap();
    let process = process_handle(worker.process_id());
    drop(ambient);
    let new_inherited = exists(&name);
    let mixed = reserve();
    let controller = reserve();
    let projection = projected(
        mixed.local_addr().unwrap().port(),
        controller.local_addr().unwrap().port(),
    );
    let resolved = ResolvedProjection::new(&projection, []).unwrap();
    worker.check(&resolved, TIMEOUT).unwrap();
    exited(&process);
    assert!(
        !new_inherited.unwrap(),
        "the explicit startup leaked an unselected inherited handle"
    );
}
