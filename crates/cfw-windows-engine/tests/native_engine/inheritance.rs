use super::*;
use std::{
    io,
    mem::size_of,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, GetHandleInformation, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT},
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
    let owner = EngineProcess::spawn_with_packet_endpoint(
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
    // Exercise owner loss through the public ownership contract. Drop alone
    // proves nothing: require the retained native process and pipe observations.
    drop(owner);
    exited(&retained);
    assert!(
        server
            .receive(Instant::now() + Duration::from_secs(5))
            .is_err(),
        "packet client remained open after the owned engine retired"
    );
    server.close().unwrap();
}

const DIRECT: &str = r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#;
const FAKE_IP: &str = r#"{"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],"fake_ip":{"exclude":["+.lan"]}}}"#;

fn tunnel_config(mtu: u16, controller: u16) -> PreparedConfig {
    tunnel_config_for(DIRECT, mtu, controller)
}

/// The product Tunnel data plane, admitted through the checked shared request.
fn tunnel_config_for(source: &str, mtu: u16, controller: u16) -> PreparedConfig {
    let settings = EngineSettings {
        tunnel_mtu: mtu,
        controller_port: controller,
        ..EngineSettings::default()
    };
    let projection = ValidatedSingBoxProfile::parse(source)
        .unwrap()
        .project_with_tunnel_stack(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::Tunnel,
            &settings,
            cfw_singbox_config::TunnelStack::Gvisor,
        )
        .unwrap();
    let request = cfw_engine_api::EngineStartRequest {
        context: cfw_engine_api::EngineCommandContext {
            installation_id: uuid::Uuid::new_v4().to_string(),
            config_epoch: 1,
            generation: 1,
        },
        mode: ProjectionMode::Tunnel,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().to_owned(),
        config_content_digest: projection.configuration_digest().to_owned(),
        config_digest: projection.digest().to_owned(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: Some(cfw_engine_api::TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu,
            system_proxy_port: None,
        }),
    };
    cfw_windows_engine::CheckedStartConfiguration::new(request)
        .unwrap()
        .prepare_tunnel_data_plane([])
        .unwrap()
}

fn alive(handle: &OwnedHandle) -> bool {
    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) == WAIT_TIMEOUT }
}

fn refused(result: Result<cfw_windows_engine::RunningChild, Error>, message: &str) {
    match result {
        Err(Error::Protocol(actual)) => assert_eq!(actual, message),
        other => panic!("start was not refused before any effect: {other:?}"),
    }
}

#[test]
fn listener_only_engine_refuses_a_tunnel_data_plane_before_any_effect() {
    let temporary = tempfile::tempdir().unwrap();
    let controller = reserve();
    let tunnel = tunnel_config(1500, controller.local_addr().unwrap().port());
    let mut worker = EngineProcess::spawn(
        executable(),
        &temporary.path().join("listener only"),
        TIMEOUT,
    )
    .unwrap();
    let process = process_handle(worker.process_id());
    refused(
        worker.start(&tunnel, TIMEOUT),
        "Tunnel data plane requires its exact inherited packet endpoint",
    );
    assert!(
        alive(&process),
        "refused admission tore down the idle child"
    );
    drop(controller);
    let mixed = reserve();
    let controller = reserve();
    let projection = projected(
        mixed.local_addr().unwrap().port(),
        controller.local_addr().unwrap().port(),
    );
    let local = PreparedConfig::local_proxy(&projection, []).unwrap();
    drop((mixed, controller));
    worker.start(&local, TIMEOUT).unwrap();
    worker.stop(TIMEOUT).unwrap();
    exited(&process);
}

#[test]
fn packet_fed_engine_admits_only_its_exact_tunnel_and_closes_its_endpoint_on_stop() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut server, client) =
        cfw_windows_engine::tunnel::PacketServer::create(uuid::Uuid::new_v4(), 1500).unwrap();
    let mut worker = EngineProcess::spawn_with_packet_endpoint(
        executable(),
        &temporary.path().join("packet fed"),
        TIMEOUT,
        None,
        client,
    )
    .unwrap();
    let process = process_handle(worker.process_id());
    let mixed = reserve();
    let controller = reserve();
    let projection = projected(
        mixed.local_addr().unwrap().port(),
        controller.local_addr().unwrap().port(),
    );
    let local = PreparedConfig::local_proxy(&projection, []).unwrap();
    refused(
        worker.start(&local, TIMEOUT),
        "packet endpoint cannot feed a listener-only data plane",
    );
    let port = controller.local_addr().unwrap().port();
    refused(
        worker.start(&tunnel_config(9000, port), TIMEOUT),
        "Tunnel data plane requires its exact inherited packet endpoint",
    );
    assert!(
        alive(&process),
        "refused admission tore down the idle child"
    );
    drop((mixed, controller));
    let tunnel = tunnel_config(1500, port);
    let running = worker.start(&tunnel, TIMEOUT).unwrap();
    assert_eq!(running.configuration_digest, tunnel.digest());
    let stopped = worker.stop(TIMEOUT).unwrap();
    assert_eq!(stopped.process_id, running.process_id);
    exited(&process);
    assert_endpoint_closed(&mut server);
}

/// After the stopped receipt and process exit the endpoint reports its peer
/// closing. Packets the running stack queued are drained first.
fn assert_endpoint_closed(server: &mut cfw_windows_engine::tunnel::PacketServer) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut queued = 0;
    loop {
        match server.receive(deadline) {
            Ok(Some(_)) if queued < 64 => queued += 1,
            Ok(other) => panic!(
                "packet client stayed open after the engine retired ({queued} queued, last {:?})",
                other.map(|packet| packet.as_bytes().len())
            ),
            Err(cfw_windows_engine::tunnel::Error::Transport(
                cfw_windows_engine::ServiceTransportError::Io(error),
            )) if matches!(error.raw_os_error(), Some(109 | 232)) => break,
            Err(error) => panic!("packet endpoint failed without its peer closing: {error}"),
        }
    }
    server.close().unwrap();
}

#[test]
fn packet_fed_worker_refuses_a_candidate_check() {
    let temporary = tempfile::tempdir().unwrap();
    let (mut server, client) =
        cfw_windows_engine::tunnel::PacketServer::create(uuid::Uuid::new_v4(), 1500).unwrap();
    let worker = EngineProcess::spawn_with_packet_endpoint(
        executable(),
        &temporary.path().join("packet check"),
        TIMEOUT,
        None,
        client,
    )
    .unwrap();
    let process = process_handle(worker.process_id());
    let mixed = reserve();
    let controller = reserve();
    let projection = projected(
        mixed.local_addr().unwrap().port(),
        controller.local_addr().unwrap().port(),
    );
    let resolved = ResolvedProjection::new(&projection, []).unwrap();
    match worker.check(&resolved, TIMEOUT) {
        Err(Error::Protocol(message)) => {
            assert_eq!(message, "packet-fed worker cannot run a check")
        }
        other => panic!("packet-fed worker ran a candidate check: {other:?}"),
    }
    // A refused one-shot check retires its worker.
    exited(&process);
    assert_endpoint_closed(&mut server);
}

#[test]
fn packet_fed_tunnel_keeps_its_fake_ip_cache_in_the_private_runtime() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = temporary.path().join("fake ip runtime");
    for round in 0..2 {
        let controller = reserve();
        let config = tunnel_config_for(FAKE_IP, 1500, controller.local_addr().unwrap().port());
        drop(controller);
        let (mut server, client) =
            cfw_windows_engine::tunnel::PacketServer::create(uuid::Uuid::new_v4(), 1500).unwrap();
        let mut worker = EngineProcess::spawn_with_packet_endpoint(
            executable(),
            &runtime,
            TIMEOUT,
            None,
            client,
        )
        .unwrap();
        let process = process_handle(worker.process_id());
        let running = worker.start(&config, TIMEOUT).unwrap();
        assert_eq!(worker.observe(TIMEOUT).unwrap(), running);
        worker.stop(TIMEOUT).unwrap();
        exited(&process);
        drop(worker);
        assert_endpoint_closed(&mut server);
        assert!(
            runtime.join("routing-cache.db").is_file(),
            "round {round}: the projected cache is not in the private runtime"
        );
    }
    assert!(
        !std::env::current_dir()
            .unwrap()
            .join("routing-cache.db")
            .exists()
    );
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
