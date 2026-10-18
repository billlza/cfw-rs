//! Mandatory in the native engine CI job, after building the real worker.
//! Missing artifacts fail; no mocked worker or skipped test is accepted.
#![cfg(windows)]

#[path = "native_engine/credentials.rs"]
mod credentials;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_engine::{
    EngineProcess, Error, PreparedConfig, ResolvedProjection, VerifiedExecutable,
};
use windows_sys::Win32::{
    Foundation::WAIT_OBJECT_0,
    System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    },
};

const TIMEOUT: Duration = Duration::from_secs(15);

fn fixture() -> (PathBuf, [u8; 32], String) {
    let path = PathBuf::from(
        std::env::var_os("CFW_ENGINE_HOST_PATH").expect("native worker path is mandatory"),
    );
    let text = std::env::var("CFW_ENGINE_HOST_SHA256").expect("native worker digest is mandatory");
    assert_eq!(text.len(), 64);
    let mut digest = [0; 32];
    for (index, value) in digest.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    let version =
        std::env::var("CFW_ENGINE_HOST_VERSION").expect("native worker version is mandatory");
    (path, digest, version)
}

fn executable() -> VerifiedExecutable {
    let (path, digest, version) = fixture();
    VerifiedExecutable::open(&path, digest, &version).expect("verified native worker")
}

fn projected(mixed: u16, controller: u16) -> cfw_singbox_config::ProjectedConfig {
    ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
        .unwrap()
        .project(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::LocalProxy,
            &EngineSettings {
                mixed_port: mixed,
                controller_port: controller,
                ..EngineSettings::default()
            },
        )
        .unwrap()
}

fn reserve() -> TcpListener {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()
}

fn process_handle(pid: u32) -> OwnedHandle {
    let raw = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!raw.is_null(), "cannot retain test child process identity");
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

fn exited(handle: &OwnedHandle) {
    assert_eq!(
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 5000) },
        WAIT_OBJECT_0
    );
}

fn request(address: SocketAddr, text: &str) -> String {
    let mut socket = TcpStream::connect_timeout(&address, TIMEOUT).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    socket.write_all(text.as_bytes()).unwrap();
    let mut response = String::new();
    socket
        .take(64 * 1024)
        .read_to_string(&mut response)
        .unwrap();
    response
}

#[test]
fn all_projected_modes_are_checked_without_starting_their_occupied_listeners() {
    let temporary = tempfile::tempdir().unwrap();
    let mixed = reserve();
    let controller = reserve();
    let settings = EngineSettings {
        mixed_port: mixed.local_addr().unwrap().port(),
        controller_port: controller.local_addr().unwrap().port(),
        ..EngineSettings::default()
    };
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap();
    for (index, mode) in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ]
    .into_iter()
    .enumerate()
    {
        let projection = profile
            .project("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", mode, &settings)
            .unwrap();
        let resolved = ResolvedProjection::new(&projection, []).unwrap();
        let directory = temporary.path().join(format!("check-{index}"));
        let child = EngineProcess::spawn(executable(), &directory, TIMEOUT).unwrap();
        let pid = child.process_id();
        let handle = process_handle(pid);
        let checked = child.check(&resolved, TIMEOUT).unwrap();
        assert_eq!(checked.process_id, pid);
        assert_eq!(checked.configuration_digest, projection.digest());
        exited(&handle);
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
    }
    // These remain owned by the test throughout; a check that accidentally
    // starts either mixed or controller listeners cannot pass the real engine.
    assert_eq!(mixed.local_addr().unwrap().port(), settings.mixed_port);
    assert_eq!(
        controller.local_addr().unwrap().port(),
        settings.controller_port
    );
}

#[test]
fn rust_owner_runs_real_projected_http_then_closes_and_releases_listeners() {
    let temporary = tempfile::tempdir().unwrap();
    let mixed = reserve();
    let controller = reserve();
    let mixed_address = mixed.local_addr().unwrap();
    let controller_address = controller.local_addr().unwrap();
    let projection = projected(mixed_address.port(), controller_address.port());
    let config = PreparedConfig::local_proxy(&projection, []).unwrap();
    let mut child =
        EngineProcess::spawn(executable(), &temporary.path().join("runtime"), TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    drop(mixed);
    drop(controller);
    let running = child.start(&config, TIMEOUT).unwrap();
    assert_eq!(running.configuration_digest, projection.digest());
    assert_eq!(child.observe(TIMEOUT).unwrap(), running);

    let server = reserve();
    let destination = server.local_addr().unwrap();
    server.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let (mut socket, _) = loop {
            match server.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("loopback peer accept failed: {error}"),
            }
        };
        // Windows accepted sockets can retain the listener's nonblocking
        // mode. The accept loop is bounded separately; peer I/O uses deadlines.
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 8192);
        }
        assert!(header.starts_with(b"GET /host-lifecycle HTTP/1.1\r\n"));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\ncfw-owned-engine").unwrap();
    });
    let response = request(
        mixed_address,
        &format!(
            "GET http://{destination}/host-lifecycle HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("cfw-owned-engine"));
    worker.join().unwrap();

    let denied = request(
        controller_address,
        "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(denied.starts_with("HTTP/1.1 401"));
    let accepted = request(
        controller_address,
        &format!(
            "GET /version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            projection.clash_api().expose_secret()
        ),
    );
    assert!(accepted.starts_with("HTTP/1.1 200"));
    let stopped = child.stop(TIMEOUT).unwrap();
    assert_eq!(stopped.process_id, running.process_id);
    assert_eq!(stopped.configuration_digest, projection.digest());
    exited(&handle);
    let _mixed = TcpListener::bind(mixed_address).unwrap();
    let _controller = TcpListener::bind(controller_address).unwrap();
}

#[test]
fn startup_conflict_fails_and_cleans_partial_runtime_without_stopped_receipt() {
    let temporary = tempfile::tempdir().unwrap();
    let occupied = reserve();
    let controller = reserve();
    let config = PreparedConfig::local_proxy(
        &projected(
            occupied.local_addr().unwrap().port(),
            controller.local_addr().unwrap().port(),
        ),
        [],
    )
    .unwrap();
    let controller_address = controller.local_addr().unwrap();
    drop(controller);
    let mut child =
        EngineProcess::spawn(executable(), &temporary.path().join("runtime"), TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    assert!(matches!(
        child.start(&config, TIMEOUT),
        Err(Error::Rejected("start_failed"))
    ));
    exited(&handle);
    assert!(child.observe(TIMEOUT).is_err());
    let _released = TcpListener::bind(controller_address).unwrap();
}

#[test]
fn crashed_child_cannot_be_reported_as_running() {
    let temporary = tempfile::tempdir().unwrap();
    let mixed = reserve();
    let controller = reserve();
    let config = PreparedConfig::local_proxy(
        &projected(
            mixed.local_addr().unwrap().port(),
            controller.local_addr().unwrap().port(),
        ),
        [],
    )
    .unwrap();
    let mut child =
        EngineProcess::spawn(executable(), &temporary.path().join("runtime"), TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    drop(mixed);
    drop(controller);
    child.start(&config, TIMEOUT).unwrap();
    assert_ne!(unsafe { TerminateProcess(handle.as_raw_handle(), 17) }, 0);
    exited(&handle);
    assert!(matches!(child.observe(TIMEOUT), Err(Error::Exited)));
}

#[test]
fn deadline_failure_and_owner_drop_reap_the_real_child() {
    for timeout_failure in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let mixed = reserve();
        let controller = reserve();
        let address = mixed.local_addr().unwrap();
        let config = PreparedConfig::local_proxy(
            &projected(address.port(), controller.local_addr().unwrap().port()),
            [],
        )
        .unwrap();
        let mut child =
            EngineProcess::spawn(executable(), &temporary.path().join("runtime"), TIMEOUT).unwrap();
        let handle = process_handle(child.process_id());
        drop(mixed);
        drop(controller);
        child.start(&config, TIMEOUT).unwrap();
        if timeout_failure {
            assert!(matches!(
                child.observe(Duration::from_nanos(1)),
                Err(Error::Timeout)
            ));
        }
        drop(child);
        exited(&handle);
        let _released = TcpListener::bind(address).unwrap();
    }
}

#[test]
fn wrong_binary_or_version_cannot_become_an_owner() {
    let (path, mut hash, version) = fixture();
    hash[0] ^= 1;
    assert!(matches!(
        VerifiedExecutable::open(&path, hash, &version),
        Err(Error::ExecutableIdentity)
    ));
    let (_, hash, _) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let wrong_version = VerifiedExecutable::open(&path, hash, "0.0.0").unwrap();
    assert!(matches!(
        EngineProcess::spawn(wrong_version, &temporary.path().join("runtime"), TIMEOUT),
        Err(Error::Protocol("response identity"))
    ));
}
