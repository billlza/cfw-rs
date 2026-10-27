use super::*;
use cfw_engine_api::{
    CredentialProvision, CredentialProvisionRequest, ProfileDelayTestRequest, ProfileProbeFailure,
};
use cfw_singbox_config::{CredentialKind, CredentialSecret};
use cfw_windows_credentials::WindowsCredentialStore;
use cfw_windows_engine::{CheckedProbeConfiguration, WindowsSystemProxy};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

const PROFILE: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

fn candidate(
    profile: &ValidatedSingBoxProfile,
    names: Vec<String>,
    target: String,
    timeout: u16,
) -> ProfileDelayTestRequest {
    let projection = profile
        .project_proxy_probe(
            PROFILE,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    ProfileDelayTestRequest {
        audience: projection.credential_audience().clone(),
        config_json: projection.as_json().into(),
        credential_slots: projection.credential_slots().to_vec(),
        proxies: names,
        timeout_ms: timeout,
        target_url: Some(target),
        expected_status: Some("204".into()),
    }
}
fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(TIMEOUT)).unwrap();
                socket.set_write_timeout(Some(TIMEOUT)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "native probe did not reach fixture"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("native probe fixture accept: {error}"),
        }
    }
}
fn head(socket: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() <= 8192);
    }
    assert!(header.starts_with(b"HEAD /native-probe HTTP/1.1\r\n"));
}
fn closed(socket: &mut TcpStream) {
    let mut byte = [0];
    // Winsock reports orderly EOF or WSAECONNRESET for the peer's abortive
    // close. A receive timeout or unrelated I/O failure proves neither.
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("probe retained its socket or closure was unproven: {other:?}"),
    }
}
fn empty(directory: &std::path::Path) {
    assert!(std::fs::read_dir(directory).unwrap().next().is_none());
}

#[test]
fn profile_probe_resolves_dpapi_into_real_socks_and_retires_without_proxy_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let peer = private_interface_listener();
    let address = peer.local_addr().unwrap();
    let user = "probe-native-user";
    let password = "probe-native-secret";
    let profile=ValidatedSingBoxProfile::parse(&serde_json::json!({"outbounds":[{"type":"socks5","tag":"node",
        "server":address.ip().to_string(),"server_port":address.port(),"authentication":{
        "username_credential_ref":{"id":"33333333-3333-4333-8333-333333333333","kind":"socks5_username"},
        "password_credential_ref":{"id":"44444444-4444-4444-8444-444444444444","kind":"socks5_password"}}}]}).to_string()).unwrap();
    let refs = profile.credential_references();
    let vault = WindowsCredentialStore::new(temporary.path().join("vault"));
    let entries = refs
        .iter()
        .map(|reference| {
            CredentialProvision::new(
                reference,
                CredentialSecret::new(match reference.kind() {
                    CredentialKind::Socks5Username => user,
                    CredentialKind::Socks5Password => password,
                    _ => panic!("wrong fixture kind"),
                })
                .unwrap(),
            )
        })
        .collect();
    vault
        .provision(CredentialProvisionRequest::new(PROFILE, &profile, entries).unwrap())
        .unwrap();
    let request = candidate(
        &profile,
        vec!["node".into()],
        "http://192.0.2.9/native-probe".into(),
        3000,
    );
    let checked = CheckedProbeConfiguration::new(request).unwrap();
    let material = vault
        .resolve_for_engine(
            checked.credential_audience(),
            &checked.credential_references(),
        )
        .unwrap();
    let probe = checked.resolve(material.expose_to_engine()).unwrap();
    drop(material);
    let proxy = WindowsSystemProxy::new(&temporary.path().join("proxy-observation")).unwrap();
    let before = proxy.snapshot().unwrap();
    let mixed = reserve();
    let controller = reserve();
    let server = thread::spawn(move || {
        let mut socket = accept(&peer);
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        socket.write_all(&[5, 2]).unwrap();
        let mut auth = [0; 2];
        socket.read_exact(&mut auth).unwrap();
        assert_eq!(auth[0], 1);
        let mut actual = vec![0; auth[1] as usize];
        socket.read_exact(&mut actual).unwrap();
        assert_eq!(actual, user.as_bytes());
        let mut length = [0];
        socket.read_exact(&mut length).unwrap();
        let mut actual = vec![0; length[0] as usize];
        socket.read_exact(&mut actual).unwrap();
        assert_eq!(actual, password.as_bytes());
        socket.write_all(&[1, 0]).unwrap();
        let mut connect = [0; 10];
        socket.read_exact(&mut connect).unwrap();
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 9, 0, 80]);
        socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        head(&mut socket);
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let directory = temporary.path().join("probe");
    let child = EngineProcess::spawn(executable(), &directory, TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    let result = child.probe(&probe, TIMEOUT).unwrap();
    server.join().unwrap();
    exited(&handle);
    empty(&directory);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "node");
    assert!(result[0].delay.is_some_and(|delay| delay > 0));
    assert_eq!(result[0].error_kind, None);
    assert_eq!(proxy.snapshot().unwrap(), before);
    assert!(mixed.local_addr().is_ok() && controller.local_addr().is_ok());
}

#[test]
fn profile_probe_cancellation_retires_the_exact_child_and_socket() {
    let temporary = tempfile::tempdir().unwrap();
    let origin = reserve();
    let address = origin.local_addr().unwrap();
    let (requested, received) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let mut socket = accept(&origin);
        head(&mut socket);
        requested.send(()).unwrap();
        closed(&mut socket);
    });
    let probe = CheckedProbeConfiguration::new(candidate(
        &ValidatedSingBoxProfile::direct(),
        vec!["direct".into()],
        format!("http://{address}/native-probe"),
        10000,
    ))
    .unwrap()
    .resolve([])
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancel);
    let directory = temporary.path().join("cancelled");
    let worker_directory = directory.clone();
    let (launched, pid) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let child = EngineProcess::spawn_cancellable(
            executable(),
            &worker_directory,
            TIMEOUT,
            Some(signal),
        )
        .unwrap();
        launched.send(child.process_id()).unwrap();
        child.probe(&probe, TIMEOUT)
    });
    let handle = process_handle(pid.recv_timeout(TIMEOUT).unwrap());
    received.recv_timeout(TIMEOUT).unwrap();
    cancel.store(true, Ordering::Release);
    assert!(matches!(worker.join().unwrap(), Err(Error::Cancelled)));
    exited(&handle);
    server.join().unwrap();
    empty(&directory);
}

#[test]
fn profile_probe_timeout_and_large_ordered_results_leave_no_worker() {
    let temporary = tempfile::tempdir().unwrap();
    let origin = reserve();
    let address = origin.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut socket = accept(&origin);
        head(&mut socket);
        closed(&mut socket);
    });
    let profile = ValidatedSingBoxProfile::direct();
    let request = candidate(
        &profile,
        vec!["direct".into()],
        format!("http://{address}/native-probe"),
        1000,
    );
    let probe = CheckedProbeConfiguration::new(request)
        .unwrap()
        .resolve([])
        .unwrap();
    let directory = temporary.path().join("timeout");
    let child = EngineProcess::spawn(executable(), &directory, TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    let rows = child.probe(&probe, TIMEOUT).unwrap();
    exited(&handle);
    server.join().unwrap();
    empty(&directory);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].delay, None);
    assert_eq!(rows[0].error_kind, Some(ProfileProbeFailure::Timeout));
    let names: Vec<_> = (0..32)
        .map(|i| format!("{i}-{}", "n".repeat(500)))
        .collect();
    let request = candidate(
        &profile,
        names.clone(),
        "https://example.invalid/unused".into(),
        100,
    );
    let probe = CheckedProbeConfiguration::new(request)
        .unwrap()
        .resolve([])
        .unwrap();
    let directory = temporary.path().join("large");
    let child = EngineProcess::spawn(executable(), &directory, TIMEOUT).unwrap();
    let handle = process_handle(child.process_id());
    let rows = child.probe(&probe, TIMEOUT).unwrap();
    exited(&handle);
    empty(&directory);
    assert_eq!(rows.len(), 32);
    for (row, name) in rows.iter().zip(&names) {
        assert_eq!(&row.name, name);
        assert_eq!(row.delay, None);
        assert_eq!(row.error_kind, Some(ProfileProbeFailure::NotFound));
    }
}
