use super::*;

use cfw_engine_api::{CredentialProvision, CredentialProvisionRequest};
use cfw_singbox_config::{CredentialKind, CredentialSecret};
use cfw_windows_credentials::WindowsCredentialStore;
use serde_json::json;

#[test]
fn dpapi_material_reaches_the_real_engine_and_authenticates_a_socks_outbound() {
    const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const USER: &str = "cfw-test-node-user";
    const PASSWORD: &str = "cfw-test-node-password-7293";
    let temporary = tempfile::tempdir().unwrap();
    // Imported proxy endpoints deliberately reject loopback IPs. Use this
    // runner's own private interface without weakening that production rule.
    // UDP connect selects a route locally; no datagram is sent to the address.
    let route = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    route.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
    let std::net::IpAddr::V4(local) = route.local_addr().unwrap().ip() else {
        panic!("native Windows credential fixture requires an IPv4 interface");
    };
    assert!(
        local.is_private(),
        "native Windows credential fixture requires a private interface"
    );
    let peer = TcpListener::bind((local, 0)).unwrap();
    let address = peer.local_addr().unwrap();
    let source = json!({"outbounds":[{
        "type":"socks5", "tag":"proxy", "server":local.to_string(), "server_port":address.port(),
        "authentication":{
            "username_credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"socks5_username"},
            "password_credential_ref":{"id":"22222222-2222-4222-8222-222222222222","kind":"socks5_password"}
        }
    }]}).to_string();
    let profile = ValidatedSingBoxProfile::parse(&source).unwrap();
    let references = profile.credential_references();
    let store = WindowsCredentialStore::new(temporary.path().join("vault"));
    let entries = references
        .iter()
        .map(|reference| {
            let value = match reference.kind() {
                CredentialKind::Socks5Username => USER,
                CredentialKind::Socks5Password => PASSWORD,
                _ => panic!("unexpected fixture credential kind"),
            };
            CredentialProvision::new(reference, CredentialSecret::new(value).unwrap())
        })
        .collect();
    store
        .provision(CredentialProvisionRequest::new(PROFILE, &profile, entries).unwrap())
        .unwrap();

    let mixed = reserve();
    let controller = reserve();
    let mixed_address = mixed.local_addr().unwrap();
    let projection = profile
        .project(
            PROFILE,
            ProjectionMode::LocalProxy,
            &EngineSettings {
                mixed_port: mixed_address.port(),
                controller_port: controller.local_addr().unwrap().port(),
                ..EngineSettings::default()
            },
        )
        .unwrap();
    let material = WindowsCredentialStore::new(temporary.path().join("vault"))
        .resolve_for_engine(projection.credential_audience(), &references)
        .unwrap();
    let config = PreparedConfig::local_proxy(&projection, material.expose_to_engine()).unwrap();
    drop(material);
    assert!(!source.contains(PASSWORD));
    assert!(!format!("{config:?}").contains(PASSWORD));

    peer.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let (mut socket, _) = loop {
            match peer.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("SOCKS fixture accept failed: {error}"),
            }
        };
        // Switch the accepted Windows socket out of the bounded accept
        // loop's nonblocking mode before exercising timed protocol reads.
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut greeting = [0; 2];
        socket.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; usize::from(greeting[1])];
        socket.read_exact(&mut methods).unwrap();
        assert!(
            methods.contains(&2),
            "engine did not offer credential authentication"
        );
        socket.write_all(&[5, 2]).unwrap();
        let mut auth = [0; 2];
        socket.read_exact(&mut auth).unwrap();
        assert_eq!(auth[0], 1);
        let mut username = vec![0; usize::from(auth[1])];
        socket.read_exact(&mut username).unwrap();
        let mut length = [0];
        socket.read_exact(&mut length).unwrap();
        let mut password = vec![0; usize::from(length[0])];
        socket.read_exact(&mut password).unwrap();
        assert_eq!(username, USER.as_bytes());
        assert_eq!(password, PASSWORD.as_bytes());
        socket.write_all(&[1, 0]).unwrap();
        let mut connect = [0; 10];
        socket.read_exact(&mut connect).unwrap();
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 9, 0, 80]);
        socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 8192);
        }
        assert!(header.starts_with(b"GET /credential-flow HTTP/1.1\r\n"));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\ncfw-vault-to-proxy").unwrap();
    });

    let mut child =
        EngineProcess::spawn(executable(), &temporary.path().join("runtime"), TIMEOUT).unwrap();
    drop(mixed);
    drop(controller);
    child.start(&config, TIMEOUT).unwrap();
    drop(config);
    let response = request(
        mixed_address,
        "GET http://192.0.2.9/credential-flow HTTP/1.1\r\nHost: 192.0.2.9\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("cfw-vault-to-proxy"));
    worker.join().unwrap();
    child.stop(TIMEOUT).unwrap();
    for directory in ["vault", "runtime"] {
        for entry in std::fs::read_dir(temporary.path().join(directory)).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(PASSWORD.len())
                    .any(|value| value == PASSWORD.as_bytes()),
                "credential persisted outside DPAPI"
            );
        }
    }
}
