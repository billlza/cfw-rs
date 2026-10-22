//! Actual Windows TCP and UDP over IPv4 and IPv6 -> Wintun -> packet pump ->
//! the real engine's gVisor packet endpoint -> its SOCKS5 outbound -> a local
//! fixture node, and every reply back the same way. Validation only: the CI runner account owns
//! the adapter, the fixture address/host route, the pump and the engine. No
//! Authority lease, TunnelWorker handoff, default route, DNS, firewall or
//! product backend is involved, so product TUN stays unavailable.
use super::{
    Result,
    library::{self, Library},
    network, record,
};
use crate::{
    CheckedStartConfiguration, EngineProcess, VerifiedExecutable,
    tunnel::{PacketPump, PacketServer},
};
use cfw_engine_api::{EngineCommandContext, EngineStartRequest, TunnelNetworkOptions};
use cfw_singbox_config::{EngineSettings, ProjectionMode, TunnelStack, ValidatedSingBoxProfile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::windows::io::AsRawSocket,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::{
    IP_DONTFRAGMENT, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG, SOCKET, setsockopt,
};

mod socks;
use socks::{
    BULK_BYTES, Fixture, HTTP_TARGETS, UDP_TARGETS, bulk, family, hex, http_host, transform,
    udp_overhead,
};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TIMEOUT: Duration = Duration::from_secs(15);
const MTUS: [u16; 3] = [1280, 1500, 9000];

/// The pinned engine image every run admits afresh.
struct EngineImage<'a> {
    path: &'a Path,
    digest: [u8; 32],
    version: &'a str,
}

/// What every MTU case shares: the loaded driver, the engine, the fixture
/// node's host address and where receipts go.
struct Run<'a> {
    library: &'a Library,
    engine: EngineImage<'a>,
    host: Ipv4Addr,
    output: &'a Path,
    source: &'a str,
}

/// The engine's private working directory for one case. Declared before the
/// engine owner so it is removed after that owner, also on a failed case.
struct RuntimeDirectory(std::path::PathBuf);
impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if self.0.exists()
            && let Err(error) = std::fs::remove_dir_all(&self.0)
        {
            eprintln!("forwarding runtime directory cleanup failed: {error}");
        }
    }
}

/// One adapter's native identity.
struct Owned<'a> {
    id: uuid::Uuid,
    name: &'a str,
    luid: u64,
}

pub(super) fn run(
    dll: &Path,
    engine: &Path,
    engine_sha256: &str,
    engine_version: &str,
    output: &Path,
    source: &str,
) -> Result<()> {
    if !dll.is_absolute() || !engine.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("invalid Wintun forwarding validation paths".into());
    }
    let digest = sha256(engine_sha256)?;
    std::fs::create_dir(output).map_err(|error| error.to_string())?;
    let peer =
        crate::NativePeerProcess::open(std::process::id()).map_err(|error| error.to_string())?;
    // Chosen before any adapter exists: the fixture node lives on the
    // runner's own private address, outside the single owned host route.
    let host = private_address()?;
    record(
        output,
        "initial.json",
        &json!({"source":source,"process_id":peer.process_id(),
        "process_creation_time":peer.identity().process_creation_time(),
        "integrity_rid":peer.identity().integrity_rid(),"local_system":peer.identity().is_local_system(),
        "dll_sha256":crate::runtime_host::wintun_image_pin().map_err(|error| error.to_string())?.sha256,
        "engine_sha256":engine_sha256,"engine_version":engine_version,"fixture_host":host.to_string(),
        "release_accepted":false}),
    )?;
    let mut cases = Vec::new();
    let result = (|| {
        let library = Library::load_for_validation(dll).map_err(|error| error.to_string())?;
        let run = Run {
            library: &library,
            engine: EngineImage {
                path: engine,
                digest,
                version: engine_version,
            },
            host,
            output,
            source,
        };
        let operation = (|| {
            for mtu in MTUS {
                cases.push(forward(&run, mtu)?);
            }
            Ok(())
        })();
        combine(
            operation,
            library.close().map_err(|error| error.to_string()),
        )
    })();
    let saved = record(
        output,
        "result.json",
        &json!({"source":source,"success":result.is_ok(),"failure":result.as_ref().err(),
        "cases":cases,"ip_families":["ipv4","ipv6"],
        "owned_addresses":["192.0.2.10/32","2001:db8:1::10/128"],
        "owned_host_routes":["192.0.2.123/32","2001:db8:1::123/128"],
        "wintun_engine_forwarding_verified":result.is_ok(),
        "authority_lease_exercised":false,"system_to_user_handoff_exercised":false,
        "default_routes_modified":false,"dns_modified":false,"firewall_modified":false,
        "product_tunnel_backend_exercised":false,"release_accepted":false}),
    );
    combine(result, saved)
}

fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}

fn sha256(text: &str) -> Result<[u8; 32]> {
    let mut digest = [0u8; 32];
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("engine digest is not lowercase SHA-256 hex".into());
    }
    for (index, value) in digest.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(digest)
}

/// UDP connect selects a route without sending a datagram.
fn private_address() -> Result<Ipv4Addr> {
    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|error| error.to_string())?;
    route
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(|error| error.to_string())?;
    match route.local_addr().map_err(|error| error.to_string())?.ip() {
        IpAddr::V4(address) if address.is_private() => Ok(address),
        other => Err(format!(
            "forwarding fixture requires a private IPv4 interface, found {other}"
        )),
    }
}

fn reserve_loopback_port() -> Result<u16> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
    Ok(listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port())
}

/// The product Tunnel projection, admitted through the checked shared request.
fn tunnel_request(node: SocketAddr, mtu: u16) -> Result<EngineStartRequest> {
    let profile = ValidatedSingBoxProfile::parse(
        &json!({"outbounds":[{"type":"socks5","tag":"proxy",
            "server":node.ip().to_string(),"server_port":node.port()}]})
        .to_string(),
    )
    .map_err(|error| error.to_string())?;
    let settings = EngineSettings {
        tunnel_mtu: mtu,
        controller_port: reserve_loopback_port()?,
        ..EngineSettings::default()
    };
    let projection = profile
        .project_with_tunnel_stack(
            PROFILE,
            ProjectionMode::Tunnel,
            &settings,
            TunnelStack::Gvisor,
        )
        .map_err(|error| error.to_string())?;
    Ok(EngineStartRequest {
        context: EngineCommandContext {
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
        tunnel_options: Some(TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu,
            system_proxy_port: None,
        }),
    })
}

fn forward(run: &Run<'_>, mtu: u16) -> Result<Value> {
    let (output, source) = (run.output, run.source);
    let id = uuid::Uuid::new_v4();
    let adapter = run.library.create(id).map_err(|error| error.to_string())?;
    let luid = adapter.luid();
    let name = adapter.name().to_owned();
    record(
        output,
        &format!("mtu-{mtu}-created.json"),
        &json!({"source":source,"mtu":mtu,"interface_guid":id,"luid":luid,"name":name,"adapter_created":true}),
    )?;
    let operation = (|| {
        let mut session = adapter.session(mtu).map_err(|error| error.to_string())?;
        let mut owned = network::OwnedNetwork::configure(&adapter, id, mtu, true)?;
        let identity = Owned {
            id,
            name: &name,
            luid,
        };
        let exercised = exercise(run, &mut session, &identity, mtu);
        let restored = owned.restore();
        drop(session);
        let mut receipt = combine(exercised, restored)?;
        receipt["original_mtu"] = json!(owned.original_mtu());
        receipt["original_ipv6_interface"] = json!(owned.original_ipv6().map(|original| {
            json!({"mtu":original.mtu,"dad_transmits":original.dad_transmits,
            "router_discovery":original.router_discovery})
        }));
        receipt["owned_route_address_mtu_restored"] = json!(true);
        Ok(receipt)
    })();
    drop(adapter);
    let absent = library::wait_absent(luid, &name).map_err(|error| error.to_string());
    let mut receipt = combine(operation, absent)?;
    network::require_unused_addresses_and_route()?;
    receipt["source"] = json!(source);
    receipt["mtu"] = json!(mtu);
    receipt["interface_guid"] = json!(id);
    receipt["luid"] = json!(luid);
    receipt["name"] = json!(name);
    receipt["adapter_absence_observed"] = json!(true);
    receipt["fixture_addresses_and_host_route_absent"] = json!(true);
    receipt["release_accepted"] = json!(false);
    record(output, &format!("mtu-{mtu}-complete.json"), &receipt)?;
    Ok(receipt)
}

fn exercise(
    run: &Run<'_>,
    session: &mut crate::tunnel::Session<'_>,
    adapter: &Owned<'_>,
    mtu: u16,
) -> Result<Value> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    // Fixture threads start before the inheritable packet endpoint exists.
    let fixture = Fixture::start(run.host, &nonce)?;
    let request = tunnel_request(fixture.address(), mtu)?;
    let configuration_digest = request.config_digest.clone();
    let config = CheckedStartConfiguration::new(request)
        .and_then(|checked| checked.prepare_tunnel_data_plane([]))
        .map_err(|error| error.to_string())?;
    let executable =
        VerifiedExecutable::open(run.engine.path, run.engine.digest, run.engine.version)
            .map_err(|error| error.to_string())?;
    let (server, client) =
        PacketServer::create(adapter.id, mtu).map_err(|error| error.to_string())?;
    let runtime =
        RuntimeDirectory(std::env::temp_dir().join(format!("cfw-tunnel-forwarding-{nonce}")));
    let mut process =
        EngineProcess::spawn_with_packet_endpoint(executable, &runtime.0, TIMEOUT, None, client)
            .map_err(|error| error.to_string())?;
    let running = process
        .start(&config, TIMEOUT)
        .map_err(|error| error.to_string())?;
    let before =
        library::counters(adapter.luid, adapter.name).map_err(|error| error.to_string())?;
    let (traffic, observed, stopped, retired) = thread::scope(|scope| {
        let pump = match PacketPump::start(scope, &mut *session, server) {
            Ok(pump) => pump,
            Err(error) => {
                let stopped = process.stop(TIMEOUT).map_err(|error| error.to_string());
                return (
                    Err(format!("start the packet pump: {error}")),
                    None,
                    stopped,
                    None,
                );
            }
        };
        let control = pump.control();
        let traffic = exchange(&fixture, mtu);
        let observed = traffic
            .as_ref()
            .ok()
            .map(|_| process.observe(TIMEOUT).map_err(|error| error.to_string()));
        // The engine closes its endpoint first; the pump only observes it.
        control.expect_peer_close();
        let stopped = process.stop(TIMEOUT).map_err(|error| error.to_string());
        let retired = if stopped.is_ok() {
            pump.finish(Instant::now() + Duration::from_secs(5))
                .map(Some)
                .map_err(|error| error.to_string())
        } else {
            pump.stop().map(|_| None).map_err(|error| error.to_string())
        };
        (traffic, observed, stopped, Some(retired))
    });
    let after = library::counters(adapter.luid, adapter.name).map_err(|error| error.to_string());
    let mut failures = Vec::new();
    let traffic = traffic
        .map_err(|error| failures.push(format!("traffic: {error}")))
        .ok();
    let observed = match observed {
        Some(Ok(observed)) => Some(observed),
        Some(Err(error)) => {
            failures.push(format!("engine observation after traffic: {error}"));
            None
        }
        None => None,
    };
    let stopped = stopped
        .map_err(|error| failures.push(format!("engine stop: {error}")))
        .ok();
    let retirement = match retired {
        Some(Ok(Some(retirement))) => Some(retirement),
        Some(Ok(None)) => None,
        Some(Err(error)) => {
            failures.push(format!("pump retirement: {error}"));
            None
        }
        None => None,
    };
    let after = after
        .map_err(|error| failures.push(format!("adapter counters: {error}")))
        .ok();
    let (Some(traffic), Some(observed), Some(stopped), Some(retirement), Some(after)) =
        (traffic, observed, stopped, retirement, after)
    else {
        drop(process);
        let fixture = fixture
            .finish()
            .err()
            .map(|error| format!("; fixture: {error}"))
            .unwrap_or_default();
        return Err(format!("{}{fixture}", failures.join("; ")));
    };
    if observed.process_id != running.process_id
        || observed.configuration_digest != configuration_digest
        || stopped.process_id != running.process_id
        || stopped.configuration_digest != configuration_digest
    {
        return Err("engine observation or stop belongs to another runtime".into());
    }
    let report = *retirement.report();
    if report.to_engine.largest_packet != usize::from(mtu)
        || report.to_system.largest_packet != usize::from(mtu)
        || report.to_engine.packets == 0
        || report.to_system.packets == 0
    {
        return Err(format!(
            "pump did not carry full-MTU packets in both directions: {report:?}"
        ));
    }
    let control = causal_control(&fixture)?;
    let accepted = fixture.accepted();
    let observations = fixture.finish()?;
    require_fixture_flows(&observations, mtu)?;
    drop(process);
    std::fs::remove_dir_all(&runtime.0)
        .map_err(|error| format!("remove the engine runtime directory: {error}"))?;
    Ok(json!({
        "nonce":nonce,"engine_process_id":running.process_id,"configuration_digest":configuration_digest,
        "engine_observed_running_after_traffic":true,"engine_stopped_cleanly":true,
        "traffic":traffic,"pump":{
            "to_engine":{"packets":report.to_engine.packets,"bytes":report.to_engine.bytes,"largest_packet":report.to_engine.largest_packet},
            "to_system":{"packets":report.to_system.packets,"bytes":report.to_system.bytes,"largest_packet":report.to_system.largest_packet},
            "ring_full_waits":report.ring_full_waits,"peer_close_code":retirement.peer_close_code(),
            "server_endpoint_closed":true},
        "interface_counters":{"before":before,"after":after},
        "causal_control":control,"fixture_accepted_connections":accepted,"fixture":observations,
        "windows_to_engine_forwarding_verified":true,"engine_to_windows_forwarding_verified":true
    }))
}

/// Both families: TCP bulk both ways and one full-MTU UDP datagram each.
fn exchange(fixture: &Fixture, mtu: u16) -> Result<Value> {
    let mut families = serde_json::Map::new();
    for (local, http, udp) in [
        (IpAddr::V4(network::LOCAL), HTTP_TARGETS[0], UDP_TARGETS[0]),
        (IpAddr::V6(network::LOCAL6), HTTP_TARGETS[1], UDP_TARGETS[1]),
    ] {
        let tcp = tcp_exchange(fixture, local, http)?;
        let udp = udp_exchange(fixture, local, udp, mtu)?;
        families.insert(family(http).to_owned(), json!({"tcp":tcp,"udp":udp}));
    }
    Ok(Value::Object(families))
}

fn tcp_exchange(fixture: &Fixture, local: IpAddr, target: SocketAddr) -> Result<Value> {
    let nonce = fixture.nonce();
    let family = family(target);
    let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)
        .map_err(|error| format!("{family} TCP through the adapter: {error}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|error| error.to_string())?;
    let observed_local = stream.local_addr().map_err(|error| error.to_string())?;
    let remote = stream.peer_addr().map_err(|error| error.to_string())?;
    if observed_local.ip() != local || remote.ip() != target.ip() || remote.port() != target.port()
    {
        return Err(format!(
            "{family} TCP did not use the owned adapter path: {observed_local} -> {remote}"
        ));
    }
    let upload = bulk(nonce, &format!("upload-{family}"), BULK_BYTES);
    let request = format!(
        "POST /cfw-tunnel-forwarding/{nonce}/{family} HTTP/1.1\r\nHost: {}\r\nContent-Length: {BULK_BYTES}\r\nConnection: close\r\n\r\n",
        http_host(target)
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&upload))
        .map_err(|error| format!("{family} TCP upload: {error}"))?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|error| format!("{family} TCP response header: {error}"))?;
        header.push(byte[0]);
        if header.len() > 8192 {
            return Err("HTTP response header exceeds its bound".into());
        }
    }
    let header = String::from_utf8(header).map_err(|_| "HTTP response header is not UTF-8")?;
    let upload_sha256 = hex(&Sha256::digest(&upload));
    if !header.starts_with("HTTP/1.1 200 OK\r\n")
        || !header.contains(&format!("\r\nContent-Length: {BULK_BYTES}\r\n"))
        || !header.contains(&format!("\r\nX-Upload-Sha256: {upload_sha256}\r\n"))
    {
        return Err(format!(
            "{family} HTTP response does not confirm the exact upload"
        ));
    }
    let mut download = vec![0u8; BULK_BYTES];
    stream
        .read_exact(&mut download)
        .map_err(|error| format!("{family} TCP download: {error}"))?;
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err("HTTP response carried bytes beyond its length".into()),
        Err(error) => return Err(format!("{family} TCP close: {error}")),
    }
    if download != bulk(nonce, &format!("download-{family}"), BULK_BYTES) {
        return Err(format!(
            "{family} downloaded bytes differ from the node's content"
        ));
    }
    Ok(
        json!({"local":observed_local.to_string(),"remote":remote.to_string(),
        "upload_bytes":BULK_BYTES,"upload_sha256":upload_sha256,"download_bytes":BULK_BYTES,
        "download_sha256":hex(&Sha256::digest(&download))}),
    )
}

fn udp_exchange(fixture: &Fixture, local: IpAddr, target: SocketAddr, mtu: u16) -> Result<Value> {
    let family = family(target);
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).map_err(|error| error.to_string())?;
    let (level, option) = match local {
        IpAddr::V4(_) => (IPPROTO_IP, IP_DONTFRAGMENT),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_DONTFRAG),
    };
    let enabled: u32 = 1;
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            option,
            (&enabled as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    } != 0
    {
        return Err(format!(
            "set {family} UDP don't-fragment: {}",
            std::io::Error::last_os_error()
        ));
    }
    socket
        .connect(target)
        .and_then(|()| socket.set_read_timeout(Some(TIMEOUT)))
        .map_err(|error| error.to_string())?;
    let observed_local = socket.local_addr().map_err(|error| error.to_string())?;
    if observed_local.ip() != local {
        return Err(format!(
            "{family} UDP did not use the owned adapter address: {observed_local}"
        ));
    }
    let payload = bulk(
        fixture.nonce(),
        &format!("udp-{family}"),
        usize::from(mtu) - udp_overhead(target),
    );
    if socket.send(&payload).map_err(|error| error.to_string())? != payload.len() {
        return Err(format!(
            "Windows {family} UDP send did not accept the complete datagram"
        ));
    }
    let mut buffer = vec![0u8; usize::from(mtu)];
    let received = socket
        .recv(&mut buffer)
        .map_err(|error| format!("{family} UDP answer through the adapter: {error}"))?;
    if buffer[..received] != transform(&payload) {
        return Err(format!(
            "Windows {family} UDP did not receive the node's exact answer"
        ));
    }
    Ok(
        json!({"local":observed_local.to_string(),"remote":target.to_string(),
        "request_bytes":payload.len(),"answer_bytes":received,"dont_fragment":true,
        "request_sha256":hex(&Sha256::digest(&payload))}),
    )
}

/// With the engine stopped and the pump retired, the same routes, addresses
/// and session remain: a new connection in either family must find no
/// forwarder at all.
fn causal_control(fixture: &Fixture) -> Result<Value> {
    let before = fixture.accepted();
    let mut families = serde_json::Map::new();
    for target in HTTP_TARGETS {
        let family = family(target);
        let started = Instant::now();
        match TcpStream::connect_timeout(&target, Duration::from_secs(3)) {
            Err(error) if error.kind() == ErrorKind::TimedOut => {}
            Ok(_) => {
                return Err(format!(
                    "{family} TCP connected through the adapter without a running pump"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "unexpected {family} control connect result: {error}"
                ));
            }
        }
        families.insert(
            family.to_owned(),
            json!({"control_wait_ms":started.elapsed().as_millis()}),
        );
    }
    if fixture.accepted() != before {
        return Err("the node accepted a connection without a running pump".into());
    }
    Ok(
        json!({"connect_without_pump_timed_out":true,"families":families,
        "node_connections_unchanged":true}),
    )
}

/// Exactly one CONNECT and one UDP datagram per family for this run's fixed
/// targets. Other background flows are recorded by the fixture, never served.
fn require_fixture_flows(observations: &Value, mtu: u16) -> Result<()> {
    let flows = observations["observations"]
        .as_array()
        .ok_or("fixture observations are missing")?;
    for (http, udp) in HTTP_TARGETS.into_iter().zip(UDP_TARGETS) {
        let connects = flows
            .iter()
            .filter(|flow| flow["command"] == "connect" && flow["target"] == http.to_string())
            .count();
        let served: Vec<_> = flows
            .iter()
            .filter(|flow| flow["command"] == "udp_associate")
            .filter_map(|flow| flow["served"].as_array())
            .flatten()
            .filter(|datagram| datagram["target"] == udp.to_string())
            .collect();
        if connects != 1
            || served.len() != 1
            || served[0]["bytes"] != json!(usize::from(mtu) - udp_overhead(udp))
        {
            return Err(format!(
                "fixture did not observe exactly the run's {} flows: {observations}",
                family(http)
            ));
        }
    }
    Ok(())
}
