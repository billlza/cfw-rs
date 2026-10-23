//! The installed product's Tunnel mode through the shared backend: SYSTEM's
//! adapter, routes, resolvers and packet pump with the UserAgent-hosted
//! engine, real system DNS and TCP traffic through the tunnel, the engine's
//! own record of that connection, and verified retirement of the network.
//! The engine's DIRECT outbound binds to the physical interface, so the
//! runner keeps its connectivity while the default route enters the tunnel.
use super::*;
use cfw_engine_api::{
    EngineBackend, EngineCommandContext, EngineStartRequest, NativeEngineStatus,
    TunnelInstallOutcome, TunnelNetworkOptions,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, TunnelStack, ValidatedSingBoxProfile};
use cfw_windows_engine::{backend::WindowsEngineBackend, runtime_host::InstalledDesktop};
use std::{
    io::Write,
    net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND},
        NetworkManagement::{
            IpHelper::{ConvertInterfaceGuidToLuid, GetBestRoute2, MIB_IPFORWARD_ROW2},
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET},
    },
    core::GUID,
};

/// Windows' own network connectivity probe: a fixed body over plain HTTP.
const PROBE_HOST: &str = "www.msftconnecttest.com";
const PROBE_PATH: &str = "/connecttest.txt";
const PROBE_BODY: &str = "Microsoft Connect Test";
const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TUNNEL_MTU: u16 = 1500;

pub(super) fn exercise(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("tunnel_open", 0)?;
    let desktop = Arc::new(InstalledDesktop::open().map_err(|e| e.to_string())?);
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            desktop
                .paths()
                .root
                .join("installed-validation-backend-tunnel.log"),
        )
        .map_err(|e| e.to_string())?;
    let backend = WindowsEngineBackend::new(Arc::clone(&desktop), diagnostics);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(exercise_async(&desktop, &backend, progress))
}

async fn exercise_async(
    desktop: &InstalledDesktop,
    backend: &WindowsEngineBackend,
    progress: &mut Progress,
) -> Result<serde_json::Value> {
    if backend.query_status().await.map_err(|e| e.to_string())? != NativeEngineStatus::Off {
        return Err("tunnel suite did not begin from verified native Off".into());
    }
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    if lineage.generation != 8 {
        return Err("tunnel suite began with a different persisted generation".into());
    }
    let installation =
        uuid::Uuid::parse_str(&lineage.session.installation_id).map_err(|e| e.to_string())?;
    let adapter = cfw_windows_engine::tunnel::adapter_guid(installation);
    if adapter_luid(adapter)?.is_some() {
        return Err("a tunnel adapter existed before the tunnel suite".into());
    }
    let original_proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    // The probe address is resolved and routed before the tunnel exists, so
    // the physical route can be compared with the tunnel's and restored one.
    let direct_target = resolve()?;
    let direct_route = best_route(direct_target)?;

    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
    let settings = EngineSettings {
        mixed_port: mixed.local_addr().map_err(|e| e.to_string())?.port(),
        controller_port: controller_address.port(),
        tunnel_mtu: TUNNEL_MTU,
        enable_ipv6: false,
        bypass_private_networks: true,
        ..Default::default()
    };
    let generation = desktop
        .generations()
        .reserve_generation(lineage.generation)
        .map_err(|e| e.to_string())?;
    let context = EngineCommandContext {
        installation_id: lineage.session.installation_id.clone(),
        config_epoch: lineage.session.config_epoch,
        generation,
    };
    let (request, secret) = tunnel_request(&settings, context.clone())?;
    drop((controller, mixed));

    progress.record("tunnel_check", generation)?;
    backend
        .check_configuration(request.clone())
        .await
        .map_err(|e| e.to_string())?;
    if backend
        .install_tunnel(context.clone())
        .await
        .map_err(|e| e.to_string())?
        != TunnelInstallOutcome::Ready
    {
        return Err("installed tunnel service was not ready".into());
    }
    backend
        .authorize_tunnel_configuration(request.clone())
        .await
        .map_err(|e| e.to_string())?;
    progress.record("tunnel_start", generation)?;
    let started = backend
        .start_tunnel(request)
        .await
        .map_err(|e| e.to_string())?;
    progress.record("tunnel_ready", generation)?;
    let platform = cfw_engine_api::EngineRuntimePlatform::Windows;
    if started.context != context || !started.ready || started.owner != platform.tunnel_owner() {
        return Err("shared backend started an unrelated tunnel runtime".into());
    }
    let expected = NativeEngineStatus::Tunnel {
        runtime: started.clone(),
    };
    for _ in 0..3 {
        if backend.query_status().await.map_err(|e| e.to_string())? != expected {
            return Err("tunnel status changed its live identity".into());
        }
    }
    let active = checks::snapshot()?;
    let tunnel_luid = adapter_luid(adapter)?.ok_or("tunnel adapter is absent while Active")?;

    // The adapter's resolver is the address plan's DNS peer, which only the
    // engine serves, inside the tunnel.
    progress.record("tunnel_traffic", generation)?;
    let answered = query_tunnel_resolver(PROBE_HOST)?;
    let target = resolve()?;
    let routed = best_route(target)?;
    if routed != tunnel_luid {
        return Err(format!(
            "the system route to {target} does not enter the tunnel adapter"
        ));
    }
    let observed = probe_through_tunnel(target, controller_address, &secret)?;
    progress.record("tunnel_traffic_complete", generation)?;

    let mut wrong = context.clone();
    wrong.generation = wrong
        .generation
        .checked_add(1)
        .ok_or("generation overflow")?;
    let rejected = backend
        .stop_tunnel(wrong)
        .await
        .expect_err("foreign tunnel stop must fail");
    if rejected.kind != cfw_engine_api::BackendErrorKind::StaleOperation {
        return Err(format!("foreign tunnel stop failure changed: {rejected}"));
    }
    progress.record("tunnel_stop", generation)?;
    backend
        .stop_tunnel(context.clone())
        .await
        .map_err(|e| e.to_string())?;
    // An exact repeated stop is a read of independently verified Off.
    backend
        .stop_tunnel(context.clone())
        .await
        .map_err(|e| e.to_string())?;
    if backend.query_status().await.map_err(|e| e.to_string())? != NativeEngineStatus::Off {
        return Err("tunnel stop omitted native Off".into());
    }
    progress.record("tunnel_off", generation)?;
    if adapter_luid(adapter)?.is_some() {
        return Err("tunnel adapter remained after verified Off".into());
    }
    let restored = best_route(direct_target)?;
    if restored != direct_route {
        return Err("the physical route was not restored after the tunnel stopped".into());
    }
    if desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?
        != original_proxy
    {
        return Err("tunnel mode changed the user's proxy settings".into());
    }
    let _controller = TcpListener::bind(controller_address)
        .map_err(|e| format!("tunnel controller remained: {e}"))?;
    Ok(serde_json::json!({
        "tunnel_runtime": true,
        "runtime": started,
        "active": active,
        "off": checks::snapshot()?,
        "adapter": adapter.to_string(),
        "adapter_luid": tunnel_luid,
        "system_route_entered_tunnel": true,
        "tunnel_resolver_answers": answered.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "engine_recorded_tunnel_connection": observed,
        "fresh_queries": 3,
        "stale_stop_rejected": true,
        "idempotent_stop": true,
        "adapter_absent_after_off": true,
        "physical_route_restored": true,
        "proxy_unchanged": true,
        "listeners_released": true,
    }))
}

/// The coordinator's Windows projection: the packet-endpoint stack, whose
/// tunnel binds the engine's own sockets to the physical interface.
fn tunnel_request(
    settings: &EngineSettings,
    context: EngineCommandContext,
) -> Result<(EngineStartRequest, String)> {
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .map_err(|e| e.to_string())?;
    let projection = profile
        .project_with_tunnel_stack(
            PROFILE,
            ProjectionMode::Tunnel,
            settings,
            TunnelStack::Gvisor,
        )
        .map_err(|e| e.to_string())?;
    let secret = projection.clash_api().expose_secret().to_owned();
    Ok((
        EngineStartRequest {
            context,
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
                mtu: settings.tunnel_mtu,
                system_proxy_port: None,
            }),
        },
        secret,
    ))
}

/// One DNS A query to the adapter's resolver, which the engine serves.
fn query_tunnel_resolver(name: &str) -> Result<Vec<Ipv4Addr>> {
    const ID: u16 = 0x4346;
    let peer: Ipv4Addr = cfw_singbox_config::TUNNEL_ADDRESS_PLAN
        .ipv4_dns_peer
        .parse()
        .map_err(|_| "tunnel DNS peer is malformed")?;
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&ID.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let length = u8::try_from(label.len()).map_err(|_| "DNS label is too long")?;
        query.push(length);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    socket
        .send_to(&query, (peer, 53))
        .map_err(|e| format!("query the tunnel resolver: {e}"))?;
    let mut reply = [0u8; 1500];
    let (length, from) = socket
        .recv_from(&mut reply)
        .map_err(|e| format!("tunnel resolver did not answer: {e}"))?;
    if from != SocketAddr::from((peer, 53)) {
        return Err("DNS answer came from another address".into());
    }
    parse_a_records(&reply[..length], ID, query.len())
}

fn parse_a_records(reply: &[u8], id: u16, question_end: usize) -> Result<Vec<Ipv4Addr>> {
    let field = |offset: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            reply
                .get(offset..offset + 2)
                .ok_or("DNS answer is truncated")?
                .try_into()
                .map_err(|_| "DNS field")?,
        ))
    };
    let flags = field(2)?;
    if field(0)? != id || flags & 0x8000 == 0 || flags & 0x000f != 0 || field(4)? != 1 {
        return Err(format!(
            "tunnel resolver answer is not a successful reply: {flags:#06x}"
        ));
    }
    let answers = field(6)?;
    let mut offset = question_end;
    let mut addresses = Vec::new();
    for _ in 0..answers {
        // Owner name: labels ending in zero, or a compression pointer.
        loop {
            let length = *reply.get(offset).ok_or("DNS answer is truncated")?;
            if length & 0xc0 == 0xc0 {
                offset += 2;
                break;
            }
            offset += 1 + usize::from(length);
            if length == 0 {
                break;
            }
        }
        let kind = field(offset)?;
        let size = usize::from(field(offset + 8)?);
        let data = reply
            .get(offset + 10..offset + 10 + size)
            .ok_or("DNS answer is truncated")?;
        if kind == 1 && size == 4 {
            addresses.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        offset += 10 + size;
    }
    if addresses.is_empty() {
        return Err("tunnel resolver returned no IPv4 address".into());
    }
    Ok(addresses)
}

fn resolve() -> Result<Ipv4Addr> {
    (PROBE_HOST, 80)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {PROBE_HOST}: {e}"))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{PROBE_HOST} has no IPv4 address"))
}

/// Fetch the probe over a connection the system routes into the tunnel and,
/// while it is open, find that connection in the engine's own table.
fn probe_through_tunnel(
    target: Ipv4Addr,
    controller: SocketAddr,
    secret: &str,
) -> Result<serde_json::Value> {
    let mut socket = TcpStream::connect_timeout(&SocketAddr::from((target, 80)), LIMIT)
        .map_err(|e| format!("connect to {target} through the tunnel: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let local = socket.local_addr().map_err(|e| e.to_string())?;
    write!(
        socket,
        "GET {PROBE_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: keep-alive\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let response = read_http_response(&mut socket)?;
    if !response.starts_with("HTTP/1.1 200") || !response.ends_with(PROBE_BODY) {
        return Err("the probe response through the tunnel differs".into());
    }
    let connections = controller_connections(controller, secret)?;
    let recorded = connections["connections"]
        .as_array()
        .ok_or("engine connection table is malformed")?
        .iter()
        .find(|connection| {
            let metadata = &connection["metadata"];
            metadata["type"] == "tun/cfw-tunnel"
                && metadata["network"] == "tcp"
                && metadata["destinationPort"] == "80"
                && metadata["destinationIP"] == target.to_string()
                && metadata["sourcePort"] == local.port().to_string()
        })
        .cloned()
        .ok_or("the engine did not record the probe connection on its tunnel inbound")?;
    drop(socket);
    Ok(serde_json::json!({
        "inbound": recorded["metadata"]["type"],
        "source_ip": recorded["metadata"]["sourceIP"],
        "destination_ip": recorded["metadata"]["destinationIP"],
        "host": recorded["metadata"]["host"],
        "chains": recorded["chains"],
        "local_address": local.to_string(),
    }))
}

/// One HTTP/1.1 response with a Content-Length body, read to its end.
fn read_http_response(socket: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = socket.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("probe connection closed before its response completed".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 65536 {
            return Err("probe response exceeds its bound".into());
        }
        let text = String::from_utf8_lossy(&bytes);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or("probe response has no content length")?;
            if bytes.len() >= end + 4 + length {
                return Ok(text[..end + 4 + length].to_owned());
            }
        }
    }
}

fn controller_connections(address: SocketAddr, secret: &str) -> Result<serde_json::Value> {
    let mut socket =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut request = zeroize::Zeroizing::new(String::with_capacity(256));
    request.push_str(
        "GET /connections HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer ",
    );
    request.push_str(secret);
    request.push_str("\r\n\r\n");
    socket
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    socket
        .take(262_145)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    if response.len() > 262_144 || !response.starts_with(b"HTTP/1.1 200") {
        return Err("engine controller did not return its connection table".into());
    }
    let text = String::from_utf8(response).map_err(|e| e.to_string())?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or("engine controller response has no body")?;
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_owned()
    };
    serde_json::from_str(body.trim()).map_err(|e| e.to_string())
}

fn dechunk(mut body: &str) -> Result<String> {
    let mut output = String::new();
    loop {
        let (size, rest) = body
            .split_once("\r\n")
            .ok_or("chunked controller body is truncated")?;
        let size = usize::from_str_radix(size.trim(), 16).map_err(|e| e.to_string())?;
        if size == 0 {
            return Ok(output);
        }
        output.push_str(rest.get(..size).ok_or("chunk is truncated")?);
        body = rest
            .get(size..)
            .and_then(|rest| rest.strip_prefix("\r\n"))
            .ok_or("chunk terminator is missing")?;
    }
}

fn adapter_luid(adapter: uuid::Uuid) -> Result<Option<u64>> {
    let (data1, data2, data3, data4) = adapter.as_fields();
    let guid = GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    };
    let mut luid = NET_LUID_LH { Value: 0 };
    match unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) } {
        0 => Ok(Some(unsafe { luid.Value })),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        status => Err(format!("map the tunnel adapter GUID: status {status}")),
    }
}

/// The interface Windows itself selects for a destination.
fn best_route(destination: Ipv4Addr) -> Result<u64> {
    let target = SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(destination.octets()),
                },
            },
            ..Default::default()
        },
    };
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        )
    };
    if status != 0 {
        return Err(format!(
            "observe the best route to {destination}: status {status}"
        ));
    }
    Ok(unsafe { route.InterfaceLuid.Value })
}
