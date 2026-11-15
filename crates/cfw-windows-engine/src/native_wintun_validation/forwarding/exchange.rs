//! The Windows side of one forwarding case: sockets on the adapter's own
//! addresses that carry the bulk exchange to the node's fixed targets, and
//! the control that finds no forwarder once the engine and the pump are gone.
use super::{
    super::{Result, network},
    TIMEOUT,
    socks::{
        BULK_BYTES, Fixture, HTTP_TARGETS, UDP_TARGETS, bulk, family, hex, http_host, transform,
        udp_overhead,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    os::windows::io::AsRawSocket,
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::{
    IP_DONTFRAGMENT, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG, SOCKET, setsockopt,
};

/// Both families: TCP bulk both ways and one full-MTU UDP datagram each.
pub(super) fn exchange(fixture: &Fixture, mtu: u16) -> Result<Value> {
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
pub(super) fn causal_control(fixture: &Fixture) -> Result<Value> {
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
