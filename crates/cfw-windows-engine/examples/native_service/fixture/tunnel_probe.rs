//! Observations of the installed product's tunnel network that both the
//! backend Tunnel suite and the installed GUI's Tunnel session make: the
//! installation's adapter, the interface Windows selects for a destination,
//! and one plain HTTP fetch that the system itself routes. A fetch proves the
//! tunnel only when its socket's source address is the adapter's own address.
use super::*;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs},
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
    Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET},
};

/// Windows' own network connectivity probe: a fixed body over plain HTTP.
pub(super) const PROBE_HOST: &str = "www.msftconnecttest.com";
const PROBE_PATH: &str = "/connecttest.txt";
const PROBE_BODY: &str = "Microsoft Connect Test";

/// One completed fetch whose connection is still open.
pub(super) struct Fetched {
    pub(super) socket: TcpStream,
    pub(super) local: SocketAddr,
}

/// The probe host's first IPv4 address from the system resolver.
pub(super) fn resolve() -> Result<Ipv4Addr> {
    (PROBE_HOST, 80)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {PROBE_HOST}: {e}"))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{PROBE_HOST} has no IPv4 address"))
}

/// The tunnel adapter's IPv4 address in the shared address plan.
pub(super) fn adapter_address() -> Result<Ipv4Addr> {
    cfw_singbox_config::TUNNEL_ADDRESS_PLAN
        .ipv4_address
        .parse()
        .map_err(|_| "tunnel address plan is malformed".into())
}

/// Fetch the probe from `target` over a connection the system routes, and
/// require that Windows sent it from the tunnel adapter's own address.
pub(super) fn fetch_through_tunnel(target: Ipv4Addr) -> Result<Fetched> {
    let mut socket =
        TcpStream::connect_timeout(&SocketAddr::from((target, 80)), Duration::from_secs(10))
            .map_err(|e| format!("connect to {target} through the tunnel: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let local = socket.local_addr().map_err(|e| e.to_string())?;
    if local.ip() != std::net::IpAddr::V4(adapter_address()?) {
        return Err(format!(
            "the connection to {target} left from {local}, not the tunnel adapter"
        ));
    }
    write!(
        socket,
        "GET {PROBE_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: keep-alive\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let response = read_http_response(&mut socket)?;
    if !response.starts_with("HTTP/1.1 200") || !response.ends_with(PROBE_BODY) {
        return Err("the probe response through the tunnel differs".into());
    }
    Ok(Fetched { socket, local })
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

/// The LUID of the installation's tunnel adapter, if Windows has it, from
/// the product's own interface lookup.
pub(super) fn adapter_luid(adapter: uuid::Uuid) -> Result<Option<u64>> {
    cfw_windows_engine::tunnel::interface_luid(adapter).map_err(|e| e.to_string())
}

/// The interface Windows itself selects for a destination.
pub(super) fn best_route(destination: Ipv4Addr) -> Result<u64> {
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
