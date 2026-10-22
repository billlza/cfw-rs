//! A bounded SOCKS5 endpoint standing in for a remote proxy node. It accepts
//! only this host's own address as client (the engine's outbound source) and
//! serves only the fixed forwarding targets; every other request is refused
//! and recorded. It is never an open proxy and never dials anything itself.
use super::super::{
    Result,
    network::{REMOTE, REMOTE6},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read, Write},
    net::{
        IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
        UdpSocket,
    },
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The node serves exactly these targets, one TCP and one UDP per family.
pub(super) const HTTP_TARGETS: [SocketAddr; 2] = [
    SocketAddr::V4(SocketAddrV4::new(REMOTE, 80)),
    SocketAddr::V6(SocketAddrV6::new(REMOTE6, 80, 0, 0)),
];
pub(super) const UDP_TARGETS: [SocketAddr; 2] = [
    SocketAddr::V4(SocketAddrV4::new(REMOTE, 54321)),
    SocketAddr::V6(SocketAddrV6::new(REMOTE6, 54321, 0, 0)),
];
pub(super) const BULK_BYTES: usize = 512 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAXIMUM_CONNECTIONS: usize = 64;
const MAXIMUM_DATAGRAM: usize = 65535;

/// Deterministic, nonce-bound content for one direction of the bulk exchange.
pub(super) fn bulk(nonce: &str, purpose: &str, length: usize) -> Vec<u8> {
    let seed = Sha256::digest(format!("{nonce}:{purpose}").as_bytes());
    let mut bytes = Vec::with_capacity(length + 32);
    let mut block = 0u64;
    while bytes.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(block.to_be_bytes());
        bytes.extend_from_slice(&hasher.finalize());
        block += 1;
    }
    bytes.truncate(length);
    bytes
}

pub(super) fn family(target: SocketAddr) -> &'static str {
    match target {
        SocketAddr::V4(_) => "ipv4",
        SocketAddr::V6(_) => "ipv6",
    }
}

/// The IP header without options plus the 8-byte UDP header: a full-MTU
/// datagram carries the MTU minus this as payload.
pub(super) fn udp_overhead(target: SocketAddr) -> usize {
    match target {
        SocketAddr::V4(_) => 20 + 8,
        SocketAddr::V6(_) => 40 + 8,
    }
}

/// The HTTP Host value for a literal target on port 80, bracketed for IPv6.
pub(super) fn http_host(target: SocketAddr) -> String {
    match target {
        SocketAddr::V4(target) => target.ip().to_string(),
        SocketAddr::V6(target) => format!("[{}]", target.ip()),
    }
}

/// The relay's answer differs from the request in every byte.
pub(super) fn transform(data: &[u8]) -> Vec<u8> {
    data.iter().map(|byte| byte ^ 0x5a).collect()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Recorded observations stay readable even if a handler thread panicked;
    // that handler's own join result still reports the panic.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Records {
    observations: Vec<Value>,
    failures: Vec<String>,
    handlers: Vec<JoinHandle<()>>,
}

pub(super) struct Fixture {
    address: SocketAddr,
    nonce: String,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    records: Arc<Mutex<Records>>,
    acceptor: Option<JoinHandle<()>>,
}

impl Fixture {
    pub(super) fn start(host: Ipv4Addr, nonce: &str) -> Result<Self> {
        let listener =
            TcpListener::bind(SocketAddrV4::new(host, 0)).map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let records = Arc::new(Mutex::new(Records::default()));
        let acceptor = {
            let (stop, accepted, records) = (stop.clone(), accepted.clone(), records.clone());
            let nonce = nonce.to_owned();
            thread::Builder::new()
                .name("cfw-forwarding-socks".into())
                .spawn(move || accept(listener, host, nonce, stop, accepted, records))
                .map_err(|error| error.to_string())?
        };
        Ok(Self {
            address,
            nonce: nonce.to_owned(),
            stop,
            accepted,
            records,
            acceptor: Some(acceptor),
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Connections accepted so far, including refused ones.
    pub(super) fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }

    /// Stop accepting, join every handler and return the observations. Any
    /// handler failure, including a panic, fails the whole fixture.
    pub(super) fn finish(mut self) -> Result<Value> {
        self.stop.store(true, Ordering::Release);
        let mut failures = Vec::new();
        if let Some(acceptor) = self.acceptor.take()
            && acceptor.join().is_err()
        {
            failures.push("SOCKS acceptor panicked".to_owned());
        }
        let handlers = std::mem::take(&mut lock(&self.records).handlers);
        for handler in handlers {
            if handler.join().is_err() {
                failures.push("SOCKS connection handler panicked".to_owned());
            }
        }
        let records = std::mem::take(&mut *lock(&self.records));
        failures.extend(records.failures);
        if failures.is_empty() {
            Ok(
                json!({"address":self.address.to_string(),"accepted":self.accepted(),
                "observations":records.observations}),
            )
        } else {
            Err(format!("SOCKS fixture: {}", failures.join("; ")))
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // finish() reports; an early-return path still stops the threads.
        self.stop.store(true, Ordering::Release);
    }
}

fn accept(
    listener: TcpListener,
    host: Ipv4Addr,
    nonce: String,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    records: Arc<Mutex<Records>>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let count = accepted.fetch_add(1, Ordering::AcqRel) + 1;
                if count > MAXIMUM_CONNECTIONS {
                    lock(&records).failures.push(format!(
                        "SOCKS fixture exceeded {MAXIMUM_CONNECTIONS} connections"
                    ));
                    drop(stream);
                    continue;
                }
                let (stop, records_for_handler) = (stop.clone(), records.clone());
                let nonce = nonce.clone();
                let spawned = thread::Builder::new()
                    .name("cfw-forwarding-socks-connection".into())
                    .spawn(move || {
                        let outcome = serve(stream, peer, host, &nonce, &stop);
                        let mut records = lock(&records_for_handler);
                        match outcome {
                            Ok(observation) => records.observations.push(observation),
                            // The run's own flows are still required exactly
                            // by the caller, so recording this hides nothing.
                            Err(Failure::Interrupted(error)) => records.observations.push(
                                json!({"peer":peer.to_string(),"handshake_interrupted":error}),
                            ),
                            Err(Failure::Broken(error)) => {
                                records.failures.push(format!("{peer}: {error}"))
                            }
                        }
                    });
                match spawned {
                    Ok(handler) => lock(&records).handlers.push(handler),
                    Err(error) => lock(&records)
                        .failures
                        .push(format!("SOCKS handler start: {error}")),
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => {
                lock(&records)
                    .failures
                    .push(format!("SOCKS accept: {error}"));
                return;
            }
        }
    }
}

/// A handshake the engine abandoned, for example while it stops, is recorded.
/// Anything else fails the fixture, including any break in the run's flows.
enum Failure {
    Interrupted(String),
    Broken(String),
}
impl Failure {
    fn broken(self) -> Self {
        match self {
            Self::Interrupted(error) | Self::Broken(error) => Self::Broken(error),
        }
    }
}
impl From<String> for Failure {
    fn from(value: String) -> Self {
        Self::Broken(value)
    }
}
impl From<&str> for Failure {
    fn from(value: &str) -> Self {
        Self::Broken(value.to_owned())
    }
}
type Served<T> = std::result::Result<T, Failure>;

fn io(error: std::io::Error) -> Failure {
    if matches!(
        error.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    ) {
        Failure::Interrupted(error.to_string())
    } else {
        Failure::Broken(error.to_string())
    }
}

fn text(error: std::io::Error) -> String {
    error.to_string()
}

/// The requested destination. A domain is recorded but never resolved.
enum Target {
    Address(SocketAddr),
    Domain(String, u16),
}
impl std::fmt::Display for Target {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(address) => write!(formatter, "{address}"),
            Self::Domain(name, port) => write!(formatter, "{name}:{port}"),
        }
    }
}

fn read_target(stream: &mut TcpStream) -> Served<Target> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind).map_err(io)?;
    let ip = match kind[0] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).map_err(io)?;
            Some(IpAddr::from(octets))
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).map_err(io)?;
            Some(IpAddr::from(octets))
        }
        3 => None,
        other => return Err(format!("SOCKS address type {other} is not served").into()),
    };
    let name = match ip {
        Some(_) => None,
        None => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).map_err(io)?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name).map_err(io)?;
            Some(String::from_utf8_lossy(&name).into_owned())
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).map_err(io)?;
    let port = u16::from_be_bytes(port);
    Ok(match (ip, name) {
        (Some(ip), _) => Target::Address(SocketAddr::new(ip, port)),
        (None, Some(name)) => Target::Domain(name, port),
        (None, None) => return Err("SOCKS target has neither address nor name".into()),
    })
}

fn reply(stream: &mut TcpStream, code: u8, bound: SocketAddrV4) -> Served<()> {
    let mut message = vec![5, code, 0, 1];
    message.extend_from_slice(&bound.ip().octets());
    message.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&message).map_err(io)
}

fn serve(
    mut stream: TcpStream,
    peer: SocketAddr,
    host: Ipv4Addr,
    nonce: &str,
    stop: &AtomicBool,
) -> Served<Value> {
    if peer.ip() != IpAddr::V4(host) {
        return Err("SOCKS client is not this host's own address".into());
    }
    stream.set_nonblocking(false).map_err(io)?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).map_err(io)?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err("invalid SOCKS5 greeting".into());
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).map_err(io)?;
    if !methods.contains(&0) {
        return Err("engine did not offer the no-authentication method".into());
    }
    stream.write_all(&[5, 0]).map_err(io)?;
    let mut request = [0u8; 3];
    stream.read_exact(&mut request).map_err(io)?;
    if request[0] != 5 || request[2] != 0 {
        return Err("invalid SOCKS5 request header".into());
    }
    let target = read_target(&mut stream)?;
    match (request[1], &target) {
        (1, Target::Address(address)) if HTTP_TARGETS.contains(address) => {
            reply(&mut stream, 0, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .map_err(Failure::broken)?;
            http(&mut stream, nonce, *address).map_err(Failure::Broken)
        }
        (3, _) => {
            let relay = UdpSocket::bind(SocketAddrV4::new(host, 0)).map_err(text)?;
            let SocketAddr::V4(bound) = relay.local_addr().map_err(text)? else {
                return Err("UDP relay is not IPv4".into());
            };
            reply(&mut stream, 0, bound)?;
            associate(stream, relay, host, stop).map_err(Failure::Broken)
        }
        (command, _) => {
            // Refused: connection not allowed by ruleset. Background flows
            // are recorded, never served or dialled.
            reply(&mut stream, 2, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
            Ok(json!({"command":command,"target":target.to_string(),"refused":true}))
        }
    }
}

fn http(stream: &mut TcpStream, nonce: &str, target: SocketAddr) -> Result<Value> {
    let family = family(target);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).map_err(text)?;
        header.push(byte[0]);
        if header.len() > 8192 {
            return Err("HTTP request header exceeds its bound".into());
        }
    }
    let header = String::from_utf8(header).map_err(|_| "HTTP header is not UTF-8")?;
    let mut lines = header.split("\r\n");
    let expected = format!("POST /cfw-tunnel-forwarding/{nonce}/{family} HTTP/1.1");
    if lines.next() != Some(expected.as_str()) {
        return Err("HTTP request line does not carry this run's nonce".into());
    }
    let fields: Vec<_> = lines.collect();
    let hosts: Vec<_> = fields
        .iter()
        .filter_map(|line| line.strip_prefix("Host: "))
        .collect();
    if hosts != [http_host(target)] {
        return Err("HTTP Host does not name the SOCKS target".into());
    }
    let length = fields
        .iter()
        .filter_map(|line| line.strip_prefix("Content-Length: "))
        .map(|value| value.parse::<usize>().map_err(|_| "invalid Content-Length"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if length != [BULK_BYTES] {
        return Err("HTTP upload length differs from the bulk contract".into());
    }
    let mut upload = vec![0u8; BULK_BYTES];
    stream.read_exact(&mut upload).map_err(text)?;
    if upload != bulk(nonce, &format!("upload-{family}"), BULK_BYTES) {
        return Err("uploaded bytes differ from this run's bulk content".into());
    }
    let upload_sha256 = hex(&Sha256::digest(&upload));
    let download = bulk(nonce, &format!("download-{family}"), BULK_BYTES);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {BULK_BYTES}\r\nX-Upload-Sha256: {upload_sha256}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).map_err(text)?;
    stream.write_all(&download).map_err(text)?;
    stream.flush().map_err(text)?;
    stream.shutdown(Shutdown::Write).map_err(text)?;
    Ok(
        json!({"command":"connect","target":target.to_string(),"family":family,
        "upload_bytes":BULK_BYTES,"upload_sha256":upload_sha256,
        "download_bytes":BULK_BYTES,"download_sha256":hex(&Sha256::digest(&download))}),
    )
}

fn associate(
    control: TcpStream,
    relay: UdpSocket,
    host: Ipv4Addr,
    stop: &AtomicBool,
) -> Result<Value> {
    relay
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(text)?;
    control.set_nonblocking(true).map_err(text)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut served = Vec::new();
    let mut other = Vec::new();
    let mut buffer = vec![0u8; MAXIMUM_DATAGRAM];
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            break;
        }
        // The engine ends the association by closing its control connection.
        let mut probe = [0u8; 1];
        match control.peek(&mut probe) {
            Ok(0) => break,
            Ok(_) => return Err("unexpected bytes on the UDP association control".into()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ) =>
            {
                break;
            }
            Err(error) => return Err(text(error)),
        }
        let (length, from) = match relay.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(error) => return Err(text(error)),
        };
        if from.ip() != IpAddr::V4(host) {
            return Err("UDP relay datagram from a foreign address".into());
        }
        let datagram = &buffer[..length];
        if datagram.len() < 10 || datagram[..3] != [0, 0, 0] {
            return Err("invalid or fragmented SOCKS5 UDP header".into());
        }
        let (target, header, data) = match datagram[3] {
            1 => (
                SocketAddr::new(
                    IpAddr::from(<[u8; 4]>::try_from(&datagram[4..8]).map_err(|_| "address")?),
                    u16::from_be_bytes([datagram[8], datagram[9]]),
                ),
                &datagram[..10],
                &datagram[10..],
            ),
            4 if datagram.len() >= 22 => (
                SocketAddr::new(
                    IpAddr::from(<[u8; 16]>::try_from(&datagram[4..20]).map_err(|_| "address")?),
                    u16::from_be_bytes([datagram[20], datagram[21]]),
                ),
                &datagram[..22],
                &datagram[22..],
            ),
            kind => return Err(format!("SOCKS5 UDP address type {kind} is not served")),
        };
        if !UDP_TARGETS.contains(&target) {
            other.push(json!({"target":target.to_string(),"bytes":data.len()}));
            continue;
        }
        let mut answer = header.to_vec();
        answer.extend(transform(data));
        if relay.send_to(&answer, from).map_err(text)? != answer.len() {
            return Err("UDP relay answer was truncated".into());
        }
        served.push(json!({"target":target.to_string(),"family":family(target),
            "bytes":data.len(),"request_sha256":hex(&Sha256::digest(data))}));
    }
    Ok(json!({"command":"udp_associate","served":served,"other_targets":other}))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
