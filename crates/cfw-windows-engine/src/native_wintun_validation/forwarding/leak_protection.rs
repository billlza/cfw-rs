//! The two leak protection switches in a running engine, on the path of the
//! bulk exchange: actual Windows sockets on the adapter's own addresses,
//! Wintun, the packet pump and the engine's packet endpoint.
//!
//! Each family sends what the switches name: a TCP connection and a datagram
//! to the encrypted DNS port, a STUN binding request to the STUN port and to
//! a port the engine never sniffs, and a datagram to the STUN port that is
//! not STUN. With the switches off the node serves every one of them. With
//! both on the engine refuses all but the last. A refusal must reach the
//! socket at once, as a refused connection or a reset datagram socket, which
//! needs the engine's reset or ICMP error to pass the pump's delivery policy;
//! and the node must see nothing of a refused flow. Each probe also records
//! what Windows received meanwhile: the packets its adapter took from the
//! pump, and the ICMP messages its stack counted for the family.
use super::{
    super::{Result, network},
    socks::{Fixture, family, hex, transform},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{GetIcmpStatisticsEx, MIB_ICMP_EX_XPSP1},
    Networking::WinSock::{AF_INET, AF_INET6},
};

/// DNS over TLS and DNS over QUIC. DNS leak protection refuses the port.
const ENCRYPTED_DNS_PORT: u16 = 853;
/// The registered STUN port. WebRTC leak protection goes by the message
/// format, so only a STUN message is refused here.
const STUN_PORT: u16 = 3478;
/// POP3 over TLS, one of the ports the engine never sniffs. WebRTC leak
/// protection refuses every datagram to those.
const UNSNIFFED_PORT: u16 = 995;
/// What the probe's TCP connection carries; the node answers it transformed.
pub(super) const TOKEN_BYTES: usize = 16;
const DATAGRAM_BYTES: usize = 20;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const CONNECT: Duration = Duration::from_secs(15);
/// The node and the engine are on this host: an answer or a refusal is
/// immediate, and nothing within this bound is neither.
const ANSWER: Duration = Duration::from_secs(5);
/// The destination unreachable type of ICMP and of ICMPv6.
const DESTINATION_UNREACHABLE: usize = 3;
const DESTINATION_UNREACHABLE_V6: usize = 1;

/// Whether the node serves a connection to `target` for these probes.
pub(super) fn tcp_target(target: SocketAddr) -> bool {
    remote(target) && target.port() == ENCRYPTED_DNS_PORT
}

/// Whether the node answers a datagram to `target` for these probes.
pub(super) fn udp_target(target: SocketAddr) -> bool {
    remote(target) && [ENCRYPTED_DNS_PORT, STUN_PORT, UNSNIFFED_PORT].contains(&target.port())
}

fn remote(target: SocketAddr) -> bool {
    [IpAddr::V4(network::REMOTE), IpAddr::V6(network::REMOTE6)].contains(&target.ip())
}

fn digest(nonce: &str, purpose: &str, family: &str) -> [u8; 32] {
    Sha256::digest(format!("{nonce}:{purpose}-{family}").as_bytes()).into()
}

/// The bytes one run's probe connection to `target` carries.
pub(super) fn token(nonce: &str, target: SocketAddr) -> [u8; TOKEN_BYTES] {
    let mut token = [0u8; TOKEN_BYTES];
    token.copy_from_slice(&digest(nonce, "encrypted-dns-tcp", family(target))[..TOKEN_BYTES]);
    token
}

/// A STUN binding request (RFC 8489): its type, no attributes, the magic
/// cookie and a transaction identifier of this run.
fn stun_request(nonce: &str, purpose: &str, family: &str) -> [u8; DATAGRAM_BYTES] {
    let mut message = [0u8; DATAGRAM_BYTES];
    message[1] = 0x01;
    message[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    message[8..].copy_from_slice(&digest(nonce, purpose, family)[..12]);
    message
}

/// A datagram of the same size that no STUN reader accepts: it has no magic
/// cookie.
fn other_datagram(nonce: &str, purpose: &str, family: &str) -> [u8; DATAGRAM_BYTES] {
    let mut datagram = [0u8; DATAGRAM_BYTES];
    datagram.copy_from_slice(&digest(nonce, purpose, family)[..DATAGRAM_BYTES]);
    datagram[4..8].fill(0);
    datagram
}

/// The adapter's count of packets taken from the pump.
pub(super) type Inbound<'a> = &'a dyn Fn() -> Result<u64>;

/// What Windows had received at one moment, for one family.
#[derive(Clone, Copy)]
struct Received {
    adapter_packets: u64,
    icmp_messages: u32,
    icmp_errors: u32,
    destination_unreachable: u32,
}
impl Received {
    fn now(inbound: Inbound<'_>, target: SocketAddr) -> Result<Self> {
        let (family, unreachable) = if target.is_ipv6() {
            (AF_INET6, DESTINATION_UNREACHABLE_V6)
        } else {
            (AF_INET, DESTINATION_UNREACHABLE)
        };
        let mut statistics = MIB_ICMP_EX_XPSP1::default();
        // SAFETY: the statistics structure is owned and writable for the call.
        let status = unsafe { GetIcmpStatisticsEx(&mut statistics, u32::from(family)) };
        if status != 0 {
            return Err(format!("read the ICMP statistics: status {status}"));
        }
        let incoming = statistics.icmpInStats;
        Ok(Self {
            adapter_packets: inbound()?,
            icmp_messages: incoming.dwMsgs,
            icmp_errors: incoming.dwErrors,
            destination_unreachable: incoming.rgdwTypeCount[unreachable],
        })
    }
    /// What arrived since `before`. The ICMP counters are 32-bit counters
    /// that wrap; the adapter's never goes back.
    fn since(self, before: Self) -> Result<Value> {
        let adapter_packets = self
            .adapter_packets
            .checked_sub(before.adapter_packets)
            .ok_or("the adapter's receive counter went back")?;
        Ok(json!({
            "adapter_packets":adapter_packets,
            "icmp_messages":self.icmp_messages.wrapping_sub(before.icmp_messages),
            "icmp_errors":self.icmp_errors.wrapping_sub(before.icmp_errors),
            "icmp_destination_unreachable":
                self.destination_unreachable.wrapping_sub(before.destination_unreachable)
        }))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The node answered: the engine forwarded the flow.
    Served,
    /// The connection was refused, or the datagram socket was reset.
    Refused,
    /// A datagram with neither an answer nor a reset.
    Silent,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Refused => "refused",
            Self::Silent => "silent",
        }
    }
}

struct Observation {
    outcome: Outcome,
    elapsed: Duration,
    received: Value,
}
impl Observation {
    fn receipt(&self, target: SocketAddr) -> Value {
        json!({"target":target.to_string(),"outcome":self.outcome.label(),
        "elapsed_ms":self.elapsed.as_millis(),"windows_received":self.received})
    }
}

/// Run one probe and note what Windows received while it ran.
fn observe(
    inbound: Inbound<'_>,
    target: SocketAddr,
    probe: impl FnOnce() -> Result<Outcome>,
) -> Result<Observation> {
    let before = Received::now(inbound, target)?;
    let started = Instant::now();
    let outcome = probe()?;
    let elapsed = started.elapsed();
    Ok(Observation {
        outcome,
        elapsed,
        received: Received::now(inbound, target)?.since(before)?,
    })
}

/// One TCP connection from the adapter's own address. A served one carries
/// this run's token and reads the node's answer to its end.
fn connect(nonce: &str, local: IpAddr, target: SocketAddr) -> Result<Outcome> {
    let mut stream = match TcpStream::connect_timeout(&target, CONNECT) {
        Ok(stream) => stream,
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => return Ok(Outcome::Refused),
        Err(error) => return Err(format!("TCP to {target}: {error}")),
    };
    stream
        .set_read_timeout(Some(CONNECT))
        .and_then(|()| stream.set_write_timeout(Some(CONNECT)))
        .map_err(|error| error.to_string())?;
    let observed = stream.local_addr().map_err(|error| error.to_string())?;
    if observed.ip() != local {
        return Err(format!(
            "TCP to {target} left from {observed}, not the owned adapter address"
        ));
    }
    let token = token(nonce, target);
    stream
        .write_all(&token)
        .map_err(|error| format!("TCP to {target}: {error}"))?;
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .map_err(|error| format!("TCP answer from {target}: {error}"))?;
    if answer != transform(&token) {
        return Err(format!("TCP answer from {target} is not the node's"));
    }
    Ok(Outcome::Served)
}

/// One datagram from a new socket on the adapter's own address, so the
/// engine sees it as the first of a session, and what came back.
fn datagram(local: IpAddr, target: SocketAddr, payload: &[u8]) -> Result<Outcome> {
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).map_err(|error| error.to_string())?;
    socket
        .connect(target)
        .and_then(|()| socket.set_read_timeout(Some(ANSWER)))
        .map_err(|error| error.to_string())?;
    if socket.send(payload).map_err(|error| error.to_string())? != payload.len() {
        return Err(format!("UDP to {target} did not accept the datagram"));
    }
    let mut buffer = [0u8; 2 * DATAGRAM_BYTES];
    match socket.recv(&mut buffer) {
        Ok(received) if buffer[..received] == transform(payload) => Ok(Outcome::Served),
        Ok(_) => Err(format!("UDP answer from {target} is not the node's")),
        // Windows reports an ICMP port unreachable for a connected socket so.
        Err(error) if error.kind() == ErrorKind::ConnectionReset => Ok(Outcome::Refused),
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            Ok(Outcome::Silent)
        }
        Err(error) => Err(format!("UDP answer from {target}: {error}")),
    }
}

/// One datagram probe: where it goes, what it carries and whether the
/// switches refuse it.
struct Datagram {
    name: &'static str,
    port: u16,
    payload: [u8; DATAGRAM_BYTES],
    refusable: bool,
}

/// The datagram probes of one family.
fn datagrams(nonce: &str, family: &str) -> [Datagram; 4] {
    [
        Datagram {
            name: "encrypted_dns_udp",
            port: ENCRYPTED_DNS_PORT,
            payload: other_datagram(nonce, "encrypted-dns-udp", family),
            refusable: true,
        },
        Datagram {
            name: "stun",
            port: STUN_PORT,
            payload: stun_request(nonce, "stun", family),
            refusable: true,
        },
        Datagram {
            name: "stun_unsniffed_port",
            port: UNSNIFFED_PORT,
            payload: stun_request(nonce, "stun-unsniffed-port", family),
            refusable: true,
        },
        Datagram {
            name: "other_udp_on_stun_port",
            port: STUN_PORT,
            payload: other_datagram(nonce, "other-udp", family),
            refusable: false,
        },
    ]
}

fn remotes() -> [(IpAddr, IpAddr); 2] {
    [
        (IpAddr::V4(network::LOCAL), IpAddr::V4(network::REMOTE)),
        (IpAddr::V6(network::LOCAL6), IpAddr::V6(network::REMOTE6)),
    ]
}

/// What the probes of one case observed, and where that differs from what
/// the switches must do.
pub(super) struct Probes {
    pub(super) observed: Value,
    differences: Vec<String>,
}
impl Probes {
    /// The case's verdict on its probes, given once the rest of the case
    /// has been checked.
    pub(super) fn verdict(&self) -> Result<()> {
        if self.differences.is_empty() {
            return Ok(());
        }
        Err(format!(
            "leak protection {}: {}; observed {}",
            if self.observed["enabled"] == true {
                "on"
            } else {
                "off"
            },
            self.differences.join(", "),
            self.observed
        ))
    }
}

/// Every probe in both families. Each runs whatever the others showed, so a
/// failure reports the whole observation.
pub(super) fn probe(fixture: &Fixture, inbound: Inbound<'_>, enabled: bool) -> Probes {
    let nonce = fixture.nonce();
    let expected = |refusable: bool| {
        if enabled && refusable {
            Outcome::Refused
        } else {
            Outcome::Served
        }
    };
    let mut observed = serde_json::Map::new();
    let mut differences = Vec::new();
    for (local, remote) in remotes() {
        let family = family(SocketAddr::new(remote, 0));
        let mut probes = serde_json::Map::new();
        let mut judge =
            |name: &str, target: SocketAddr, seen: Result<Observation>, refusable: bool| {
                let receipt = match seen {
                    Ok(seen) => {
                        if seen.outcome != expected(refusable) {
                            differences.push(format!(
                                "{family} {name} was {}, not {}",
                                seen.outcome.label(),
                                expected(refusable).label()
                            ));
                        }
                        seen.receipt(target)
                    }
                    Err(error) => {
                        differences.push(format!("{family} {name}: {error}"));
                        json!({"target":target.to_string(),"failure":error})
                    }
                };
                probes.insert(name.to_owned(), receipt);
            };
        let target = SocketAddr::new(remote, ENCRYPTED_DNS_PORT);
        let seen = observe(inbound, target, || connect(nonce, local, target));
        judge("encrypted_dns_tcp", target, seen, true);
        for probe in datagrams(nonce, family) {
            let target = SocketAddr::new(remote, probe.port);
            let seen = observe(inbound, target, || datagram(local, target, &probe.payload));
            judge(probe.name, target, seen, probe.refusable);
        }
        observed.insert(family.to_owned(), Value::Object(probes));
    }
    observed.insert("enabled".into(), json!(enabled));
    Probes {
        observed: Value::Object(observed),
        differences,
    }
}

/// What the node must have seen of the probes: every one of them with the
/// switches off, and with them on only the datagram that is not STUN.
pub(super) fn require_flows(observations: &Value, nonce: &str, enabled: bool) -> Result<()> {
    let flows = observations["observations"]
        .as_array()
        .ok_or("fixture observations are missing")?;
    for (_, remote) in remotes() {
        let family = family(SocketAddr::new(remote, 0));
        let connection = SocketAddr::new(remote, ENCRYPTED_DNS_PORT).to_string();
        let connections = flows
            .iter()
            .filter(|flow| flow["target"] == connection.as_str())
            .count();
        let mut served: Vec<_> = flows
            .iter()
            .filter(|flow| flow["command"] == "udp_associate")
            .filter_map(|flow| flow["served"].as_array())
            .flatten()
            .filter_map(|datagram| {
                let target: SocketAddr = datagram["target"].as_str()?.parse().ok()?;
                (target.ip() == remote && udp_target(target)).then(|| {
                    (
                        target.port(),
                        datagram["request_sha256"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    )
                })
            })
            .collect();
        let mut expected: Vec<_> = datagrams(nonce, family)
            .into_iter()
            .filter(|probe| !(enabled && probe.refusable))
            .map(|probe| (probe.port, hex(&Sha256::digest(probe.payload))))
            .collect();
        served.sort();
        expected.sort();
        if connections != usize::from(!enabled) || served != expected {
            return Err(format!(
                "the node did not see exactly the {family} leak protection flows the engine forwards with the switches {}: {observations}",
                if enabled { "on" } else { "off" }
            ));
        }
    }
    Ok(())
}
