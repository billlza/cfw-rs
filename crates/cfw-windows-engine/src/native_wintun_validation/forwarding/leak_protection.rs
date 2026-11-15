//! The two leak protection switches in a running engine, on the path of the
//! bulk exchange: actual Windows sockets on the adapter's own addresses,
//! Wintun, the packet pump and the engine's packet endpoint.
//!
//! Each family sends what the switches name: a TCP connection and a datagram
//! to the encrypted DNS port, a STUN binding request to the STUN port and to
//! a port the engine never sniffs, and a datagram to the STUN port that is
//! not STUN. With the switches off the node serves every one of them. With
//! both on the engine refuses all but the last, and the node sees nothing of
//! a refused flow. A refused connection must be refused at its socket, which
//! needs the engine's reset to pass the pump's delivery policy. A refused
//! datagram must go unanswered while the engine's port unreachable report
//! reaches Windows: the pump delivers exactly that report and the ICMP layer
//! counts it. Whether Windows then resets the socket is recorded, not
//! required; hosted Windows discards the report instead. Each probe also
//! records what happened meanwhile: what the pump carried and refused each
//! way, the adapter's counters, and what the Windows IP, UDP and ICMP layers
//! counted for the family.
use super::{
    super::{Result, network},
    socks::{Fixture, family, hex, transform},
};
use crate::tunnel::{InterfaceCounters, PumpReport};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

mod counted;
use counted::{Counted, Reported};

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

/// The engine's port unreachable report about one probe datagram: an IP
/// header, the ICMP header, and the whole datagram it refused.
fn report_bytes(ipv6: bool) -> u64 {
    let header: u64 = if ipv6 { 40 } else { 20 };
    2 * (header + 8) + DATAGRAM_BYTES as u64
}

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

/// Where a probe reads what happened while it ran.
pub(super) struct Sources<'a> {
    /// The owned adapter's counters.
    pub(super) adapter: &'a dyn Fn() -> Result<InterfaceCounters>,
    /// The running pump's report, which may trail by one packet.
    pub(super) pump: &'a dyn Fn() -> PumpReport,
}

/// Engine reports Windows returned unaccepted while the probes ran.
#[derive(Clone, Copy, Default)]
pub(super) struct Discarded {
    pub(super) packets: u64,
    pub(super) bytes: u64,
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

/// What the switches require of one probe.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// The node answers.
    Served,
    /// The connection is refused at its socket.
    Refused,
    /// No answer, and the engine's port unreachable report reaches Windows.
    Unanswered,
}
impl Expected {
    fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Refused => "refused",
            Self::Unanswered => "unanswered",
        }
    }
}

struct Observation {
    outcome: Outcome,
    elapsed: Duration,
    counted: Value,
    reported: Reported,
}
impl Observation {
    fn receipt(&self, target: SocketAddr, expected: Expected) -> Value {
        json!({"target":target.to_string(),"expected":expected.label(),
        "outcome":self.outcome.label(),"elapsed_ms":self.elapsed.as_millis(),
        "counted":self.counted})
    }

    /// Whether the probe did what `expected` requires, and what Windows
    /// returned unaccepted of the engine's report meanwhile.
    fn judge(&self, expected: Expected, ipv6: bool) -> Result<Discarded> {
        let report = self.reported;
        match (expected, self.outcome) {
            (Expected::Served, Outcome::Served) | (Expected::Refused, Outcome::Refused) => {
                Ok(Discarded::default())
            }
            // A reset socket is Windows' own word that the report arrived.
            (Expected::Unanswered, Outcome::Refused) => Ok(Discarded::default()),
            // Five quiet seconds let every counter settle: the pump delivered
            // exactly the report, the adapter passed it to the stack, and the
            // ICMP layer counted it, whatever the stack did with it then.
            (Expected::Unanswered, Outcome::Silent)
                if report.delivered == 1
                    && report.delivered_bytes == report_bytes(ipv6)
                    && report.received + report.returned == 1
                    && report.unreachable >= 1 =>
            {
                Ok(Discarded {
                    packets: report.returned,
                    bytes: report.returned * report_bytes(ipv6),
                })
            }
            (Expected::Unanswered, Outcome::Silent) => Err(
                "went unanswered without the engine's port unreachable report reaching Windows"
                    .to_owned(),
            ),
            (expected, outcome) => {
                Err(format!("was {}, not {}", outcome.label(), expected.label()))
            }
        }
    }
}

/// Run one probe and note what happened while it ran.
fn observe(
    sources: &Sources<'_>,
    target: SocketAddr,
    probe: impl FnOnce() -> Result<Outcome>,
) -> Result<Observation> {
    let before = Counted::now(sources, target)?;
    let started = Instant::now();
    let outcome = probe()?;
    let elapsed = started.elapsed();
    let (counted, reported) = Counted::now(sources, target)?.since(&before)?;
    Ok(Observation {
        outcome,
        elapsed,
        counted,
        reported,
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
    discarded: Discarded,
}
impl Probes {
    /// The case's verdict on its probes and, when they did what the
    /// switches require, the engine reports Windows returned unaccepted.
    pub(super) fn verdict(&self) -> Result<Discarded> {
        if self.differences.is_empty() {
            return Ok(self.discarded);
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
pub(super) fn probe(fixture: &Fixture, sources: &Sources<'_>, enabled: bool) -> Probes {
    let nonce = fixture.nonce();
    let named = |refusal: Expected| if enabled { refusal } else { Expected::Served };
    let mut observed = serde_json::Map::new();
    let mut differences = Vec::new();
    let mut discarded = Discarded::default();
    for (local, remote) in remotes() {
        let family = family(SocketAddr::new(remote, 0));
        let mut probes = serde_json::Map::new();
        let mut judge = |name: &str,
                         target: SocketAddr,
                         seen: Result<Observation>,
                         expected: Expected| {
            let receipt = match seen {
                Ok(seen) => {
                    match seen.judge(expected, target.is_ipv6()) {
                        Ok(returned) => {
                            discarded.packets += returned.packets;
                            discarded.bytes += returned.bytes;
                        }
                        Err(difference) => {
                            differences.push(format!("{family} {name} {difference}"));
                        }
                    }
                    seen.receipt(target, expected)
                }
                Err(error) => {
                    differences.push(format!("{family} {name}: {error}"));
                    json!({"target":target.to_string(),"expected":expected.label(),"failure":error})
                }
            };
            probes.insert(name.to_owned(), receipt);
        };
        let target = SocketAddr::new(remote, ENCRYPTED_DNS_PORT);
        let seen = observe(sources, target, || connect(nonce, local, target));
        judge("encrypted_dns_tcp", target, seen, named(Expected::Refused));
        for probe in datagrams(nonce, family) {
            let target = SocketAddr::new(remote, probe.port);
            let seen = observe(sources, target, || datagram(local, target, &probe.payload));
            let expected = if probe.refusable {
                named(Expected::Unanswered)
            } else {
                Expected::Served
            };
            judge(probe.name, target, seen, expected);
        }
        observed.insert(family.to_owned(), Value::Object(probes));
    }
    observed.insert("enabled".into(), json!(enabled));
    Probes {
        observed: Value::Object(observed),
        differences,
        discarded,
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
