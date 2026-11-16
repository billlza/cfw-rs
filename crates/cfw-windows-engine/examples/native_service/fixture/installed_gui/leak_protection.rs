//! The leak protection switches of the installed GUI, observed from the same
//! user session while TUN Mode runs. A connection to a DNS over TLS resolver
//! and a STUN binding request to a public STUN server are left to the
//! system's own routing, which sends both into the tunnel. With the switches
//! off the selected route carries them: the connection opens and the server
//! answers the request with this computer's address. With both on the engine
//! refuses them: the connection is reset, the request goes unanswered, and
//! other traffic still passes.
use super::{
    super::tunnel_probe::{
        adapter_address, adapter_luid, best_route, fetch_through_tunnel, resolve,
    },
    network::{ObservedGui, proxy_digest, proxy_snapshot},
    *,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};

/// Public DNS over TLS resolvers. The first probe keeps the first one that
/// accepts a connection, and the later probes return to it.
const RESOLVERS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
];
/// Public STUN servers, kept the same way.
const STUN_SERVERS: [(&str, u16); 2] =
    [("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302)];
const ENCRYPTED_DNS_PORT: u16 = 853;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const CONNECT: Duration = Duration::from_secs(5);
/// A STUN client retransmits an unanswered request (RFC 8489 section 6.2.1).
const STUN_TRANSMISSIONS: usize = 3;
const STUN_ANSWER: Duration = Duration::from_secs(1);

/// What Windows reported for one flow.
struct Attempt {
    target: SocketAddr,
    outcome: &'static str,
    elapsed: Duration,
    error: Option<String>,
}
impl Attempt {
    fn receipt(&self) -> serde_json::Value {
        serde_json::json!({
            "target": self.target, "outcome": self.outcome,
            "elapsed_ms": self.elapsed.as_millis(), "error": self.error
        })
    }
}

/// Require that Windows sent a flow from the tunnel adapter's own address.
fn require_adapter_source(local: SocketAddr, target: SocketAddr) -> Result<()> {
    if local.ip() != IpAddr::V4(adapter_address()?) {
        return Err(format!(
            "the flow to {target} left from {local}, not the tunnel adapter"
        ));
    }
    Ok(())
}

/// Require that Windows routes a destination into the tunnel adapter.
fn require_tunnel_route(destination: Ipv4Addr, luid: u64) -> Result<()> {
    if best_route(destination)? != luid {
        return Err(format!(
            "the system route to {destination} does not enter the GUI's tunnel adapter"
        ));
    }
    Ok(())
}

/// One connection to a resolver's DNS over TLS port: `connected`, `refused`,
/// or `failed` with the error of a host that did not answer in time.
fn connect(resolver: Ipv4Addr) -> Result<Attempt> {
    let target = SocketAddr::from((resolver, ENCRYPTED_DNS_PORT));
    let started = std::time::Instant::now();
    let (outcome, error) = match TcpStream::connect_timeout(&target, CONNECT) {
        Ok(socket) => {
            require_adapter_source(socket.local_addr().map_err(|e| e.to_string())?, target)?;
            ("connected", None)
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => ("refused", None),
        Err(error) => ("failed", Some(error.to_string())),
    };
    Ok(Attempt {
        target,
        outcome,
        elapsed: started.elapsed(),
        error,
    })
}

/// Whether `answer` is a binding success response to the request with this
/// transaction identifier. The mapped address it carries is not kept.
fn binding_success(answer: &[u8], transaction: &[u8; 12]) -> bool {
    answer.len() >= 20
        && answer[..2] == [0x01, 0x01]
        && answer[4..8] == STUN_MAGIC_COOKIE
        && answer[8..20] == transaction[..]
}

/// One STUN binding request to `target`, sent again while unanswered:
/// `answered`, `refused` when an ICMP error reset the socket, or `silent`.
fn stun(target: SocketAddr) -> Result<Attempt> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    socket
        .connect(target)
        .map_err(|e| format!("route a datagram to {target}: {e}"))?;
    require_adapter_source(socket.local_addr().map_err(|e| e.to_string())?, target)?;
    socket
        .set_read_timeout(Some(STUN_ANSWER))
        .map_err(|e| e.to_string())?;
    let mut transaction = [0u8; 12];
    transaction.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..12]);
    // A binding request without attributes: its type, a zero length, the
    // magic cookie and the transaction identifier.
    let mut request = [0u8; 20];
    request[1] = 1;
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    request[8..].copy_from_slice(&transaction);
    let started = std::time::Instant::now();
    let mut answer = [0u8; 1500];
    let mut outcome = "silent";
    for _ in 0..STUN_TRANSMISSIONS {
        socket
            .send(&request)
            .map_err(|e| format!("send a STUN request to {target}: {e}"))?;
        match socket.recv(&mut answer) {
            Ok(received) if binding_success(&answer[..received], &transaction) => {
                outcome = "answered";
                break;
            }
            Ok(_) => return Err(format!("{target} answered with another STUN message")),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                outcome = "refused";
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(format!("await an answer from {target}: {error}")),
        }
    }
    Ok(Attempt {
        target,
        outcome,
        elapsed: started.elapsed(),
        error: None,
    })
}

/// A STUN server's first IPv4 address from the system resolver.
fn stun_server(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| format!("{host} has no IPv4 address"))
}

/// Which probe this is: the first one keeps a resolver and a STUN server,
/// the later ones return to them.
enum Kept {
    Any,
    Same(Ipv4Addr, SocketAddr),
}
fn kept(operation: &str, resolver: &str, server: &str) -> Result<Kept> {
    match (operation, resolver, server) {
        ("leak-open", "any", "any") => Ok(Kept::Any),
        ("leak-refused" | "leak-reopened", resolver, server) => {
            let resolver = resolver
                .parse()
                .ok()
                .filter(|address| RESOLVERS.contains(address))
                .ok_or("the kept resolver is not one of the probe's own")?;
            let server = server
                .parse::<SocketAddr>()
                .ok()
                .filter(|address| {
                    address.is_ipv4()
                        && STUN_SERVERS.iter().any(|(_, port)| *port == address.port())
                })
                .ok_or("the kept STUN server is not one of the probe's own")?;
            Ok(Kept::Same(resolver, server))
        }
        _ => Err("unknown GUI leak protection probe".into()),
    }
}

/// The resolver to keep: the first candidate whose connection ends as
/// `expected`.
fn keep_resolver(
    candidates: &[Ipv4Addr],
    expected: &str,
    luid: u64,
) -> Result<(Ipv4Addr, serde_json::Value)> {
    let mut attempts = Vec::new();
    for resolver in candidates {
        require_tunnel_route(*resolver, luid)?;
        let attempt = connect(*resolver)?;
        let reached = attempt.outcome == expected;
        attempts.push(attempt.receipt());
        if reached {
            return Ok((*resolver, serde_json::Value::Array(attempts)));
        }
    }
    Err(format!(
        "no DNS over TLS connection through the tunnel was {expected}: {}",
        serde_json::Value::Array(attempts)
    ))
}

/// The STUN server to keep: the first candidate that answers.
fn keep_stun_server(luid: u64) -> Result<(Attempt, serde_json::Value)> {
    let mut attempts = Vec::new();
    for (host, port) in STUN_SERVERS {
        let target = stun_server(host, port)?;
        let SocketAddr::V4(address) = target else {
            return Err(format!("{host} resolved to {target}"));
        };
        require_tunnel_route(*address.ip(), luid)?;
        let attempt = stun(target)?;
        attempts.push(serde_json::json!({"server": host, "attempt": attempt.receipt()}));
        if attempt.outcome == "answered" {
            return Ok((attempt, serde_json::Value::Array(attempts)));
        }
    }
    Err(format!(
        "no STUN server answered through the tunnel: {}",
        serde_json::Value::Array(attempts)
    ))
}

pub(super) fn probe(
    operation: &str,
    installation: &str,
    kept_resolver: &str,
    kept_server: &str,
) -> Result<()> {
    let kept = kept(operation, kept_resolver, kept_server)?;
    let protected = operation == "leak-refused";
    let (source, receipts) = validation_context()?;
    let installation =
        uuid::Uuid::parse_str(installation).map_err(|_| "invalid GUI installation identity")?;
    let observed = ObservedGui::open(&source, &receipts)?;
    let before = proxy_snapshot()?;
    let digest = proxy_digest(&before)?;
    if digest != observed.original_proxy_digest()? {
        return Err("TUN Mode changed the original user proxy options".into());
    }
    let adapter = cfw_windows_engine::tunnel::adapter_guid(installation);
    let luid =
        adapter_luid(adapter)?.ok_or("the GUI's tunnel adapter is absent while TUN Mode is on")?;
    let flow = if protected { "refused" } else { "connected" };
    let ((resolver, attempts), stun_attempt, stun_attempts) = match kept {
        Kept::Any => {
            let (attempt, attempts) = keep_stun_server(luid)?;
            (keep_resolver(&RESOLVERS, flow, luid)?, attempt, attempts)
        }
        Kept::Same(resolver, server) => {
            let SocketAddr::V4(address) = server else {
                return Err("the kept STUN server is not IPv4".into());
            };
            require_tunnel_route(*address.ip(), luid)?;
            let attempt = stun(server)?;
            // With both switches on the server must not learn this
            // computer's address; whether the refusal also reached the socket
            // is recorded. With them off it answers again.
            if (attempt.outcome == "answered") == protected {
                return Err(format!(
                    "the STUN request through the tunnel differs from leak protection {}: {}",
                    if protected { "on" } else { "off" },
                    attempt.receipt()
                ));
            }
            (
                keep_resolver(&[resolver], flow, luid)?,
                attempt,
                serde_json::Value::Null,
            )
        }
    };
    // What the switches do not name still passes while they are on.
    let fetched = if protected {
        Some(fetch_through_tunnel(resolve()?)?.local.to_string())
    } else {
        None
    };
    observed.recheck("leak protection probe GUI image changed during observation")?;
    if proxy_snapshot()? != before {
        return Err(format!(
            "user proxy options changed during the {operation} probe"
        ));
    }
    write(
        &receipts,
        &format!("{operation}-probe.json"),
        &serde_json::json!({
            "document": "cfw-installed-gui-leak-protection-probe-v1", "source": source,
            "operation": operation,
            "gui_process_id": observed.pid,
            "gui_process_creation_time": observed.process.identity().process_creation_time(),
            "gui_same_user_session": true, "installation_id": installation,
            "adapter": adapter, "adapter_luid": luid, "route_entered_tunnel": true,
            "resolver": resolver, "encrypted_dns_attempts": attempts,
            "encrypted_dns_tcp": flow, "stun": stun_attempt.receipt(),
            "stun_candidates": stun_attempts,
            "http_local_address": fetched, "http_through_tunnel_verified": protected,
            "user_proxy_sha256": digest, "user_proxy_unchanged": true,
            "release_accepted": false
        }),
    )
}
