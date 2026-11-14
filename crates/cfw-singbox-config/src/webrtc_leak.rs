//! WebRTC leak protection: the route rules the application adds in Tunnel
//! mode so that a page cannot learn an address of this Mac from a STUN
//! server.
//!
//! A WebRTC client asks a STUN server (RFC 8489) which address its UDP packets
//! arrive from, and a page reads the answer from the candidates it gathers.
//! The page names the server, so the answer follows the server's route and not
//! the page's: a page reached through the proxy can name a server that is
//! routed DIRECT and read the real address, and a page reached directly can
//! name a proxied server and read the proxy's exit. No route gives an answer
//! that is safe for both, so the switch refuses STUN instead of routing it.
//!
//! The first rule recognises STUN by its message format. It applies to UDP
//! only and names the STUN sniffer alone, so no TCP connection waits for it
//! and no other protocol is inspected. The second rule refuses what the first
//! recognised. TURN (RFC 8656) uses the same message format, so a relay
//! allocation over UDP is refused with it, and a client falls back to a relay
//! over TCP or TLS where its service offers one.
//!
//! The engine never sniffs a destination port it takes for a mail port, on
//! any network, and the page names the server's port too. The third rule
//! therefore refuses UDP to those ports outright: no standard service uses
//! UDP on any of them, and a STUN server on one would otherwise go
//! unrecognised.
//!
//! The engine inspects the first datagram of a UDP session only. A WebRTC
//! socket opens with STUN, so it is always recognised; a socket that sends
//! something else first keeps its route, whatever follows.
//!
//! The rules follow the Direct mode rule and precede the Global mode rule, so
//! they hold in Global and Rule mode and leave Direct mode alone: there every
//! site already sees the real address. They never change a proxy mode
//! projection, where a browser's UDP leaves the Mac without passing through
//! the application at all. Neither do they cover a packet that leaves outside
//! the Tunnel's route coverage, such as one a client scopes to a physical
//! interface, because the projection cannot change what the native route owner
//! captures.

use serde_json::{Value, json};

/// The engine's name for the STUN sniffer and for the protocol it reports.
const STUN: &str = "stun";

/// The destination ports the pinned engine never sniffs (`Skip` in its
/// `common/sniff/sniff.go`): SMTP, POP3 and IMAP with their TLS variants,
/// where the server speaks first over TCP. The engine applies the list to
/// UDP as well, so it must be read again whenever the engine pin moves.
const UNSNIFFED_PORTS: [u16; 7] = [25, 110, 143, 465, 587, 993, 995];

/// The rules that recognise STUN, refuse it, and refuse UDP where the engine
/// cannot recognise it, in the order they apply.
pub(crate) fn route_rules() -> [Value; 3] {
    [
        json!({ "network": "udp", "action": "sniff", "sniffer": [STUN] }),
        json!({ "protocol": STUN, "action": "reject" }),
        json!({ "network": "udp", "port": UNSNIFFED_PORTS, "action": "reject" }),
    ]
}
