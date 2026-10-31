//! DNS leak protection: the route rule the application adds in Tunnel mode so
//! that no DNS query leaves the Mac outside the application's own encrypted
//! DNS.
//!
//! Plain DNS needs no switch: the Tunnel hijacks every port 53 flow into the
//! application's DNS, whose resolvers are DNS-over-HTTPS through the selected
//! route (see the projection). What remains is encrypted DNS that an app or a
//! system setting carries itself. DNS over TLS (RFC 7858) and DNS over QUIC
//! (RFC 9250) both use port 853, so the switch refuses every connection to
//! it, and such a client falls back to plain DNS, which is hijacked. DNS over
//! HTTPS shares port 443 with ordinary traffic and cannot be told apart
//! without a list of resolvers, so it is not covered; neither is a query that
//! leaves outside the Tunnel's route coverage, such as one scoped to a LAN
//! interface, because the projection cannot change what the native route
//! owner captures.
//!
//! The rule follows the port 53 hijack and precedes the mode rules, so it
//! holds in Rule, Global and Direct mode alike, and it never changes a proxy
//! mode projection, where the application does not own the host DNS. The
//! refusal replies (TCP reset, ICMP unreachable), so the client fails at once
//! instead of waiting for a timeout.

use serde_json::{Value, json};

/// The port DNS over TLS and DNS over QUIC use.
const ENCRYPTED_DNS_PORT: u16 = 853;

/// The rule that refuses DNS over TLS and DNS over QUIC.
pub(crate) fn route_rule() -> Value {
    json!({ "port": ENCRYPTED_DNS_PORT, "action": "reject" })
}
