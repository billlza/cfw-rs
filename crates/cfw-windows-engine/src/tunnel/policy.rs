//! Which engine packets the Windows IP stack may receive through the adapter.
//! Every engine-to-system packet is injected as if it arrived on the adapter,
//! so a packet is delivered only when it is addressed to the adapter's own
//! address of its family, comes from an address a remote peer can hold, and
//! carries TCP, UDP or ICMP without IPv4 options or IPv6 extension headers
//! other than one fragment header. The engine's gVisor stack only answers
//! flows Windows routed into the adapter, so its genuine packets match; the
//! pinned sing-tun echoes Windows' own multicast, broadcast and link-local
//! packets back unchanged, and those are refused here instead of re-entering
//! the stack. Link-local sources are refused because no proxied reply can
//! carry one, while ICMPv6 router advertisements and redirects require one.
//! ICMP is limited to echo replies and to destination unreachable, time
//! exceeded and parameter problem reports (ICMPv6 also packet too big) that
//! arrive unfragmented and quote a packet Windows sent from the adapter's own
//! address. Redirects, router and neighbour discovery, multicast listener
//! messages and every other type are refused, so the engine cannot change the
//! host's routes, neighbours or group membership, nor report errors for flows
//! that never used the tunnel. Neighbour solicitations and advertisements are
//! counted apart: Windows checks that the adapter's on-link neighbours are
//! reachable, and gVisor advertises every address the engine routes.
use super::{
    Result,
    packet::{Header, Message},
};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const ICMPV4: u8 = 1;
const ICMPV6: u8 = 58;
const IPV4_TRANSPORTS: [u8; 3] = [ICMPV4, 6, 17];
const IPV6_TRANSPORTS: [u8; 3] = [6, 17, ICMPV6];
const ICMPV4_ECHO_REPLY: u8 = 0;
/// Destination unreachable, time exceeded, parameter problem.
const ICMPV4_ERRORS: [u8; 3] = [3, 11, 12];
const ICMPV6_ECHO_REPLY: u8 = 129;
/// Destination unreachable, packet too big, time exceeded, parameter problem.
const ICMPV6_ERRORS: [u8; 4] = [1, 2, 3, 4];
/// Neighbour solicitation and advertisement.
const ICMPV6_NEIGHBOR: [u8; 2] = [135, 136];

/// The adapter's own unicast addresses: IPv4 always, IPv6 only when the
/// tunnel enables it. Build it from the addresses actually assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryPolicy {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Not addressed to the adapter's own address of the packet's family.
    Destination,
    /// A source no remote peer can hold, or the adapter's own address.
    Source,
    /// IPv4 options, IPv6 extension headers other than one fragment
    /// header, a protocol outside TCP, UDP and ICMP or ICMPv6, or an ICMP
    /// message other than an echo reply or an unfragmented destination
    /// unreachable, packet too big, time exceeded or parameter problem
    /// report that quotes the adapter's own address.
    Protocol,
    /// A whole ICMPv6 neighbour solicitation or advertisement, refused like
    /// the rest of neighbour discovery but counted apart, since gVisor answers
    /// Windows' reachability checks of the adapter's on-link neighbours.
    Neighbor,
}
impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Destination => "destination",
            Self::Source => "source",
            Self::Protocol => "protocol",
            Self::Neighbor => "neighbor",
        })
    }
}

/// One refused engine packet. Checks apply in the order of `RefusalReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub reason: RefusalReason,
    pub source: IpAddr,
    pub destination: IpAddr,
}

impl DeliveryPolicy {
    pub fn new(ipv4: Ipv4Addr, ipv6: Option<Ipv6Addr>) -> Result<Self> {
        if !remote_ipv4(ipv4) {
            return Err(format!("{ipv4} cannot be the adapter's own IPv4 address").into());
        }
        if let Some(ipv6) = ipv6
            && !remote_ipv6(ipv6)
        {
            return Err(format!("{ipv6} cannot be the adapter's own IPv6 address").into());
        }
        Ok(Self { ipv4, ipv6 })
    }

    pub fn ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    pub(super) fn admit(&self, header: &Header) -> std::result::Result<(), Refusal> {
        let (source, destination, reason) = match *header {
            Header::V4 {
                source,
                destination,
                transport,
                message,
                quoted,
            } => (
                IpAddr::V4(source),
                IpAddr::V4(destination),
                if destination != self.ipv4 {
                    Some(RefusalReason::Destination)
                } else if !remote_ipv4(source) || source == self.ipv4 {
                    Some(RefusalReason::Source)
                } else if !transport.is_some_and(|protocol| IPV4_TRANSPORTS.contains(&protocol))
                    || (transport == Some(ICMPV4)
                        && !icmp_admitted(
                            message,
                            ICMPV4_ECHO_REPLY,
                            &ICMPV4_ERRORS,
                            quoted == Some(self.ipv4),
                        ))
                {
                    Some(RefusalReason::Protocol)
                } else {
                    None
                },
            ),
            Header::V6 {
                source,
                destination,
                transport,
                message,
                quoted,
            } => (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                if self.ipv6 != Some(destination) {
                    Some(RefusalReason::Destination)
                } else if !remote_ipv6(source) || self.ipv6 == Some(source) {
                    Some(RefusalReason::Source)
                } else if transport == Some(ICMPV6) && neighbor(message) {
                    Some(RefusalReason::Neighbor)
                } else if !transport.is_some_and(|protocol| IPV6_TRANSPORTS.contains(&protocol))
                    || (transport == Some(ICMPV6)
                        && !icmp_admitted(
                            message,
                            ICMPV6_ECHO_REPLY,
                            &ICMPV6_ERRORS,
                            quoted.is_some() && quoted == self.ipv6,
                        ))
                {
                    Some(RefusalReason::Protocol)
                } else {
                    None
                },
            ),
        };
        match reason {
            None => Ok(()),
            Some(reason) => Err(Refusal {
                reason,
                source,
                destination,
            }),
        }
    }
}

/// An echo reply may be fragmented. An error report is at most 576 (IPv4) or
/// 1280 (IPv6) bytes, so it must be whole and quote a packet Windows sent from
/// the adapter's own address. A later fragment has no type to check and cannot
/// be reassembled without its first fragment, which is checked; it cannot
/// overwrite the type either, since it starts at least eight bytes in.
fn icmp_admitted(message: Message, echo_reply: u8, errors: &[u8], quotes_own: bool) -> bool {
    match message {
        Message::Whole(Some(kind)) => kind == echo_reply || (errors.contains(&kind) && quotes_own),
        Message::First(Some(kind)) => kind == echo_reply,
        Message::Continuation => true,
        Message::Whole(None) | Message::First(None) => false,
    }
}

/// A whole neighbour solicitation or advertisement. Neighbour discovery is
/// never fragmented, so a fragment of one remains a protocol refusal.
fn neighbor(message: Message) -> bool {
    matches!(message, Message::Whole(Some(kind)) if ICMPV6_NEIGHBOR.contains(&kind))
}

/// A unicast address outside this-network, loopback, link-local, multicast
/// and limited broadcast.
fn remote_ipv4(address: Ipv4Addr) -> bool {
    !(address.octets()[0] == 0
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast())
}

/// A unicast address outside link-local and multicast. `to_ipv4` also covers
/// the unspecified and loopback addresses and every IPv4-compatible or
/// IPv4-mapped address, none of which appears on the wire.
fn remote_ipv6(address: Ipv6Addr) -> bool {
    !(address.to_ipv4().is_some() || address.is_unicast_link_local() || address.is_multicast())
}

#[cfg(test)]
mod tests;
