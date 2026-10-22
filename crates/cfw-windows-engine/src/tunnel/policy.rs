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
//! carry one, while router advertisements and redirects require one.
use super::{Result, packet::Header};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const IPV4_TRANSPORTS: [u8; 3] = [1, 6, 17];
const IPV6_TRANSPORTS: [u8; 3] = [6, 17, 58];

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
    /// header, or a protocol outside TCP, UDP and ICMP or ICMPv6.
    Protocol,
}
impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Destination => "destination",
            Self::Source => "source",
            Self::Protocol => "protocol",
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
            } => (
                IpAddr::V4(source),
                IpAddr::V4(destination),
                if destination != self.ipv4 {
                    Some(RefusalReason::Destination)
                } else if !remote_ipv4(source) || source == self.ipv4 {
                    Some(RefusalReason::Source)
                } else if !transport.is_some_and(|protocol| IPV4_TRANSPORTS.contains(&protocol)) {
                    Some(RefusalReason::Protocol)
                } else {
                    None
                },
            ),
            Header::V6 {
                source,
                destination,
                transport,
            } => (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                if self.ipv6 != Some(destination) {
                    Some(RefusalReason::Destination)
                } else if !remote_ipv6(source) || self.ipv6 == Some(source) {
                    Some(RefusalReason::Source)
                } else if !transport.is_some_and(|protocol| IPV6_TRANSPORTS.contains(&protocol)) {
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
mod tests {
    use super::*;

    const OWN4: Ipv4Addr = Ipv4Addr::new(198, 18, 64, 1);
    const OWN6: Ipv6Addr = Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 1);
    const PEER4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const PEER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 7);

    fn policy() -> DeliveryPolicy {
        DeliveryPolicy::new(OWN4, Some(OWN6)).unwrap()
    }

    fn v4(source: Ipv4Addr, destination: Ipv4Addr, transport: Option<u8>) -> Header {
        Header::V4 {
            source,
            destination,
            transport,
        }
    }

    fn v6(source: Ipv6Addr, destination: Ipv6Addr, transport: Option<u8>) -> Header {
        Header::V6 {
            source,
            destination,
            transport,
        }
    }

    fn refused(policy: &DeliveryPolicy, header: Header) -> RefusalReason {
        let refusal = policy.admit(&header).unwrap_err();
        let (source, destination) = match header {
            Header::V4 {
                source,
                destination,
                ..
            } => (IpAddr::V4(source), IpAddr::V4(destination)),
            Header::V6 {
                source,
                destination,
                ..
            } => (IpAddr::V6(source), IpAddr::V6(destination)),
        };
        assert_eq!((refusal.source, refusal.destination), (source, destination));
        refusal.reason
    }

    #[test]
    fn packet_policy_accepts_only_unicast_adapter_addresses() {
        for (ipv4, ipv6) in [
            (OWN4, Some(OWN6)),
            (OWN4, None),
            (
                Ipv4Addr::new(192, 0, 2, 10),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10)),
            ),
            (
                Ipv4Addr::new(10, 0, 0, 1),
                Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ] {
            let policy = DeliveryPolicy::new(ipv4, ipv6).unwrap();
            assert_eq!((policy.ipv4(), policy.ipv6()), (ipv4, ipv6));
        }
        for ipv4 in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 255, 255, 255),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 255),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(DeliveryPolicy::new(ipv4, None).is_err(), "{ipv4}");
        }
        for ipv6 in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv4Addr::new(192, 0, 2, 10).to_ipv6_compatible(),
            Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        ] {
            assert!(DeliveryPolicy::new(OWN4, Some(ipv6)).is_err(), "{ipv6}");
        }
    }

    #[test]
    fn packet_policy_admits_remote_replies_to_the_adapter_address() {
        let policy = policy();
        // DNS peer, fake-IP, private and public peers in the product plan.
        for source in [
            Ipv4Addr::new(198, 18, 64, 2),
            Ipv4Addr::new(198, 19, 0, 1),
            Ipv4Addr::new(10, 1, 2, 3),
            PEER4,
        ] {
            for protocol in [1, 6, 17] {
                policy.admit(&v4(source, OWN4, Some(protocol))).unwrap();
            }
        }
        for source in [
            Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 2, 0xffff, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5),
            PEER6,
        ] {
            for protocol in [6, 17, 58] {
                policy.admit(&v6(source, OWN6, Some(protocol))).unwrap();
            }
        }
    }

    #[test]
    fn packet_policy_refuses_every_other_destination() {
        let policy = policy();
        for destination in [
            Ipv4Addr::new(198, 18, 64, 0),
            Ipv4Addr::new(198, 18, 64, 2),
            Ipv4Addr::new(198, 18, 64, 3),
            Ipv4Addr::new(224, 0, 0, 22),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::LOCALHOST,
            PEER4,
        ] {
            assert_eq!(
                refused(&policy, v4(PEER4, destination, Some(17))),
                RefusalReason::Destination,
                "{destination}"
            );
        }
        for destination in [
            Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 2),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            OWN4.to_ipv6_mapped(),
            Ipv6Addr::LOCALHOST,
            PEER6,
        ] {
            assert_eq!(
                refused(&policy, v6(PEER6, destination, Some(17))),
                RefusalReason::Destination,
                "{destination}"
            );
        }
        // Without an IPv6 address, no IPv6 packet has a destination here.
        let ipv4_only = DeliveryPolicy::new(OWN4, None).unwrap();
        assert_eq!(
            refused(&ipv4_only, v6(PEER6, OWN6, Some(17))),
            RefusalReason::Destination
        );
        ipv4_only.admit(&v4(PEER4, OWN4, Some(17))).unwrap();
    }

    #[test]
    fn packet_policy_refuses_sources_no_remote_peer_can_hold() {
        let policy = policy();
        for source in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 9, 9, 9),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            OWN4,
        ] {
            assert_eq!(
                refused(&policy, v4(source, OWN4, Some(6))),
                RefusalReason::Source,
                "{source}"
            );
        }
        for source in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped(),
            Ipv4Addr::new(8, 8, 8, 8).to_ipv6_compatible(),
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfebf, 0xffff, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            OWN6,
        ] {
            assert_eq!(
                refused(&policy, v6(source, OWN6, Some(58))),
                RefusalReason::Source,
                "{source}"
            );
        }
    }

    #[test]
    fn packet_policy_admits_only_engine_transports_without_options() {
        let policy = policy();
        for protocol in [0, 2, 4, 41, 47, 50, 89, 255] {
            assert_eq!(
                refused(&policy, v4(PEER4, OWN4, Some(protocol))),
                RefusalReason::Protocol,
                "{protocol}"
            );
        }
        assert_eq!(
            refused(&policy, v4(PEER4, OWN4, None)),
            RefusalReason::Protocol
        );
        // Hop-by-hop, routing, fragment (nested or truncated), no-next-header,
        // destination options and encapsulations are never engine output.
        for protocol in [0, 1, 4, 41, 43, 44, 59, 60, 135] {
            assert_eq!(
                refused(&policy, v6(PEER6, OWN6, Some(protocol))),
                RefusalReason::Protocol,
                "{protocol}"
            );
        }
        assert_eq!(
            refused(&policy, v6(PEER6, OWN6, None)),
            RefusalReason::Protocol
        );
    }

    #[test]
    fn packet_policy_names_each_refusal_reason() {
        assert_eq!(RefusalReason::Destination.to_string(), "destination");
        assert_eq!(RefusalReason::Source.to_string(), "source");
        assert_eq!(RefusalReason::Protocol.to_string(), "protocol");
    }

    #[test]
    fn packet_policy_reports_the_first_failing_check() {
        let policy = policy();
        assert_eq!(
            refused(&policy, v4(Ipv4Addr::LOCALHOST, PEER4, None)),
            RefusalReason::Destination
        );
        assert_eq!(
            refused(&policy, v4(Ipv4Addr::LOCALHOST, OWN4, None)),
            RefusalReason::Source
        );
        assert_eq!(
            refused(
                &policy,
                v6(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, Some(0))
            ),
            RefusalReason::Destination
        );
        assert_eq!(
            refused(&policy, v6(OWN6, OWN6, Some(0))),
            RefusalReason::Source
        );
    }
}
