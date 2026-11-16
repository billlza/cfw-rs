use super::*;

const OWN4: Ipv4Addr = Ipv4Addr::new(198, 18, 64, 1);
const OWN6: Ipv6Addr = Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 1);
const PEER4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const PEER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 7);

fn policy() -> DeliveryPolicy {
    DeliveryPolicy::new(OWN4, Some(OWN6)).unwrap()
}

/// For ICMP the message is a whole echo reply; other transports ignore it.
fn v4(source: Ipv4Addr, destination: Ipv4Addr, transport: Option<u8>) -> Header {
    Header::V4 {
        source,
        destination,
        transport,
        message: Message::Whole(Some(0)),
        quoted: None,
    }
}

fn v6(source: Ipv6Addr, destination: Ipv6Addr, transport: Option<u8>) -> Header {
    Header::V6 {
        source,
        destination,
        transport,
        message: Message::Whole(Some(129)),
        quoted: None,
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
    assert_eq!(RefusalReason::Neighbor.to_string(), "neighbor");
}

#[test]
fn packet_policy_admits_only_echo_replies_and_errors_about_tunnel_packets() {
    let policy = policy();
    let icmp4 = |message, quoted| Header::V4 {
        source: PEER4,
        destination: OWN4,
        transport: Some(1),
        message,
        quoted,
    };
    let icmp6 = |message, quoted| Header::V6 {
        source: PEER6,
        destination: OWN6,
        transport: Some(58),
        message,
        quoted,
    };
    // Echo replies, also fragmented, and errors quoting the adapter.
    for message in [Message::Whole(Some(0)), Message::First(Some(0))] {
        policy.admit(&icmp4(message, None)).unwrap();
    }
    for kind in [3, 11, 12] {
        policy
            .admit(&icmp4(Message::Whole(Some(kind)), Some(OWN4)))
            .unwrap();
        // An error about another sender, about no packet, or fragmented.
        for (message, quoted) in [
            (Message::Whole(Some(kind)), Some(PEER4)),
            (Message::Whole(Some(kind)), Some(Ipv4Addr::new(10, 0, 0, 2))),
            (Message::Whole(Some(kind)), None),
            (Message::First(Some(kind)), Some(OWN4)),
        ] {
            assert_eq!(
                refused(&policy, icmp4(message, quoted)),
                RefusalReason::Protocol,
                "{kind} {quoted:?}"
            );
        }
    }
    // Echo request, source quench, redirect, router advertisement and
    // solicitation, timestamp, information and address mask messages, and
    // ICMPv6's neighbour discovery numbers, which name nothing in ICMPv4.
    for kind in [8, 4, 5, 9, 10, 13, 14, 15, 16, 17, 18, 30, 135, 136, 255] {
        for message in [Message::Whole(Some(kind)), Message::First(Some(kind))] {
            assert_eq!(
                refused(&policy, icmp4(message, Some(OWN4))),
                RefusalReason::Protocol,
                "{kind}"
            );
        }
    }
    for message in [Message::Whole(Some(129)), Message::First(Some(129))] {
        policy.admit(&icmp6(message, None)).unwrap();
    }
    for kind in [1, 2, 3, 4] {
        policy
            .admit(&icmp6(Message::Whole(Some(kind)), Some(OWN6)))
            .unwrap();
        for (message, quoted) in [
            (Message::Whole(Some(kind)), Some(PEER6)),
            (Message::Whole(Some(kind)), None),
            (Message::First(Some(kind)), Some(OWN6)),
        ] {
            assert_eq!(
                refused(&policy, icmp6(message, quoted)),
                RefusalReason::Protocol,
                "{kind} {quoted:?}"
            );
        }
    }
    // Echo request, multicast listener, router discovery, redirect,
    // renumbering, inverse discovery, MLDv2, mobility and multicast router
    // discovery messages.
    for kind in [
        128, 130, 131, 132, 133, 134, 137, 138, 141, 142, 143, 144, 145, 146, 147, 151, 152, 153,
        200, 255,
    ] {
        for message in [Message::Whole(Some(kind)), Message::First(Some(kind))] {
            assert_eq!(
                refused(&policy, icmp6(message, Some(OWN6))),
                RefusalReason::Protocol,
                "{kind}"
            );
        }
    }
    // A whole neighbour solicitation or advertisement is counted apart; a
    // fragment of one is no neighbour discovery.
    for kind in [135, 136] {
        assert_eq!(
            refused(&policy, icmp6(Message::Whole(Some(kind)), None)),
            RefusalReason::Neighbor,
            "{kind}"
        );
        assert_eq!(
            refused(&policy, icmp6(Message::First(Some(kind)), None)),
            RefusalReason::Protocol,
            "{kind}"
        );
    }
    // Without an IPv6 address, an ICMPv6 error cannot quote one; the
    // destination check refuses it first.
    let ipv4_only = DeliveryPolicy::new(OWN4, None).unwrap();
    assert_eq!(
        refused(&ipv4_only, icmp6(Message::Whole(Some(2)), Some(OWN6))),
        RefusalReason::Destination
    );
    // A message too short for its type is refused; a later fragment
    // carries no type and is admitted.
    for message in [Message::Whole(None), Message::First(None)] {
        assert_eq!(
            refused(&policy, icmp4(message, Some(OWN4))),
            RefusalReason::Protocol
        );
        assert_eq!(
            refused(&policy, icmp6(message, Some(OWN6))),
            RefusalReason::Protocol
        );
    }
    policy.admit(&icmp4(Message::Continuation, None)).unwrap();
    policy.admit(&icmp6(Message::Continuation, None)).unwrap();
    // TCP and UDP do not depend on the message position, its first byte
    // or a quoted address.
    for message in [
        Message::Whole(None),
        Message::Whole(Some(5)),
        Message::First(Some(134)),
        Message::Continuation,
    ] {
        for transport in [6, 17] {
            policy
                .admit(&Header::V4 {
                    source: PEER4,
                    destination: OWN4,
                    transport: Some(transport),
                    message,
                    quoted: Some(PEER4),
                })
                .unwrap();
            policy
                .admit(&Header::V6 {
                    source: PEER6,
                    destination: OWN6,
                    transport: Some(transport),
                    message,
                    quoted: None,
                })
                .unwrap();
        }
    }
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
    // A neighbour advertisement is counted apart only once it is addressed
    // to the adapter from a remote peer.
    let advertisement = |source, destination| Header::V6 {
        source,
        destination,
        transport: Some(58),
        message: Message::Whole(Some(136)),
        quoted: None,
    };
    assert_eq!(
        refused(&policy, advertisement(PEER6, PEER6)),
        RefusalReason::Destination
    );
    assert_eq!(
        refused(
            &policy,
            advertisement(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), OWN6)
        ),
        RefusalReason::Source
    );
}
