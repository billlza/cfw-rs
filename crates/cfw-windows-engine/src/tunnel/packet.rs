use super::{Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

const IPV6_FRAGMENT: u8 = 44;

/// The fixed-offset facts of one packet, built by `validate` after the
/// packet's framing was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Header {
    V4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        /// The protocol field, reported only for a header without options:
        /// the delivery policy admits none.
        transport: Option<u8>,
        message: Message,
        /// The source of an IPv4 header quoted after an 8-byte ICMP header.
        quoted: Option<Ipv4Addr>,
    },
    V6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        /// The next header, or the one after a single fragment header;
        /// None when that fragment header is truncated.
        transport: Option<u8>,
        message: Message,
        /// The source of an IPv6 header quoted after an 8-byte ICMPv6 header.
        quoted: Option<Ipv6Addr>,
    },
}

/// Which part of its transport message a packet carries. The first byte of
/// the message (an ICMP type) is None when the packet ends before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Message {
    /// An unfragmented packet.
    Whole(Option<u8>),
    /// The first fragment of a fragmented message.
    First(Option<u8>),
    /// A later fragment, which carries no transport header and cannot be
    /// reassembled without the first fragment.
    Continuation,
}

pub(super) fn validate_mtu(mtu: u16) -> Result<()> {
    // Preserve the shared projection's complete MTU range. A lower authority
    // protocol limit must not silently narrow this data-plane contract.
    if !(1280..=9000).contains(&mtu) {
        return Err("MTU is outside 1280..=9000".into());
    }
    Ok(())
}

pub(super) fn validate(packet: &[u8], mtu: u16) -> Result<Header> {
    validate_mtu(mtu)?;
    if packet.is_empty() || packet.len() > usize::from(mtu) {
        return Err(Error::Packet);
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20
                || header > packet.len()
                || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
            {
                return Err(Error::Packet);
            }
            // Flags/fragment word: reserved, DF and MF bits, then a 13-bit offset.
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            let first_byte = packet.get(header).copied();
            let message = if fragment & 0x1fff != 0 {
                Message::Continuation
            } else if fragment & 0x2000 != 0 {
                Message::First(first_byte)
            } else {
                Message::Whole(first_byte)
            };
            Ok(Header::V4 {
                source: Ipv4Addr::from(octets::<4>(&packet[12..16])?),
                destination: Ipv4Addr::from(octets::<4>(&packet[16..20])?),
                transport: (header == 20).then_some(packet[9]),
                message,
                quoted: quoted_ipv4_source(packet, header + 8),
            })
        }
        6 if packet.len() >= 40 => {
            if usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len() {
                return Err(Error::Packet);
            }
            let (transport, message, start) = match packet[6] {
                // The fragment offset is the high 13 bits of bytes 42-43. Any
                // fragment header makes the packet a fragment, offset 0 or not.
                IPV6_FRAGMENT if packet.len() >= 48 => (
                    Some(packet[40]),
                    if u16::from_be_bytes([packet[42], packet[43]]) >> 3 != 0 {
                        Message::Continuation
                    } else {
                        Message::First(packet.get(48).copied())
                    },
                    48,
                ),
                IPV6_FRAGMENT => (None, Message::First(None), 48),
                next => (Some(next), Message::Whole(packet.get(40).copied()), 40),
            };
            Ok(Header::V6 {
                source: Ipv6Addr::from(octets::<16>(&packet[8..24])?),
                destination: Ipv6Addr::from(octets::<16>(&packet[24..40])?),
                transport,
                message,
                quoted: quoted_ipv6_source(packet, start + 8),
            })
        }
        _ => Err(Error::Packet),
    }
}

/// The source of a complete IPv4 header beginning at `start`.
fn quoted_ipv4_source(packet: &[u8], start: usize) -> Option<Ipv4Addr> {
    let quoted = packet.get(start..start.checked_add(20)?)?;
    (quoted[0] >> 4 == 4).then(|| Ipv4Addr::new(quoted[12], quoted[13], quoted[14], quoted[15]))
}

/// The source of a complete IPv6 header beginning at `start`.
fn quoted_ipv6_source(packet: &[u8], start: usize) -> Option<Ipv6Addr> {
    let quoted = packet.get(start..start.checked_add(40)?)?;
    let source = <[u8; 16]>::try_from(&quoted[8..24]).ok()?;
    (quoted[0] >> 4 == 6).then(|| Ipv6Addr::from(source))
}

fn octets<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::Packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_projected_mtu_range_accepts_exact_ipv4_and_ipv6_packets() {
        for mtu in [1280u16, 1500, 9000] {
            let mut ipv4 = vec![0; usize::from(mtu)];
            ipv4[0] = 0x45;
            ipv4[2..4].copy_from_slice(&mtu.to_be_bytes());
            validate(&ipv4, mtu).unwrap();
            // IPv4 fragments and options remain a packet, not a new protocol.
            ipv4[0] = 0x46;
            ipv4[6] = 0x20;
            validate(&ipv4, mtu).unwrap();
            let mut ipv6 = vec![0; usize::from(mtu)];
            ipv6[0] = 0x60;
            ipv6[4..6].copy_from_slice(&(mtu - 40).to_be_bytes());
            validate(&ipv6, mtu).unwrap();
        }
    }

    #[test]
    fn packet_header_reads_addresses_transport_and_message_at_fixed_offsets() {
        let own = Ipv4Addr::new(198, 18, 64, 1);
        let mut ipv4 = vec![0; 60];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&60u16.to_be_bytes());
        ipv4[9] = 1;
        ipv4[12..16].copy_from_slice(&[203, 0, 113, 7]);
        ipv4[16..20].copy_from_slice(&own.octets());
        ipv4[20] = 3;
        // The ICMP error quotes the IPv4 header Windows sent from `own`.
        ipv4[28] = 0x45;
        ipv4[40..44].copy_from_slice(&own.octets());
        let v4 = |transport, message, quoted| Header::V4 {
            source: Ipv4Addr::new(203, 0, 113, 7),
            destination: own,
            transport,
            message,
            quoted,
        };
        assert_eq!(
            validate(&ipv4, 1500).unwrap(),
            v4(Some(1), Message::Whole(Some(3)), Some(own))
        );
        // Reserved and don't-fragment bits leave the packet whole.
        for flags in [0x80, 0x40, 0xc0] {
            ipv4[6] = flags;
            assert_eq!(
                validate(&ipv4, 1500).unwrap(),
                v4(Some(1), Message::Whole(Some(3)), Some(own))
            );
        }
        // More fragments follow: the first fragment still carries the type.
        ipv4[6] = 0x20;
        assert_eq!(
            validate(&ipv4, 1500).unwrap(),
            v4(Some(1), Message::First(Some(3)), Some(own))
        );
        // Any non-zero offset, in either byte, is a later fragment.
        for (high, low) in [(0x00, 0x01), (0x01, 0x00), (0x3f, 0xff)] {
            ipv4[6] = high;
            ipv4[7] = low;
            assert_eq!(
                validate(&ipv4, 1500).unwrap(),
                v4(Some(1), Message::Continuation, Some(own))
            );
        }
        ipv4[6..8].fill(0);
        // A quoted header of another version, or a truncated one, quotes nothing.
        ipv4[28] = 0x65;
        assert_eq!(
            validate(&ipv4, 1500).unwrap(),
            v4(Some(1), Message::Whole(Some(3)), None)
        );
        ipv4[28] = 0x45;
        let mut short = ipv4[..47].to_vec();
        short[2..4].copy_from_slice(&47u16.to_be_bytes());
        assert_eq!(
            validate(&short, 1500).unwrap(),
            v4(Some(1), Message::Whole(Some(3)), None)
        );
        // A header with options reports no transport; its message follows them.
        ipv4[0] = 0x46;
        ipv4[24] = 9;
        assert!(matches!(
            validate(&ipv4, 1500).unwrap(),
            Header::V4 {
                transport: None,
                message: Message::Whole(Some(9)),
                ..
            }
        ));
        // A packet that ends with its header carries no message byte.
        let mut bare = ipv4[..20].to_vec();
        bare[0] = 0x45;
        bare[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(
            validate(&bare, 1500).unwrap(),
            v4(Some(1), Message::Whole(None), None)
        );

        let source = Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 7);
        let destination = Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 1);
        let mut ipv6 = vec![0; 104];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&64u16.to_be_bytes());
        ipv6[6] = 58;
        ipv6[8..24].copy_from_slice(&source.octets());
        ipv6[24..40].copy_from_slice(&destination.octets());
        ipv6[40] = 2;
        // Packet too big quotes the IPv6 header Windows sent from `destination`.
        ipv6[48] = 0x60;
        ipv6[56..72].copy_from_slice(&destination.octets());
        let v6 = |transport, message, quoted| Header::V6 {
            source,
            destination,
            transport,
            message,
            quoted,
        };
        assert_eq!(
            validate(&ipv6, 1500).unwrap(),
            v6(Some(58), Message::Whole(Some(2)), Some(destination))
        );
        ipv6[48] = 0x40;
        assert_eq!(
            validate(&ipv6, 1500).unwrap(),
            v6(Some(58), Message::Whole(Some(2)), None)
        );
        // One fragment header: its protocol is the transport, the first
        // fragment's message begins after it, and the quote moves with it.
        let mut fragment = vec![0; 112];
        fragment[..40].copy_from_slice(&ipv6[..40]);
        fragment[4..6].copy_from_slice(&72u16.to_be_bytes());
        fragment[6] = IPV6_FRAGMENT;
        fragment[40] = 58;
        fragment[48] = 2;
        fragment[56] = 0x60;
        fragment[64..80].copy_from_slice(&destination.octets());
        assert_eq!(
            validate(&fragment, 1500).unwrap(),
            v6(Some(58), Message::First(Some(2)), Some(destination))
        );
        // Reserved bits and the M flag keep it the first fragment.
        for low in [0x01, 0x06, 0x07] {
            fragment[43] = low;
            assert_eq!(
                validate(&fragment, 1500).unwrap(),
                v6(Some(58), Message::First(Some(2)), Some(destination))
            );
        }
        // Any offset bit, in either byte, makes it a later fragment.
        for (high, low) in [(0x00, 0x08), (0x01, 0x00), (0xff, 0xf8)] {
            fragment[42] = high;
            fragment[43] = low;
            assert_eq!(
                validate(&fragment, 1500).unwrap(),
                v6(Some(58), Message::Continuation, Some(destination))
            );
        }
        // A fragment header cut short leaves no transport to read.
        let mut truncated = fragment[..47].to_vec();
        truncated[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            validate(&truncated, 1500).unwrap(),
            v6(None, Message::First(None), None)
        );
    }

    #[test]
    fn malformed_truncated_or_oversized_packets_are_rejected_without_padding() {
        for bytes in [vec![], vec![0x45; 19], vec![0x60; 39], vec![0x70; 40]] {
            assert!(validate(&bytes, 1500).is_err());
        }
        let mut packet = vec![0; 1500];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes());
        for mtu in [0, 1279, 1280, 9001] {
            assert!(validate(&packet, mtu).is_err());
        }
        for length in [20u16, 1499, 1501] {
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            assert!(validate(&packet, 1500).is_err());
        }
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes());
        packet[0] = 0x44;
        assert!(validate(&packet, 1500).is_err());
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&1461u16.to_be_bytes());
        assert!(validate(&packet, 1500).is_err());
    }
}
