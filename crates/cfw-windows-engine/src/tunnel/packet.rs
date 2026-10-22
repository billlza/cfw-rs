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
    },
    V6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        /// The next header, or the one after a single fragment header;
        /// None when that fragment header is truncated.
        transport: Option<u8>,
    },
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
            Ok(Header::V4 {
                source: Ipv4Addr::from(octets::<4>(&packet[12..16])?),
                destination: Ipv4Addr::from(octets::<4>(&packet[16..20])?),
                transport: (header == 20).then_some(packet[9]),
            })
        }
        6 if packet.len() >= 40 => {
            if usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len() {
                return Err(Error::Packet);
            }
            let transport = match packet[6] {
                IPV6_FRAGMENT => (packet.len() >= 48).then(|| packet[40]),
                next => Some(next),
            };
            Ok(Header::V6 {
                source: Ipv6Addr::from(octets::<16>(&packet[8..24])?),
                destination: Ipv6Addr::from(octets::<16>(&packet[24..40])?),
                transport,
            })
        }
        _ => Err(Error::Packet),
    }
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
    fn packet_header_reads_addresses_and_transport_at_fixed_offsets() {
        let mut ipv4 = vec![0; 60];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&60u16.to_be_bytes());
        ipv4[9] = 6;
        ipv4[12..16].copy_from_slice(&[203, 0, 113, 7]);
        ipv4[16..20].copy_from_slice(&[198, 18, 64, 1]);
        assert_eq!(
            validate(&ipv4, 1500).unwrap(),
            Header::V4 {
                source: Ipv4Addr::new(203, 0, 113, 7),
                destination: Ipv4Addr::new(198, 18, 64, 1),
                transport: Some(6),
            }
        );
        // A header with options reports no transport.
        ipv4[0] = 0x46;
        assert!(matches!(
            validate(&ipv4, 1500).unwrap(),
            Header::V4 {
                transport: None,
                ..
            }
        ));

        let source = Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 7);
        let destination = Ipv6Addr::new(0x2001, 2, 0, 0x64, 0, 0, 0, 1);
        let mut ipv6 = vec![0; 48];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv6[6] = 17;
        ipv6[8..24].copy_from_slice(&source.octets());
        ipv6[24..40].copy_from_slice(&destination.octets());
        ipv6[40] = 58;
        let header = |transport| Header::V6 {
            source,
            destination,
            transport,
        };
        assert_eq!(validate(&ipv6, 1500).unwrap(), header(Some(17)));
        // One fragment header: the protocol it carries is the transport.
        ipv6[6] = IPV6_FRAGMENT;
        assert_eq!(validate(&ipv6, 1500).unwrap(), header(Some(58)));
        // A fragment header cut short leaves no transport to read.
        let mut truncated = ipv6[..47].to_vec();
        truncated[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(validate(&truncated, 1500).unwrap(), header(None));
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
