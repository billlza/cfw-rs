use super::{Error, Result};

pub(super) fn validate_mtu(mtu: u16) -> Result<()> {
    // Preserve the shared projection's complete MTU range. A lower authority
    // protocol limit must not silently narrow this data-plane contract.
    if !(1280..=9000).contains(&mtu) {
        return Err("MTU is outside 1280..=9000".into());
    }
    Ok(())
}

pub(super) fn validate(packet: &[u8], mtu: u16) -> Result<()> {
    validate_mtu(mtu)?;
    if packet.is_empty() || packet.len() > usize::from(mtu) {
        return Err(Error::Packet);
    }
    let valid = match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            header >= 20
                && header <= packet.len()
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        6 if packet.len() >= 40 => {
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(Error::Packet) }
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
