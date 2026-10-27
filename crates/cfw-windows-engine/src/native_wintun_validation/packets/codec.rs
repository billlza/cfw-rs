//! Only the disposable fixture's exact IPv4 UDP flow may receive a reply.
use super::Result;

fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|pair| u32::from(pair[0]) * 256 + u32::from(*pair.get(1).unwrap_or(&0)))
        .sum()
}
fn finish(mut value: u32) -> u16 {
    while value > 0xffff {
        value = (value & 0xffff) + (value >> 16);
    }
    !(value as u16)
}
fn udp_checksum(packet: &[u8]) -> u16 {
    finish(sum(&packet[12..20]) + 17 + (packet.len() - 20) as u32 + sum(&packet[20..]))
}

pub(super) fn reply(
    packet: &[u8],
    local: [u8; 4],
    remote: [u8; 4],
    local_port: u16,
    remote_port: u16,
    payload: &[u8],
) -> Result<Option<Vec<u8>>> {
    if packet.len() < 20 {
        return Err("packet fixture received a truncated IP header".into());
    }
    if packet[0] >> 4 != 4 || packet[9] != 17 || packet[12..16] != local || packet[16..20] != remote
    {
        return Ok(None);
    }
    if packet.len() < 28
        || packet.len() > 9000
        || packet[0] != 0x45
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
    {
        return Err("fixture UDP request has invalid length, options or fragmentation".into());
    }
    if u16::from_be_bytes([packet[20], packet[21]]) != local_port
        || u16::from_be_bytes([packet[22], packet[23]]) != remote_port
    {
        return Ok(None);
    }
    if payload.is_empty()
        || packet[28..] != *payload
        || usize::from(u16::from_be_bytes([packet[24], packet[25]])) != packet.len() - 20
        || finish(sum(&packet[..20])) != 0
        || (packet[26..28] != [0, 0] && udp_checksum(packet) != 0)
    {
        return Err("fixture UDP payload, length or checksum differs".into());
    }
    let mut reply = packet.to_vec();
    reply[12..16].copy_from_slice(&remote);
    reply[16..20].copy_from_slice(&local);
    reply[20..22].copy_from_slice(&remote_port.to_be_bytes());
    reply[22..24].copy_from_slice(&local_port.to_be_bytes());
    reply[28] ^= 0xff;
    reply[10..12].fill(0);
    let checksum = finish(sum(&reply[..20]));
    reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    reply[26..28].fill(0);
    let checksum = udp_checksum(&reply);
    reply[26..28].copy_from_slice(&(if checksum == 0 { 0xffff } else { checksum }).to_be_bytes());
    Ok(Some(reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCAL: [u8; 4] = [192, 0, 2, 10];
    const REMOTE: [u8; 4] = [192, 0, 2, 123];
    fn request(mtu: u16) -> Vec<u8> {
        let mut packet = vec![0; usize::from(mtu)];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[8] = 64;
        packet[2..4].copy_from_slice(&mtu.to_be_bytes());
        packet[12..16].copy_from_slice(&LOCAL);
        packet[16..20].copy_from_slice(&REMOTE);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&54321u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(mtu - 20).to_be_bytes());
        packet[28..].fill(0x7b);
        let checksum = finish(sum(&packet[..20]));
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }
    #[test]
    fn response_preserves_full_mtu_and_returns_a_distinct_payload_with_valid_checksums() {
        for mtu in [1280, 1500, 9000] {
            let request = request(mtu);
            let original = request.clone();
            let response = reply(&request, LOCAL, REMOTE, 12345, 54321, &request[28..])
                .unwrap()
                .unwrap();
            assert_eq!(request, original);
            assert_eq!(response.len(), usize::from(mtu));
            assert_eq!(&response[12..16], &REMOTE);
            assert_eq!(&response[16..20], &LOCAL);
            assert_eq!(response[28], request[28] ^ 0xff);
            assert_eq!(&response[29..], &request[29..]);
            assert_eq!(finish(sum(&response[..20])), 0);
            assert_eq!(udp_checksum(&response), 0);
        }
    }
    #[test]
    fn foreign_flows_are_not_answered_and_corrupt_fixture_requests_fail() {
        let packet = request(1500);
        let payload = packet[28..].to_vec();
        assert!(
            reply(&packet, LOCAL, REMOTE, 54321, 12345, &payload)
                .unwrap()
                .is_none()
        );
        for index in [2, 6, 10, 24, 28] {
            let mut changed = packet.clone();
            changed[index] ^= 1;
            assert!(reply(&changed, LOCAL, REMOTE, 12345, 54321, &payload).is_err());
        }
        assert!(reply(&packet[..27], LOCAL, REMOTE, 12345, 54321, &payload).is_err());
        assert!(reply(&packet, LOCAL, REMOTE, 12345, 54321, &[]).is_err());
    }
}
