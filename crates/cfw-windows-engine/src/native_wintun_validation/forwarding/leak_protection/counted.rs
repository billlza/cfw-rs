//! What one leak protection probe window shows: what the pump carried and
//! refused, the adapter's counters, and what the Windows IP, UDP and ICMP
//! layers counted for the probe's family.
use super::Sources;
use crate::{
    native_wintun_validation::Result,
    tunnel::{InterfaceCounters, PumpReport},
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        GetIcmpStatisticsEx, GetIpStatisticsEx, GetUdpStatisticsEx, MIB_ICMP_EX_XPSP1,
        MIB_IPSTATS_LH, MIB_UDPSTATS, MIBICMPSTATS_EX_XPSP1,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

/// Destination unreachable in ICMPv4 and in ICMPv6.
const UNREACHABLE4: u8 = 3;
const UNREACHABLE6: u8 = 1;

/// One family's counters of the Windows IP, UDP and ICMP layers.
#[derive(Clone, Copy)]
struct Stack {
    ip: MIB_IPSTATS_LH,
    udp: MIB_UDPSTATS,
    icmp: MIB_ICMP_EX_XPSP1,
}
impl Stack {
    fn read(ipv6: bool) -> Result<Self> {
        let family = u32::from(if ipv6 { AF_INET6 } else { AF_INET });
        let mut stack = Self {
            ip: MIB_IPSTATS_LH::default(),
            udp: MIB_UDPSTATS::default(),
            icmp: MIB_ICMP_EX_XPSP1::default(),
        };
        // SAFETY: each structure is owned and writable for its call.
        let statuses = unsafe {
            [
                GetIpStatisticsEx(&mut stack.ip, family),
                GetUdpStatisticsEx(&mut stack.udp, family),
                GetIcmpStatisticsEx(&mut stack.icmp, family),
            ]
        };
        if statuses != [0; 3] {
            return Err(format!("read the Windows stack counters: {statuses:?}"));
        }
        Ok(stack)
    }
}

/// What the pump, the adapter and the stack had counted at one moment.
pub(super) struct Counted {
    ipv6: bool,
    pump: PumpReport,
    adapter: InterfaceCounters,
    stack: Stack,
}
impl Counted {
    pub(super) fn now(sources: &Sources<'_>, target: SocketAddr) -> Result<Self> {
        Ok(Self {
            ipv6: target.is_ipv6(),
            pump: (sources.pump)(),
            adapter: (sources.adapter)()?,
            stack: Stack::read(target.is_ipv6())?,
        })
    }
    /// What changed since `before`. The pump's and the adapter's counters
    /// never go back; the stack's are 32-bit counters that wrap.
    pub(super) fn since(&self, before: &Self) -> Result<(Value, Reported)> {
        let grew = |now: u64, then: u64| {
            now.checked_sub(then)
                .ok_or_else(|| "a pump or adapter counter went back".to_owned())
        };
        let wrap = |now: u32, then: u32| now.wrapping_sub(then);
        let (pump, then) = (&self.pump, &before.pump);
        let (adapter, earlier) = (&self.adapter, &before.adapter);
        let (ip, ip_then) = (&self.stack.ip, &before.stack.ip);
        let (udp, udp_then) = (&self.stack.udp, &before.stack.udp);
        let (inbound, inbound_then) =
            (&self.stack.icmp.icmpInStats, &before.stack.icmp.icmpInStats);
        let unreachable = usize::from(if self.ipv6 {
            UNREACHABLE6
        } else {
            UNREACHABLE4
        });
        let reported = Reported {
            delivered: grew(pump.to_system.packets, then.to_system.packets)?,
            delivered_bytes: grew(pump.to_system.bytes, then.to_system.bytes)?,
            received: grew(adapter.in_unicast_packets, earlier.in_unicast_packets)?,
            returned: grew(adapter.in_errors, earlier.in_errors)?,
            unreachable: wrap(
                inbound.rgdwTypeCount[unreachable],
                inbound_then.rgdwTypeCount[unreachable],
            ),
        };
        let counted = json!({
            "pump":{
                "to_engine":grew(pump.to_engine.packets, then.to_engine.packets)?,
                "to_system":reported.delivered,
                "to_system_bytes":reported.delivered_bytes,
                "refused_destination":grew(pump.refused.destination.packets, then.refused.destination.packets)?,
                "refused_source":grew(pump.refused.source.packets, then.refused.source.packets)?,
                "refused_protocol":grew(pump.refused.protocol.packets, then.refused.protocol.packets)?,
                "refused_protocol_bytes":grew(pump.refused.protocol.bytes, then.refused.protocol.bytes)?,
                "refused_neighbor":grew(pump.refused.neighbor.packets, then.refused.neighbor.packets)?},
            "adapter":{
                "in_unicast":reported.received,
                "in_non_unicast":grew(adapter.in_non_unicast_packets, earlier.in_non_unicast_packets)?,
                "in_discards":grew(adapter.in_discards, earlier.in_discards)?,
                "in_errors":reported.returned,
                "out_unicast":grew(adapter.out_unicast_packets, earlier.out_unicast_packets)?},
            "ip":{
                "in_receives":wrap(ip.dwInReceives, ip_then.dwInReceives),
                "in_header_errors":wrap(ip.dwInHdrErrors, ip_then.dwInHdrErrors),
                "in_address_errors":wrap(ip.dwInAddrErrors, ip_then.dwInAddrErrors),
                "in_discards":wrap(ip.dwInDiscards, ip_then.dwInDiscards),
                "in_delivers":wrap(ip.dwInDelivers, ip_then.dwInDelivers),
                "out_requests":wrap(ip.dwOutRequests, ip_then.dwOutRequests),
                "out_discards":wrap(ip.dwOutDiscards, ip_then.dwOutDiscards),
                "out_no_routes":wrap(ip.dwOutNoRoutes, ip_then.dwOutNoRoutes)},
            "udp":{
                "in_datagrams":wrap(udp.dwInDatagrams, udp_then.dwInDatagrams),
                "no_ports":wrap(udp.dwNoPorts, udp_then.dwNoPorts),
                "in_errors":wrap(udp.dwInErrors, udp_then.dwInErrors),
                "out_datagrams":wrap(udp.dwOutDatagrams, udp_then.dwOutDatagrams)},
            "icmp_in":icmp(inbound, inbound_then),
            "icmp_out":icmp(&self.stack.icmp.icmpOutStats, &before.stack.icmp.icmpOutStats)
        });
        Ok((counted, reported))
    }
}

/// What one probe window shows of the engine's answer to a datagram.
#[derive(Clone, Copy)]
pub(super) struct Reported {
    /// Packets and bytes the pump delivered to Windows.
    pub(super) delivered: u64,
    pub(super) delivered_bytes: u64,
    /// What the adapter made of them: received, or returned unaccepted by
    /// the stack, which Wintun counts as a receive error.
    pub(super) received: u64,
    pub(super) returned: u64,
    /// Destination unreachable reports the ICMP layer counted.
    pub(super) unreachable: u32,
}

/// One direction of ICMP: messages, errors, and every type whose count changed.
fn icmp(now: &MIBICMPSTATS_EX_XPSP1, then: &MIBICMPSTATS_EX_XPSP1) -> Value {
    let types: serde_json::Map<_, _> = now
        .rgdwTypeCount
        .iter()
        .zip(then.rgdwTypeCount.iter())
        .enumerate()
        .filter(|(_, (now, then))| now != then)
        .map(|(kind, (now, then))| (kind.to_string(), json!(now.wrapping_sub(*then))))
        .collect();
    json!({"messages":now.dwMsgs.wrapping_sub(then.dwMsgs),
        "errors":now.dwErrors.wrapping_sub(then.dwErrors),"types":types})
}
