//! The addresses, routes and resolvers SYSTEM gives its own tunnel adapter for
//! one Tunnel run. Pure data derived from the digest-bound network options the
//! authenticated UserAgent presents; the Windows owner applies and reads it
//! back. Every route names only that adapter, so retiring the adapter retires
//! the routes, addresses and resolver settings with it.
//!
//! The values follow the macOS 0.5.0 provider: the shared address plan, a
//! default route in each enabled family less the excluded ranges, and the
//! address plan's DNS peers as the adapter's only resolvers. Excluded ranges
//! are subtracted from the default route instead of being installed as
//! separate bypass routes, so nothing is written to another interface.
use super::{Result, endpoint::HANDOFF_MTU};
use cfw_engine_api::TunnelNetworkOptions;
use cfw_singbox_config::TUNNEL_ADDRESS_PLAN;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Private, link-local, multicast and limited-broadcast ranges the macOS
/// provider excludes when the profile bypasses private networks.
const PRIVATE_IPV4: [(Ipv4Addr, u8); 6] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];
const PRIVATE_IPV6: [(Ipv6Addr, u8); 3] = [
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

/// A network prefix whose host bits are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    network: Ipv4Addr,
    length: u8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv6Prefix {
    network: Ipv6Addr,
    length: u8,
}
impl Ipv4Prefix {
    #[cfg(test)]
    fn new(address: Ipv4Addr, length: u8) -> Result<Self> {
        let range = Range::new(u128::from(u32::from(address)), length, 32)?;
        Ok(Self::from_range(range))
    }
    fn from_range(range: Range) -> Self {
        Self {
            network: Ipv4Addr::from(range.value as u32),
            length: range.length,
        }
    }
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }
    pub fn length(&self) -> u8 {
        self.length
    }
}
impl Ipv6Prefix {
    #[cfg(test)]
    fn new(address: Ipv6Addr, length: u8) -> Result<Self> {
        let range = Range::new(u128::from(address), length, 128)?;
        Ok(Self::from_range(range))
    }
    fn from_range(range: Range) -> Self {
        Self {
            network: Ipv6Addr::from(range.value),
            length: range.length,
        }
    }
    pub fn network(&self) -> Ipv6Addr {
        self.network
    }
    pub fn length(&self) -> u8 {
        self.length
    }
}
impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.length)
    }
}
impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.length)
    }
}

/// One family's adapter address, its on-link prefix, the resolver peer the
/// engine serves inside that prefix, and the routes into the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyPlan<A, P> {
    pub address: A,
    pub prefix_length: u8,
    pub dns_peer: A,
    pub routes: Vec<P>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelNetworkPlan {
    mtu: u16,
    ipv4: FamilyPlan<Ipv4Addr, Ipv4Prefix>,
    ipv6: Option<FamilyPlan<Ipv6Addr, Ipv6Prefix>>,
}

impl TunnelNetworkPlan {
    /// Only the handoff MTU range is admitted: the adapter MTU equals the
    /// endpoint MTU the Authority attests in `PacketPumpLimits`.
    pub fn new(options: &TunnelNetworkOptions) -> Result<Self> {
        if !HANDOFF_MTU.contains(&options.mtu) {
            return Err(format!(
                "tunnel MTU {} is outside the handed-over range",
                options.mtu
            )
            .into());
        }
        let mut excluded_ipv4 = Vec::new();
        if options.bypass_private_networks {
            for (network, length) in PRIVATE_IPV4 {
                excluded_ipv4.push(Range::new(u128::from(u32::from(network)), length, 32)?);
            }
        }
        for host in options.direct_ipv4_hosts.as_slice() {
            excluded_ipv4.push(Range::new(u128::from(u32::from(*host)), 32, 32)?);
        }
        let ipv4 = FamilyPlan {
            address: parse(TUNNEL_ADDRESS_PLAN.ipv4_address)?,
            prefix_length: TUNNEL_ADDRESS_PLAN.ipv4_prefix_length,
            dns_peer: parse(TUNNEL_ADDRESS_PLAN.ipv4_dns_peer)?,
            routes: subtract(Range::DEFAULT_ROUTE, &excluded_ipv4, 32)
                .into_iter()
                .map(Ipv4Prefix::from_range)
                .collect(),
        };
        let ipv6 = if options.ipv6_enabled {
            let mut excluded = Vec::new();
            if options.bypass_private_networks {
                for (network, length) in PRIVATE_IPV6 {
                    excluded.push(Range::new(u128::from(network), length, 128)?);
                }
            }
            Some(FamilyPlan {
                address: parse(TUNNEL_ADDRESS_PLAN.ipv6_address)?,
                prefix_length: TUNNEL_ADDRESS_PLAN.ipv6_prefix_length,
                dns_peer: parse(TUNNEL_ADDRESS_PLAN.ipv6_dns_peer)?,
                routes: subtract(Range::DEFAULT_ROUTE, &excluded, 128)
                    .into_iter()
                    .map(Ipv6Prefix::from_range)
                    .collect(),
            })
        } else {
            None
        };
        let plan = Self {
            mtu: options.mtu,
            ipv4,
            ipv6,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        // The DNS peer must be on-link: Windows reaches it through the adapter
        // without a route, and the engine answers it inside the tunnel.
        let on_link = |address: u128, peer: u128, length: u8, width: u8| {
            length < width
                && Range::new(address & !mask(width - length), length, width).is_ok_and(|network| {
                    network.contains(
                        Range {
                            value: peer,
                            length: width,
                        },
                        width,
                    )
                })
        };
        if !on_link(
            u128::from(u32::from(self.ipv4.address)),
            u128::from(u32::from(self.ipv4.dns_peer)),
            self.ipv4.prefix_length,
            32,
        ) || self.ipv4.address == self.ipv4.dns_peer
            || self.ipv4.routes.is_empty()
        {
            return Err("tunnel IPv4 address plan is inconsistent".into());
        }
        if let Some(ipv6) = &self.ipv6
            && (!on_link(
                u128::from(ipv6.address),
                u128::from(ipv6.dns_peer),
                ipv6.prefix_length,
                128,
            ) || ipv6.address == ipv6.dns_peer
                || ipv6.routes.is_empty())
        {
            return Err("tunnel IPv6 address plan is inconsistent".into());
        }
        Ok(())
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }
    pub fn ipv4(&self) -> &FamilyPlan<Ipv4Addr, Ipv4Prefix> {
        &self.ipv4
    }
    pub fn ipv6(&self) -> Option<&FamilyPlan<Ipv6Addr, Ipv6Prefix>> {
        self.ipv6.as_ref()
    }
    /// The adapter's own addresses, from which the owner builds its
    /// `DeliveryPolicy` once they are assigned.
    pub fn delivery_policy(&self) -> Result<super::DeliveryPolicy> {
        super::DeliveryPolicy::new(
            self.ipv4.address,
            self.ipv6.as_ref().map(|family| family.address),
        )
    }
}

/// The interface GUID of an installation's tunnel adapter: fixed for the
/// installation, so Windows keeps one network profile for it and a stale
/// adapter is found by identity rather than by name.
pub fn adapter_guid(installation: uuid::Uuid) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    const LABEL: &[u8] = b"cfw.windows.tunnel-adapter.v1\0";
    let digest = Sha256::new()
        .chain_update(LABEL)
        .chain_update(installation.as_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

fn parse<A: std::str::FromStr>(text: &str) -> Result<A> {
    text.parse()
        .map_err(|_| format!("tunnel address plan value {text} is malformed").into())
}

/// A prefix as an integer in a `width`-bit address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    value: u128,
    length: u8,
}
impl Range {
    fn new(value: u128, length: u8, width: u8) -> Result<Self> {
        if length > width || (width < 128 && value >> width != 0) {
            return Err("tunnel route prefix is outside its address family".into());
        }
        let host_bits = width - length;
        if host_bits > 0 && value & mask(host_bits) != 0 {
            return Err("tunnel route prefix has host bits set".into());
        }
        Ok(Self { value, length })
    }
    const DEFAULT_ROUTE: Self = Self {
        value: 0,
        length: 0,
    };
    /// Whether `other` lies within this prefix.
    fn contains(self, other: Self, width: u8) -> bool {
        self.length <= other.length
            && (self.length == 0
                || (self.value >> (width - self.length)) == (other.value >> (width - self.length)))
    }
    fn overlaps(self, other: Self, width: u8) -> bool {
        self.contains(other, width) || other.contains(self, width)
    }
    fn halves(self, width: u8) -> (Self, Self) {
        let length = self.length + 1;
        let upper = self.value | (1u128 << (width - length));
        (
            Self {
                value: self.value,
                length,
            },
            Self {
                value: upper,
                length,
            },
        )
    }
}
fn mask(bits: u8) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// The smallest set of prefixes covering `base` minus every excluded prefix,
/// in ascending address order.
fn subtract(base: Range, excluded: &[Range], width: u8) -> Vec<Range> {
    let mut output = Vec::new();
    subtract_into(base, excluded, width, &mut output);
    output
}
fn subtract_into(base: Range, excluded: &[Range], width: u8, output: &mut Vec<Range>) {
    if excluded.iter().any(|range| range.contains(base, width)) {
        return;
    }
    if !excluded.iter().any(|range| range.overlaps(base, width)) {
        output.push(base);
        return;
    }
    // An exclusion lies strictly inside `base`, so `base` is shorter than
    // `width` and splitting terminates at the exclusion's own length.
    let (lower, upper) = base.halves(width);
    subtract_into(lower, excluded, width, output);
    subtract_into(upper, excluded, width, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_singbox_config::DirectIpv4HostRoutes;

    fn options(
        ipv6_enabled: bool,
        bypass_private_networks: bool,
        mtu: u16,
    ) -> TunnelNetworkOptions {
        TunnelNetworkOptions {
            ipv6_enabled,
            bypass_private_networks,
            direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
            mtu,
            system_proxy_port: None,
        }
    }
    fn v4(text: &str) -> Ipv4Prefix {
        let (address, length) = text.split_once('/').unwrap();
        Ipv4Prefix::new(address.parse().unwrap(), length.parse().unwrap()).unwrap()
    }
    fn v6(text: &str) -> Ipv6Prefix {
        let (address, length) = text.split_once('/').unwrap();
        Ipv6Prefix::new(address.parse().unwrap(), length.parse().unwrap()).unwrap()
    }
    fn covers_v4(routes: &[Ipv4Prefix], address: Ipv4Addr) -> bool {
        routes.iter().any(|route| {
            Range::new(u128::from(u32::from(route.network)), route.length, 32)
                .unwrap()
                .contains(
                    Range {
                        value: u128::from(u32::from(address)),
                        length: 32,
                    },
                    32,
                )
        })
    }
    fn covers_v6(routes: &[Ipv6Prefix], address: Ipv6Addr) -> bool {
        routes.iter().any(|route| {
            Range::new(u128::from(route.network), route.length, 128)
                .unwrap()
                .contains(
                    Range {
                        value: u128::from(address),
                        length: 128,
                    },
                    128,
                )
        })
    }

    #[test]
    fn tunnel_routes_cover_everything_when_private_networks_are_not_bypassed() {
        let plan = TunnelNetworkPlan::new(&options(true, false, 1500)).unwrap();
        assert_eq!(plan.ipv4().routes, [v4("0.0.0.0/0")]);
        assert_eq!(plan.ipv6().unwrap().routes, [v6("::/0")]);
        assert_eq!(plan.mtu(), 1500);
        assert_eq!(plan.ipv4().address, Ipv4Addr::new(198, 18, 64, 1));
        assert_eq!(plan.ipv4().dns_peer, Ipv4Addr::new(198, 18, 64, 2));
        assert_eq!(plan.ipv4().prefix_length, 30);
        let ipv6 = plan.ipv6().unwrap();
        assert_eq!(ipv6.address, "2001:2:0:64::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.dns_peer, "2001:2:0:64::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.prefix_length, 126);
        let policy = plan.delivery_policy().unwrap();
        assert_eq!(policy.ipv4(), plan.ipv4().address);
        assert_eq!(policy.ipv6(), Some(ipv6.address));
    }

    #[test]
    fn tunnel_routes_without_ipv6_leave_the_family_unconfigured() {
        let plan = TunnelNetworkPlan::new(&options(false, false, 1280)).unwrap();
        assert!(plan.ipv6().is_none());
        assert_eq!(plan.delivery_policy().unwrap().ipv6(), None);
    }

    #[test]
    fn tunnel_routes_subtract_exactly_the_macos_private_ranges() {
        let plan = TunnelNetworkPlan::new(&options(true, true, 1500)).unwrap();
        let routes = &plan.ipv4().routes;
        for excluded in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.10.20",
            "224.0.0.251",
            "239.255.255.250",
            "255.255.255.255",
        ] {
            assert!(!covers_v4(routes, excluded.parse().unwrap()), "{excluded}");
        }
        for included in [
            "0.0.0.0",
            "1.1.1.1",
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "198.18.64.2",
            "223.255.255.255",
            "240.0.0.0",
            "255.255.255.254",
        ] {
            assert!(covers_v4(routes, included.parse().unwrap()), "{included}");
        }
        // The minimal ordered cover, as Python's `ipaddress` computes it with
        // `address_exclude` followed by `collapse_addresses`.
        assert_eq!(
            routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            MINIMAL_PRIVATE_BYPASS_IPV4
        );
        let ipv6 = &plan.ipv6().unwrap().routes;
        for excluded in ["fd00::1", "fc00::", "fe80::1", "febf::1", "ff02::fb"] {
            assert!(!covers_v6(ipv6, excluded.parse().unwrap()), "{excluded}");
        }
        for included in [
            "::",
            "2001:4860:4860::8888",
            "fbff::1",
            "fec0::1",
            "2001:2:0:64::2",
        ] {
            assert!(covers_v6(ipv6, included.parse().unwrap()), "{included}");
        }
        assert_eq!(
            ipv6.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "::/1",
                "8000::/2",
                "c000::/3",
                "e000::/4",
                "f000::/5",
                "f800::/6",
                "fe00::/9",
                "fec0::/10"
            ]
        );
    }

    const MINIMAL_PRIVATE_BYPASS_IPV4: [&str; 67] = [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/3",
        "160.0.0.0/5",
        "168.0.0.0/8",
        "169.0.0.0/9",
        "169.128.0.0/10",
        "169.192.0.0/11",
        "169.224.0.0/12",
        "169.240.0.0/13",
        "169.248.0.0/14",
        "169.252.0.0/15",
        "169.255.0.0/16",
        "170.0.0.0/7",
        "172.0.0.0/12",
        "172.32.0.0/11",
        "172.64.0.0/10",
        "172.128.0.0/9",
        "173.0.0.0/8",
        "174.0.0.0/7",
        "176.0.0.0/4",
        "192.0.0.0/9",
        "192.128.0.0/11",
        "192.160.0.0/13",
        "192.169.0.0/16",
        "192.170.0.0/15",
        "192.172.0.0/14",
        "192.176.0.0/12",
        "192.192.0.0/10",
        "193.0.0.0/8",
        "194.0.0.0/7",
        "196.0.0.0/6",
        "200.0.0.0/5",
        "208.0.0.0/4",
        "240.0.0.0/5",
        "248.0.0.0/6",
        "252.0.0.0/7",
        "254.0.0.0/8",
        "255.0.0.0/9",
        "255.128.0.0/10",
        "255.192.0.0/11",
        "255.224.0.0/12",
        "255.240.0.0/13",
        "255.248.0.0/14",
        "255.252.0.0/15",
        "255.254.0.0/16",
        "255.255.0.0/17",
        "255.255.128.0/18",
        "255.255.192.0/19",
        "255.255.224.0/20",
        "255.255.240.0/21",
        "255.255.248.0/22",
        "255.255.252.0/23",
        "255.255.254.0/24",
        "255.255.255.0/25",
        "255.255.255.128/26",
        "255.255.255.192/27",
        "255.255.255.224/28",
        "255.255.255.240/29",
        "255.255.255.248/30",
        "255.255.255.252/31",
        "255.255.255.254/32",
    ];

    #[test]
    fn tunnel_routes_subtract_release_transport_host_routes() {
        let mut options = options(false, false, 1500);
        options.direct_ipv4_hosts = serde_json::from_value(serde_json::json!([
            cfw_singbox_config::RELEASE_PACKET_TRANSPORT_IPV4
        ]))
        .unwrap();
        let plan = TunnelNetworkPlan::new(&options).unwrap();
        let host = cfw_singbox_config::RELEASE_PACKET_TRANSPORT_IPV4;
        assert!(!covers_v4(&plan.ipv4().routes, host));
        assert_eq!(plan.ipv4().routes.len(), 32);
        let neighbour = Ipv4Addr::from(u32::from(host) ^ 1);
        assert!(covers_v4(&plan.ipv4().routes, neighbour));
    }

    #[test]
    fn tunnel_routes_admit_only_the_handed_over_mtu_range() {
        for mtu in [1280, 1400, 1500] {
            assert_eq!(
                TunnelNetworkPlan::new(&options(false, true, mtu))
                    .unwrap()
                    .mtu(),
                mtu
            );
        }
        for mtu in [0, 576, 1279, 1501, 9000] {
            assert!(
                TunnelNetworkPlan::new(&options(false, true, mtu)).is_err(),
                "{mtu}"
            );
        }
    }

    #[test]
    fn tunnel_adapter_guid_is_fixed_per_installation_and_rfc_variant() {
        let first = uuid::Uuid::from_u128(0x0123_4567_89ab_4cde_8f01_2345_6789_abcd);
        let second = uuid::Uuid::from_u128(0x0123_4567_89ab_4cde_8f01_2345_6789_abce);
        assert_eq!(adapter_guid(first), adapter_guid(first));
        assert_ne!(adapter_guid(first), adapter_guid(second));
        assert_ne!(adapter_guid(first), first);
        assert_eq!(adapter_guid(first).get_variant(), uuid::Variant::RFC4122);
        assert_eq!(adapter_guid(first).get_version_num(), 8);
        assert!(!adapter_guid(uuid::Uuid::nil()).is_nil());
        // A fixed vector keeps the GUID stable across releases, so a stale
        // adapter of an earlier build is still recognised. Computed outside
        // this crate: SHA-256 of the label and the installation bytes, first
        // 16 bytes, with the version 8 and RFC 4122 variant bits applied.
        assert_eq!(
            adapter_guid(first).to_string(),
            "3973d380-a0f5-84a4-b10a-a5cf301ee965"
        );
    }

    #[test]
    fn route_ranges_reject_host_bits_and_foreign_lengths() {
        assert!(Range::new(1, 31, 32).is_err());
        assert!(Range::new(0, 33, 32).is_err());
        assert!(Range::new(1u128 << 32, 0, 32).is_err());
        assert!(Range::new(0, 129, 128).is_err());
        assert!(Range::new(u128::MAX, 128, 128).is_ok());
        assert_eq!(subtract(Range::DEFAULT_ROUTE, &[], 32).len(), 1);
        assert!(subtract(Range::DEFAULT_ROUTE, &[Range::DEFAULT_ROUTE], 32).is_empty());
        let half = Range::new(0, 1, 32).unwrap();
        assert_eq!(
            subtract(Range::DEFAULT_ROUTE, &[half], 32),
            [Range::new(1u128 << 31, 1, 32).unwrap()]
        );
    }
}
