use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ReleaseDnsEvidenceCase;

/// The one external IPv4 transport endpoint whose physical direct-route
/// projection is admitted by the release Packet matrix.
pub const RELEASE_PACKET_TRANSPORT_IPV4: Ipv4Addr = Ipv4Addr::new(35, 194, 216, 98);

const NO_DIRECT_IPV4_HOSTS: [Ipv4Addr; 0] = [];
const RELEASE_TRANSPORT_DIRECT_IPV4_HOSTS: [Ipv4Addr; 1] = [RELEASE_PACKET_TRANSPORT_IPV4];

/// A closed, serialized direct-host route set.
///
/// The wire representation is deliberately the actual IPv4 address array so
/// the native configuration identity binds the route bytes, not a semantic
/// boolean. Only the empty ordinary set and the single reviewed release
/// transport endpoint are accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectIpv4HostRoutes {
    release_transport: bool,
}

impl DirectIpv4HostRoutes {
    pub const fn none() -> Self {
        Self {
            release_transport: false,
        }
    }

    pub fn as_slice(&self) -> &'static [Ipv4Addr] {
        if self.release_transport {
            &RELEASE_TRANSPORT_DIRECT_IPV4_HOSTS
        } else {
            &NO_DIRECT_IPV4_HOSTS
        }
    }

    pub const fn is_empty(self) -> bool {
        !self.release_transport
    }

    pub(crate) const fn release_transport() -> Self {
        Self {
            release_transport: true,
        }
    }
}

impl Serialize for DirectIpv4HostRoutes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DirectIpv4HostRoutes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addresses = Vec::<Ipv4Addr>::deserialize(deserializer)?;
        match addresses.as_slice() {
            [] => Ok(Self::none()),
            [address] if *address == RELEASE_PACKET_TRANSPORT_IPV4 => Ok(Self::release_transport()),
            _ => Err(de::Error::custom(
                "direct IPv4 host routes differ from the closed source-owned sets",
            )),
        }
    }
}

/// The source-owned physical Packet cases. A caller may select a reviewed case
/// but cannot supply a route, DNS endpoint, profile document, or transport IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePacketEvidenceCase {
    TcpIpv4,
    TcpIpv6,
    Udp,
    Quic,
    DnsAPrimary,
    DnsASecondary,
    DnsAaaaPrimary,
    DnsAaaaSecondary,
    LanBypass,
    IncludedRoutes,
    ExcludedRoutes,
    StopCleanup,
    Ipv6DisabledAbsence,
}

impl ReleasePacketEvidenceCase {
    pub const ALL: [Self; 13] = [
        Self::TcpIpv4,
        Self::TcpIpv6,
        Self::Udp,
        Self::Quic,
        Self::DnsAPrimary,
        Self::DnsASecondary,
        Self::DnsAaaaPrimary,
        Self::DnsAaaaSecondary,
        Self::LanBypass,
        Self::IncludedRoutes,
        Self::ExcludedRoutes,
        Self::StopCleanup,
        Self::Ipv6DisabledAbsence,
    ];

    pub(crate) const fn direct_ipv4_hosts(self) -> DirectIpv4HostRoutes {
        match self {
            Self::ExcludedRoutes => DirectIpv4HostRoutes::release_transport(),
            _ => DirectIpv4HostRoutes::none(),
        }
    }

    pub(crate) const fn dns_evidence_case(self) -> Option<ReleaseDnsEvidenceCase> {
        match self {
            Self::DnsAPrimary => Some(ReleaseDnsEvidenceCase::PrimaryIpv4),
            Self::DnsASecondary => Some(ReleaseDnsEvidenceCase::SecondaryIpv4),
            Self::DnsAaaaPrimary => Some(ReleaseDnsEvidenceCase::PrimaryIpv6),
            Self::DnsAaaaSecondary => Some(ReleaseDnsEvidenceCase::SecondaryIpv6),
            _ => None,
        }
    }
}
