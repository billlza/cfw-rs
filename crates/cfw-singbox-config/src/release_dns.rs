use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The four source-owned DNS projections used by physical release evidence.
///
/// The caller chooses only a reviewed case. Addresses, transport and port are
/// compiled into this crate and cannot be supplied by profiles, settings or a
/// renderer command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseDnsEvidenceCase {
    PrimaryIpv4,
    PrimaryIpv6,
    SecondaryIpv4,
    SecondaryIpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseDnsEvidenceEndpoint {
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
    pub(crate) tag: &'static str,
}

impl ReleaseDnsEvidenceCase {
    pub(crate) const fn endpoint(self) -> ReleaseDnsEvidenceEndpoint {
        let (address, tag) = match self {
            Self::PrimaryIpv4 => (
                IpAddr::V4(Ipv4Addr::new(34, 80, 107, 183)),
                "cfw-release-dns-primary-ipv4",
            ),
            Self::PrimaryIpv6 => (
                IpAddr::V6(Ipv6Addr::new(0x2600, 0x1900, 0x4030, 0x5afb, 0, 1, 0, 0)),
                "cfw-release-dns-primary-ipv6",
            ),
            Self::SecondaryIpv4 => (
                IpAddr::V4(Ipv4Addr::new(35, 200, 12, 109)),
                "cfw-release-dns-secondary-ipv4",
            ),
            Self::SecondaryIpv6 => (
                IpAddr::V6(Ipv6Addr::new(0x2600, 0x1900, 0x4050, 0x08de, 0, 0, 0, 0)),
                "cfw-release-dns-secondary-ipv6",
            ),
        };
        ReleaseDnsEvidenceEndpoint {
            address,
            port: 53,
            tag,
        }
    }
}
