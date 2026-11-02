pub use crate::engine_settings::{AuthenticatedDnsServer, DEFAULT_MIXED_PORT, EngineSettings};

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    ConfigError, CredentialAudience, CredentialSlot, DirectIpv4HostRoutes,
    MINIMUM_REMOTE_TLS_VERSION, ValidatedSingBoxProfile,
    controller::ClashApiEndpoint,
    credentials::validate_slots,
    profile_projection::DomainResolverTags,
    sha256_hex,
    validation::{DnsProjection, canonicalize},
};

mod dns_servers;
mod probe;
mod projector;

pub(crate) use dns_servers::validate_authenticated_dns_pool;
pub use probe::ProxyProbe;

const AUTHENTICATED_DNS_PRIMARY_TAG: &str = "cfw-authenticated-dns-0";
const AUTHENTICATED_DNS_SECONDARY_TAG: &str = "cfw-authenticated-dns-1";

/// Schema of the configuration identity document shared with the macOS engine
/// owner protocol. This changes whenever fields that cross that boundary gain
/// new closed vocabulary.
pub const CONFIGURATION_IDENTITY_SCHEMA_VERSION: u16 = 7;

/// Compute the shared native-boundary identity without changing its schema.
/// This is a canonical digest calculation, not request/lease authorization;
/// callers separately validate mode, options and credential-slot semantics.
pub fn configuration_identity_digest(
    configuration_sha256: &str,
    credential_audience: &CredentialAudience,
    credential_slots: &[CredentialSlot],
    mode: ProjectionMode,
    network_options: &impl Serialize,
) -> Result<String, serde_json::Error> {
    let identity = canonicalize(json!({
        "configuration_sha256": configuration_sha256,
        "credential_audience": credential_audience,
        "credential_slots": credential_slots,
        "mode": match mode {
            ProjectionMode::LocalProxy => "local_proxy",
            ProjectionMode::SystemProxy => "system_proxy",
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => "tunnel",
        },
        "network_options": serde_json::to_value(network_options)?,
        "schema_version": CONFIGURATION_IDENTITY_SCHEMA_VERSION,
    }));
    Ok(sha256_hex(serde_json::to_string(&identity)?.as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAddressPlan {
    pub ipv4_address: &'static str,
    pub ipv4_prefix_length: u8,
    pub ipv4_dns_peer: &'static str,
    pub ipv6_address: &'static str,
    pub ipv6_prefix_length: u8,
    pub ipv6_dns_peer: &'static str,
}

/// Application-owned identities in every projection. Native admission
/// boundaries compare these exact values; they are not profile choices.
pub const SYSTEM_PROXY_INBOUND_TAG: &str = "cfw-system-proxy";
pub const TUNNEL_INBOUND_TAG: &str = "cfw-tunnel";
/// Relative to the engine's private working directory.
pub const ROUTING_CACHE_PATH: &str = "routing-cache.db";

pub const TUNNEL_ADDRESS_PLAN: TunnelAddressPlan = TunnelAddressPlan {
    ipv4_address: "198.18.64.1",
    ipv4_prefix_length: 30,
    ipv4_dns_peer: "198.18.64.2",
    ipv6_address: "2001:2:0:64::1",
    ipv6_prefix_length: 126,
    ipv6_dns_peer: "2001:2:0:64::2",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionMode {
    LocalProxy,
    SystemProxy,
    Tunnel,
    TunnelSystemProxy,
}

impl ProjectionMode {
    pub const fn has_tunnel(self) -> bool {
        matches!(self, Self::Tunnel | Self::TunnelSystemProxy)
    }
}

/// Packet-processing implementation selected by the trusted native backend.
/// This is not an imported profile field or a user preference. It is selected
/// before canonicalization so both configuration digests bind the actual stack.
/// `Gvisor` is the Windows packet-endpoint stack, whose tunnel projections
/// also bind the engine's outbound sockets to the physical default interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStack {
    System,
    Gvisor,
}

impl TunnelStack {
    const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Gvisor => "gvisor",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProjectedConfig {
    mode: ProjectionMode,
    credential_audience: CredentialAudience,
    json: String,
    credential_slots: Vec<CredentialSlot>,
    clash_api: ClashApiEndpoint,
    configuration_digest: String,
    direct_ipv4_hosts: DirectIpv4HostRoutes,
    digest: String,
}

impl fmt::Debug for ProjectedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedConfig")
            .field("mode", &self.mode)
            .field("credential_audience", &self.credential_audience)
            .field("credential_slots", &self.credential_slots)
            .field("clash_api", &self.clash_api)
            .field("configuration_digest", &self.configuration_digest)
            .field("direct_ipv4_hosts", &self.direct_ipv4_hosts)
            .field("digest", &self.digest)
            .field("json", &"[REDACTED CONFIG TEMPLATE]")
            .finish()
    }
}

impl ProjectedConfig {
    pub fn mode(&self) -> ProjectionMode {
        self.mode
    }

    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.credential_audience
    }

    pub fn as_json(&self) -> &str {
        &self.json
    }

    pub fn credential_slots(&self) -> &[CredentialSlot] {
        &self.credential_slots
    }

    /// The application-owned controller this configuration exposes.
    pub fn clash_api(&self) -> ClashApiEndpoint {
        self.clash_api
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    pub fn direct_ipv4_hosts(&self) -> DirectIpv4HostRoutes {
        self.direct_ipv4_hosts
    }
}
