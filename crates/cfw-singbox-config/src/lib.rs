//! Validation and deterministic projection for the supported sing-box subset.
//!
//! The application owns listeners, logging, experimental APIs, and privileged
//! selectors. Imported profiles may only describe routing and outbound policy.

mod controller;
mod credentials;
mod error;
mod profile;
mod profile_projection;
mod profile_validation;
mod projection;
mod release_dns;
mod release_packet;
mod validation;

/// Product-owned minimum for every remote TLS connection emitted by the
/// runtime projection. Profiles deliberately cannot override this policy.
/// BCP 195 interoperability floor. TLS 1.3 is negotiated whenever the peer
/// supports it; rustls does not offer obsolete protocol versions or cipher
/// suites. QUIC protocols independently require TLS 1.3.
pub const MINIMUM_REMOTE_TLS_VERSION: &str = "1.2";

pub use controller::{
    CLASH_API_ADDRESS, ClashApiEndpoint, DEFAULT_CLASH_API_PORT, MIN_CLASH_API_PORT,
};
pub use credentials::{
    CredentialAudience, CredentialBinding, CredentialKind, CredentialRef, CredentialSecret,
    CredentialSlot, CredentialSlotError, CredentialTarget, InvalidCredentialAudience,
    InvalidCredentialRef, InvalidCredentialSecret, MAX_CREDENTIAL_SLOTS,
};
pub use error::ConfigError;
pub use profile::MAX_OUTBOUNDS;
pub use projection::{
    AuthenticatedDnsServer, CONFIGURATION_IDENTITY_SCHEMA_VERSION, DEFAULT_MIXED_PORT,
    EngineSettings, ProjectedConfig, ProjectionMode, TUNNEL_ADDRESS_PLAN, TunnelAddressPlan,
};
pub use release_dns::ReleaseDnsEvidenceCase;
pub use release_packet::{
    DirectIpv4HostRoutes, RELEASE_PACKET_TRANSPORT_IPV4, ReleasePacketEvidenceCase,
};
pub use validation::{
    MAX_ENGINE_CONFIG_BYTES, MAX_PROFILE_BYTES, MAX_PROFILE_NODES, ValidatedSingBoxProfile,
    sha256_hex,
};

#[cfg(test)]
mod tests;
