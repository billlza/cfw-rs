//! Validation and deterministic projection for the supported sing-box subset.
//!
//! The application owns listeners, logging, experimental APIs, and privileged
//! selectors. Imported profiles may only describe routing and outbound policy.

mod credentials;
mod error;
mod profile;
mod profile_projection;
mod profile_validation;
mod projection;
mod validation;

pub use credentials::{
    CredentialKind, CredentialRef, CredentialSecret, CredentialSlot, CredentialSlotError,
    CredentialTarget, InvalidCredentialRef, InvalidCredentialSecret, MAX_CREDENTIAL_SLOTS,
};
pub use error::ConfigError;
pub use projection::{
    AuthenticatedDnsServer, EngineSettings, ProjectedConfig, ProjectionMode, TUNNEL_ADDRESS_PLAN,
    TunnelAddressPlan,
};
pub use validation::{
    MAX_ENGINE_CONFIG_BYTES, MAX_PROFILE_BYTES, MAX_PROFILE_NODES, ValidatedSingBoxProfile,
    sha256_hex,
};

#[cfg(test)]
mod tests;
