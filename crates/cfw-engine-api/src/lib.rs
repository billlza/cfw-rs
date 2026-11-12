//! Stable product-facing types for the networking engine and its OS integration.
//!
//! No type in this crate exposes Tauri, Apple framework, libbox, or Clash API
//! implementation details. Native adapters translate at this boundary.

pub mod authority_v1;
mod credential_rebind;
pub use credential_rebind::CredentialRebindRequest;

pub use cfw_singbox_config::{
    AuthenticatedDnsServer, CredentialAudience, CredentialBinding, CredentialKind, CredentialRef,
    CredentialSecret, CredentialSlot, CredentialTarget, DirectIpv4HostRoutes, EngineSettings,
    MAX_CREDENTIAL_SLOTS, ValidatedSingBoxProfile,
};

// Version 10 separates local-core ownership and adds candidate checking and
// same-profile credential rebinding. The complete Host/native graph advances
// together; older bridges cannot attest these operations.
mod profile_probe;
pub use cfw_singbox_config::ProjectionMode as EngineStartMode;
pub use profile_probe::{
    ProfileDelayBackend, ProfileDelayTestRequest, ProfileProbeFailure, ProfileProxyDelay,
};

pub const ENGINE_PROTOCOL_VERSION: u16 = 10;

mod backend;
mod backend_error;
mod credential_garbage_collection;
mod credential_presence;
mod credential_provision;
mod credential_vault;
mod cutover;
mod identity;
mod mode;
mod native_bridge;
mod native_service;
mod start_request;
mod state;
mod tunnel;

pub use backend::{BackendFuture, EngineBackend, SystemProxyAuthorization};
pub use backend_error::{BackendError, BackendErrorKind, RetryDirective};
pub use credential_garbage_collection::{
    CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionReceipt, CredentialGarbageCollectionRequest,
    CredentialGarbageCollectionRequestError, CredentialProfileCatalogEntry,
    MAX_CREDENTIAL_CATALOG_PROFILES,
};
pub use credential_presence::{
    CredentialPresence, CredentialPresenceRequest, CredentialPresenceWireRequest,
};
pub use credential_provision::{
    CredentialProvision, CredentialProvisionRequest, CredentialProvisionRequestError,
    CredentialVaultReceipt,
};
pub use credential_vault::{
    CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionPreviewFuture,
    CredentialPresenceFuture, CredentialVaultError, CredentialVaultFuture,
    CredentialVaultProvisioner,
};
pub use cutover::{
    CutoverPreflightAttestation, CutoverPreflightBackend, CutoverPreflightFuture,
    CutoverPreflightOutcome, CutoverPreflightRequest, CutoverPreflightRequestError,
};
pub use identity::{
    EngineCommandContext, EngineGenerationStore, EngineLineage, EngineSessionIdentity,
    RuntimeIdentity,
};
pub use mode::{EngineMode, EngineOwner, EngineRuntimePlatform};
pub use native_bridge::{
    InstallationRecoveryIdentity, InstallationRecoveryState, NativeBridgeCommand,
    NativeBridgeFailure, NativeBridgeResult, NativeRequestEnvelope, NativeResponseEnvelope,
};
pub use native_service::{
    NativeServiceEngineStatus, NativeServiceMaintenanceAction, NativeServiceMaintenanceResult,
    NativeServiceOffProofProfile, NativeServiceRegistrationStatus,
};
pub use start_request::EngineStartRequest;
pub use state::{EngineEvent, EngineSnapshot, EngineState, NativeEngineStatus};
pub use tunnel::{
    TunnelApprovalBackend, TunnelApprovalFuture, TunnelApprovalWait, TunnelInstallOutcome,
    TunnelMtuError, TunnelMtuLimits, TunnelNetworkOptions,
};

/// Maximum number of exact audience/reference bindings admitted by the native
/// credential vault. Reusing one UUID in two profiles consumes two entries.
pub use cfw_singbox_config::MAX_CREDENTIAL_VAULT_BINDINGS;

#[cfg(test)]
mod test_support;
