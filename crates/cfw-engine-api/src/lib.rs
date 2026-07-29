//! Stable product-facing types for the mutually-exclusive networking engines.
//!
//! No type in this crate exposes Tauri, Apple framework, libbox, or Clash API
//! implementation details. Native adapters translate at this boundary.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod authority_v1;

pub use cfw_singbox_config::{
    AuthenticatedDnsServer, CredentialAudience, CredentialBinding, CredentialKind, CredentialRef,
    CredentialSecret, CredentialSlot, CredentialTarget, EngineSettings, MAX_CREDENTIAL_SLOTS,
    ValidatedSingBoxProfile,
};

// Version 3 adds the closed credential-slot contract. A version 2 native
// bridge would ignore those slots and could otherwise attempt to start libbox
// with the deliberately empty credential placeholders.
pub const ENGINE_PROTOCOL_VERSION: u16 = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    #[default]
    Off,
    SystemProxy,
    Tunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineOwner {
    ProxyAgent,
    PacketTunnelSystemExtension,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSessionIdentity {
    pub installation_id: String,
    pub config_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLineage {
    pub session: EngineSessionIdentity,
    pub generation: u64,
}

pub trait EngineGenerationStore: Send + Sync + 'static {
    fn load(&self) -> Result<EngineLineage, String>;
    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCommandContext {
    pub installation_id: String,
    pub config_epoch: u64,
    pub generation: u64,
}

impl EngineCommandContext {
    pub fn new(session: &EngineSessionIdentity, generation: u64) -> Self {
        Self {
            installation_id: session.installation_id.clone(),
            config_epoch: session.config_epoch,
            generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub owner: EngineOwner,
    pub context: EngineCommandContext,
    pub config_digest: String,
    pub ready: bool,
}

/// Complete native observation used to reconcile coordinator ownership after
/// the host process restarts. Each running variant identifies the native
/// endpoint that supplied the attestation; the embedded owner must agree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeEngineStatus {
    #[default]
    Off,
    SystemProxy {
        runtime: RuntimeIdentity,
    },
    Tunnel {
        runtime: RuntimeIdentity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineState {
    Off,
    ProxyStarting {
        generation: u64,
    },
    ProxyActive {
        runtime: RuntimeIdentity,
    },
    ProxyStopping {
        generation: u64,
    },
    TunnelInstalling {
        generation: u64,
    },
    AwaitingApproval {
        generation: u64,
    },
    TunnelStarting {
        generation: u64,
    },
    TunnelActive {
        runtime: RuntimeIdentity,
    },
    TunnelStopping {
        generation: u64,
    },
    Failed {
        generation: u64,
        target: EngineMode,
        error: String,
    },
}

impl EngineState {
    pub fn active_mode(&self) -> EngineMode {
        match self {
            Self::ProxyActive { .. } => EngineMode::SystemProxy,
            Self::TunnelActive { .. } => EngineMode::Tunnel,
            _ => EngineMode::Off,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub desired_mode: EngineMode,
    pub state: EngineState,
    pub generation: u64,
    pub config_digest: Option<String>,
}

impl Default for EngineSnapshot {
    fn default() -> Self {
        Self {
            desired_mode: EngineMode::Off,
            state: EngineState::Off,
            generation: 0,
            config_digest: None,
        }
    }
}

/// Typed application event surface for engine state and fail-closed boundary
/// failures. Consumers must still validate a reported active snapshot against
/// its runtime identity, generation, digest, and readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    SnapshotChanged { snapshot: EngineSnapshot },
    BoundaryFailure { code: String, message: String },
}

impl EngineEvent {
    pub fn boundary_failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BoundaryFailure {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStartRequest {
    pub context: EngineCommandContext,
    /// Exact validated profile identity authorized to resolve every credential
    /// slot in this request. It is included in `config_digest`.
    pub credential_audience: CredentialAudience,
    pub config_json: String,
    /// SHA-256 of config_json, used to verify exact in-memory runtime bytes at
    /// every native owner boundary.
    pub config_content_digest: String,
    /// Identity digest covering configuration content and mode-specific OS
    /// network options. Runtime readiness and idempotence bind to this value.
    pub config_digest: String,
    /// Closed, secret-free instructions for the authenticated native vault.
    /// Every target points at an empty string in `config_json`; only the native
    /// boundary may replace those placeholders immediately before libbox start.
    pub credential_slots: Vec<CredentialSlot>,
    pub tunnel_options: Option<TunnelNetworkOptions>,
}

impl fmt::Debug for EngineStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineStartRequest")
            .field("context", &self.context)
            .field("credential_audience", &self.credential_audience)
            .field("config_json", &"[REDACTED CONFIG TEMPLATE]")
            .field("config_content_digest", &self.config_content_digest)
            .field("config_digest", &self.config_digest)
            .field("credential_slots", &self.credential_slots)
            .field("tunnel_options", &self.tunnel_options)
            .finish()
    }
}

/// One borrowed secret in an atomic profile-vault provisioning request.
pub struct CredentialProvision<'a> {
    reference: &'a CredentialRef,
    secret: CredentialSecret<'a>,
}

impl<'a> CredentialProvision<'a> {
    pub fn new(reference: &'a CredentialRef, secret: CredentialSecret<'a>) -> Self {
        Self { reference, secret }
    }

    pub fn reference(&self) -> &CredentialRef {
        self.reference
    }

    pub fn secret(&self) -> &CredentialSecret<'a> {
        &self.secret
    }
}

impl fmt::Debug for CredentialProvision<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialProvision")
            .field("reference", &self.reference)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Borrowed batch that must be committed by the native vault as one immutable
/// unit.
///
/// A successful return means every new entry is durable. An existing UUID is
/// admitted only when both its kind and secret bytes are exactly identical,
/// making retries idempotent. Changing either is an immutable-reference
/// conflict; credential rotation must generate a new UUID and update the
/// profile. Any error must leave the prior vault unchanged. This contract
/// prevents partial import and keeps runtime identity bound to public
/// reference IDs without deriving a digest from secret bytes.
/// The request carries the validated profile's complete unique reference set
/// plus a supplied subset. The native compare-and-swap transaction admits an
/// omitted reference only when the immutable vault already contains it with
/// the same kind; every missing reference must be supplied in this batch.
pub struct CredentialProvisionRequest<'a> {
    audience: CredentialAudience,
    required_references: Vec<CredentialRef>,
    entries: Vec<CredentialProvision<'a>>,
}

impl<'a> CredentialProvisionRequest<'a> {
    pub fn new(
        profile_id: impl Into<String>,
        profile: &ValidatedSingBoxProfile,
        entries: Vec<CredentialProvision<'a>>,
    ) -> Result<Self, CredentialProvisionRequestError> {
        let audience = CredentialAudience::new(profile_id, profile.digest())
            .map_err(|_| CredentialProvisionRequestError::InvalidAudience)?;
        if entries.len() > MAX_CREDENTIAL_SLOTS {
            return Err(CredentialProvisionRequestError::TooManyEntries);
        }
        let mut ids = BTreeSet::new();
        let required = profile
            .credential_references()
            .into_iter()
            .collect::<BTreeSet<_>>();
        for entry in &entries {
            if !ids.insert(entry.reference.id()) {
                return Err(CredentialProvisionRequestError::DuplicateReference);
            }
            if !required.contains(entry.reference) {
                return Err(CredentialProvisionRequestError::UnexpectedReference);
            }
        }
        Ok(Self {
            audience,
            required_references: required.into_iter().collect(),
            entries,
        })
    }

    pub fn profile_id(&self) -> &str {
        self.audience.profile_id()
    }

    pub fn audience(&self) -> &CredentialAudience {
        &self.audience
    }

    pub fn entries(&self) -> &[CredentialProvision<'a>] {
        &self.entries
    }

    pub fn required_references(&self) -> &[CredentialRef] {
        &self.required_references
    }
}

impl fmt::Debug for CredentialProvisionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialProvisionRequest")
            .field("audience", &self.audience)
            .field("required_references", &self.required_references)
            .field("entries", &self.entries)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialProvisionRequestError {
    #[error("credential request audience must contain a canonical profile UUID and digest")]
    InvalidAudience,
    #[error("credential provisioning request exceeds the entry limit")]
    TooManyEntries,
    #[error("credential provisioning request contains a duplicate reference")]
    DuplicateReference,
    #[error("credential provisioning request contains a reference absent from the profile")]
    UnexpectedReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialVaultReceipt {
    pub profile_id: String,
    pub profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPresence {
    pub reference: CredentialRef,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPresenceRequest {
    audience: CredentialAudience,
    references: Vec<CredentialRef>,
}

/// Maximum number of exact audience/reference bindings admitted by the native
/// credential vault. Reusing one UUID in two profiles consumes two entries.
pub const MAX_CREDENTIAL_VAULT_BINDINGS: usize = 512;
/// Mirrors the bounded profile repository catalog. Profiles without
/// credentials remain in the catalog so its digest describes the complete
/// canonical repository rather than only the currently interesting subset.
pub const MAX_CREDENTIAL_CATALOG_PROFILES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfileCatalogEntry {
    audience: CredentialAudience,
    references: Vec<CredentialRef>,
}

impl CredentialProfileCatalogEntry {
    pub fn new(
        audience: CredentialAudience,
        mut references: Vec<CredentialRef>,
    ) -> Result<Self, CredentialGarbageCollectionRequestError> {
        validate_and_sort_profile_references(&mut references)?;
        Ok(Self {
            audience,
            references,
        })
    }

    pub fn audience(&self) -> &CredentialAudience {
        &self.audience
    }

    pub fn references(&self) -> &[CredentialRef] {
        &self.references
    }

    pub fn bindings(&self) -> impl Iterator<Item = CredentialBinding> + '_ {
        self.references
            .iter()
            .cloned()
            .map(|reference| CredentialBinding::new(self.audience.clone(), reference))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGarbageCollectionRequest {
    snapshot_digest: String,
    catalog: Vec<CredentialProfileCatalogEntry>,
}

impl CredentialGarbageCollectionRequest {
    pub fn new(
        snapshot_digest: impl Into<String>,
        mut catalog: Vec<CredentialProfileCatalogEntry>,
    ) -> Result<Self, CredentialGarbageCollectionRequestError> {
        let snapshot_digest = snapshot_digest.into();
        validate_snapshot_digest(&snapshot_digest)?;
        validate_and_sort_catalog(&mut catalog)?;
        Ok(Self {
            snapshot_digest,
            catalog,
        })
    }

    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    pub fn catalog(&self) -> &[CredentialProfileCatalogEntry] {
        &self.catalog
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGarbageCollectionPreview {
    pub snapshot_digest: String,
    pub vault_revision: String,
    pub orphan_bindings: Vec<CredentialBinding>,
    pub orphan_count: u32,
}

impl CredentialGarbageCollectionPreview {
    pub fn validate(&self) -> Result<(), CredentialGarbageCollectionRequestError> {
        validate_snapshot_digest(&self.snapshot_digest)?;
        if !is_canonical_uuid(&self.vault_revision) {
            return Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision);
        }
        let mut canonical = self.orphan_bindings.clone();
        validate_and_sort_bindings(&mut canonical)?;
        if canonical != self.orphan_bindings
            || usize::try_from(self.orphan_count).ok() != Some(canonical.len())
        {
            return Err(CredentialGarbageCollectionRequestError::InvalidPreview);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGarbageCollectionCommitRequest {
    snapshot_digest: String,
    catalog: Vec<CredentialProfileCatalogEntry>,
    expected_vault_revision: String,
    expected_orphan_bindings: Vec<CredentialBinding>,
}

impl CredentialGarbageCollectionCommitRequest {
    /// Binds a commit to both the repository snapshot re-read under its
    /// cross-process lock and the exact native preview confirmation.
    pub fn new(
        repository: CredentialGarbageCollectionRequest,
        preview: &CredentialGarbageCollectionPreview,
    ) -> Result<Self, CredentialGarbageCollectionRequestError> {
        if repository.snapshot_digest != preview.snapshot_digest {
            return Err(CredentialGarbageCollectionRequestError::SnapshotChanged);
        }
        if !is_canonical_uuid(&preview.vault_revision) {
            return Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision);
        }
        let mut expected_orphan_bindings = preview.orphan_bindings.clone();
        validate_and_sort_bindings(&mut expected_orphan_bindings)?;
        if expected_orphan_bindings != preview.orphan_bindings
            || usize::try_from(preview.orphan_count).ok() != Some(expected_orphan_bindings.len())
        {
            return Err(CredentialGarbageCollectionRequestError::InvalidPreview);
        }
        Ok(Self {
            snapshot_digest: repository.snapshot_digest,
            catalog: repository.catalog,
            expected_vault_revision: preview.vault_revision.clone(),
            expected_orphan_bindings,
        })
    }

    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    pub fn catalog(&self) -> &[CredentialProfileCatalogEntry] {
        &self.catalog
    }

    pub fn expected_vault_revision(&self) -> &str {
        &self.expected_vault_revision
    }

    pub fn expected_orphan_bindings(&self) -> &[CredentialBinding] {
        &self.expected_orphan_bindings
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGarbageCollectionReceipt {
    pub vault_revision: String,
    pub deleted_count: u32,
}

impl CredentialGarbageCollectionReceipt {
    pub fn validate(&self) -> Result<(), CredentialGarbageCollectionRequestError> {
        if is_canonical_uuid(&self.vault_revision) {
            Ok(())
        } else {
            Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision)
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialGarbageCollectionRequestError {
    #[error("credential repository snapshot digest must be lowercase SHA-256")]
    InvalidSnapshotDigest,
    #[error("credential garbage-collection catalog exceeds the profile limit")]
    TooManyProfiles,
    #[error("credential garbage-collection catalog exceeds the vault binding limit")]
    TooManyBindings,
    #[error("credential garbage-collection catalog contains a duplicate profile id")]
    DuplicateProfile,
    #[error("one profile catalog entry contains a duplicate credential UUID")]
    DuplicateReference,
    #[error("credential garbage-collection binding set contains a duplicate entry")]
    DuplicateBinding,
    #[error("credential garbage-collection preview contains an invalid vault revision")]
    InvalidVaultRevision,
    #[error("credential garbage-collection preview is not canonical")]
    InvalidPreview,
    #[error("credential repository changed after garbage-collection preview")]
    SnapshotChanged,
}

fn validate_snapshot_digest(digest: &str) -> Result<(), CredentialGarbageCollectionRequestError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CredentialGarbageCollectionRequestError::InvalidSnapshotDigest)
    }
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn validate_and_sort_profile_references(
    references: &mut [CredentialRef],
) -> Result<(), CredentialGarbageCollectionRequestError> {
    if references.len() > MAX_CREDENTIAL_SLOTS {
        return Err(CredentialGarbageCollectionRequestError::TooManyBindings);
    }
    references.sort();
    let mut ids = BTreeSet::new();
    if references
        .iter()
        .any(|reference| !ids.insert(reference.id()))
    {
        return Err(CredentialGarbageCollectionRequestError::DuplicateReference);
    }
    Ok(())
}

fn validate_and_sort_catalog(
    catalog: &mut [CredentialProfileCatalogEntry],
) -> Result<(), CredentialGarbageCollectionRequestError> {
    if catalog.len() > MAX_CREDENTIAL_CATALOG_PROFILES {
        return Err(CredentialGarbageCollectionRequestError::TooManyProfiles);
    }
    catalog.sort_by(|left, right| left.audience.cmp(&right.audience));
    let mut profile_ids = BTreeSet::new();
    let mut binding_count = 0_usize;
    for entry in catalog {
        if !profile_ids.insert(entry.audience.profile_id()) {
            return Err(CredentialGarbageCollectionRequestError::DuplicateProfile);
        }
        validate_and_sort_profile_references(&mut entry.references)?;
        binding_count = binding_count
            .checked_add(entry.references.len())
            .ok_or(CredentialGarbageCollectionRequestError::TooManyBindings)?;
        if binding_count > MAX_CREDENTIAL_VAULT_BINDINGS {
            return Err(CredentialGarbageCollectionRequestError::TooManyBindings);
        }
    }
    Ok(())
}

fn validate_and_sort_bindings(
    bindings: &mut [CredentialBinding],
) -> Result<(), CredentialGarbageCollectionRequestError> {
    if bindings.len() > MAX_CREDENTIAL_VAULT_BINDINGS {
        return Err(CredentialGarbageCollectionRequestError::TooManyBindings);
    }
    bindings.sort();
    if bindings.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CredentialGarbageCollectionRequestError::DuplicateBinding);
    }
    Ok(())
}

fn validate_and_sort_references(
    references: &mut [CredentialRef],
) -> Result<(), CredentialGarbageCollectionRequestError> {
    validate_and_sort_profile_references(references)
}

impl CredentialPresenceRequest {
    pub fn new(
        profile_id: impl Into<String>,
        profile: &ValidatedSingBoxProfile,
    ) -> Result<Self, CredentialProvisionRequestError> {
        let audience = CredentialAudience::new(profile_id, profile.digest())
            .map_err(|_| CredentialProvisionRequestError::InvalidAudience)?;
        let references = profile.credential_references();
        if references.len() > MAX_CREDENTIAL_SLOTS {
            return Err(CredentialProvisionRequestError::TooManyEntries);
        }
        let mut ids = BTreeSet::new();
        for reference in &references {
            if !ids.insert(reference.id()) {
                return Err(CredentialProvisionRequestError::DuplicateReference);
            }
        }
        Ok(Self {
            audience,
            references,
        })
    }

    pub fn profile_id(&self) -> &str {
        self.audience.profile_id()
    }

    pub fn audience(&self) -> &CredentialAudience {
        &self.audience
    }

    pub fn references(&self) -> &[CredentialRef] {
        &self.references
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialVaultError {
    #[error("credential vault is unavailable")]
    Unavailable,
    #[error("credential vault access was denied")]
    AccessDenied,
    #[error("credential UUID already exists with different immutable material")]
    ImmutableConflict,
    #[error("credential vault rejected invalid material")]
    InvalidMaterial,
    #[error("credential vault data is corrupt")]
    Corrupt,
    #[error("credential vault does not exist")]
    MissingVault,
    #[error("credential vault schema requires explicit migration")]
    MigrationRequired,
    #[error("credential vault changed after maintenance preview")]
    ConcurrentModification,
    #[error("credential vault failed internally")]
    Internal,
}

pub type CredentialVaultFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CredentialVaultReceipt, CredentialVaultError>> + Send + 'a>>;
pub type CredentialPresenceFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Vec<CredentialPresence>, CredentialVaultError>> + Send + 'a>,
>;
pub type CredentialGarbageCollectionPreviewFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<CredentialGarbageCollectionPreview, CredentialVaultError>>
            + Send
            + 'a,
    >,
>;
pub type CredentialGarbageCollectionCommitFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<CredentialGarbageCollectionReceipt, CredentialVaultError>>
            + Send
            + 'a,
    >,
>;

/// Native boundary for atomically provisioning one immutable credential set.
/// There is intentionally no overwrite operation and no default or in-memory
/// production fallback.
pub trait CredentialVaultProvisioner: Send + Sync + 'static {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a>;

    fn query_profile_credentials(
        &self,
        request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_>;

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_>;

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelNetworkOptions {
    pub ipv6_enabled: bool,
    pub bypass_private_networks: bool,
    pub mtu: u16,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoverPreflightRequest {
    target: EngineMode,
    system_proxy_request: EngineStartRequest,
    tunnel_request: EngineStartRequest,
}

impl CutoverPreflightRequest {
    pub fn new(
        target: EngineMode,
        system_proxy_request: EngineStartRequest,
        tunnel_request: EngineStartRequest,
    ) -> Result<Self, CutoverPreflightRequestError> {
        if target == EngineMode::Off {
            return Err(CutoverPreflightRequestError::ActiveTargetRequired);
        }
        if system_proxy_request.tunnel_options.is_some() || tunnel_request.tunnel_options.is_none()
        {
            return Err(CutoverPreflightRequestError::ProjectionModeMismatch);
        }
        if system_proxy_request.context != tunnel_request.context
            || system_proxy_request.context.config_epoch == 0
            || system_proxy_request.context.generation == 0
        {
            return Err(CutoverPreflightRequestError::InvalidContext);
        }
        if system_proxy_request.credential_audience != tunnel_request.credential_audience {
            return Err(CutoverPreflightRequestError::CredentialAudienceMismatch);
        }
        let system_references = system_proxy_request
            .credential_slots
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<BTreeSet<_>>();
        let tunnel_references = tunnel_request
            .credential_slots
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<BTreeSet<_>>();
        if system_references != tunnel_references {
            return Err(CutoverPreflightRequestError::CredentialReferenceMismatch);
        }
        Ok(Self {
            target,
            system_proxy_request,
            tunnel_request,
        })
    }

    pub fn target(&self) -> EngineMode {
        self.target
    }

    pub fn system_proxy_request(&self) -> &EngineStartRequest {
        &self.system_proxy_request
    }

    pub fn tunnel_request(&self) -> &EngineStartRequest {
        &self.tunnel_request
    }
}

impl fmt::Debug for CutoverPreflightRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CutoverPreflightRequest")
            .field("target", &self.target)
            .field("system_proxy_request", &self.system_proxy_request)
            .field("tunnel_request", &self.tunnel_request)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CutoverPreflightRequestError {
    #[error("cutover preflight requires a non-Off target")]
    ActiveTargetRequired,
    #[error("cutover preflight projection modes do not match their slots")]
    ProjectionModeMismatch,
    #[error("cutover preflight requires a nonzero engine context")]
    InvalidContext,
    #[error("cutover preflight projections do not reference the same credentials")]
    CredentialReferenceMismatch,
    #[error("cutover preflight projections do not have the same credential audience")]
    CredentialAudienceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoverPreflightAttestation {
    pub attestation_id: String,
    pub target: EngineMode,
    pub context: EngineCommandContext,
    pub system_proxy_config_digest: String,
    pub tunnel_config_digest: String,
    pub credential_audience: CredentialAudience,
    pub credential_references: Vec<CredentialRef>,
    pub valid_for_millis: u32,
}

impl CutoverPreflightAttestation {
    pub const MAXIMUM_VALIDITY_MILLIS: u32 = 300_000;

    pub fn validate(&self) -> bool {
        is_canonical_uuid(&self.attestation_id)
            && is_canonical_uuid(&self.context.installation_id)
            && self.target != EngineMode::Off
            && self.context.config_epoch > 0
            && self.context.generation > 0
            && validate_snapshot_digest(&self.system_proxy_config_digest).is_ok()
            && validate_snapshot_digest(&self.tunnel_config_digest).is_ok()
            && self.valid_for_millis > 0
            && self.valid_for_millis <= Self::MAXIMUM_VALIDITY_MILLIS
            && {
                let mut canonical = self.credential_references.clone();
                validate_and_sort_references(&mut canonical).is_ok()
                    && canonical == self.credential_references
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CutoverPreflightOutcome {
    AwaitingApproval {
        target: EngineMode,
        context: EngineCommandContext,
        system_proxy_config_digest: String,
        tunnel_config_digest: String,
        credential_audience: CredentialAudience,
    },
    Ready {
        attestation: CutoverPreflightAttestation,
    },
}

pub type CutoverPreflightFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CutoverPreflightOutcome, BackendError>> + Send + 'a>>;

/// Read-only replacement validation used immediately before the one-way
/// legacy cutover. Implementations may request System Extension activation,
/// but must never start libbox, bind a listener, start a VPN, or mutate system
/// proxy, route, or DNS state.
pub trait CutoverPreflightBackend: Send + Sync + 'static {
    fn preflight_cutover(&self, request: CutoverPreflightRequest) -> CutoverPreflightFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelInstallOutcome {
    Ready,
    AwaitingApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendErrorKind {
    Busy,
    ResourceExhausted,
    JournalCapacityExhausted,
    PermissionDenied,
    ApprovalDenied,
    ConfigurationRejected,
    CredentialsUnavailable,
    CredentialConflict,
    CredentialVaultMissing,
    CredentialMigrationRequired,
    CredentialGcConflict,
    ProxyAgentApprovalRequired,
    GlobalAuthorityUnavailable,
    GlobalAuthorityRegistrationRequired,
    GlobalAuthorityApprovalRequired,
    GlobalAuthorityIdentityRejected,
    GlobalAuthorityProtocolMismatch,
    GlobalAuthorityRecovering,
    GlobalAuthorityTimeout,
    GlobalAuthorityInterrupted,
    GlobalLeaseConflict,
    ReplayRejected,
    StaleOperation,
    TicketExpired,
    TicketAlreadyRedeemed,
    TicketInvalid,
    CompensationConflict,
    CleanupUnproven,
    Quarantined,
    InvalidMessage,
    SecretBoundsExceeded,
    SecretLifecycleViolation,
    JournalCorrupt,
    OwnerUnresponsive,
    IdentityRejected,
    Timeout,
    Unavailable,
    #[serde(other)]
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDirective {
    Never,
    IdempotentReadOnly,
    RegistrationStatusChange,
    CompatibleSoftwareUpdate,
    FreshSnapshotAfterOff,
    FreshContext,
    FreshGenerationAfterOff,
    ExplicitReconciliation,
    MaintenanceRequired,
}

impl BackendErrorKind {
    pub const AUTHORITY_KINDS: [Self; 25] = [
        Self::GlobalAuthorityUnavailable,
        Self::GlobalAuthorityRegistrationRequired,
        Self::GlobalAuthorityApprovalRequired,
        Self::GlobalAuthorityIdentityRejected,
        Self::GlobalAuthorityProtocolMismatch,
        Self::GlobalAuthorityRecovering,
        Self::GlobalAuthorityTimeout,
        Self::GlobalAuthorityInterrupted,
        Self::Busy,
        Self::ResourceExhausted,
        Self::JournalCapacityExhausted,
        Self::GlobalLeaseConflict,
        Self::ReplayRejected,
        Self::StaleOperation,
        Self::TicketExpired,
        Self::TicketAlreadyRedeemed,
        Self::TicketInvalid,
        Self::SecretBoundsExceeded,
        Self::SecretLifecycleViolation,
        Self::CompensationConflict,
        Self::CleanupUnproven,
        Self::Quarantined,
        Self::InvalidMessage,
        Self::JournalCorrupt,
        Self::OwnerUnresponsive,
    ];

    pub const fn retry_directive(self) -> RetryDirective {
        match self {
            Self::ResourceExhausted
            | Self::OwnerUnresponsive
            | Self::GlobalAuthorityTimeout
            | Self::GlobalAuthorityInterrupted
            | Self::Timeout
            | Self::Unavailable => RetryDirective::IdempotentReadOnly,
            Self::JournalCapacityExhausted => RetryDirective::MaintenanceRequired,
            Self::CredentialMigrationRequired => RetryDirective::Never,
            Self::ProxyAgentApprovalRequired
            | Self::GlobalAuthorityUnavailable
            | Self::GlobalAuthorityRegistrationRequired
            | Self::GlobalAuthorityApprovalRequired => RetryDirective::RegistrationStatusChange,
            Self::GlobalAuthorityProtocolMismatch => RetryDirective::CompatibleSoftwareUpdate,
            Self::Busy | Self::GlobalLeaseConflict => RetryDirective::FreshSnapshotAfterOff,
            Self::ReplayRejected | Self::StaleOperation => RetryDirective::FreshContext,
            Self::TicketExpired | Self::TicketAlreadyRedeemed => {
                RetryDirective::FreshGenerationAfterOff
            }
            Self::GlobalAuthorityRecovering
            | Self::SecretLifecycleViolation
            | Self::CompensationConflict
            | Self::CleanupUnproven
            | Self::Quarantined
            | Self::JournalCorrupt => RetryDirective::ExplicitReconciliation,
            Self::PermissionDenied
            | Self::ApprovalDenied
            | Self::ConfigurationRejected
            | Self::CredentialsUnavailable
            | Self::CredentialConflict
            | Self::CredentialVaultMissing
            | Self::CredentialGcConflict
            | Self::GlobalAuthorityIdentityRejected
            | Self::TicketInvalid
            | Self::InvalidMessage
            | Self::SecretBoundsExceeded
            | Self::IdentityRejected
            | Self::Internal => RetryDirective::Never,
        }
    }

    pub const fn allows_automatic_retry(self, is_idempotent_read_only: bool) -> bool {
        is_idempotent_read_only
            && matches!(self.retry_directive(), RetryDirective::IdempotentReadOnly)
    }

    pub const fn stable_message(self) -> &'static str {
        match self {
            Self::Busy => "Global Authority mutation is busy.",
            Self::ResourceExhausted => "Global Authority read capacity is exhausted.",
            Self::JournalCapacityExhausted => {
                "The Global Authority journal reached its fixed capacity and requires maintenance."
            }
            Self::PermissionDenied => "The native operation was denied.",
            Self::ApprovalDenied => "Required operating-system approval was denied.",
            Self::ConfigurationRejected => "The native configuration was rejected.",
            Self::CredentialsUnavailable => "Required credentials are unavailable.",
            Self::CredentialConflict => "Credential material conflicts with an immutable entry.",
            Self::CredentialVaultMissing => "The credential vault is unavailable.",
            Self::CredentialMigrationRequired => {
                "The credential vault uses an unsupported schema and must be cleared and reprovisioned."
            }
            Self::CredentialGcConflict => "Credential cleanup requires a fresh preview.",
            Self::ProxyAgentApprovalRequired => {
                "ProxyAgent approval is required in System Settings."
            }
            Self::GlobalAuthorityUnavailable => "Global Authority is unavailable.",
            Self::GlobalAuthorityRegistrationRequired => {
                "Global Authority registration is required."
            }
            Self::GlobalAuthorityApprovalRequired => "Global Authority approval is required.",
            Self::GlobalAuthorityIdentityRejected => "Global Authority peer identity was rejected.",
            Self::GlobalAuthorityProtocolMismatch => "Global Authority protocol is incompatible.",
            Self::GlobalAuthorityRecovering => {
                "Global Authority is recovering; starts are disabled."
            }
            Self::GlobalAuthorityTimeout => "The Authority operation timed out.",
            Self::GlobalAuthorityInterrupted => "The Authority connection was interrupted.",
            Self::GlobalLeaseConflict => "A conflicting Global Authority lease exists.",
            Self::ReplayRejected => "Authority replay protection rejected the context.",
            Self::StaleOperation => "Authority operation context is stale.",
            Self::TicketExpired => "The Authority start ticket expired.",
            Self::TicketAlreadyRedeemed => "The Authority start ticket was already redeemed.",
            Self::TicketInvalid => "The Authority start ticket is invalid.",
            Self::CompensationConflict => "Tunnel preference compensation conflicted.",
            Self::CleanupUnproven => "Global cleanup could not be proven.",
            Self::Quarantined => "Global Authority is quarantined pending reconciliation.",
            Self::InvalidMessage => "The Authority message is invalid.",
            Self::SecretBoundsExceeded => "Authority secret material exceeds a fixed bound.",
            Self::SecretLifecycleViolation => "Authority secret lifecycle verification failed.",
            Self::JournalCorrupt => "The Authority journal is corrupt.",
            Self::OwnerUnresponsive => "The Authority engine owner is unresponsive.",
            Self::IdentityRejected => "The native peer identity was rejected.",
            Self::Timeout => "The native operation timed out.",
            Self::Unavailable => "The native operation is unavailable.",
            Self::Internal => "The native bridge failed at a stable internal boundary.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{kind:?}: {message}")]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// Native engine operations used by the application coordinator.
///
/// A successful stop is a barrier: the process has stopped libbox, released
/// its cross-process lease, and will issue no more callbacks for that runtime.
pub trait EngineBackend: Send + Sync + 'static {
    /// Queries both native owners and returns one fresh, mutually-exclusive
    /// typed observation. Implementations must reject conflicting simultaneous
    /// owners instead of selecting one, and must not return a cached Active
    /// result after the ProxyAgent, provider, libbox runtime, or readiness
    /// attestation has disappeared. A running result is valid only when its
    /// owner, command context, configuration digest, and readiness are all
    /// currently proven at the native boundary.
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus>;

    fn start_system_proxy(&self, request: EngineStartRequest)
    -> BackendFuture<'_, RuntimeIdentity>;

    fn stop_system_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome>;

    /// Cancels only the local wait for a submitted System Extension approval.
    /// It must not be implemented by stopping a tunnel runtime. The adapter
    /// remains responsible for reconciling any late OS delegate completion.
    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity>;

    fn stop_tunnel(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;
}

/// Versioned command sent over the narrow Rust/Swift host boundary.
///
/// This is the only product-level native wire command. Swift maps it onto the
/// already-versioned ProxyAgent and Packet Tunnel command envelopes; it does
/// not expose an independent product state machine.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "opcode", content = "payload", rename_all = "snake_case")]
pub enum NativeBridgeCommand {
    QueryStatus,
    StartSystemProxy {
        request: EngineStartRequest,
    },
    StopSystemProxy {
        context: EngineCommandContext,
    },
    InstallTunnel {
        context: EngineCommandContext,
    },
    CancelTunnelInstall {
        context: EngineCommandContext,
    },
    StartTunnel {
        request: EngineStartRequest,
    },
    StopTunnel {
        context: EngineCommandContext,
    },
    QueryCredentialPresence {
        request: CredentialPresenceWireRequest,
    },
    PreflightCutover {
        request: CutoverPreflightRequest,
    },
    PreviewCredentialGarbageCollection {
        request: CredentialGarbageCollectionRequest,
    },
    CommitCredentialGarbageCollection {
        request: CredentialGarbageCollectionCommitRequest,
    },
}

impl fmt::Debug for NativeBridgeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryStatus => formatter.write_str("QueryStatus"),
            Self::StartSystemProxy { request } => formatter
                .debug_struct("StartSystemProxy")
                .field("request", request)
                .finish(),
            Self::StopSystemProxy { context } => formatter
                .debug_struct("StopSystemProxy")
                .field("context", context)
                .finish(),
            Self::InstallTunnel { context } => formatter
                .debug_struct("InstallTunnel")
                .field("context", context)
                .finish(),
            Self::CancelTunnelInstall { context } => formatter
                .debug_struct("CancelTunnelInstall")
                .field("context", context)
                .finish(),
            Self::StartTunnel { request } => formatter
                .debug_struct("StartTunnel")
                .field("request", request)
                .finish(),
            Self::StopTunnel { context } => formatter
                .debug_struct("StopTunnel")
                .field("context", context)
                .finish(),
            Self::QueryCredentialPresence { request } => formatter
                .debug_struct("QueryCredentialPresence")
                .field("request", request)
                .finish(),
            Self::PreflightCutover { request } => formatter
                .debug_struct("PreflightCutover")
                .field("request", request)
                .finish(),
            Self::PreviewCredentialGarbageCollection { request } => formatter
                .debug_struct("PreviewCredentialGarbageCollection")
                .field("request", request)
                .finish(),
            Self::CommitCredentialGarbageCollection { request } => formatter
                .debug_struct("CommitCredentialGarbageCollection")
                .field("request", request)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRequestEnvelope {
    pub schema_version: u16,
    pub request_id: uuid::Uuid,
    pub command: NativeBridgeCommand,
}

impl NativeRequestEnvelope {
    pub fn new(command: NativeBridgeCommand) -> Self {
        Self {
            schema_version: ENGINE_PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4(),
            command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NativeBridgeResult {
    Status(NativeEngineStatus),
    Runtime(RuntimeIdentity),
    TunnelInstall(TunnelInstallOutcome),
    Acknowledged,
    CredentialReceipt(CredentialVaultReceipt),
    CredentialPresence(Vec<CredentialPresence>),
    CredentialGarbageCollectionPreview(CredentialGarbageCollectionPreview),
    CredentialGarbageCollectionReceipt(CredentialGarbageCollectionReceipt),
    CutoverPreflight(CutoverPreflightOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPresenceWireRequest {
    pub audience: CredentialAudience,
    pub references: Vec<CredentialRef>,
}

impl From<CredentialPresenceRequest> for CredentialPresenceWireRequest {
    fn from(request: CredentialPresenceRequest) -> Self {
        Self {
            audience: request.audience,
            references: request.references,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBridgeFailure {
    pub code: BackendErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeResponseEnvelope {
    pub schema_version: u16,
    pub request_id: Option<uuid::Uuid>,
    pub result: Option<NativeBridgeResult>,
    pub failure: Option<NativeBridgeFailure>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const CREDENTIAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    #[test]
    fn engine_start_debug_redacts_the_configuration_template() {
        let request = EngineStartRequest {
            context: EngineCommandContext {
                installation_id: PROFILE_ID.into(),
                config_epoch: 1,
                generation: 2,
            },
            credential_audience: CredentialAudience::new(PROFILE_ID, "03".repeat(32))
                .expect("audience"),
            config_json: "never-print-this-config".into(),
            config_content_digest: "01".repeat(32),
            config_digest: "02".repeat(32),
            credential_slots: Vec::new(),
            tunnel_options: None,
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("never-print-this-config"));
        assert!(debug.contains("REDACTED CONFIG TEMPLATE"));

        let mut wire = serde_json::to_value(&request).expect("request wire");
        wire.as_object_mut()
            .expect("request object")
            .remove("credential_slots");
        assert!(serde_json::from_value::<EngineStartRequest>(wire).is_err());
    }

    #[test]
    fn credential_provisioning_request_is_bounded_unique_and_redacted() {
        let reference = CredentialRef::new(CREDENTIAL_ID, CredentialKind::TrojanPassword)
            .expect("canonical reference");
        let profile = ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{CREDENTIAL_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
        ))
        .expect("typed profile");
        let secret = CredentialSecret::new("never-print-this-secret").expect("bounded secret");
        let request = CredentialProvisionRequest::new(
            PROFILE_ID,
            &profile,
            vec![CredentialProvision::new(&reference, secret)],
        )
        .expect("provision request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("never-print-this-secret"));
        assert_eq!(request.profile_id(), PROFILE_ID);

        let first = CredentialSecret::new("first").expect("first secret");
        let second = CredentialSecret::new("second").expect("second secret");
        assert!(matches!(
            CredentialProvisionRequest::new(
                PROFILE_ID,
                &profile,
                vec![
                    CredentialProvision::new(&reference, first),
                    CredentialProvision::new(&reference, second),
                ],
            ),
            Err(CredentialProvisionRequestError::DuplicateReference)
        ));

        let existing_only = CredentialProvisionRequest::new(PROFILE_ID, &profile, Vec::new())
            .expect("the vault validates omitted references atomically");
        assert_eq!(
            existing_only.required_references(),
            std::slice::from_ref(&reference)
        );
        assert!(existing_only.entries().is_empty());
        assert!(matches!(
            CredentialProvisionRequest::new(
                PROFILE_ID,
                &ValidatedSingBoxProfile::direct(),
                vec![CredentialProvision::new(
                    &reference,
                    CredentialSecret::new("unexpected").expect("bounded secret"),
                )],
            ),
            Err(CredentialProvisionRequestError::UnexpectedReference)
        ));
    }

    #[test]
    fn native_bridge_v4_contract_fixtures_decode_in_rust() {
        let query: NativeRequestEnvelope = serde_json::from_str(include_str!(
            "../../../contracts/native-bridge-v4/query-request.json"
        ))
        .expect("query fixture");
        assert_eq!(query.schema_version, ENGINE_PROTOCOL_VERSION);
        assert!(matches!(query.command, NativeBridgeCommand::QueryStatus));

        let preview: NativeRequestEnvelope = serde_json::from_str(include_str!(
            "../../../contracts/native-bridge-v4/gc-preview-request.json"
        ))
        .expect("GC preview fixture");
        let NativeBridgeCommand::PreviewCredentialGarbageCollection { request } = preview.command
        else {
            panic!("fixture command kind");
        };
        assert_eq!(request.snapshot_digest(), "ab".repeat(32));
        assert_eq!(request.catalog().len(), 1);
        assert_eq!(request.catalog()[0].references().len(), 1);

        let response: NativeResponseEnvelope = serde_json::from_str(include_str!(
            "../../../contracts/native-bridge-v4/gc-preview-response.json"
        ))
        .expect("GC preview response fixture");
        let Some(NativeBridgeResult::CredentialGarbageCollectionPreview(preview)) = response.result
        else {
            panic!("fixture response kind");
        };
        assert_eq!(preview.orphan_count, 1);
        assert_eq!(
            preview.vault_revision,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        );
    }

    #[derive(Deserialize)]
    struct AuthorityErrorContract {
        errors: Vec<AuthorityErrorFixture>,
    }

    #[derive(Deserialize)]
    struct AuthorityErrorFixture {
        code: String,
        retry: String,
        message: String,
    }

    #[test]
    fn authority_error_fixture_is_unique_complete_and_stable() {
        let contract: AuthorityErrorContract = serde_json::from_str(include_str!(
            "../../../fixtures/authority-v1/error-contract.json"
        ))
        .expect("authority error fixture");
        assert_eq!(
            contract.errors.len(),
            BackendErrorKind::AUTHORITY_KINDS.len()
        );

        let mut codes = BTreeSet::new();
        for entry in contract.errors {
            assert!(codes.insert(entry.code.clone()), "duplicate Authority code");
            let kind: BackendErrorKind = serde_json::from_str(&format!("\"{}\"", entry.code))
                .expect("known Authority wire code");
            assert!(BackendErrorKind::AUTHORITY_KINDS.contains(&kind));
            assert_eq!(
                serde_json::to_value(kind).expect("wire code"),
                serde_json::Value::String(entry.code)
            );
            assert_eq!(kind.stable_message(), entry.message);
            assert_eq!(
                serde_json::to_value(kind.retry_directive()).expect("retry directive"),
                serde_json::Value::String(entry.retry)
            );
            assert!(!kind.allows_automatic_retry(false));
            assert_eq!(
                kind.allows_automatic_retry(true),
                kind.retry_directive() == RetryDirective::IdempotentReadOnly
            );
        }
    }

    #[test]
    fn unknown_wire_error_is_internal_and_never_retryable() {
        let unknown: BackendErrorKind =
            serde_json::from_str("\"future_authority_code\"").expect("safe unknown mapping");
        assert_eq!(unknown, BackendErrorKind::Internal);
        assert_eq!(unknown.retry_directive(), RetryDirective::Never);
        assert!(!unknown.allows_automatic_retry(true));
    }

    #[test]
    fn proxy_agent_approval_has_a_typed_registration_retry_contract() {
        let kind = BackendErrorKind::ProxyAgentApprovalRequired;
        assert_eq!(
            serde_json::to_value(kind).expect("wire code"),
            serde_json::Value::String("proxy_agent_approval_required".into())
        );
        assert_eq!(
            kind.retry_directive(),
            RetryDirective::RegistrationStatusChange
        );
        assert!(!kind.allows_automatic_retry(true));
        assert_eq!(
            kind.stable_message(),
            "ProxyAgent approval is required in System Settings."
        );
    }

    #[test]
    fn native_public_query_json_contract_is_unchanged() {
        let bytes = include_bytes!("../../../contracts/native-bridge-v4/query-request.json");
        let request: NativeRequestEnvelope =
            serde_json::from_slice(bytes).expect("public query request fixture");
        assert_eq!(
            serde_json::to_value(request).expect("request value"),
            serde_json::from_slice::<serde_json::Value>(bytes).expect("fixture value")
        );
    }

    #[test]
    fn garbage_collection_commit_is_bound_to_the_exact_preview_snapshot() {
        let live = CredentialRef::new(CREDENTIAL_ID, CredentialKind::TrojanPassword)
            .expect("canonical reference");
        let audience = CredentialAudience::new(PROFILE_ID, "ef".repeat(32)).expect("audience");
        let catalog = CredentialProfileCatalogEntry::new(audience.clone(), vec![live.clone()])
            .expect("catalog entry");
        let repository = CredentialGarbageCollectionRequest::new("ab".repeat(32), vec![catalog])
            .expect("repository snapshot");
        let preview = CredentialGarbageCollectionPreview {
            snapshot_digest: "ab".repeat(32),
            vault_revision: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
            orphan_bindings: Vec::new(),
            orphan_count: 0,
        };
        let commit = CredentialGarbageCollectionCommitRequest::new(repository, &preview)
            .expect("bound commit");
        assert_eq!(commit.snapshot_digest(), preview.snapshot_digest);
        assert_eq!(commit.catalog()[0].audience(), &audience);
        assert_eq!(commit.catalog()[0].references(), &[live]);

        let changed = CredentialGarbageCollectionRequest::new("cd".repeat(32), Vec::new())
            .expect("changed repository snapshot");
        assert_eq!(
            CredentialGarbageCollectionCommitRequest::new(changed, &preview),
            Err(CredentialGarbageCollectionRequestError::SnapshotChanged)
        );
    }
}
