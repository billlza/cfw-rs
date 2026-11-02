//! Read-only preflight of the replacement runtimes before the one-way legacy cutover.

use std::{collections::BTreeSet, fmt, pin::Pin};

use cfw_singbox_config::{CredentialAudience, CredentialRef};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BackendError, EngineCommandContext, EngineMode, EngineStartMode, EngineStartRequest,
    credential_garbage_collection::{
        is_canonical_uuid, validate_and_sort_references, validate_snapshot_digest,
    },
};

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
        if !matches!(target, EngineMode::SystemProxy | EngineMode::Tunnel) {
            return Err(CutoverPreflightRequestError::ActiveTargetRequired);
        }
        if system_proxy_request.mode != EngineStartMode::SystemProxy
            || tunnel_request.mode != EngineStartMode::Tunnel
            || system_proxy_request.tunnel_options.is_some()
            || tunnel_request.tunnel_options.is_none()
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
            && matches!(self.target, EngineMode::SystemProxy | EngineMode::Tunnel)
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
