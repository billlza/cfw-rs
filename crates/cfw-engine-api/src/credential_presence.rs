//! Queries for which of a profile's credentials the native vault holds.

use std::collections::BTreeSet;

use cfw_singbox_config::{CredentialAudience, CredentialRef, ValidatedSingBoxProfile};
use serde::{Deserialize, Serialize};

use crate::{CredentialProvisionRequestError, MAX_CREDENTIAL_SLOTS};

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
