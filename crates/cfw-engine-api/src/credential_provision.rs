//! Atomic provisioning of one profile's credentials into the native vault.

use std::{collections::BTreeSet, fmt};

use cfw_singbox_config::{
    CredentialAudience, CredentialRef, CredentialSecret, ValidatedSingBoxProfile,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::MAX_CREDENTIAL_SLOTS;

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
/// profile. A confirmed failure leaves the prior vault unchanged.
/// `OutcomeUnknown` does not assert rollback: a timeout or a failed durability
/// confirmation can occur after publication. This contract
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
        mut entries: Vec<CredentialProvision<'a>>,
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
            entry
                .secret
                .validate_for_kind(entry.reference.kind())
                .map_err(|_| CredentialProvisionRequestError::InvalidSecret)?;
            if !ids.insert(entry.reference.id()) {
                return Err(CredentialProvisionRequestError::DuplicateReference);
            }
            if !required.contains(entry.reference) {
                return Err(CredentialProvisionRequestError::UnexpectedReference);
            }
        }
        entries.sort_by(|left, right| left.reference.cmp(right.reference));
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
    #[error("credential provisioning request contains material invalid for its credential kind")]
    InvalidSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialVaultReceipt {
    pub profile_id: String,
    pub profile_digest: String,
}

#[cfg(test)]
mod tests;
