//! Previewed, snapshot-bound removal of vault bindings no profile references.

use std::collections::BTreeSet;

use cfw_singbox_config::{
    CredentialAudience, CredentialBinding, CredentialRef, MAX_CREDENTIAL_VAULT_BINDINGS,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::MAX_CREDENTIAL_SLOTS;

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

pub(crate) fn validate_snapshot_digest(
    digest: &str,
) -> Result<(), CredentialGarbageCollectionRequestError> {
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

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
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

pub(crate) fn validate_and_sort_references(
    references: &mut [CredentialRef],
) -> Result<(), CredentialGarbageCollectionRequestError> {
    validate_and_sort_profile_references(references)
}

#[cfg(test)]
mod tests;
