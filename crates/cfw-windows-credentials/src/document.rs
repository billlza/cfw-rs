use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use cfw_engine_api::{CredentialProfileCatalogEntry, CredentialVaultError as Error};
use cfw_singbox_config::{
    CredentialAudience, CredentialBinding, CredentialRef, CredentialSecret, MAX_CREDENTIAL_SLOTS,
    MAX_CREDENTIAL_VAULT_BINDINGS,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

// Match the GA vault's resource bounds. Ciphertext has a separate allowance
// for DPAPI metadata; plaintext is always checked again after decryption.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TOTAL_SECRET_BYTES: usize = 448 * 1024;
const SCHEMA_VERSION: u16 = 1;

#[derive(Clone)]
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    fn new(value: &str, reference: &CredentialRef) -> Result<Self, Error> {
        CredentialSecret::new(value)
            .and_then(|secret| secret.validate_for_kind(reference.kind()))
            .map_err(|_| Error::InvalidMaterial)?;
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    pub(crate) fn text(&self) -> &str {
        &self.0
    }

    fn same(&self, other: &str) -> bool {
        bool::from(self.text().as_bytes().ct_eq(other.as_bytes()))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.text())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    binding: CredentialBinding,
    secret: Secret,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    schema_version: u16,
    pub(crate) revision: Uuid,
    entries: Vec<Entry>,
}

/// Engine-only material. It is deliberately not serializable and its Debug
/// output is redacted. Drop erases every owned secret buffer.
#[derive(Debug)]
pub struct ResolvedCredentials {
    entries: Vec<(CredentialRef, Secret)>,
}

impl ResolvedCredentials {
    /// Only the native engine's credential injection boundary should consume
    /// these borrowed bytes. Never include them in UI responses or diagnostics.
    pub fn expose_to_engine(&self) -> impl Iterator<Item = (&CredentialRef, &str)> {
        self.entries
            .iter()
            .map(|(reference, secret)| (reference, secret.text()))
    }
}

impl Document {
    pub(crate) fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: Uuid::new_v4(),
            entries: Vec::new(),
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::Corrupt);
        }
        #[derive(Deserialize)]
        struct Version {
            schema_version: u16,
        }
        let version: Version = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        if version.schema_version != SCHEMA_VERSION {
            return Err(Error::MigrationRequired);
        }
        let document: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        document.validate().map_err(|_| Error::Corrupt)?;
        // This rejects duplicate fields, alternate UUID spellings, reordering,
        // trailing whitespace, and noncanonical secret encodings as one format.
        if document.encode()?.as_slice() != bytes {
            return Err(Error::Corrupt);
        }
        Ok(document)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.entries.len() > MAX_CREDENTIAL_VAULT_BINDINGS {
            return Err(Error::CapacityExceeded);
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].binding >= pair[1].binding)
        {
            return Err(Error::Corrupt);
        }
        let mut by_id: BTreeMap<&str, &Entry> = BTreeMap::new();
        let mut total = 0_usize;
        for entry in &self.entries {
            let reference = entry.binding.reference();
            CredentialSecret::new(entry.secret.text())
                .and_then(|value| value.validate_for_kind(reference.kind()))
                .map_err(|_| Error::InvalidMaterial)?;
            total = total
                .checked_add(entry.secret.text().len())
                .ok_or(Error::CapacityExceeded)?;
            if total > MAX_TOTAL_SECRET_BYTES {
                return Err(Error::CapacityExceeded);
            }
            if let Some(previous) = by_id.insert(reference.id(), entry)
                && (previous.binding.reference() != reference
                    || !previous.secret.same(entry.secret.text()))
            {
                return Err(Error::ImmutableConflict);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        // Allocate once so growing the serializer cannot leave secret-bearing
        // copies in discarded Vec allocations. Partial output is erased too.
        let mut output = BoundedOutput(Zeroizing::new(Vec::with_capacity(MAX_DOCUMENT_BYTES)));
        serde_json::to_writer(&mut output, self).map_err(|_| Error::CapacityExceeded)?;
        Ok(output.0)
    }

    pub(crate) fn provision(
        &mut self,
        audience: &CredentialAudience,
        required: &[CredentialRef],
        supplied: &[(&CredentialRef, &str)],
    ) -> Result<bool, Error> {
        validate_references(required)?;
        let required_set: BTreeSet<_> = required.iter().collect();
        let mut supplied_by_id = BTreeMap::new();
        for &(reference, secret) in supplied {
            if !required_set.contains(reference)
                || supplied_by_id
                    .insert(reference.id(), (reference, secret))
                    .is_some()
            {
                return Err(Error::InvalidMaterial);
            }
        }
        let mut changed = false;
        for reference in required {
            let binding = CredentialBinding::new(audience.clone(), reference.clone());
            match supplied_by_id.get(reference.id()) {
                Some((_, secret)) => {
                    let secret = Secret::new(secret, reference)?;
                    for existing in self
                        .entries
                        .iter()
                        .filter(|entry| entry.binding.reference().id() == reference.id())
                    {
                        if existing.binding.reference() != reference
                            || !existing.secret.same(secret.text())
                        {
                            return Err(Error::ImmutableConflict);
                        }
                    }
                    if !self.entries.iter().any(|entry| entry.binding == binding) {
                        self.entries.push(Entry { binding, secret });
                        changed = true;
                    }
                }
                None => {
                    // Another audience holding the UUID never grants this
                    // audience access without explicit material or rebind.
                    if !self.entries.iter().any(|entry| entry.binding == binding) {
                        return Err(Error::InvalidMaterial);
                    }
                }
            }
        }
        self.entries
            .sort_by(|left, right| left.binding.cmp(&right.binding));
        self.validate()?;
        Ok(changed)
    }

    pub(crate) fn presence(
        &self,
        audience: &CredentialAudience,
        references: &[CredentialRef],
    ) -> Result<Vec<cfw_engine_api::CredentialPresence>, Error> {
        validate_references(references)?;
        references
            .iter()
            .map(|reference| {
                let existing = self.entries.iter().find(|entry| {
                    entry.binding.audience() == audience
                        && entry.binding.reference().id() == reference.id()
                });
                if existing.is_some_and(|entry| entry.binding.reference() != reference) {
                    return Err(Error::InvalidMaterial);
                }
                Ok(cfw_engine_api::CredentialPresence {
                    reference: reference.clone(),
                    present: existing.is_some(),
                })
            })
            .collect()
    }

    pub(crate) fn resolve(
        &self,
        audience: &CredentialAudience,
        references: &[CredentialRef],
    ) -> Result<ResolvedCredentials, Error> {
        validate_references(references)?;
        let mut entries = Vec::with_capacity(references.len());
        for reference in references {
            let binding = CredentialBinding::new(audience.clone(), reference.clone());
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.binding == binding)
                .ok_or(Error::InvalidMaterial)?;
            entries.push((reference.clone(), entry.secret.clone()));
        }
        Ok(ResolvedCredentials { entries })
    }

    pub(crate) fn orphans(
        &self,
        catalog: &[CredentialProfileCatalogEntry],
        runtime: &[CredentialBinding],
    ) -> Result<Vec<CredentialBinding>, Error> {
        if runtime.len() > MAX_CREDENTIAL_VAULT_BINDINGS {
            return Err(Error::CapacityExceeded);
        }
        let live: BTreeSet<_> = catalog
            .iter()
            .flat_map(CredentialProfileCatalogEntry::bindings)
            .chain(runtime.iter().cloned())
            .collect();
        if live.len() > MAX_CREDENTIAL_VAULT_BINDINGS {
            return Err(Error::CapacityExceeded);
        }
        let stored: BTreeSet<_> = self.entries.iter().map(|entry| &entry.binding).collect();
        if live.iter().any(|binding| !stored.contains(binding)) {
            return Err(Error::InvalidMaterial);
        }
        Ok(self
            .entries
            .iter()
            .filter(|entry| !live.contains(&entry.binding))
            .map(|entry| entry.binding.clone())
            .collect())
    }

    pub(crate) fn remove(&mut self, orphans: &[CredentialBinding]) {
        let orphans: BTreeSet<_> = orphans.iter().collect();
        self.entries
            .retain(|entry| !orphans.contains(&entry.binding));
    }
}

fn validate_references(references: &[CredentialRef]) -> Result<(), Error> {
    if references.len() > MAX_CREDENTIAL_SLOTS {
        return Err(Error::CapacityExceeded);
    }
    if references
        .iter()
        .map(CredentialRef::id)
        .collect::<BTreeSet<_>>()
        .len()
        != references.len()
    {
        return Err(Error::InvalidMaterial);
    }
    Ok(())
}

struct BoundedOutput(Zeroizing<Vec<u8>>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DOCUMENT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "credential document exceeds its limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
