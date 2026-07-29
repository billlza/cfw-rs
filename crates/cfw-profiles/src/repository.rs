use std::fs::File;
use std::path::PathBuf;

use cfw_singbox_config::{CredentialAudience, CredentialRef, ValidatedSingBoxProfile, sha256_hex};
use serde::Serialize;
use uuid::Uuid;

use crate::envelope::{
    decode, encode, encode_with_timestamp, normalize_name, profile_file_name,
    profile_id_from_file_name, validate_profile_id,
};
use crate::selection::{ProfileSelection, decode as decode_selection, encode as encode_selection};
use crate::storage::RepositoryDirectory;
use crate::storage::ensure_entry_capacity;
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError, SELECTION_FILE_NAME,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileImportResult {
    pub id: String,
    pub name: String,
    pub bytes: usize,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRecord {
    pub id: String,
    pub name: String,
    pub bytes: usize,
    pub digest: String,
    pub created_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProfile {
    pub record: ProfileRecord,
    pub profile: ValidatedSingBoxProfile,
    /// Subscription URL this profile was fetched from, when it has one.
    ///
    /// It is deliberately absent from [`ProfileRecord`], so listing profiles
    /// cannot publish a token-bearing URL: only an explicit single-profile load
    /// can reach it.
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRepositorySnapshot {
    pub profiles: Vec<ProfileRecord>,
    pub selected_profile_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileCredentialSnapshot {
    pub snapshot_digest: String,
    pub catalog: Vec<ProfileCredentialCatalogEntry>,
    pub selected_profile_id: Option<String>,
    pub profile_count: usize,
}

/// One complete, secret-free repository profile identity for native credential
/// garbage collection. Entries with no references are retained so the
/// snapshot digest still covers the full profile catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileCredentialCatalogEntry {
    pub audience: CredentialAudience,
    pub references: Vec<CredentialRef>,
}

/// Holds the repository's cross-process exclusive lock for a credential GC
/// commit. The native vault transaction must finish before this value drops,
/// otherwise a newly imported profile could race the live-reference check.
pub struct LockedProfileCredentialSnapshot {
    snapshot: ProfileCredentialSnapshot,
    _directory: RepositoryDirectory,
}

/// Selected profile plus the repository's cross-process exclusive lock. This
/// guard closes the gap between destructive legacy retirement validation and
/// starting the exact profile that was validated.
pub struct LockedSelectedProfile {
    stored: StoredProfile,
    _directory: RepositoryDirectory,
}

impl LockedSelectedProfile {
    pub fn stored(&self) -> &StoredProfile {
        &self.stored
    }
}

impl LockedProfileCredentialSnapshot {
    pub fn snapshot(&self) -> &ProfileCredentialSnapshot {
        &self.snapshot
    }
}

struct RepositorySnapshot {
    records: Vec<ProfileRecord>,
    stored_bytes: u64,
    selection: Option<ProfileSelection>,
    credential_catalog: Vec<ProfileCredentialCatalogEntry>,
}

struct RepositoryProfiles {
    records: Vec<ProfileRecord>,
    stored_bytes: u64,
    has_selection: bool,
    credential_catalog: Vec<ProfileCredentialCatalogEntry>,
}

#[derive(Serialize)]
struct CredentialSnapshotIdentity<'a> {
    schema_version: u16,
    catalog: &'a [ProfileCredentialCatalogEntry],
    selected_profile_id: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ProfileRepository {
    profiles_dir: PathBuf,
}

impl ProfileRepository {
    pub fn new(profiles_dir: impl Into<PathBuf>) -> Self {
        Self {
            profiles_dir: profiles_dir.into(),
        }
    }

    pub fn import(
        &self,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.import_with_source(name, profile, None)
    }

    /// Imports a profile together with the subscription URL it came from.
    ///
    /// The URL is stored as opaque bounded text. This crate never fetches it;
    /// refreshing a subscription is the caller's transport decision.
    pub fn import_with_source(
        &self,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        // Do not add new state alongside a corrupt, legacy, or interrupted
        // entry. The one-way migration API is the only path that clears those.
        let existing = self.read_all(&directory)?;
        let prospective_bindings = credential_binding_count(&existing.credential_catalog)?
            .checked_add(profile.credential_references().len())
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        // A successful read proves the repository contains at most the
        // documented limit. Import must still reject the next write when it
        // is already full; otherwise the 4,097th entry would be committed and
        // only discovered by a later operation.
        ensure_entry_capacity(existing.records.len())?;
        let id = Uuid::new_v4().hyphenated().to_string();
        let name = normalize_name(name.unwrap_or("Local profile"))?;
        let bytes = encode(&id, &name, profile, source_url)?;
        ensure_repository_bytes(existing.stored_bytes, bytes.len())?;
        directory.write_new_atomic(&profile_file_name(&id), &bytes)?;
        Ok(ProfileImportResult {
            id,
            name,
            bytes: profile.as_json().len(),
            digest: profile.digest().to_string(),
        })
    }

    /// Replaces the document of an existing profile in place.
    ///
    /// The identity stays stable so an edited or re-fetched subscription keeps
    /// its credentials and its selection. When the replaced profile is the
    /// selected one, its selection metadata is rebound to the new digest under
    /// the same exclusive lock, so no reader can observe the digest mismatch
    /// that a bare profile rewrite would create.
    pub fn replace(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        let id = validate_profile_id(id)?;
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let existing = self.read_all(&directory)?;
        let file = directory.open_profile_file(id)?;
        let replaced_bytes = file.metadata()?.len();
        let current = self.decode(id, file)?;
        let existing_bindings = credential_binding_count(&existing.credential_catalog)?;
        let prospective_bindings = existing_bindings
            .checked_sub(current.profile.credential_references().len())
            .and_then(|count| count.checked_add(profile.credential_references().len()))
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        let name = match name {
            Some(name) => normalize_name(name)?,
            None => current.record.name.clone(),
        };
        let bytes = encode(id, &name, profile, source_url)?;
        ensure_repository_bytes(
            existing.stored_bytes.saturating_sub(replaced_bytes),
            bytes.len(),
        )?;
        let selection = existing
            .selection
            .as_ref()
            .filter(|selection| selection.profile_id() == id)
            .map(|_| ProfileSelection::new(id, profile.digest()))
            .transpose()?;
        directory.write_replace_atomic(&profile_file_name(id), &bytes)?;
        if let Some(selection) = selection {
            directory.write_replace_atomic(SELECTION_FILE_NAME, &encode_selection(&selection)?)?;
        }
        Ok(ProfileImportResult {
            id: id.to_owned(),
            name,
            bytes: profile.as_json().len(),
            digest: profile.digest().to_string(),
        })
    }

    /// Renames a profile and/or rebinds its subscription URL without touching
    /// the validated document, so neither the digest nor the selection changes.
    pub fn update_metadata(
        &self,
        id: &str,
        name: Option<&str>,
        source_url: Option<&str>,
    ) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let existing = self.read_all(&directory)?;
        let file = directory.open_profile_file(id)?;
        let replaced_bytes = file.metadata()?.len();
        let current = self.decode(id, file)?;
        let name = match name {
            Some(name) => normalize_name(name)?,
            None => current.record.name.clone(),
        };
        // The document and its creation time are preserved: renaming or
        // rebinding a subscription URL is not an update of the profile itself.
        let bytes = encode_with_timestamp(
            id,
            &name,
            &current.profile,
            source_url,
            current.record.created_epoch_secs,
        )?;
        ensure_repository_bytes(
            existing.stored_bytes.saturating_sub(replaced_bytes),
            bytes.len(),
        )?;
        directory.write_replace_atomic(&profile_file_name(id), &bytes)?;
        let mut record = current.record;
        record.name = name;
        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<ProfileRecord>, ProfileError> {
        self.snapshot().map(|snapshot| snapshot.profiles)
    }

    /// Repository entry name of an existing profile.
    ///
    /// This is the only path from a profile id to a filesystem name. It returns
    /// the bare entry name, never a full path, so a caller can reveal or open
    /// the stored envelope without being able to construct a name the repository
    /// would not accept.
    pub fn profile_entry_name(&self, id: &str) -> Result<Option<String>, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        let file_name = profile_file_name(id);
        if directory.entry_exists(&file_name)? {
            Ok(Some(file_name))
        } else {
            Ok(None)
        }
    }

    pub fn snapshot(&self) -> Result<ProfileRepositorySnapshot, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(ProfileRepositorySnapshot {
                profiles: Vec::new(),
                selected_profile_id: None,
            });
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        self.read_all(&directory)
            .map(|snapshot| ProfileRepositorySnapshot {
                profiles: snapshot.records,
                selected_profile_id: snapshot
                    .selection
                    .map(|selection| selection.profile_id().to_owned()),
            })
    }

    /// Returns one lock-consistent, secret-free identity for credential vault
    /// garbage collection. Every managed profile contributes its immutable
    /// references, including selected and newly imported unselected profiles.
    pub fn credential_snapshot(&self) -> Result<ProfileCredentialSnapshot, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return build_credential_snapshot(&[], None);
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let snapshot = self.read_all(&directory)?;
        build_credential_snapshot(&snapshot.credential_catalog, snapshot.selection.as_ref())
    }

    pub fn lock_credential_snapshot(
        &self,
    ) -> Result<LockedProfileCredentialSnapshot, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let snapshot = self.read_all(&directory)?;
        let snapshot =
            build_credential_snapshot(&snapshot.credential_catalog, snapshot.selection.as_ref())?;
        Ok(LockedProfileCredentialSnapshot {
            snapshot,
            _directory: directory,
        })
    }

    fn read_all(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<RepositorySnapshot, ProfileError> {
        let profiles = self.read_profiles(directory)?;
        let mut stored_bytes = profiles.stored_bytes;
        let selection = if profiles.has_selection {
            let file = directory.open_selection_file()?;
            stored_bytes = stored_bytes
                .checked_add(file.metadata()?.len())
                .ok_or(ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
            if stored_bytes > MAX_REPOSITORY_BYTES {
                return Err(ProfileError::RepositoryTooLarge {
                    actual: stored_bytes,
                });
            }
            Some(decode_selection(file)?)
        } else {
            None
        };

        if let Some(selection) = &selection {
            let record = profiles
                .records
                .iter()
                .find(|record| record.id == selection.profile_id())
                .ok_or_else(|| {
                    ProfileError::SelectedProfileMissing(selection.profile_id().to_owned())
                })?;
            if record.digest != selection.profile_digest() {
                return Err(ProfileError::SelectedProfileDigestMismatch {
                    id: selection.profile_id().to_owned(),
                    expected: selection.profile_digest().to_owned(),
                    actual: record.digest.clone(),
                });
            }
        }

        Ok(RepositorySnapshot {
            records: profiles.records,
            stored_bytes,
            selection,
            credential_catalog: profiles.credential_catalog,
        })
    }

    fn read_profiles(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<RepositoryProfiles, ProfileError> {
        let mut ids = Vec::new();
        let mut has_selection = false;
        for file_name in directory.entry_names()? {
            let file_name = file_name
                .to_str()
                .ok_or_else(|| ProfileError::UnexpectedEntry("non-UTF-8 filename".into()))?;
            if file_name == SELECTION_FILE_NAME {
                has_selection = true;
            } else {
                ids.push(profile_id_from_file_name(file_name)?.to_string());
            }
        }
        ids.sort_unstable();

        let mut records = Vec::with_capacity(ids.len());
        let mut credential_catalog = Vec::with_capacity(ids.len());
        let mut credential_binding_count = 0_usize;
        let mut stored_bytes = 0_u64;
        for id in ids {
            let file = directory.open_profile_file(&id)?;
            let file_length = file.metadata()?.len();
            stored_bytes = stored_bytes
                .checked_add(file_length)
                .ok_or(ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
            if stored_bytes > MAX_REPOSITORY_BYTES {
                return Err(ProfileError::RepositoryTooLarge {
                    actual: stored_bytes,
                });
            }
            let stored = self.decode(&id, file)?;
            let mut references = stored.profile.credential_references();
            references.sort();
            credential_binding_count = credential_binding_count
                .checked_add(references.len())
                .ok_or(ProfileError::TooManyCredentialReferences)?;
            ensure_credential_reference_capacity(credential_binding_count)?;
            let audience = CredentialAudience::new(&stored.record.id, &stored.record.digest)
                .map_err(|_| ProfileError::InvalidCredentialAudience(stored.record.id.clone()))?;
            credential_catalog.push(ProfileCredentialCatalogEntry {
                audience,
                references,
            });
            records.push(stored.record);
        }
        records.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        credential_catalog.sort_by(|left, right| left.audience.cmp(&right.audience));
        Ok(RepositoryProfiles {
            records,
            stored_bytes,
            has_selection,
            credential_catalog,
        })
    }

    pub fn load(&self, id: &str) -> Result<Option<StoredProfile>, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        match directory.open_profile_file(id) {
            Ok(file) => self.decode(id, file).map(Some),
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub fn load_selected(&self) -> Result<Option<StoredProfile>, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let snapshot = self.read_all(&directory)?;
        let Some(selection) = snapshot.selection else {
            return Ok(None);
        };
        let file = directory.open_profile_file(selection.profile_id())?;
        self.decode(selection.profile_id(), file).map(Some)
    }

    pub fn require_selected(&self) -> Result<StoredProfile, ProfileError> {
        self.load_selected()?.ok_or(ProfileError::NoSelectedProfile)
    }

    pub fn lock_selected(&self) -> Result<LockedSelectedProfile, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let snapshot = self.read_all(&directory)?;
        let selection = snapshot.selection.ok_or(ProfileError::NoSelectedProfile)?;
        let file = directory.open_profile_file(selection.profile_id())?;
        let stored = self.decode(selection.profile_id(), file)?;
        Ok(LockedSelectedProfile {
            stored,
            _directory: directory,
        })
    }

    pub fn select(&self, id: &str) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Err(ProfileError::SelectedProfileMissing(id.to_owned()));
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;

        // Selecting a known-good profile is also the explicit recovery path
        // for malformed or stale selection metadata. Profile envelopes remain
        // fully validated before the replacement is committed.
        let profiles = self.read_profiles(&directory)?;
        let record = profiles
            .records
            .iter()
            .find(|record| record.id == id)
            .cloned()
            .ok_or_else(|| ProfileError::SelectedProfileMissing(id.to_owned()))?;
        let selection = ProfileSelection::new(&record.id, &record.digest)?;
        let bytes = encode_selection(&selection)?;
        ensure_repository_bytes(profiles.stored_bytes, bytes.len())?;
        directory.write_replace_atomic(SELECTION_FILE_NAME, &bytes)?;
        Ok(record)
    }

    pub fn delete(&self, id: &str) -> Result<bool, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(false);
        };
        directory.lock_exclusive()?;
        directory.recover_owned_temporaries()?;
        let snapshot = self.read_all(&directory)?;
        if snapshot
            .selection
            .as_ref()
            .is_some_and(|selection| selection.profile_id() == id)
        {
            return Err(ProfileError::SelectedProfileDeletion(id.to_owned()));
        }
        let file = match directory.open_profile_file(id) {
            Ok(file) => file,
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        self.decode(id, file)?;
        directory.unlink(&profile_file_name(id))?;
        directory.sync_committed(&profile_file_name(id))?;
        Ok(true)
    }

    /// Permanently removes the contents of the application-managed profiles
    /// directory without reading, converting, backing up, or following them.
    ///
    /// This one-way migration API intentionally refuses to traverse real
    /// subdirectories. Symlinks are unlinked as directory entries, so their
    /// external targets are never touched.
    pub fn clear_managed_profiles(&self) -> Result<usize, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(0);
        };
        directory.lock_exclusive()?;
        let entries = directory.entry_names()?;
        for name in &entries {
            if directory.entry_is_directory(name)? {
                return Err(ProfileError::UnexpectedManagedSubdirectory(
                    name.to_string_lossy().into_owned(),
                ));
            }
        }
        let mut removed = 0;
        for name in &entries {
            if let Err(error) = directory.unlink_os(name) {
                if removed == 0 {
                    return Err(error);
                }
                return Err(ProfileError::PartialManagedCleanup {
                    removed,
                    operation: error.to_string(),
                });
            }
            removed += 1;
        }
        if removed > 0 {
            directory.sync_committed("managed profile cleanup")?;
        }
        Ok(entries.len())
    }

    fn decode(&self, id: &str, file: File) -> Result<StoredProfile, ProfileError> {
        let decoded = decode(id, file)?;
        Ok(StoredProfile {
            source_url: decoded.source_url,
            record: ProfileRecord {
                id: id.to_string(),
                name: decoded.name,
                bytes: decoded.profile.as_json().len(),
                digest: decoded.digest,
                created_epoch_secs: decoded.created_epoch_secs,
            },
            profile: decoded.profile,
        })
    }
}

fn build_credential_snapshot(
    catalog: &[ProfileCredentialCatalogEntry],
    selection: Option<&ProfileSelection>,
) -> Result<ProfileCredentialSnapshot, ProfileError> {
    let selected_profile_id = selection.map(ProfileSelection::profile_id);
    let identity = CredentialSnapshotIdentity {
        schema_version: 2,
        catalog,
        selected_profile_id,
    };
    let bytes = serde_json::to_vec(&identity)?;
    Ok(ProfileCredentialSnapshot {
        snapshot_digest: sha256_hex(&bytes),
        catalog: catalog.to_vec(),
        selected_profile_id: selected_profile_id.map(ToOwned::to_owned),
        profile_count: catalog.len(),
    })
}

fn credential_binding_count(
    catalog: &[ProfileCredentialCatalogEntry],
) -> Result<usize, ProfileError> {
    catalog.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(entry.references.len())
            .ok_or(ProfileError::TooManyCredentialReferences)
    })
}

fn ensure_repository_bytes(current: u64, additional: usize) -> Result<(), ProfileError> {
    let additional = u64::try_from(additional)
        .map_err(|_| ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
    let actual = current
        .checked_add(additional)
        .ok_or(ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
    if actual > MAX_REPOSITORY_BYTES {
        Err(ProfileError::RepositoryTooLarge { actual })
    } else {
        Ok(())
    }
}

fn ensure_credential_reference_capacity(actual: usize) -> Result<(), ProfileError> {
    if actual > MAX_REPOSITORY_CREDENTIAL_REFERENCES {
        Err(ProfileError::TooManyCredentialReferences)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_credential_reference_capacity, ensure_repository_bytes};
    use crate::{MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError};

    #[test]
    fn aggregate_repository_limit_is_checked_before_a_new_write() {
        ensure_repository_bytes(MAX_REPOSITORY_BYTES - 1, 1).expect("exact limit is admitted");
        assert!(matches!(
            ensure_repository_bytes(MAX_REPOSITORY_BYTES, 1),
            Err(ProfileError::RepositoryTooLarge { actual })
                if actual == MAX_REPOSITORY_BYTES + 1
        ));
        assert!(matches!(
            ensure_repository_bytes(u64::MAX, 1),
            Err(ProfileError::RepositoryTooLarge { actual: u64::MAX })
        ));
    }

    #[test]
    fn aggregate_credential_refs_cannot_exceed_the_native_vault_capacity() {
        ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES)
            .expect("exact vault capacity is admitted");
        assert!(matches!(
            ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES + 1),
            Err(ProfileError::TooManyCredentialReferences)
        ));
    }
}
