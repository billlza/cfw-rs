use std::fs::File;
use std::path::PathBuf;

use cfw_singbox_config::{CredentialAudience, CredentialRef, ValidatedSingBoxProfile, sha256_hex};
use serde::Serialize;
use uuid::Uuid;

use crate::envelope::{
    decode, encode, encode_with_timestamp, normalize_name, normalize_source_url, profile_file_name,
    profile_id_from_file_name, validate_profile_id,
};
use crate::selected_replace::{self, SelectedProfileReplaceIntent};
use crate::selection::{ProfileSelection, decode as decode_selection, encode as encode_selection};
use crate::storage::RepositoryDirectory;
use crate::storage::ensure_entry_capacity;
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError,
    SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedReplaceRecovery {
    None,
    Aborted,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedReplaceState {
    Previous,
    ReplacementProfileWithPreviousSelection,
    Replacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileImportResult {
    pub id: String,
    pub name: String,
    pub bytes: usize,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactProfileImportOutcome {
    pub profile: ProfileImportResult,
    pub created: bool,
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

/// Holds the repository's cross-process exclusive lock across a credential
/// vault prepare and the profile commit that makes that audience live.
///
/// Credential garbage collection takes the same lock before re-reading its
/// repository snapshot and committing a vault deletion. Keeping this guard
/// alive across vault provisioning closes the otherwise unsafe window where a
/// prepared audience could be collected before its profile becomes visible.
pub struct LockedCredentialProfileMutation {
    repository: ProfileRepository,
    directory: RepositoryDirectory,
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

impl LockedCredentialProfileMutation {
    /// Commits one exact-ID import and then releases the repository lock.
    pub fn commit_exact_import(
        self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        self.repository
            .import_with_id_and_source_outcome_in_directory(
                &self.directory,
                id,
                name,
                profile,
                source_url,
            )
    }

    /// Commits one compare-and-swap replacement and then releases the lock.
    pub fn commit_replace_if_unchanged(
        self,
        expected: &StoredProfile,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        validate_stored_profile(expected)?;
        self.repository.replace_with_timestamp_in_directory(
            &self.directory,
            ProfileReplacement {
                id: &expected.record.id,
                name,
                profile,
                source_url,
                created_epoch_secs: None,
                expected: Some(expected),
            },
        )
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

struct ProfileReplacement<'a> {
    id: &'a str,
    name: Option<&'a str>,
    profile: &'a ValidatedSingBoxProfile,
    source_url: Option<&'a str>,
    created_epoch_secs: Option<u64>,
    expected: Option<&'a StoredProfile>,
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
        let id = Uuid::new_v4().hyphenated().to_string();
        self.import_with_id_and_source(&id, name, profile, source_url)
    }

    /// Imports one profile under an exact caller-owned UUID.
    ///
    /// Migration credentials are bound to the profile UUID and digest, so a
    /// retry must reuse the same identity. An exact replay returns the existing
    /// record. Reusing the UUID with any different name, profile, or source URL
    /// is an explicit conflict and never overwrites the durable entry.
    pub fn import_with_id_and_source(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.import_with_id_and_source_outcome(id, name, profile, source_url)
            .map(|outcome| outcome.profile)
    }

    /// Exact-ID import with a lock-bound created/replayed disposition.
    /// Callers must use this outcome instead of a separate preflight `load`
    /// when compensating a newly created entry after a surrounding transaction.
    pub fn import_with_id_and_source_outcome(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.import_with_id_and_source_outcome_in_directory(
            &directory, id, name, profile, source_url,
        )
    }

    fn import_with_id_and_source_outcome_in_directory(
        &self,
        directory: &RepositoryDirectory,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let id = validate_profile_id(id)?;
        let name = normalize_name(name.unwrap_or("Local profile"))?;
        // Do not add new state alongside a corrupt, legacy, or interrupted
        // entry. The one-way migration API is the only path that clears those.
        let existing = self.read_all(directory)?;
        if existing.records.iter().any(|record| record.id == id) {
            let current = self.decode(id, directory.open_profile_file(id)?)?;
            if current.record.name == name
                && current.profile == *profile
                && current.source_url.as_deref() == source_url
            {
                return Ok(ExactProfileImportOutcome {
                    profile: ProfileImportResult {
                        id: id.to_owned(),
                        name,
                        bytes: profile.as_json().len(),
                        digest: profile.digest().to_string(),
                    },
                    created: false,
                });
            }
            return Err(ProfileError::AlreadyExists(id.to_owned()));
        }
        let prospective_bindings = credential_binding_count(&existing.credential_catalog)?
            .checked_add(profile.credential_references().len())
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        // A successful read proves the repository contains at most the
        // documented limit. Import must still reject the next write when it
        // is already full; otherwise the 4,097th entry would be committed and
        // only discovered by a later operation.
        ensure_entry_capacity(existing.records.len())?;
        let bytes = encode(id, &name, profile, source_url)?;
        ensure_repository_bytes(existing.stored_bytes, bytes.len())?;
        directory.write_new_atomic(&profile_file_name(id), &bytes)?;
        Ok(ExactProfileImportOutcome {
            profile: ProfileImportResult {
                id: id.to_owned(),
                name,
                bytes: profile.as_json().len(),
                digest: profile.digest().to_string(),
            },
            created: true,
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
        self.replace_with_timestamp(id, name, profile, source_url, None, None)
            .map(|(result, _stored)| result)
    }

    /// Replaces a profile only when its complete stored identity still matches
    /// the caller's pre-I/O snapshot.
    ///
    /// Subscription fetches happen outside the repository lock. This compare-
    /// and-swap boundary prevents a delayed response from overwriting a newer
    /// document, name, source URL, or credential-reference set.
    pub fn replace_if_unchanged(
        &self,
        expected: &StoredProfile,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        validate_stored_profile(expected)?;
        self.replace_with_timestamp(
            &expected.record.id,
            name,
            profile,
            source_url,
            None,
            Some(expected),
        )
    }

    /// Restores a previously loaded profile after a surrounding transaction
    /// fails. Unlike a normal replacement, rollback preserves the original
    /// timestamp as well as identity, name, profile, source URL, credentials,
    /// and selected digest.
    pub fn restore(&self, stored: &StoredProfile) -> Result<ProfileImportResult, ProfileError> {
        validate_stored_profile(stored)?;
        self.replace_with_timestamp(
            &stored.record.id,
            Some(&stored.record.name),
            &stored.profile,
            stored.source_url.as_deref(),
            Some(stored.record.created_epoch_secs),
            None,
        )
        .map(|(result, _stored)| result)
    }

    /// Restores a prior snapshot only if the transaction's replacement is
    /// still current. A failed vault operation must never roll the repository
    /// back over a newer user edit or subscription response.
    pub fn restore_if_unchanged(
        &self,
        expected_current: &StoredProfile,
        stored: &StoredProfile,
    ) -> Result<ProfileImportResult, ProfileError> {
        validate_stored_profile(expected_current)?;
        validate_stored_profile(stored)?;
        if expected_current.record.id != stored.record.id {
            return Err(ProfileError::ProfileChanged {
                id: stored.record.id.clone(),
            });
        }
        self.replace_with_timestamp(
            &stored.record.id,
            Some(&stored.record.name),
            &stored.profile,
            stored.source_url.as_deref(),
            Some(stored.record.created_epoch_secs),
            Some(expected_current),
        )
        .map(|(result, _stored)| result)
    }

    fn replace_with_timestamp(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
        created_epoch_secs: Option<u64>,
        expected: Option<&StoredProfile>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.replace_with_timestamp_in_directory(
            &directory,
            ProfileReplacement {
                id,
                name,
                profile,
                source_url,
                created_epoch_secs,
                expected,
            },
        )
    }

    fn replace_with_timestamp_in_directory(
        &self,
        directory: &RepositoryDirectory,
        replacement: ProfileReplacement<'_>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        let ProfileReplacement {
            id,
            name,
            profile,
            source_url,
            created_epoch_secs,
            expected,
        } = replacement;
        let id = validate_profile_id(id)?;
        let existing = self.read_all(directory)?;
        let file = directory.open_profile_file(id)?;
        let replaced_bytes = file.metadata()?.len();
        let current = self.decode(id, file)?;
        if expected.is_some_and(|expected| expected != &current) {
            return Err(ProfileError::ProfileChanged { id: id.to_owned() });
        }
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
        let timestamp = match created_epoch_secs {
            Some(timestamp) => timestamp,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let bytes = encode_with_timestamp(id, &name, profile, source_url, timestamp)?;
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
        let result = ProfileImportResult {
            id: id.to_owned(),
            name: name.clone(),
            bytes: profile.as_json().len(),
            digest: profile.digest().to_string(),
        };
        let stored = StoredProfile {
            record: ProfileRecord {
                id: id.to_owned(),
                name,
                bytes: profile.as_json().len(),
                digest: profile.digest().to_string(),
                created_epoch_secs: timestamp,
            },
            profile: profile.clone(),
            source_url: source_url.map(ToOwned::to_owned),
        };

        let replacement_changes_selected_digest =
            selection.is_some() && current.record.digest != stored.record.digest;
        if replacement_changes_selected_digest {
            let intent = SelectedProfileReplaceIntent::new(
                id,
                &current.record.digest,
                &stored.record.digest,
                &stored_envelope_digest(&current)?,
                &sha256_hex(&bytes),
            )?;
            let intent_bytes = intent.encode()?;
            let prospective_bytes = existing
                .stored_bytes
                .saturating_sub(replaced_bytes)
                .saturating_add(bytes.len() as u64);
            ensure_repository_bytes(prospective_bytes, intent_bytes.len())?;
            if let Err(operation) =
                directory.write_new_atomic(SELECTED_REPLACE_FILE_NAME, &intent_bytes)
            {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::None | SelectedReplaceRecovery::Aborted => {
                        Err(operation)
                    }
                    SelectedReplaceRecovery::Committed => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery:
                                "an unstarted replacement was unexpectedly reported committed"
                                    .into(),
                        })
                    }
                };
            }

            if let Err(operation) = directory.write_replace_atomic(&profile_file_name(id), &bytes) {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed => Ok((result, stored)),
                    SelectedReplaceRecovery::Aborted => Err(operation),
                    SelectedReplaceRecovery::None => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: "replacement intent disappeared before recovery".into(),
                    }),
                };
            }

            let selection = selection.expect("selected digest change has selection metadata");
            if let Err(operation) =
                directory.write_replace_atomic(SELECTION_FILE_NAME, &encode_selection(&selection)?)
            {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed => Ok((result, stored)),
                    SelectedReplaceRecovery::Aborted | SelectedReplaceRecovery::None => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery:
                                "profile replacement committed but selection did not roll forward"
                                    .into(),
                        })
                    }
                };
            }

            if let Err(operation) = self.finish_selected_replace(directory) {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed | SelectedReplaceRecovery::None => {
                        Ok((result, stored))
                    }
                    SelectedReplaceRecovery::Aborted => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery: "replacement cleanup reverted after both commits".into(),
                        })
                    }
                };
            }
        } else {
            directory.write_replace_atomic(&profile_file_name(id), &bytes)?;
        }
        Ok((result, stored))
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        build_credential_snapshot(&snapshot.credential_catalog, snapshot.selection.as_ref())
    }

    pub fn lock_credential_snapshot(
        &self,
    ) -> Result<LockedProfileCredentialSnapshot, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        let snapshot =
            build_credential_snapshot(&snapshot.credential_catalog, snapshot.selection.as_ref())?;
        Ok(LockedProfileCredentialSnapshot {
            snapshot,
            _directory: directory,
        })
    }

    /// Begins a credential-bearing profile mutation under the same
    /// cross-process lock used by credential garbage-collection commits.
    pub fn begin_credential_profile_mutation(
        &self,
    ) -> Result<LockedCredentialProfileMutation, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        Ok(LockedCredentialProfileMutation {
            repository: self.clone(),
            directory,
        })
    }

    fn recover_repository(&self, directory: &RepositoryDirectory) -> Result<(), ProfileError> {
        directory.recover_owned_temporaries()?;
        self.recover_selected_replace(directory).map(|_| ())
    }

    fn recover_selected_replace(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<SelectedReplaceRecovery, ProfileError> {
        if !directory.entry_exists(SELECTED_REPLACE_FILE_NAME)? {
            return Ok(SelectedReplaceRecovery::None);
        }
        let intent = selected_replace::decode(directory.open_selected_replace_file()?)?;
        match self.selected_replace_state(directory, &intent)? {
            SelectedReplaceState::Previous => {
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Aborted)
            }
            SelectedReplaceState::ReplacementProfileWithPreviousSelection => {
                let selection = ProfileSelection::new(
                    intent.profile_id(),
                    intent.replacement_profile_digest(),
                )?;
                directory
                    .write_replace_atomic(SELECTION_FILE_NAME, &encode_selection(&selection)?)?;
                if self.selected_replace_state(directory, &intent)?
                    != SelectedReplaceState::Replacement
                {
                    return Err(ProfileError::SelectedReplaceConflict(
                        "selection roll-forward did not produce the exact replacement state".into(),
                    ));
                }
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Committed)
            }
            SelectedReplaceState::Replacement => {
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Committed)
            }
        }
    }

    fn recover_after_selected_replace_error(
        &self,
        directory: &RepositoryDirectory,
        operation: &ProfileError,
    ) -> Result<SelectedReplaceRecovery, ProfileError> {
        directory
            .recover_owned_temporaries()
            .and_then(|_| self.recover_selected_replace(directory))
            .map_err(|recovery| ProfileError::SelectedReplaceRecovery {
                operation: operation.to_string(),
                recovery: recovery.to_string(),
            })
    }

    fn selected_replace_state(
        &self,
        directory: &RepositoryDirectory,
        intent: &SelectedProfileReplaceIntent,
    ) -> Result<SelectedReplaceState, ProfileError> {
        let current = self
            .decode(
                intent.profile_id(),
                directory
                    .open_profile_file(intent.profile_id())
                    .map_err(|error| {
                        ProfileError::SelectedReplaceConflict(format!(
                            "replacement profile is unavailable: {error}"
                        ))
                    })?,
            )
            .map_err(|error| {
                ProfileError::SelectedReplaceConflict(format!(
                    "replacement profile is unreadable: {error}"
                ))
            })?;
        let selection = decode_selection(directory.open_selection_file().map_err(|error| {
            ProfileError::SelectedReplaceConflict(format!(
                "selected-profile metadata is unavailable: {error}"
            ))
        })?)
        .map_err(|error| {
            ProfileError::SelectedReplaceConflict(format!(
                "selected-profile metadata is unreadable: {error}"
            ))
        })?;
        if selection.profile_id() != intent.profile_id() {
            return Err(ProfileError::SelectedReplaceConflict(
                "selected profile identity changed while replacement intent was pending".into(),
            ));
        }

        let current_envelope_digest = stored_envelope_digest(&current)?;
        let current_profile_digest = current.record.digest.as_str();
        let selected_profile_digest = selection.profile_digest();
        if current_envelope_digest == intent.previous_envelope_digest()
            && current_profile_digest == intent.previous_profile_digest()
            && selected_profile_digest == intent.previous_profile_digest()
        {
            Ok(SelectedReplaceState::Previous)
        } else if current_envelope_digest == intent.replacement_envelope_digest()
            && current_profile_digest == intent.replacement_profile_digest()
            && selected_profile_digest == intent.previous_profile_digest()
        {
            Ok(SelectedReplaceState::ReplacementProfileWithPreviousSelection)
        } else if current_envelope_digest == intent.replacement_envelope_digest()
            && current_profile_digest == intent.replacement_profile_digest()
            && selected_profile_digest == intent.replacement_profile_digest()
        {
            Ok(SelectedReplaceState::Replacement)
        } else {
            Err(ProfileError::SelectedReplaceConflict(
                "profile envelope and selection do not match an allowed transaction phase".into(),
            ))
        }
    }

    fn finish_selected_replace(&self, directory: &RepositoryDirectory) -> Result<(), ProfileError> {
        directory.unlink(SELECTED_REPLACE_FILE_NAME)?;
        directory.sync_committed(SELECTED_REPLACE_FILE_NAME)
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;
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
        self.recover_repository(&directory)?;

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
        self.recover_repository(&directory)?;
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

fn validate_stored_profile(stored: &StoredProfile) -> Result<(), ProfileError> {
    validate_profile_id(&stored.record.id)?;
    if stored.record.digest != stored.profile.digest()
        || stored.record.bytes != stored.profile.as_json().len()
    {
        return Err(ProfileError::DigestMismatch {
            id: stored.record.id.clone(),
        });
    }
    if normalize_name(&stored.record.name)? != stored.record.name {
        return Err(ProfileError::InvalidName);
    }
    if let Some(source_url) = stored.source_url.as_deref()
        && normalize_source_url(source_url)? != source_url
    {
        return Err(ProfileError::InvalidSourceUrl);
    }
    Ok(())
}

fn stored_envelope_digest(stored: &StoredProfile) -> Result<String, ProfileError> {
    validate_stored_profile(stored)?;
    let bytes = encode_with_timestamp(
        &stored.record.id,
        &stored.record.name,
        &stored.profile,
        stored.source_url.as_deref(),
        stored.record.created_epoch_secs,
    )?;
    Ok(sha256_hex(&bytes))
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
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use uuid::Uuid;

    use super::{
        ProfileRepository, SelectedProfileReplaceIntent, StoredProfile,
        ensure_credential_reference_capacity, ensure_repository_bytes, sha256_hex,
        stored_envelope_digest,
    };
    use crate::envelope::{encode_with_timestamp, profile_file_name};
    use crate::selection::{ProfileSelection, encode as encode_selection};
    use crate::{
        MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError,
        SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME, ValidatedSingBoxProfile,
    };

    fn repository(name: &str) -> (PathBuf, ProfileRepository) {
        let root = std::env::temp_dir().join(format!(
            "cfw-selected-replace-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let repository = ProfileRepository::new(root.join("profiles"));
        (root, repository)
    }

    fn profile(tag: &str) -> ValidatedSingBoxProfile {
        ValidatedSingBoxProfile::parse(&format!(
            r#"{{"route":{{"final":"{tag}"}},"outbounds":[{{"tag":"{tag}","type":"direct"}}]}}"#
        ))
        .expect("valid profile")
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write test repository entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private test entry mode");
    }

    fn stage_selected_replace(
        root: &Path,
        original: &StoredProfile,
        replacement: &ValidatedSingBoxProfile,
    ) -> (SelectedProfileReplaceIntent, Vec<u8>) {
        let replacement_bytes = encode_with_timestamp(
            &original.record.id,
            "Replacement",
            replacement,
            original.source_url.as_deref(),
            original.record.created_epoch_secs + 1,
        )
        .expect("replacement envelope");
        let intent = SelectedProfileReplaceIntent::new(
            &original.record.id,
            &original.record.digest,
            replacement.digest(),
            &stored_envelope_digest(original).expect("original envelope digest"),
            &sha256_hex(&replacement_bytes),
        )
        .expect("replacement intent");
        write_private(
            &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
            &intent.encode().expect("intent bytes"),
        );
        (intent, replacement_bytes)
    }

    fn selected_fixture(name: &str) -> (PathBuf, ProfileRepository, StoredProfile) {
        let (root, repository) = repository(name);
        let imported = repository
            .import(Some("Original"), &profile("direct-original"))
            .expect("import original");
        repository.select(&imported.id).expect("select original");
        let original = repository
            .load_selected()
            .expect("load selected")
            .expect("selected original");
        (root, repository, original)
    }

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

    #[test]
    fn selected_replace_recovery_aborts_an_untouched_intent_idempotently() {
        let (root, repository, original) = selected_fixture("old-old");
        stage_selected_replace(&root, &original, &profile("direct-replacement"));

        assert_eq!(
            repository
                .load_selected()
                .expect("recover untouched intent")
                .expect("selected original"),
            original
        );
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        assert_eq!(
            repository
                .load_selected()
                .expect("repeat recovered read")
                .expect("selected original"),
            original
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_recovery_rolls_selection_forward_after_profile_commit() {
        let (root, repository, original) = selected_fixture("new-old");
        let replacement = profile("direct-replacement");
        let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
        write_private(
            &root
                .join("profiles")
                .join(profile_file_name(&original.record.id)),
            &replacement_bytes,
        );

        let recovered = repository
            .load_selected()
            .expect("roll selection forward")
            .expect("selected replacement");
        assert_eq!(recovered.profile, replacement);
        assert_eq!(recovered.record.name, "Replacement");
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        assert_eq!(
            repository
                .load_selected()
                .expect("repeat recovered read")
                .expect("selected replacement"),
            recovered
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_recovery_cleans_an_already_committed_intent() {
        let (root, repository, original) = selected_fixture("new-new");
        let replacement = profile("direct-replacement");
        let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
        write_private(
            &root
                .join("profiles")
                .join(profile_file_name(&original.record.id)),
            &replacement_bytes,
        );
        let replacement_selection =
            ProfileSelection::new(&original.record.id, replacement.digest())
                .expect("replacement selection");
        write_private(
            &root.join("profiles").join(SELECTION_FILE_NAME),
            &encode_selection(&replacement_selection).expect("selection bytes"),
        );

        assert_eq!(
            repository
                .load_selected()
                .expect("clean committed intent")
                .expect("selected replacement")
                .profile,
            replacement
        );
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_recovery_never_overwrites_a_different_selection() {
        let (root, repository, original) = selected_fixture("selection-changed");
        let other = repository
            .import(Some("Other"), &profile("direct-other"))
            .expect("import other profile");
        let replacement = profile("direct-replacement");
        let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
        write_private(
            &root
                .join("profiles")
                .join(profile_file_name(&original.record.id)),
            &replacement_bytes,
        );
        let other_selection =
            ProfileSelection::new(&other.id, &other.digest).expect("other selection");
        let other_selection_bytes = encode_selection(&other_selection).expect("selection bytes");
        write_private(
            &root.join("profiles").join(SELECTION_FILE_NAME),
            &other_selection_bytes,
        );

        assert!(matches!(
            repository.snapshot(),
            Err(ProfileError::SelectedReplaceConflict(_))
        ));
        assert_eq!(
            fs::read(root.join("profiles").join(SELECTION_FILE_NAME))
                .expect("read preserved selection"),
            other_selection_bytes
        );
        assert!(
            root.join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_recovery_preserves_intent_when_required_state_is_missing() {
        let (root, repository, original) = selected_fixture("missing-selection");
        stage_selected_replace(&root, &original, &profile("direct-replacement"));
        fs::remove_file(root.join("profiles").join(SELECTION_FILE_NAME))
            .expect("remove selection for fault fixture");

        assert!(matches!(
            repository.load_selected(),
            Err(ProfileError::SelectedReplaceConflict(_))
        ));
        assert!(
            root.join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_recovery_rejects_a_missing_or_third_profile_envelope() {
        let (missing_root, missing_repository, missing_original) =
            selected_fixture("missing-profile");
        stage_selected_replace(
            &missing_root,
            &missing_original,
            &profile("direct-replacement"),
        );
        fs::remove_file(
            missing_root
                .join("profiles")
                .join(profile_file_name(&missing_original.record.id)),
        )
        .expect("remove profile for fault fixture");
        assert!(matches!(
            missing_repository.snapshot(),
            Err(ProfileError::SelectedReplaceConflict(_))
        ));
        assert!(
            missing_root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(missing_root).expect("remove missing-profile repository");

        let (third_root, third_repository, third_original) = selected_fixture("third-profile");
        stage_selected_replace(&third_root, &third_original, &profile("direct-replacement"));
        let third_bytes = encode_with_timestamp(
            &third_original.record.id,
            "Unexpected third state",
            &profile("direct-third"),
            third_original.source_url.as_deref(),
            third_original.record.created_epoch_secs + 2,
        )
        .expect("third envelope");
        write_private(
            &third_root
                .join("profiles")
                .join(profile_file_name(&third_original.record.id)),
            &third_bytes,
        );
        assert!(matches!(
            third_repository.snapshot(),
            Err(ProfileError::SelectedReplaceConflict(_))
        ));
        assert!(
            third_root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(third_root).expect("remove third-profile repository");
    }

    #[test]
    fn same_content_metadata_replace_needs_no_multi_file_intent() {
        let (root, repository, original) = selected_fixture("metadata-only");
        repository
            .replace(
                &original.record.id,
                Some("Renamed without content change"),
                &original.profile,
                Some("https://example.com/rebound"),
            )
            .expect("metadata-only selected replacement");

        let selected = repository
            .load_selected()
            .expect("load metadata replacement")
            .expect("selected profile");
        assert_eq!(selected.record.name, "Renamed without content change");
        assert_eq!(selected.record.digest, original.record.digest);
        assert_eq!(
            selected.source_url.as_deref(),
            Some("https://example.com/rebound")
        );
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn selected_replace_intent_must_be_private_canonical_and_bounded() {
        let (mode_root, mode_repository, mode_original) = selected_fixture("intent-mode");
        stage_selected_replace(&mode_root, &mode_original, &profile("direct-replacement"));
        let mode_path = mode_root.join("profiles").join(SELECTED_REPLACE_FILE_NAME);
        fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o644))
            .expect("weaken intent mode for fixture");
        assert!(matches!(
            mode_repository.snapshot(),
            Err(ProfileError::UnsafeSelectedReplaceFile)
        ));
        fs::remove_dir_all(mode_root).expect("remove mode repository");

        let (canonical_root, canonical_repository, canonical_original) =
            selected_fixture("intent-canonical");
        stage_selected_replace(
            &canonical_root,
            &canonical_original,
            &profile("direct-replacement"),
        );
        let canonical_path = canonical_root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME);
        let mut noncanonical = fs::read(&canonical_path).expect("read canonical intent");
        noncanonical.push(b'\n');
        write_private(&canonical_path, &noncanonical);
        assert!(matches!(
            canonical_repository.snapshot(),
            Err(ProfileError::InvalidSelectedReplace(_))
        ));
        fs::remove_dir_all(canonical_root).expect("remove canonical repository");

        let (size_root, size_repository, size_original) = selected_fixture("intent-size");
        stage_selected_replace(&size_root, &size_original, &profile("direct-replacement"));
        write_private(
            &size_root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
            &vec![b'x'; crate::MAX_SELECTED_REPLACE_BYTES + 1],
        );
        assert!(matches!(
            size_repository.snapshot(),
            Err(ProfileError::SelectedReplaceTooLarge { .. })
        ));
        fs::remove_dir_all(size_root).expect("remove size repository");
    }

    #[test]
    fn selected_replace_intent_symlink_is_never_followed() {
        let (root, repository, _original) = selected_fixture("intent-symlink");
        let target = root.join("outside-intent");
        write_private(&target, b"not an intent");
        symlink(
            &target,
            root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        )
        .expect("create intent symlink fixture");

        assert!(matches!(
            repository.snapshot(),
            Err(ProfileError::UnsafeSelectedReplaceFile)
        ));
        assert_eq!(
            fs::read(&target).expect("read symlink target"),
            b"not an intent"
        );
        fs::remove_dir_all(root).expect("remove symlink repository");
    }
}
