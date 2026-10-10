use std::fs::File;
use std::path::PathBuf;

use cfw_singbox_config::{
    ConfigError, CredentialAudience, CredentialRef, ValidatedSingBoxProfile, sha256_hex,
};
use serde::Serialize;
use uuid::Uuid;

use crate::envelope::{
    DecodedEntry, decode, encode, encode_with_timestamp, normalize_name, normalize_source_url,
    profile_file_name, profile_id_from_file_name, validate_profile_id,
};
use crate::selected_replace::{self, SelectedProfileReplaceIntent};
use crate::selection::{ProfileSelection, decode as decode_selection, encode as encode_selection};
use crate::storage::RepositoryDirectory;
use crate::storage::ensure_entry_capacity;
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError, ProfileLabel,
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
    pub source_kind: ProfileSourceKind,
}

/// Source information safe to include in a list without exposing a subscription URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSourceKind {
    Local,
    Subscription,
}

impl ProfileSourceKind {
    fn from_source_url(source_url: Option<&str>) -> Self {
        match source_url {
            Some(_) => Self::Subscription,
            None => Self::Local,
        }
    }
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

/// A stored profile whose envelope is intact but whose document, provider
/// sources or saved proxy selections fail current profile validation, for
/// example a node an earlier build accepted.
///
/// It carries no document, so it cannot be selected, loaded, started or used
/// in place of another profile. Deleting it is the only operation it supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvalidProfileRecord {
    pub id: String,
    pub name: String,
    pub created_epoch_secs: u64,
    pub source_kind: ProfileSourceKind,
    #[serde(serialize_with = "serialize_validation_error")]
    pub error: ConfigError,
}

impl InvalidProfileRecord {
    fn label(&self) -> ProfileLabel {
        ProfileLabel {
            id: self.id.clone(),
            name: self.name.clone(),
        }
    }

    /// The error every load, selection or start of this entry reports.
    fn load_error(&self) -> ProfileError {
        ProfileError::StoredProfileInvalid {
            id: self.id.clone(),
            name: self.name.clone(),
            source: self.error.clone(),
        }
    }
}

fn serialize_validation_error<S: serde::Serializer>(
    error: &ConfigError,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(error)
}

/// What [`ProfileRepository::delete`] may do when the selection names the
/// deleted entry and that entry fails validation. A selected valid profile is
/// never deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSelection {
    /// Refuse, keeping the entry and the selection.
    Keep,
    /// Remove the selection with the entry, leaving no profile selected. The
    /// caller must know that nothing can be running the selected profile.
    Clear,
}

/// What the selection record names, read under the repository lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSelectionState {
    Unselected,
    Valid(Box<StoredProfile>),
    /// The selected entry fails validation. Nothing can be running it, since
    /// no build that rejects its document starts it.
    Invalid(InvalidProfileRecord),
}

impl ProfileSelectionState {
    /// The prior profile of an online change (`ProfileChange::previous_profile`),
    /// which carries its proxy selections and is compared with the running
    /// runtime. An invalid selection yields none: every start loads the
    /// selected profile strictly, so no runtime can be running an entry that
    /// fails validation. Any other use needs [`Self::into_loaded`].
    pub fn into_valid(self) -> Option<StoredProfile> {
        match self {
            Self::Valid(stored) => Some(*stored),
            Self::Unselected | Self::Invalid(_) => None,
        }
    }

    /// The selected profile for an operation that uses it; an invalid
    /// selection is reported with its validation error.
    pub fn into_loaded(self) -> Result<Option<StoredProfile>, ProfileError> {
        match self {
            Self::Unselected => Ok(None),
            Self::Valid(stored) => Ok(Some(*stored)),
            Self::Invalid(record) => Err(record.load_error()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRepositorySnapshot {
    pub profiles: Vec<ProfileRecord>,
    /// Entries that fail current validation, ordered like `profiles`. The
    /// selection may name one of them; it is then reported, never loaded.
    pub invalid_profiles: Vec<InvalidProfileRecord>,
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
    /// Reads selection under the lock retained through online preparation.
    pub fn selected_profile(&self) -> Result<ProfileSelectionState, ProfileError> {
        let snapshot = self.repository.read_all(&self.directory)?;
        let Some(selection) = snapshot.selection else {
            return Ok(ProfileSelectionState::Unselected);
        };
        let file = self.directory.open_profile_file(selection.profile_id())?;
        Ok(
            match self.repository.decode_entry(selection.profile_id(), file)? {
                StoredEntry::Valid(stored) => ProfileSelectionState::Valid(stored),
                StoredEntry::Invalid(entry) => ProfileSelectionState::Invalid(entry.record),
            },
        )
    }

    pub fn profile(&self, id: &str) -> Result<StoredProfile, ProfileError> {
        let id = validate_profile_id(id)?;
        self.repository
            .decode(id, self.directory.open_profile_file(id)?)
    }

    /// Selection is committed only after a candidate runtime is ready. A failed
    /// durable write restores the prior selection before releasing the lock.
    pub fn commit_selection(self, id: &str) -> Result<ProfileRecord, ProfileError> {
        self.select_recovering(id)
    }

    pub fn commit_exact_import_and_select(
        self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
        activate: bool,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let imported = self
            .repository
            .import_with_id_and_source_outcome_in_directory(
                &self.directory,
                id,
                name,
                profile,
                source_url,
            )?;
        if activate && imported.created {
            self.select_recovering(id)?;
        }
        Ok(imported)
    }

    fn select_recovering(&self, id: &str) -> Result<ProfileRecord, ProfileError> {
        let previous = self.repository.read_all(&self.directory)?.selection;
        match self.repository.select_in_directory(&self.directory, id) {
            Ok(record) => Ok(record),
            Err(operation) => {
                let recovery = (|| {
                    if let Some(previous) = previous {
                        self.directory.write_replace_atomic(
                            SELECTION_FILE_NAME,
                            &encode_selection(&previous)?,
                        )?;
                    } else if self.directory.entry_exists(SELECTION_FILE_NAME)? {
                        self.directory.unlink(SELECTION_FILE_NAME)?;
                        self.directory.sync_committed(SELECTION_FILE_NAME)?;
                    }
                    Ok::<_, ProfileError>(())
                })();
                match recovery {
                    Ok(()) => Err(operation),
                    Err(recovery) => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: recovery.to_string(),
                    }),
                }
            }
        }
    }

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
        let selection = self.repository.read_all(&self.directory)?.selection;
        let result = self.repository.replace_with_timestamp_in_directory(
            &self.directory,
            ProfileReplacement {
                id: &expected.record.id,
                name,
                profile,
                source_url,
                created_epoch_secs: None,
                expected: Some(expected),
            },
        );
        match result {
            Ok(committed) => Ok(committed),
            Err(operation) => {
                if matches!(&operation, ProfileError::ProfileChanged { .. }) {
                    return Err(operation);
                }
                // A post-rename durability failure may have exposed the new
                // file. Under the retained lock, compensate only the exact
                // old/candidate states; never overwrite an unrelated edit.
                let recovery = (|| {
                    let current = self.profile(&expected.record.id)?;
                    if current == *expected
                        && !self.directory.entry_exists(SELECTED_REPLACE_FILE_NAME)?
                    {
                        return Ok(());
                    }
                    if current != *expected {
                        let candidate_name = name
                            .map(normalize_name)
                            .transpose()?
                            .unwrap_or_else(|| expected.record.name.clone());
                        if current.profile != *profile
                            || current.record.name != candidate_name
                            || current.source_url.as_deref() != source_url
                        {
                            return Err(ProfileError::ProfileChanged {
                                id: expected.record.id.clone(),
                            });
                        }
                        let bytes = encode_with_timestamp(
                            &expected.record.id,
                            &expected.record.name,
                            &expected.profile,
                            expected.source_url.as_deref(),
                            expected.record.created_epoch_secs,
                        )?;
                        self.directory.write_replace_atomic(
                            &profile_file_name(&expected.record.id),
                            &bytes,
                        )?;
                    }
                    if let Some(selection) =
                        selection.filter(|value| value.profile_id() == expected.record.id)
                    {
                        self.directory.write_replace_atomic(
                            SELECTION_FILE_NAME,
                            &encode_selection(&selection)?,
                        )?;
                    }
                    self.repository.recover_repository(&self.directory)?;
                    Ok::<_, ProfileError>(())
                })();
                match recovery {
                    Ok(()) => Err(operation),
                    Err(recovery) => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: recovery.to_string(),
                    }),
                }
            }
        }
    }
}

struct RepositorySnapshot {
    records: Vec<ProfileRecord>,
    invalid: Vec<InvalidEntry>,
    stored_bytes: u64,
    selection: Option<ProfileSelection>,
    credential_catalog: Vec<ProfileCredentialCatalogEntry>,
}

impl RepositorySnapshot {
    fn invalid(&self, id: &str) -> Option<&InvalidEntry> {
        find_invalid(&self.invalid, id)
    }
}

fn find_invalid<'a>(entries: &'a [InvalidEntry], id: &str) -> Option<&'a InvalidEntry> {
    entries.iter().find(|entry| entry.record.id == id)
}

struct RepositoryProfiles {
    records: Vec<ProfileRecord>,
    invalid: Vec<InvalidEntry>,
    stored_bytes: u64,
    has_selection: bool,
    credential_catalog: Vec<ProfileCredentialCatalogEntry>,
}

/// The stored digest binds a selection to an invalid entry exactly as it does
/// to a valid one; it stays private because nothing can run that document.
/// The subscription URL stays out of the listed record, as it does for valid
/// profiles.
struct InvalidEntry {
    record: InvalidProfileRecord,
    digest: String,
    envelope_digest: String,
    source_url: Option<String>,
}

enum StoredEntry {
    Valid(Box<StoredProfile>),
    Invalid(InvalidEntry),
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
        // An intact entry that fails validation does not block other imports,
        // since importing a corrected node is how it is replaced; its own id
        // stays taken, and reported as invalid, until it is deleted.
        let existing = self.read_all(directory)?;
        if let Some(entry) = existing.invalid(id) {
            return Err(entry.record.load_error());
        }
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
        // The catalog counts validated documents only; the native vault still
        // enforces its own capacity for references an invalid entry kept.
        let prospective_bindings = credential_binding_count(&existing.credential_catalog)?
            .checked_add(profile.credential_references().len())
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        // A successful read proves the repository contains at most the
        // documented limit. Import must still reject the next write when it
        // is already full; otherwise the 4,097th entry would be committed and
        // only discovered by a later operation.
        ensure_entry_capacity(existing.records.len() + existing.invalid.len())?;
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
                source_kind: ProfileSourceKind::from_source_url(source_url),
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
        record.source_kind = ProfileSourceKind::from_source_url(source_url);
        Ok(record)
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
                invalid_profiles: Vec::new(),
                selected_profile_id: None,
            });
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.read_all(&directory)
            .map(|snapshot| ProfileRepositorySnapshot {
                profiles: snapshot.records,
                invalid_profiles: snapshot
                    .invalid
                    .into_iter()
                    .map(|entry| entry.record)
                    .collect(),
                selected_profile_id: snapshot
                    .selection
                    .map(|selection| selection.profile_id().to_owned()),
            })
    }

    /// Returns one lock-consistent, secret-free identity for credential vault
    /// garbage collection. Every managed profile contributes its immutable
    /// references, including selected and newly imported unselected profiles.
    /// It is refused while any entry fails validation, whose references are
    /// unknown, until that entry is deleted.
    pub fn credential_snapshot(&self) -> Result<ProfileCredentialSnapshot, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return build_credential_snapshot(&[], None);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        repository_credential_snapshot(&self.read_all(&directory)?)
    }

    pub fn lock_credential_snapshot(
        &self,
    ) -> Result<LockedProfileCredentialSnapshot, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = repository_credential_snapshot(&self.read_all(&directory)?)?;
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

    /// Begins a credential-bearing replacement only if the profile loaded
    /// before external I/O is still the exact repository value. The exclusive
    /// lock remains held across the subsequent vault prepare and repository
    /// commit, so stale subscription responses cannot create orphan audiences.
    pub fn begin_credential_profile_mutation_if_unchanged(
        &self,
        expected: &StoredProfile,
    ) -> Result<LockedCredentialProfileMutation, ProfileError> {
        validate_stored_profile(expected)?;
        let mutation = self.begin_credential_profile_mutation()?;
        let id = validate_profile_id(&expected.record.id)?;
        let current = mutation
            .repository
            .decode(id, mutation.directory.open_profile_file(id)?)?;
        if &current != expected {
            return Err(ProfileError::ProfileChanged { id: id.to_owned() });
        }
        Ok(mutation)
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
            .decode_entry(
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

        // An interrupted replacement still resolves when this build rejects
        // either document: an invalid entry is matched by its stored digests.
        let (current_envelope_digest, current_profile_digest) = match &current {
            StoredEntry::Valid(stored) => (
                stored_envelope_digest(stored)?,
                stored.record.digest.as_str(),
            ),
            StoredEntry::Invalid(entry) => (entry.envelope_digest.clone(), entry.digest.as_str()),
        };
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
            // A selection naming an invalid entry is still bound to its stored
            // digest; it is reported as selected and refused by every load.
            let digest = profiles
                .records
                .iter()
                .find(|record| record.id == selection.profile_id())
                .map(|record| &record.digest)
                .or_else(|| {
                    find_invalid(&profiles.invalid, selection.profile_id())
                        .map(|entry| &entry.digest)
                })
                .ok_or_else(|| {
                    ProfileError::SelectedProfileMissing(selection.profile_id().to_owned())
                })?;
            if digest != selection.profile_digest() {
                return Err(ProfileError::SelectedProfileDigestMismatch {
                    id: selection.profile_id().to_owned(),
                    expected: selection.profile_digest().to_owned(),
                    actual: digest.clone(),
                });
            }
        }

        Ok(RepositorySnapshot {
            records: profiles.records,
            invalid: profiles.invalid,
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
        let mut invalid = Vec::new();
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
            let stored = match self.decode_entry(&id, file)? {
                StoredEntry::Valid(stored) => *stored,
                StoredEntry::Invalid(entry) => {
                    invalid.push(entry);
                    continue;
                }
            };
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
        records
            .sort_by(|left, right| listing_order((&left.name, &left.id), (&right.name, &right.id)));
        invalid.sort_by(|left, right| {
            listing_order(
                (&left.record.name, &left.record.id),
                (&right.record.name, &right.record.id),
            )
        });
        credential_catalog.sort_by(|left, right| left.audience.cmp(&right.audience));
        Ok(RepositoryProfiles {
            records,
            invalid,
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

    /// Subscription URL of one stored profile, including one that fails
    /// validation, so its source can be imported again before it is deleted.
    /// Like [`Self::load`] it reads a single entry; lists never carry URLs.
    pub fn source_url(&self, id: &str) -> Result<Option<String>, ProfileError> {
        let id = validate_profile_id(id)?;
        let missing = || ProfileError::ProfileNotFound(id.to_owned());
        let directory =
            RepositoryDirectory::open_if_present(&self.profiles_dir)?.ok_or_else(missing)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let file = match directory.open_profile_file(id) {
            Ok(file) => file,
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing());
            }
            Err(error) => return Err(error),
        };
        Ok(match self.decode_entry(id, file)? {
            StoredEntry::Valid(stored) => stored.source_url,
            StoredEntry::Invalid(entry) => entry.source_url,
        })
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

        self.select_in_directory(&directory, id)
    }

    fn select_in_directory(
        &self,
        directory: &RepositoryDirectory,
        id: &str,
    ) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;

        // Selecting a known-good profile is also the explicit recovery path
        // for malformed or stale selection metadata. Profile envelopes remain
        // fully validated before the replacement is committed.
        let profiles = self.read_profiles(directory)?;
        let record = match profiles.records.iter().find(|record| record.id == id) {
            Some(record) => record.clone(),
            None => {
                return Err(match find_invalid(&profiles.invalid, id) {
                    Some(entry) => entry.record.load_error(),
                    None => ProfileError::SelectedProfileMissing(id.to_owned()),
                });
            }
        };
        let selection = ProfileSelection::new(&record.id, &record.digest)?;
        let bytes = encode_selection(&selection)?;
        ensure_repository_bytes(profiles.stored_bytes, bytes.len())?;
        directory.write_replace_atomic(SELECTION_FILE_NAME, &bytes)?;
        Ok(record)
    }

    /// Deletes one unselected profile, or the selected one when it fails
    /// validation and the caller holds the engine Off. Deleting never selects
    /// another profile.
    pub fn delete(
        &self,
        id: &str,
        invalid_selection: InvalidSelection,
    ) -> Result<bool, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(false);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        let clears_selection = snapshot
            .selection
            .as_ref()
            .is_some_and(|selection| selection.profile_id() == id);
        if clears_selection {
            match (snapshot.invalid(id), invalid_selection) {
                (None, _) => return Err(ProfileError::SelectedProfileDeletion(id.to_owned())),
                (Some(entry), InvalidSelection::Keep) => {
                    return Err(ProfileError::InvalidSelectionKept(entry.record.label()));
                }
                (Some(_), InvalidSelection::Clear) => {}
            }
        }
        let file = match directory.open_profile_file(id) {
            Ok(file) => file,
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        // An entry that fails validation is deleted like a valid one; corrupt
        // or unsafe entries still fail closed before anything is unlinked.
        self.decode_entry(id, file)?;
        if clears_selection {
            // Selection first: an interrupted deletion leaves the entry listed
            // and unselected, never a selection naming a missing profile.
            directory.unlink(SELECTION_FILE_NAME)?;
            directory.sync_committed(SELECTION_FILE_NAME)?;
        }
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

    /// Loads one profile for use; an entry that fails validation is an error.
    fn decode(&self, id: &str, file: File) -> Result<StoredProfile, ProfileError> {
        match self.decode_entry(id, file)? {
            StoredEntry::Valid(stored) => Ok(*stored),
            StoredEntry::Invalid(entry) => Err(entry.record.load_error()),
        }
    }

    fn decode_entry(&self, id: &str, file: File) -> Result<StoredEntry, ProfileError> {
        Ok(match decode(id, file)? {
            DecodedEntry::Valid(decoded) => {
                let decoded = *decoded;
                StoredEntry::Valid(Box::new(StoredProfile {
                    record: ProfileRecord {
                        id: id.to_string(),
                        name: decoded.name,
                        bytes: decoded.profile.as_json().len(),
                        digest: decoded.digest,
                        created_epoch_secs: decoded.created_epoch_secs,
                        source_kind: ProfileSourceKind::from_source_url(
                            decoded.source_url.as_deref(),
                        ),
                    },
                    profile: decoded.profile,
                    source_url: decoded.source_url,
                }))
            }
            DecodedEntry::Invalid(decoded) => StoredEntry::Invalid(InvalidEntry {
                record: InvalidProfileRecord {
                    id: id.to_string(),
                    name: decoded.name,
                    created_epoch_secs: decoded.created_epoch_secs,
                    source_kind: ProfileSourceKind::from_source_url(decoded.source_url.as_deref()),
                    error: decoded.error,
                },
                digest: decoded.digest,
                envelope_digest: decoded.envelope_digest,
                source_url: decoded.source_url,
            }),
        })
    }
}

/// Profiles are listed by name, then id, whether or not they validate.
fn listing_order(left: (&str, &str), right: (&str, &str)) -> std::cmp::Ordering {
    left.0.cmp(right.0).then_with(|| left.1.cmp(right.1))
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
    if stored.record.source_kind != ProfileSourceKind::from_source_url(stored.source_url.as_deref())
    {
        return Err(ProfileError::SourceKindMismatch {
            id: stored.record.id.clone(),
        });
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

fn repository_credential_snapshot(
    snapshot: &RepositorySnapshot,
) -> Result<ProfileCredentialSnapshot, ProfileError> {
    if !snapshot.invalid.is_empty() {
        return Err(ProfileError::CredentialCleanupBlocked {
            profiles: snapshot
                .invalid
                .iter()
                .map(|entry| entry.record.label())
                .collect(),
        });
    }
    build_credential_snapshot(&snapshot.credential_catalog, snapshot.selection.as_ref())
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
        ProfileRepository, ProfileSourceKind, SelectedProfileReplaceIntent, StoredProfile,
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
    fn profile_lists_derive_source_kind_without_disclosing_subscription_urls() {
        let (root, repository) = repository("source-kind");
        let local = repository
            .import(Some("本地-示例-09.18"), &profile("local"))
            .expect("local import");
        let subscription = repository
            .import_with_source(
                Some("Subscription"),
                &profile("remote"),
                Some("https://subscription.example/profile?token=private-test-value"),
            )
            .expect("subscription import");
        repository.select(&local.id).expect("select local");
        let snapshot = repository
            .snapshot()
            .expect("list without loading profiles individually");
        let local_record = snapshot
            .profiles
            .iter()
            .find(|record| record.id == local.id)
            .expect("local record");
        let remote_record = snapshot
            .profiles
            .iter()
            .find(|record| record.id == subscription.id)
            .expect("subscription record");
        assert_eq!(local_record.source_kind, ProfileSourceKind::Local);
        assert_eq!(local_record.name, "本地-示例-09.18");
        assert_eq!(remote_record.source_kind, ProfileSourceKind::Subscription);
        assert_eq!(
            snapshot.selected_profile_id.as_deref(),
            Some(local.id.as_str())
        );
        let json = serde_json::to_string(&snapshot).expect("serialize list");
        assert!(!json.contains("subscription.example"));
        assert!(!json.contains("private-test-value"));
        assert!(!json.contains("source_url"));
        for id in [&local.id, &subscription.id] {
            let stored: serde_json::Value = serde_json::from_slice(
                &fs::read(root.join("profiles").join(profile_file_name(id)))
                    .expect("read envelope"),
            )
            .expect("parse envelope");
            assert_eq!(stored["schema_version"], 1);
            assert!(
                stored.get("source_kind").is_none(),
                "source kind is derived, not persisted"
            );
        }
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn source_kind_tracks_metadata_changes_and_rollback() {
        let (root, repository, original) = selected_fixture("source-kind-update");
        let record = repository
            .update_metadata(
                &original.record.id,
                Some("Renamed"),
                Some("https://subscription.example/profile"),
            )
            .expect("bind subscription");
        assert_eq!(record.source_kind, ProfileSourceKind::Subscription);
        assert_eq!(
            record.created_epoch_secs,
            original.record.created_epoch_secs
        );
        let rebound = repository
            .load_selected()
            .expect("load selection")
            .expect("selected");
        assert_eq!(rebound.record, record);
        assert_eq!(rebound.profile, original.profile);
        repository
            .restore(&original)
            .expect("restore local metadata");
        assert_eq!(
            repository.load_selected().expect("load restored"),
            Some(original.clone())
        );
        let mut inconsistent = original;
        inconsistent.record.source_kind = ProfileSourceKind::Subscription;
        assert!(matches!(
            repository.restore(&inconsistent),
            Err(ProfileError::SourceKindMismatch { .. })
        ));
        fs::remove_dir_all(root).expect("remove test repository");
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

    /// A selected Reality node rewritten as a build before Reality required
    /// uTLS stored it: digest and selection follow the edited document.
    /// Returns the id, the stored digest and the canonical envelope bytes.
    fn store_selected_invalid(
        root: &Path,
        repository: &ProfileRepository,
    ) -> (String, String, Vec<u8>) {
        let reality = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"http","tag":"proxy","server":"proxy.example.com","server_port":443,"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}]}"#,
        )
        .expect("Reality with uTLS");
        let imported = repository
            .import(Some("Reality node"), &reality)
            .expect("import Reality node");
        repository
            .select(&imported.id)
            .expect("select Reality node");
        let earlier =
            reality
                .as_json()
                .replacen(r#","utls":{"enabled":true,"fingerprint":"chrome"}"#, "", 1);
        let digest = sha256_hex(earlier.as_bytes());
        let profiles = root.join("profiles");
        let envelope = fs::read_to_string(profiles.join(profile_file_name(&imported.id)))
            .expect("read envelope")
            .replacen(reality.as_json(), &earlier, 1)
            .replacen(reality.digest(), &digest, 1);
        write_private(
            &profiles.join(profile_file_name(&imported.id)),
            envelope.as_bytes(),
        );
        write_private(
            &profiles.join(SELECTION_FILE_NAME),
            &encode_selection(&ProfileSelection::new(&imported.id, &digest).expect("selection"))
                .expect("selection bytes"),
        );
        (imported.id, digest, envelope.into_bytes())
    }

    #[test]
    fn selected_replace_recovery_resolves_an_entry_that_no_longer_validates() {
        // Aborted: the intent replaced the entry that is now invalid.
        let (root, aborted) = repository("invalid-intent-previous");
        let (id, digest, envelope) = store_selected_invalid(&root, &aborted);
        let replacement = profile("direct-replacement");
        let replacement_bytes =
            encode_with_timestamp(&id, "Replacement", &replacement, None, 1).expect("replacement");
        let intent = SelectedProfileReplaceIntent::new(
            &id,
            &digest,
            replacement.digest(),
            &sha256_hex(&envelope),
            &sha256_hex(&replacement_bytes),
        )
        .expect("intent");
        write_private(
            &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
            &intent.encode().expect("intent bytes"),
        );
        let snapshot = aborted.snapshot().expect("recover the untouched intent");
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        assert_eq!(snapshot.selected_profile_id.as_deref(), Some(id.as_str()));
        assert_eq!(snapshot.invalid_profiles[0].id, id);
        fs::remove_dir_all(root).expect("remove test repository");

        // Rolled forward: the replacement written before the interruption is
        // the entry that is now invalid.
        let (root, rolled) = repository("invalid-intent-replacement");
        let original = profile("direct-original");
        let (id, digest, envelope) = store_selected_invalid(&root, &rolled);
        let original_bytes =
            encode_with_timestamp(&id, "Original", &original, None, 1).expect("original");
        let intent = SelectedProfileReplaceIntent::new(
            &id,
            original.digest(),
            &digest,
            &sha256_hex(&original_bytes),
            &sha256_hex(&envelope),
        )
        .expect("intent");
        write_private(
            &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
            &intent.encode().expect("intent bytes"),
        );
        write_private(
            &root.join("profiles").join(SELECTION_FILE_NAME),
            &encode_selection(&ProfileSelection::new(&id, original.digest()).expect("selection"))
                .expect("selection bytes"),
        );
        let snapshot = rolled.snapshot().expect("roll the selection forward");
        assert!(
            !root
                .join("profiles")
                .join(SELECTED_REPLACE_FILE_NAME)
                .exists()
        );
        assert_eq!(snapshot.selected_profile_id.as_deref(), Some(id.as_str()));
        assert_eq!(snapshot.invalid_profiles[0].id, id);
        assert!(matches!(
            rolled.load_selected(),
            Err(ProfileError::StoredProfileInvalid { id: invalid, .. }) if invalid == id
        ));
        fs::remove_dir_all(root).expect("remove test repository");
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
