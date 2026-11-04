use std::fs::File;
use std::path::PathBuf;

use cfw_singbox_config::{
    ConfigError, CredentialAudience, CredentialRef, ValidatedSingBoxProfile, sha256_hex,
};
use serde::Serialize;
use uuid::Uuid;

use crate::envelope::{
    DecodedEntry, decode, encode, encode_with_timestamp, normalize_name, profile_file_name,
    profile_id_from_file_name, validate_profile_id, validate_source_url,
};
use crate::selected_replace::{self, SelectedProfileReplaceIntent};
use crate::selection::{ProfileSelection, decode as decode_selection, encode as encode_selection};
use crate::storage::RepositoryDirectory;
use crate::storage::ensure_entry_capacity;
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError, ProfileLabel,
    SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME,
};

mod locked;
mod read;
mod recovery;
mod remove;
mod select;
mod snapshot;
#[cfg(test)]
mod tests;
mod write;

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
    if let Some(source_url) = stored.source_url.as_deref() {
        validate_source_url(source_url)?;
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
