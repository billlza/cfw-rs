//! Local storage for validated sing-box profiles.
//!
//! Profiles are never fetched, interpreted as scripts, or converted from legacy
//! Clash YAML. The repository accepts only [`ValidatedSingBoxProfile`] values
//! and stores them in a private application-owned directory.

mod envelope;
mod repository;
mod selected_replace;
mod selection;
mod storage;
mod storage_atomic;
#[cfg(test)]
mod storage_tests;

pub use cfw_singbox_config::ValidatedSingBoxProfile;
pub use repository::{
    ExactProfileImportOutcome, LockedCredentialProfileMutation, LockedProfileCredentialSnapshot,
    LockedSelectedProfile, ProfileCredentialCatalogEntry, ProfileCredentialSnapshot,
    ProfileImportResult, ProfileRecord, ProfileRepository, ProfileRepositorySnapshot,
    StoredProfile,
};

use cfw_singbox_config::{ConfigError, MAX_PROFILE_BYTES};
use thiserror::Error;

const PROFILE_SCHEMA_VERSION: u16 = 1;
const PROFILE_FILE_SUFFIX: &str = ".profile.json";
const SELECTION_SCHEMA_VERSION: u16 = 1;
const SELECTION_FILE_NAME: &str = "selected-profile-v1.json";
const MAX_SELECTION_BYTES: usize = 1_024;
const MAX_SELECTED_REPLACE_BYTES: usize = 1_024;
const SELECTED_REPLACE_FILE_NAME: &str = ".selected-profile-replace-v1.json";
const SELECTED_REPLACE_SCHEMA_VERSION: u16 = 1;
const MAX_PROFILE_NAME_CHARS: usize = 256;
/// Shortest string that can still be an absolute `https` URL with a host.
const MIN_SOURCE_URL_CHARS: usize = "https://a".len();
/// Subscription URLs are stored verbatim inside the bounded envelope, so they
/// are capped well below the envelope limit.
const MAX_SOURCE_URL_BYTES: usize = 2_048;
const MAX_REPOSITORY_ENTRIES: usize = 4_096;
const MAX_REPOSITORY_CREDENTIAL_REFERENCES: usize = 512;
const MAX_REPOSITORY_BYTES: u64 = 256 * 1024 * 1024;
// Both incoming profiles and their complete on-disk envelopes are bounded.
// A near-limit input can therefore be rejected after envelope construction
// rather than causing storage to exceed the documented 384 KiB ceiling.
const MAX_ENVELOPE_BYTES: usize = MAX_PROFILE_BYTES;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile repository I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("sing-box profile is invalid: {0}")]
    InvalidProfile(#[from] ConfigError),
    #[error("profile envelope JSON is invalid: {0}")]
    InvalidEnvelopeJson(#[from] serde_json::Error),
    #[error("selected-profile JSON is invalid: {0}")]
    InvalidSelectionJson(String),
    #[error(
        "profile name must contain 1 to {MAX_PROFILE_NAME_CHARS} characters and no control characters or path separators"
    )]
    InvalidName,
    #[error("profile id is not a canonical UUID: {0}")]
    InvalidProfileId(String),
    #[error(
        "subscription URL must be a bounded https URL of at most {MAX_SOURCE_URL_BYTES} bytes without whitespace"
    )]
    InvalidSourceUrl,
    #[error("profile repository path contains a NUL byte")]
    InvalidRepositoryPath,
    #[error("profile repository is not an effective-user-owned real directory")]
    UnsafeRepositoryDirectory,
    #[error("profile repository entry has an unexpected name: {0}")]
    UnexpectedEntry(String),
    #[error("profile repository exceeds the {MAX_REPOSITORY_ENTRIES}-entry limit")]
    TooManyEntries,
    #[error(
        "profile repository exceeds the {MAX_REPOSITORY_CREDENTIAL_REFERENCES}-reference credential vault capacity"
    )]
    TooManyCredentialReferences,
    #[error("stored profile has an invalid credential audience: {0}")]
    InvalidCredentialAudience(String),
    #[error(
        "profile repository would exceed the {MAX_REPOSITORY_BYTES}-byte aggregate limit: {actual} bytes"
    )]
    RepositoryTooLarge { actual: u64 },
    #[error("profile repository entry is not an effective-user-owned private regular file: {0}")]
    UnsafeProfileFile(String),
    #[error("selected-profile state is not an effective-user-owned private regular file")]
    UnsafeSelectionFile,
    #[error(
        "selected-profile replacement intent is not an effective-user-owned private regular file"
    )]
    UnsafeSelectedReplaceFile,
    #[error("stored profile exceeds the {MAX_ENVELOPE_BYTES}-byte envelope limit: {actual} bytes")]
    StoredProfileTooLarge { actual: u64 },
    #[error("selected-profile state exceeds the {MAX_SELECTION_BYTES}-byte limit: {actual} bytes")]
    SelectionTooLarge { actual: u64 },
    #[error(
        "selected-profile replacement intent exceeds the {MAX_SELECTED_REPLACE_BYTES}-byte limit: {actual} bytes"
    )]
    SelectedReplaceTooLarge { actual: u64 },
    #[error("unsupported profile envelope schema version: {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported selected-profile schema version: {0}")]
    UnsupportedSelectionSchema(u16),
    #[error("profile envelope id {stored} does not match file id {expected}")]
    IdentityMismatch { expected: String, stored: String },
    #[error("profile digest mismatch for {id}")]
    DigestMismatch { id: String },
    #[error("profile changed while an update was in progress: {id}")]
    ProfileChanged { id: String },
    #[error("profile envelope is not in canonical form: {0}")]
    NonCanonicalEnvelope(String),
    #[error("selected-profile state is not in canonical form")]
    NonCanonicalSelection,
    #[error("selected-profile replacement intent is invalid: {0}")]
    InvalidSelectedReplace(String),
    #[error("selected-profile replacement recovery conflicts with the repository state: {0}")]
    SelectedReplaceConflict(String),
    #[error(
        "selected-profile replacement failed ({operation}); deterministic recovery also failed ({recovery})"
    )]
    SelectedReplaceRecovery { operation: String, recovery: String },
    #[error("selected profile does not exist: {0}")]
    SelectedProfileMissing(String),
    #[error("no profile is selected")]
    NoSelectedProfile,
    #[error(
        "selected profile {id} changed after selection (expected digest {expected}, found {actual})"
    )]
    SelectedProfileDigestMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    #[error("selected profile must be deselected or replaced before deletion: {0}")]
    SelectedProfileDeletion(String),
    #[error("profile already exists: {0}")]
    AlreadyExists(String),
    #[error(
        "profile storage transaction failed ({operation}); temporary-file cleanup also failed ({cleanup})"
    )]
    AtomicCleanup { operation: String, cleanup: String },
    #[error(
        "repository entry {entry} was atomically renamed, but directory durability sync failed; commit state must be resnapshotted before retry: {source}"
    )]
    CommitUncertain {
        entry: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "profile directory enumeration failed ({operation}); descriptor cleanup also failed ({cleanup})"
    )]
    DirectoryEnumerationCleanup { operation: String, cleanup: String },
    #[error("system clock is before the Unix epoch: {0}")]
    InvalidSystemClock(#[from] std::time::SystemTimeError),
    #[error("legacy cleanup encountered a directory and stopped without traversing it: {0}")]
    UnexpectedManagedSubdirectory(String),
    #[error(
        "managed profile cleanup failed after removing {removed} entries; repository must be resnapshotted: {operation}"
    )]
    PartialManagedCleanup { removed: usize, operation: String },
}
