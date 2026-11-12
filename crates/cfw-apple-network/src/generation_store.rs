mod cache;
#[cfg(test)]
mod failpoint;
mod keychain;

#[cfg(test)]
mod tests;

use std::fmt::Write as _;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cfw_engine_api::{EngineGenerationStore, EngineLineage, EngineSessionIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use keychain::MacOsKeychainAuthority;

const SCHEMA_VERSION: u16 = 1;
const MAX_LINEAGE_BYTES: u64 = 4_096;

#[derive(Debug, Error)]
pub enum GenerationStoreError {
    #[error("engine lineage root has an unsafe filesystem type or owner: {0}")]
    UnsafeRoot(PathBuf),
    #[error("engine lineage cache has an unsafe filesystem type or owner: {0}")]
    UnsafeFile(PathBuf),
    #[error("engine lineage document exceeds {MAX_LINEAGE_BYTES} bytes: {0}")]
    DocumentTooLarge(u64),
    #[error("engine lineage JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("engine lineage Keychain document is not canonical JSON")]
    NonCanonicalDocument,
    #[error("engine lineage schema version is unsupported: {0}")]
    UnsupportedSchema(u16),
    #[error("engine lineage installation identifier is invalid: {0}")]
    InvalidInstallationId(String),
    #[error("engine lineage epoch must be nonzero")]
    InvalidEpoch,
    #[error("engine lineage authority revision does not match its canonical document")]
    AuthorityRevisionMismatch,
    #[error("engine lineage compare-and-swap failed: expected {expected}, found {actual}")]
    GenerationConflict { expected: u64, actual: u64 },
    #[error("engine lineage generation counter is exhausted")]
    GenerationExhausted,
    #[error("engine lineage changed while installation recovery was being authorized")]
    RecoveryConflict,
    #[error("engine lineage epoch counter is exhausted")]
    EpochExhausted,
    #[error("engine lineage Keychain load failed: {0}")]
    AuthorityLoad(String),
    #[error("engine lineage Keychain creation failed: {0}")]
    AuthorityCreate(String),
    #[error("engine lineage Keychain save failed: {0}")]
    AuthoritySave(String),
    #[error("engine lineage Keychain state is inconsistent: {0}")]
    AuthorityInconsistent(String),
    #[error(
        "engine lineage Keychain save failed: {write_error}; recovery failed: {recovery_error}"
    )]
    AuthoritySaveAndRecoveryFailed {
        write_error: String,
        recovery_error: String,
    },
    #[error("engine lineage I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "engine lineage cache write failed: {write_error}; temporary cleanup also failed: {cleanup_error}"
    )]
    WriteAndCleanupFailed {
        write_error: String,
        cleanup_error: std::io::Error,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageDocument {
    schema_version: u16,
    installation_id: Uuid,
    config_epoch: u64,
    generation: u64,
}

impl LineageDocument {
    fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            installation_id: Uuid::new_v4(),
            config_epoch: 1,
            generation: 0,
        }
    }

    fn validate(&self) -> Result<(), GenerationStoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GenerationStoreError::UnsupportedSchema(self.schema_version));
        }
        if self.installation_id.is_nil() {
            return Err(GenerationStoreError::InvalidInstallationId(
                self.installation_id.to_string(),
            ));
        }
        if self.config_epoch == 0 {
            return Err(GenerationStoreError::InvalidEpoch);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, GenerationStoreError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > MAX_LINEAGE_BYTES {
            return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GenerationStoreError> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_LINEAGE_BYTES {
            return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
        }
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate()?;
        if document.canonical_bytes()? != bytes {
            return Err(GenerationStoreError::NonCanonicalDocument);
        }
        Ok(document)
    }

    fn lineage(&self) -> EngineLineage {
        EngineLineage {
            session: EngineSessionIdentity {
                installation_id: self.installation_id.to_string(),
                config_epoch: self.config_epoch,
            },
            generation: self.generation,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AuthorityRecord {
    bytes: Vec<u8>,
    revision: String,
}

impl AuthorityRecord {
    fn from_document(document: &LineageDocument) -> Result<Self, GenerationStoreError> {
        let bytes = document.canonical_bytes()?;
        let revision = revision_for(&bytes);
        Ok(Self { bytes, revision })
    }

    fn document(&self) -> Result<LineageDocument, GenerationStoreError> {
        if revision_for(&self.bytes) != self.revision {
            return Err(GenerationStoreError::AuthorityRevisionMismatch);
        }
        LineageDocument::from_canonical_bytes(&self.bytes)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CreateOutcome {
    Created,
    AlreadyExists,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CompareExchangeOutcome {
    Swapped,
    Conflict,
}

enum CommitOutcome {
    Committed,
    Conflict(EngineLineage),
}

trait LineageAuthority: Send + Sync + 'static {
    fn load(&self) -> Result<Option<AuthorityRecord>, GenerationStoreError>;
    fn create(&self, record: &AuthorityRecord) -> Result<CreateOutcome, GenerationStoreError>;
    fn compare_exchange(
        &self,
        expected_revision: &str,
        replacement: &AuthorityRecord,
    ) -> Result<CompareExchangeOutcome, GenerationStoreError>;
}

/// Keychain-authoritative generation lineage with a repairable filesystem cache.
///
/// The Data Protection Keychain value is the only authority. The file lock is
/// cooperative serialization and the JSON file is a cache; deleting or changing
/// either can affect availability but can never select a lineage or roll it back.
pub struct KeychainEngineGenerationStore {
    root: PathBuf,
    authority: Arc<dyn LineageAuthority>,
    in_process: Mutex<()>,
}

impl KeychainEngineGenerationStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, GenerationStoreError> {
        Self::with_authority(root.into(), Arc::new(MacOsKeychainAuthority))
    }

    /// Rebinds only this user's Keychain lineage after the signed Host has
    /// authenticated the console user and proven native owners globally Off.
    /// The caller must retain exclusive engine maintenance until process exit:
    /// a running coordinator's session is immutable, even if a write fails.
    /// No root journal, other user's Keychain, or profile credential is changed.
    pub fn recover_installation(
        &self,
        expected: &EngineLineage,
        installation_id: Uuid,
        accepted_epoch: u64,
    ) -> Result<EngineLineage, GenerationStoreError> {
        self.with_lock(|| {
            // Do not create or replace a missing/corrupt item after consent.
            // The baseline was loaded before authentication, and must still
            // exist byte-for-byte when the atomic update is attempted.
            let current = self.reload_authority()?;
            let document = current.document()?;
            if &document.lineage() != expected {
                return Err(GenerationStoreError::RecoveryConflict);
            }
            let floor = if document.installation_id == installation_id {
                accepted_epoch.max(document.config_epoch)
            } else {
                accepted_epoch
            };
            let replacement_document = LineageDocument {
                schema_version: SCHEMA_VERSION,
                installation_id,
                config_epoch: floor
                    .checked_add(1)
                    .ok_or(GenerationStoreError::EpochExhausted)?,
                generation: 0,
            };
            let replacement = AuthorityRecord::from_document(&replacement_document)?;
            match self.commit_replacement(&current, &replacement)? {
                CommitOutcome::Committed => Ok(replacement_document.lineage()),
                CommitOutcome::Conflict(_) => Err(GenerationStoreError::RecoveryConflict),
            }
        })
    }

    fn with_authority(
        root: PathBuf,
        authority: Arc<dyn LineageAuthority>,
    ) -> Result<Self, GenerationStoreError> {
        cache::prepare_root(&root)?;
        Ok(Self {
            root,
            authority,
            in_process: Mutex::new(()),
        })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, GenerationStoreError>,
    ) -> Result<T, GenerationStoreError> {
        let _in_process = self
            .in_process
            .lock()
            .map_err(|error| GenerationStoreError::Io {
                operation: "lock-in-process-lineage",
                source: std::io::Error::other(error.to_string()),
            })?;
        cache::prepare_root(&self.root)?;
        let _file_lock = cache::exclusive_lock(&self.root)?;
        operation()
    }

    fn load_or_initialize(&self) -> Result<AuthorityRecord, GenerationStoreError> {
        if let Some(record) = self.authority.load()? {
            record.document()?;
            return Ok(record);
        }

        let candidate = AuthorityRecord::from_document(&LineageDocument::new())?;
        match self.authority.create(&candidate)? {
            CreateOutcome::Created => Ok(candidate),
            CreateOutcome::AlreadyExists => self
                .authority
                .load()?
                .ok_or_else(|| {
                    GenerationStoreError::AuthorityInconsistent(
                        "item disappeared after duplicate creation".into(),
                    )
                })
                .and_then(|record| {
                    record.document()?;
                    Ok(record)
                }),
        }
    }

    fn synchronize_cache(&self, record: &AuthorityRecord) -> Result<(), GenerationStoreError> {
        if matches!(cache::read(&self.root), Ok(Some(bytes)) if bytes == record.bytes) {
            return Ok(());
        }
        cache::write(&self.root, &record.bytes)
    }

    fn reload_authority(&self) -> Result<AuthorityRecord, GenerationStoreError> {
        let record = self.authority.load()?.ok_or_else(|| {
            GenerationStoreError::AuthorityInconsistent(
                "item disappeared while recovering a compare-and-swap".into(),
            )
        })?;
        record.document()?;
        Ok(record)
    }

    fn reload_and_repair(&self) -> Result<AuthorityRecord, GenerationStoreError> {
        let record = self.reload_authority()?;
        self.synchronize_cache(&record)?;
        Ok(record)
    }

    fn commit_replacement(
        &self,
        current: &AuthorityRecord,
        replacement: &AuthorityRecord,
    ) -> Result<CommitOutcome, GenerationStoreError> {
        // Cache-first: a crash before CAS leaves only a repairable cache ahead
        // of authority. No fallible filesystem operation follows a committed CAS.
        self.synchronize_cache(replacement)?;
        match self
            .authority
            .compare_exchange(&current.revision, replacement)
        {
            Ok(CompareExchangeOutcome::Swapped) => Ok(CommitOutcome::Committed),
            Ok(CompareExchangeOutcome::Conflict) => Ok(CommitOutcome::Conflict(
                self.reload_and_repair()?.document()?.lineage(),
            )),
            Err(write_error) => match self.reload_authority() {
                // An error may arrive after the atomic Keychain update. Only
                // authoritative readback of our exact replacement proves success.
                Ok(record) if &record == replacement => Ok(CommitOutcome::Committed),
                Ok(record) => match self.synchronize_cache(&record) {
                    Ok(()) => Err(write_error),
                    Err(recovery_error) => {
                        Err(GenerationStoreError::AuthoritySaveAndRecoveryFailed {
                            write_error: write_error.to_string(),
                            recovery_error: recovery_error.to_string(),
                        })
                    }
                },
                Err(recovery_error) => Err(GenerationStoreError::AuthoritySaveAndRecoveryFailed {
                    write_error: write_error.to_string(),
                    recovery_error: recovery_error.to_string(),
                }),
            },
        }
    }
}

impl EngineGenerationStore for KeychainEngineGenerationStore {
    fn load(&self) -> Result<EngineLineage, String> {
        self.with_lock(|| {
            let record = self.load_or_initialize()?;
            let document = record.document()?;
            self.synchronize_cache(&record)?;
            Ok(document.lineage())
        })
        .map_err(|error| error.to_string())
    }

    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String> {
        self.with_lock(|| {
            let current = self.load_or_initialize()?;
            let mut replacement_document = current.document()?;
            if replacement_document.generation != expected_generation {
                return Err(GenerationStoreError::GenerationConflict {
                    expected: expected_generation,
                    actual: replacement_document.generation,
                });
            }
            let next = expected_generation
                .checked_add(1)
                .ok_or(GenerationStoreError::GenerationExhausted)?;
            replacement_document.generation = next;
            let replacement = AuthorityRecord::from_document(&replacement_document)?;

            match self.commit_replacement(&current, &replacement)? {
                CommitOutcome::Committed => Ok(next),
                CommitOutcome::Conflict(actual) => Err(GenerationStoreError::GenerationConflict {
                    expected: expected_generation,
                    actual: actual.generation,
                }),
            }
        })
        .map_err(|error| error.to_string())
    }
}

fn revision_for(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut revision = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut revision, "{byte:02x}").expect("writing to a String cannot fail");
    }
    revision
}

#[cfg(test)]
fn cache_path(root: &Path) -> PathBuf {
    root.join(cache::LINEAGE_FILE)
}
