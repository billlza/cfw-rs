//! Current-user lineage authority. Credential Manager persists the canonical
//! record; a private, SID-scoped global mutex serializes all cooperating writers
//! across directories, processes and logon sessions on this machine.
use std::{
    io,
    ptr::null_mut,
    sync::{Arc, Mutex},
    time::Duration,
};

use cfw_engine_api::{EngineGenerationStore, EngineLineage, EngineSessionIdentity};
use cfw_windows_storage::{PrivateUserMutex, require_process_identity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND,
    Security::Credentials::{
        CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW,
        CredFree, CredReadW, CredWriteW,
    },
};

const TARGET: &str = "com.bill.clashforwindows.engine-lineage.v1";

#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    #[error("Windows lineage authority locking/identity: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[error("Windows lineage {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows lineage authority document is invalid or noncanonical")]
    InvalidDocument,
    #[error("Windows lineage compare-and-swap conflict: expected {expected}, found {actual}")]
    Conflict { expected: u64, actual: u64 },
    #[error("Windows lineage generation is exhausted")]
    Exhausted,
    #[error("Windows lineage authority disappeared after this store bound an installation")]
    AuthorityMissing,
    #[error("Windows lineage installation identity changed while this store was active")]
    IdentityChanged,
    #[error("Windows lineage local identity binding is poisoned")]
    BindingPoisoned,
    #[error(
        "Windows lineage publication could not be confirmed; the generation may have advanced: {source}"
    )]
    OutcomeUnknown {
        #[source]
        source: Box<LineageError>,
    },
    #[error("Windows lineage readback differs from the published record")]
    ReadbackMismatch,
    #[error(
        "Windows lineage operation failed ({operation}); mutex release also failed ({cleanup})"
    )]
    CleanupFailed {
        operation: Box<LineageError>,
        cleanup: cfw_windows_storage::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u16,
    installation_id: Uuid,
    config_epoch: u64,
    generation: u64,
}

impl Document {
    fn encode(&self) -> Result<Vec<u8>, LineageError> {
        if self.schema_version != 1 || self.installation_id.is_nil() || self.config_epoch == 0 {
            return Err(LineageError::InvalidDocument);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| LineageError::InvalidDocument)?;
        if bytes.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(LineageError::InvalidDocument);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, LineageError> {
        if bytes.is_empty() || bytes.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(LineageError::InvalidDocument);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| LineageError::InvalidDocument)?;
        if value.encode()? != bytes {
            return Err(LineageError::InvalidDocument);
        }
        Ok(value)
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

/// Persisted user lineage, not a privileged-service identity or a global-Off
/// certificate. It supplies the existing serialized application coordinator.
/// Methods block on OS APIs and belong on a dedicated native worker.
#[derive(Debug, Clone)]
pub struct WindowsEngineGenerationStore {
    target: String,
    bound_session: Arc<Mutex<Option<EngineSessionIdentity>>>,
}

impl Default for WindowsEngineGenerationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsEngineGenerationStore {
    pub fn new() -> Self {
        Self::for_target(TARGET.into())
    }

    fn for_target(target: String) -> Self {
        Self {
            target,
            bound_session: Arc::new(Mutex::new(None)),
        }
    }

    fn lock_name(&self) -> String {
        format!(
            "engine-lineage-{}",
            cfw_singbox_config::sha256_hex(self.target.as_bytes())
        )
    }

    fn locked<T>(
        &self,
        operation: impl FnOnce() -> Result<T, LineageError>,
    ) -> Result<T, LineageError> {
        require_process_identity()?;
        let guard = PrivateUserMutex::acquire(&self.lock_name(), Duration::from_secs(3))?;
        // Every path reloads and validates Credential Manager after admission,
        // including an abandoned predecessor. No cached counter is trusted.
        let result = operation();
        match (result, guard.release()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
            (Err(operation), Err(cleanup)) => Err(LineageError::CleanupFailed {
                operation: Box::new(operation),
                cleanup,
            }),
        }
    }

    pub fn load_lineage(&self) -> Result<EngineLineage, LineageError> {
        self.locked(|| self.load_or_initialize().map(|record| record.lineage()))
    }

    pub fn reserve_generation(&self, expected: u64) -> Result<u64, LineageError> {
        self.locked(|| {
            let mut document = self.load_or_initialize()?;
            if document.generation != expected {
                return Err(LineageError::Conflict {
                    expected,
                    actual: document.generation,
                });
            }
            document.generation = expected.checked_add(1).ok_or(LineageError::Exhausted)?;
            self.publish(&document)?;
            Ok(document.generation)
        })
    }

    fn load_or_initialize(&self) -> Result<Document, LineageError> {
        let mut binding = self
            .bound_session
            .lock()
            .map_err(|_| LineageError::BindingPoisoned)?;
        if let Some(document) = self.read()? {
            let session = document.lineage().session;
            if binding
                .as_ref()
                .is_some_and(|expected| *expected != session)
            {
                return Err(LineageError::IdentityChanged);
            }
            *binding = Some(session);
            return Ok(document);
        }
        if binding.is_some() {
            return Err(LineageError::AuthorityMissing);
        }
        // Only documented absence in an unbound store permits initialization.
        // Reinstallation after deliberate credential removal gets a fresh UUID;
        // an already bound coordinator cannot adopt it with its former context.
        let document = Document {
            schema_version: 1,
            installation_id: Uuid::new_v4(),
            config_epoch: 1,
            generation: 0,
        };
        self.publish(&document)?;
        *binding = Some(document.lineage().session);
        Ok(document)
    }

    fn target_wide(&self) -> Vec<u16> {
        self.target.encode_utf16().chain(Some(0)).collect()
    }

    fn read(&self) -> Result<Option<Document>, LineageError> {
        require_process_identity()?;
        let target = self.target_wide();
        let mut pointer = null_mut();
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) } == 0 {
            let source = io::Error::last_os_error();
            return if source.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                Ok(None)
            } else {
                Err(LineageError::Native {
                    operation: "read",
                    source,
                })
            };
        }
        if pointer.is_null() {
            return Err(LineageError::InvalidDocument);
        }
        struct Allocation(*mut CREDENTIALW);
        impl Drop for Allocation {
            fn drop(&mut self) {
                unsafe { CredFree(self.0.cast()) };
            }
        }
        let allocation = Allocation(pointer);
        let record = unsafe { &*allocation.0 };
        if record.Type != CRED_TYPE_GENERIC
            || record.Persist != CRED_PERSIST_LOCAL_MACHINE
            || record.Flags != 0
            || record.AttributeCount != 0
            || record.CredentialBlob.is_null()
            || record.CredentialBlobSize == 0
            || record.CredentialBlobSize > CRED_MAX_CREDENTIAL_BLOB_SIZE
            || !wide_equals(record.TargetName, &target)
        {
            return Err(LineageError::InvalidDocument);
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(record.CredentialBlob, record.CredentialBlobSize as usize)
        };
        Document::decode(bytes).map(Some)
    }

    fn publish(&self, document: &Document) -> Result<(), LineageError> {
        let mut bytes = document.encode()?;
        self.write(&mut bytes)?;
        match self.read() {
            Ok(Some(observed)) if observed == *document => Ok(()),
            Ok(_) => Err(LineageError::OutcomeUnknown {
                source: Box::new(LineageError::ReadbackMismatch),
            }),
            Err(source) => Err(LineageError::OutcomeUnknown {
                source: Box::new(source),
            }),
        }
    }

    fn write(&self, bytes: &mut [u8]) -> Result<(), LineageError> {
        require_process_identity()?;
        let mut target = self.target_wide();
        let record = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: u32::try_from(bytes.len())
                .map_err(|_| LineageError::InvalidDocument)?,
            CredentialBlob: bytes.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..CREDENTIALW::default()
        };
        // Generic records have no domain authentication semantics. Local-machine
        // persistence means this same user's future logon sessions, not all users.
        if unsafe { CredWriteW(&record, 0) } == 0 {
            return Err(LineageError::Native {
                operation: "write",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

impl EngineGenerationStore for WindowsEngineGenerationStore {
    fn load(&self) -> Result<EngineLineage, String> {
        self.load_lineage().map_err(|error| error.to_string())
    }
    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String> {
        self.reserve_generation(expected_generation)
            .map_err(|error| error.to_string())
    }
}

fn wide_equals(pointer: *const u16, expected: &[u16]) -> bool {
    if pointer.is_null() {
        return false;
    }
    for (index, wanted) in expected.iter().enumerate() {
        let actual = unsafe { *pointer.add(index) };
        if actual != *wanted {
            return false;
        }
        if actual == 0 {
            return index == expected.len() - 1;
        }
    }
    false
}

#[cfg(test)]
mod tests;
