use std::{ffi::OsStr, fs::File, io, path::Path, sync::Mutex};

use cfw_windows_storage::{Error, Publication, ReadPolicy, WriteTransaction};

use super::{AtomicWriteError, LockFileError, PrivateDocument, PrivateReadError};

pub(crate) struct PrivateDirectory {
    native: cfw_windows_storage::PrivateDirectory,
    document: PrivateDocument,
    maximum: usize,
    // Explicit `lock` retains the real cross-process transaction until this
    // directory is dropped. The mutex also serializes this object's callers.
    transaction: Mutex<Option<WriteTransaction>>,
}

impl PrivateDirectory {
    pub(crate) fn open_or_create(path: &Path, document: PrivateDocument) -> Result<Self, String> {
        let maximum = usize::try_from(document.maximum_bytes)
            .ok()
            .filter(|maximum| *maximum != 0)
            .ok_or("private document size bound is invalid")?;
        let native = cfw_windows_storage::PrivateDirectory::open_or_create(path)
            .map_err(|error| format!("{} root: {error}", document.subject))?;
        Ok(Self {
            native,
            document,
            maximum,
            transaction: Mutex::new(None),
        })
    }

    pub(crate) fn lock(&self) -> Result<(), String> {
        let mut transaction = self
            .transaction
            .lock()
            .map_err(|_| "private document transaction state is poisoned")?;
        if transaction.is_none() {
            *transaction =
                Some(self.native.write().map_err(|error| {
                    format!("failed to lock {}: {error}", self.document.subject)
                })?);
        }
        Ok(())
    }

    fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&mut WriteTransaction) -> T,
    ) -> Result<T, Error> {
        let mut retained = self.transaction.lock().map_err(|_| {
            Error::Io(io::Error::other(
                "private document transaction state is poisoned",
            ))
        })?;
        match retained.as_mut() {
            Some(transaction) => Ok(operation(transaction)),
            None => Ok(operation(&mut self.native.write()?)),
        }
    }

    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, PrivateReadError> {
        let value = self
            .with_transaction(|transaction| {
                transaction.read(self.document.file, self.maximum, ReadPolicy::Private)
            })
            .and_then(|result| result)
            .map_err(|error| {
                let detail = format!("failed to read {}: {error}", self.document.subject);
                match error {
                    Error::UnsafeFile | Error::UnexpectedDirectory | Error::TooLarge { .. } => {
                        PrivateReadError::Unusable(detail)
                    }
                    _ => PrivateReadError::Failed(detail),
                }
            })?;
        match value {
            Some(snapshot) if snapshot.bytes.is_empty() => Err(PrivateReadError::Unusable(
                format!("{} is empty", self.document.subject),
            )),
            Some(snapshot) => Ok(Some(snapshot.bytes)),
            None => Ok(None),
        }
    }

    pub(crate) fn write_atomic_with_directory_sync(
        &self,
        bytes: &[u8],
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), AtomicWriteError> {
        self.with_transaction(|transaction| {
            let failed = |error: Error| {
                AtomicWriteError::Failed(format!(
                    "failed to write {}: {error}",
                    self.document.subject
                ))
            };
            if transaction
                .read_temporary(self.document.temporary, self.maximum)
                .map_err(failed)?
                .is_some()
            {
                // Failure here has not published the intended document, even
                // if deletion of an abandoned temporary is durability-uncertain.
                transaction
                    .remove_temporary(self.document.temporary, self.maximum)
                    .map_err(failed)?;
            }
            transaction
                .publish_with_temporary_and_sync(
                    self.document.file,
                    self.document.temporary,
                    bytes,
                    self.maximum,
                    Publication::Replace,
                    sync_directory,
                )
                .map_err(|error| match error {
                    Error::CommitUncertain(error) => AtomicWriteError::CommitUncertain(format!(
                        "{} directory flush failed after publication: {error}",
                        self.document.subject
                    )),
                    error => failed(error),
                })
        })
        .map_err(|error| AtomicWriteError::Failed(error.to_string()))?
    }

    pub(crate) fn remove(&self) -> Result<(), String> {
        self.with_transaction(|transaction| {
            match transaction.unlink_managed_entry(OsStr::new(self.document.file)) {
                Ok(()) => {}
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            transaction.sync_directory()
        })
        .and_then(|result| result)
        .map_err(|error| format!("failed to remove {}: {error}", self.document.subject))
    }

    pub(crate) fn acquire_lock_file(&self, name: &'static str) -> Result<File, LockFileError> {
        self.native
            .try_lock_file(name)
            .map_err(|error| match error {
                Error::Busy => LockFileError::Busy,
                Error::UnsafeFile | Error::UnsafeDirectory | Error::TooLarge { .. } => {
                    LockFileError::UnsafeMetadata
                }
                error => LockFileError::Lock(io::Error::other(error)),
            })
    }
}
