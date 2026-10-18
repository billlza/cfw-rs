use std::path::Path;

use cfw_windows_storage::{Error, PrivateDirectory, Snapshot};

use crate::SettingsStoreError;

pub(crate) use cfw_windows_storage::{FileIdentity, ReadPolicy as FilePolicy};

pub(crate) struct SecureDirectory {
    directory: PrivateDirectory,
}

impl SecureDirectory {
    pub(crate) fn open_existing(path: &Path) -> Result<Option<Self>, SettingsStoreError> {
        Ok(PrivateDirectory::open_existing(path)?.map(|directory| Self { directory }))
    }

    pub(crate) fn open_or_create(path: &Path) -> Result<Self, SettingsStoreError> {
        Ok(Self {
            directory: PrivateDirectory::open_or_create(path)?,
        })
    }

    pub(crate) fn read_optional(
        &self,
        name: &str,
        maximum: usize,
        policy: FilePolicy,
    ) -> Result<Option<Snapshot>, SettingsStoreError> {
        Ok(self.directory.read()?.read(name, maximum, policy)?)
    }

    pub(crate) fn write_atomic(
        &self,
        name: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), SettingsStoreError> {
        Ok(self.directory.write()?.replace(name, bytes, maximum)?)
    }

    pub(crate) fn update_atomic<F>(
        &self,
        name: &str,
        maximum: usize,
        update: F,
    ) -> Result<(), SettingsStoreError>
    where
        F: FnOnce(Option<&[u8]>) -> Result<Vec<u8>, SettingsStoreError>,
    {
        let mut transaction = self.directory.write()?;
        let previous = transaction.read(name, maximum, FilePolicy::Private)?;
        let bytes = update(previous.as_ref().map(|value| value.bytes.as_slice()))?;
        Ok(transaction.replace(name, &bytes, maximum)?)
    }

    pub(crate) fn compare_and_swap_atomic(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), SettingsStoreError> {
        let mut transaction = self.directory.write()?;
        let previous = transaction.read(name, maximum, FilePolicy::Private)?;
        let revision = previous.as_ref().map(|value| value.identity.revision());
        if revision.as_deref() != expected_revision {
            return Err(SettingsStoreError::RuntimeSettingsChanged);
        }
        Ok(transaction.replace(name, bytes, maximum)?)
    }

    pub(crate) fn remove_matching(
        &self,
        name: &str,
        expected: &FileIdentity,
        maximum: usize,
        policy: FilePolicy,
    ) -> Result<(), SettingsStoreError> {
        let mut transaction = self.directory.write()?;
        let previous = transaction
            .read(name, maximum, policy)?
            .ok_or(SettingsStoreError::LegacySourceChanged)?;
        if &previous.identity != expected {
            return Err(SettingsStoreError::LegacySourceChanged);
        }
        Ok(transaction.remove(name, maximum, policy)?)
    }
}

impl From<Error> for SettingsStoreError {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(error) => Self::Io(error),
            Error::Enumeration { operation, source } => Self::Io(std::io::Error::new(
                source.kind(),
                Error::Enumeration { operation, source },
            )),
            Error::Busy | Error::MutexBusy => Self::StoreBusy,
            Error::UnsafeMutex | Error::ImpersonatedIdentity => Self::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                error,
            )),
            Error::InvalidMutexParameters => {
                Self::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
            }
            Error::InvalidName | Error::InvalidLimit => Self::InvalidPath,
            Error::UnsafeDirectory => Self::UnsafeDirectory,
            Error::UnexpectedDirectory => Self::UnsafeDirectory,
            Error::UnsafeFile => Self::UnsafeFile,
            Error::TooManyEntries { .. } | Error::InvalidDirectoryListing => {
                Self::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Windows storage directory enumeration failed its contract",
                ))
            }
            Error::InvalidSecurityDescriptor => Self::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows storage security could not be validated",
            )),
            Error::TooLarge { actual, maximum } => Self::TooLarge { actual, maximum },
            Error::CommitUncertain(error) => Self::CommitUncertain(error),
            Error::CleanupFailed { operation, cleanup } => Self::CleanupFailed {
                operation: operation.to_string(),
                cleanup: cleanup.to_string(),
            },
        }
    }
}
