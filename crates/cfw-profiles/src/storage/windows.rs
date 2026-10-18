use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::path::Path;
use std::sync::Mutex;

use cfw_windows_storage::{EntryKind, Error, PrivateDirectory, Publication, WriteTransaction};
use uuid::Uuid;

use crate::envelope::profile_file_name;
use crate::storage::{is_owned_temporary_name, remaining_directory_entry_capacity};
use crate::storage_atomic::{committed_sync_result, error_after_cleanup};
use crate::{
    MAX_ENVELOPE_BYTES, MAX_SELECTED_REPLACE_BYTES, MAX_SELECTION_BYTES, ProfileError,
    SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME,
};

pub(crate) struct RepositoryDirectory {
    directory: PrivateDirectory,
    // The OS guard lives for the complete repository/credential transaction.
    // The mutex only permits mutable access through the existing shared adapter
    // interface; it does not replace the cross-process filesystem lock.
    transaction: Mutex<Option<WriteTransaction>>,
}

impl RepositoryDirectory {
    pub(crate) fn open_or_create(path: &Path) -> Result<Self, ProfileError> {
        let directory = PrivateDirectory::open_or_create(path)
            .map_err(|error| storage_error(error, "repository directory"))?;
        Ok(Self {
            directory,
            transaction: Mutex::new(None),
        })
    }

    pub(crate) fn open_if_present(path: &Path) -> Result<Option<Self>, ProfileError> {
        Ok(PrivateDirectory::open_existing(path)
            .map_err(|error| storage_error(error, "repository directory"))?
            .map(|directory| Self {
                directory,
                transaction: Mutex::new(None),
            }))
    }

    pub(crate) fn lock_exclusive(&self) -> Result<(), ProfileError> {
        let mut transaction = self
            .transaction
            .lock()
            .map_err(|_| poisoned_transaction())?;
        if transaction.is_none() {
            *transaction = Some(
                self.directory
                    .write()
                    .map_err(|error| storage_error(error, "repository lock"))?,
            );
        }
        Ok(())
    }

    fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&mut WriteTransaction) -> Result<T, ProfileError>,
    ) -> Result<T, ProfileError> {
        let mut guard = self
            .transaction
            .lock()
            .map_err(|_| poisoned_transaction())?;
        let transaction = guard.as_mut().ok_or_else(|| {
            ProfileError::Io(io::Error::other(
                "profile repository operation requires its transaction lock",
            ))
        })?;
        operation(transaction)
    }

    pub(crate) fn entry_names(&self) -> Result<Vec<OsString>, ProfileError> {
        self.with_transaction(|transaction| {
            transaction
                .entry_names(remaining_directory_entry_capacity(0)?)
                .map_err(|error| storage_error(error, "repository enumeration"))
        })
    }

    pub(crate) fn entry_is_directory(&self, name: &OsStr) -> Result<bool, ProfileError> {
        self.with_transaction(|transaction| {
            transaction
                .entry_kind(name)
                .map(|kind| kind == EntryKind::Directory)
                .map_err(|error| storage_error(error, &name.to_string_lossy()))
        })
    }

    pub(crate) fn entry_exists(&self, name: &str) -> Result<bool, ProfileError> {
        self.with_transaction(
            |transaction| match transaction.entry_kind(OsStr::new(name)) {
                Ok(_) => Ok(true),
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(storage_error(error, name)),
            },
        )
    }

    pub(crate) fn recover_owned_temporaries(&self) -> Result<usize, ProfileError> {
        let names = self
            .entry_names()?
            .into_iter()
            .filter(|name| is_owned_temporary_name(name))
            .collect::<Vec<_>>();
        self.with_transaction(|transaction| {
            // Validate the complete recovery set before removing any entry.
            for name in &names {
                let name = name.to_str().ok_or_else(|| {
                    ProfileError::UnexpectedEntry("non-UTF-8 temporary name".into())
                })?;
                transaction
                    .validate_temporary(name)
                    .map_err(|error| match error {
                        Error::UnsafeFile => ProfileError::UnexpectedEntry(name.to_owned()),
                        error => storage_error(error, name),
                    })?;
            }
            for name in &names {
                transaction
                    .unlink_managed_entry(name)
                    .map_err(|error| storage_error(error, &name.to_string_lossy()))?;
            }
            if !names.is_empty() {
                transaction.sync_directory().map_err(|error| {
                    storage_error(error, "abandoned profile temporary recovery")
                })?;
            }
            Ok(names.len())
        })
    }

    pub(crate) fn open_profile_file(&self, id: &str) -> Result<File, ProfileError> {
        let name = profile_file_name(id);
        self.open_file(&name, ProfileError::UnsafeProfileFile(id.to_owned()))
    }

    pub(crate) fn open_selection_file(&self) -> Result<File, ProfileError> {
        self.open_file(SELECTION_FILE_NAME, ProfileError::UnsafeSelectionFile)
    }

    pub(crate) fn open_selected_replace_file(&self) -> Result<File, ProfileError> {
        self.open_file(
            SELECTED_REPLACE_FILE_NAME,
            ProfileError::UnsafeSelectedReplaceFile,
        )
    }

    fn open_file(&self, name: &str, unsafe_file: ProfileError) -> Result<File, ProfileError> {
        self.with_transaction(|transaction| {
            transaction
                .open_private_file(name)
                .map_err(|error| match error {
                    Error::UnsafeFile => unsafe_file,
                    error => storage_error(error, name),
                })
        })
    }

    pub(crate) fn unlink(&self, name: &str) -> Result<(), ProfileError> {
        self.unlink_os(OsStr::new(name))
    }

    pub(crate) fn unlink_os(&self, name: &OsStr) -> Result<(), ProfileError> {
        self.with_transaction(|transaction| {
            transaction
                .unlink_managed_entry(name)
                .map_err(|error| storage_error(error, &name.to_string_lossy()))
        })
    }

    pub(crate) fn sync_committed(&self, entry: &str) -> Result<(), ProfileError> {
        self.with_transaction(|transaction| match transaction.sync_directory() {
            Ok(()) => Ok(()),
            Err(Error::CommitUncertain(source)) => committed_sync_result(entry, Err(source)),
            Err(error) => Err(storage_error(error, entry)),
        })
    }

    pub(crate) fn write_new_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
    ) -> Result<(), ProfileError> {
        if self.entry_exists(destination)? {
            return Err(ProfileError::AlreadyExists(destination.to_owned()));
        }
        self.publish(destination, bytes, Publication::CreateNew)
    }

    pub(crate) fn write_replace_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
    ) -> Result<(), ProfileError> {
        self.publish(destination, bytes, Publication::Replace)
    }

    fn publish(
        &self,
        destination: &str,
        bytes: &[u8],
        publication: Publication,
    ) -> Result<(), ProfileError> {
        let temporary = format!(".{}.tmp", Uuid::new_v4().hyphenated());
        let maximum = match destination {
            SELECTION_FILE_NAME => MAX_SELECTION_BYTES,
            SELECTED_REPLACE_FILE_NAME => MAX_SELECTED_REPLACE_BYTES,
            _ => MAX_ENVELOPE_BYTES,
        };
        self.with_transaction(|transaction| {
            transaction
                .publish_with_temporary(destination, &temporary, bytes, maximum, publication)
                .map_err(|error| match error {
                    Error::Io(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        ProfileError::AlreadyExists(destination.to_owned())
                    }
                    error => storage_error(error, destination),
                })
        })
    }
}

pub(crate) fn private_metadata(
    file: &File,
    unsafe_file: ProfileError,
) -> Result<Metadata, ProfileError> {
    cfw_windows_storage::validate_private_file(file).map_err(|error| match error {
        Error::UnsafeFile => unsafe_file,
        error => storage_error(error, "opened profile input"),
    })?;
    Ok(file.metadata()?)
}

fn poisoned_transaction() -> ProfileError {
    ProfileError::Io(io::Error::other(
        "profile repository transaction state is poisoned",
    ))
}

fn storage_error(error: Error, entry: &str) -> ProfileError {
    match error {
        Error::Io(error) => ProfileError::Io(error),
        Error::InvalidName => ProfileError::InvalidRepositoryPath,
        Error::UnsafeDirectory => ProfileError::UnsafeRepositoryDirectory,
        Error::UnsafeFile => ProfileError::UnsafeProfileFile(entry.to_owned()),
        Error::UnexpectedDirectory => ProfileError::UnexpectedManagedSubdirectory(entry.to_owned()),
        Error::Busy => ProfileError::RepositoryBusy,
        Error::TooManyEntries { .. } => ProfileError::TooManyEntries,
        Error::TooLarge { actual, .. } => match entry {
            SELECTION_FILE_NAME => ProfileError::SelectionTooLarge { actual },
            SELECTED_REPLACE_FILE_NAME => ProfileError::SelectedReplaceTooLarge { actual },
            _ => ProfileError::StoredProfileTooLarge { actual },
        },
        Error::CommitUncertain(source) => ProfileError::CommitUncertain {
            entry: entry.to_owned(),
            source,
        },
        Error::CleanupFailed { operation, cleanup } => error_after_cleanup(
            storage_error(*operation, entry),
            Err(storage_error(*cleanup, entry)),
        ),
        Error::InvalidLimit | Error::InvalidSecurityDescriptor | Error::InvalidDirectoryListing => {
            ProfileError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                error.to_string(),
            ))
        }
    }
}
