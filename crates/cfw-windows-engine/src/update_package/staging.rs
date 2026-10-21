//! One Windows MSI transaction, with no macOS bundle extraction or volume swap.
//! The namespace lease lives through downloading, inspection and user review.

use std::path::{Path, PathBuf};

use cfw_windows_storage::{EntryKind, Error as StorageError, PrivateDirectory, WriteTransaction};
use uuid::Uuid;

const DIRECTORY: &str = "updates-msi-v1";
const PACKAGE: &str = "package.msi";
pub(super) const FINISHER: &str = "finish-update.exe";
const MAX_TRANSACTIONS: usize = 64;
const MAX_FILES: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("Windows update transaction identifier is invalid")]
    InvalidTransaction,
    #[error("Windows update staging contains an unknown namespace entry")]
    UnknownEntry,
    #[error("Windows update staging {operation}: {source}")]
    Storage {
        operation: &'static str,
        #[source]
        source: StorageError,
    },
    #[error(
        "Windows update recovery stopped after {completed} complete removals; the current entry may be partially removed: {source}"
    )]
    Recovery {
        completed: usize,
        #[source]
        source: StorageError,
    },
}

/// Retains the native parent write lease for the whole active transaction.
/// Dropping releases the lease and leaves files for the next explicit recovery.
/// This type neither authenticates the package nor authorizes installation.
pub struct UpdateStaging {
    root: PathBuf,
    name: String,
    directory: PrivateDirectory,
    lease: WriteTransaction,
}

impl UpdateStaging {
    pub fn finisher(&self) -> PathBuf {
        self.root.join(FINISHER)
    }

    pub(crate) fn belongs_to(&self, home: &Path) -> bool {
        self.root.parent() == Some(home.join(DIRECTORY).as_path())
    }

    pub(crate) fn handoff_root(home: &Path, transaction: Uuid) -> Result<PathBuf, StagingError> {
        Ok(home.join(DIRECTORY).join(transaction_name(transaction)?))
    }
    pub fn create(app_home: &Path, transaction: Uuid) -> Result<Self, StagingError> {
        let name = transaction_name(transaction)?;
        let home = PrivateDirectory::open_or_create(app_home).map_err(storage("open home"))?;
        let parent = home
            .open_or_create_child(DIRECTORY)
            .map_err(storage("open namespace"))?;
        let lease = parent.write().map_err(storage("acquire lifecycle lease"))?;
        let directory = lease
            .create_private_child(&name)
            .map_err(storage("create transaction"))?;
        Ok(Self {
            root: app_home.join(DIRECTORY).join(&name),
            name,
            directory,
            lease,
        })
    }

    /// Reopens an existing transaction under the same lifecycle lease, without
    /// creating missing directories. It grants no trust to the existing bytes.
    pub fn open_existing(app_home: &Path, transaction: Uuid) -> Result<Option<Self>, StagingError> {
        let name = transaction_name(transaction)?;
        let Some(parent) = existing_namespace(app_home)? else {
            return Ok(None);
        };
        let lease = parent.write().map_err(storage("acquire lifecycle lease"))?;
        let Some(directory) = lease
            .open_private_child(&name)
            .map_err(storage("open transaction"))?
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            root: app_home.join(DIRECTORY).join(&name),
            name,
            directory,
            lease,
        }))
    }

    pub fn directory(&self) -> &PrivateDirectory {
        &self.directory
    }

    /// The installed verification worker may use this private directory as its
    /// working directory. Callers must keep this staging owner alive meanwhile.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn package(&self) -> PathBuf {
        self.root.join(PACKAGE)
    }

    /// All users of the candidate (including the inspector's held file) must
    /// retire before removal. Native sharing violations remain errors.
    pub fn remove(self) -> Result<(), StagingError> {
        let Self {
            name,
            directory,
            mut lease,
            ..
        } = self;
        lease
            .remove_flat_child(&name, directory, MAX_FILES)
            .map_err(storage("remove transaction"))
    }

    /// Recovers abandoned transactions only after the caller has resolved any
    /// installer journal/handoff. A live staging owner prevents this entire
    /// operation. Unknown names and oversized catalogs are refused before any
    /// entry is removed; failures during a batch report prior completed entries.
    pub fn recover(app_home: &Path) -> Result<usize, StagingError> {
        let Some(parent) = existing_namespace(app_home)? else {
            return Ok(0);
        };
        let mut lease = parent.write().map_err(storage("acquire lifecycle lease"))?;
        let names = lease
            .entry_names(MAX_TRANSACTIONS)
            .map_err(storage("enumerate transactions"))?;
        let names = names
            .iter()
            .map(|name| {
                let name = name.to_str().ok_or(StagingError::UnknownEntry)?;
                let transaction = Uuid::parse_str(name).map_err(|_| StagingError::UnknownEntry)?;
                if transaction.is_nil() || transaction.hyphenated().to_string() != name {
                    return Err(StagingError::UnknownEntry);
                }
                Ok(name)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut completed = 0;
        for name in names {
            let cleanup = (|| -> Result<(), StorageError> {
                match lease.entry_kind(name.as_ref())? {
                    EntryKind::Directory => {
                        let child = lease
                            .open_private_child(name)?
                            .ok_or(StorageError::UnsafeDirectory)?;
                        lease.remove_flat_child(name, child, MAX_FILES)
                    }
                    // The reserved namespace owns these exact UUID entries,
                    // never a reparse target or any other hard link.
                    EntryKind::File | EntryKind::ReparsePoint => {
                        lease.unlink_managed_entry(name.as_ref())?;
                        lease.sync_directory()
                    }
                }
            })();
            cleanup.map_err(|source| StagingError::Recovery { completed, source })?;
            completed += 1;
        }
        Ok(completed)
    }
}

fn existing_namespace(app_home: &Path) -> Result<Option<PrivateDirectory>, StagingError> {
    let Some(home) = PrivateDirectory::open_existing(app_home).map_err(storage("open home"))?
    else {
        return Ok(None);
    };
    home.write()
        .map_err(storage("inspect home"))?
        .open_private_child(DIRECTORY)
        .map_err(storage("open namespace"))
}

fn transaction_name(transaction: Uuid) -> Result<String, StagingError> {
    if transaction.is_nil() {
        return Err(StagingError::InvalidTransaction);
    }
    Ok(transaction.hyphenated().to_string())
}

fn storage(operation: &'static str) -> impl FnOnce(StorageError) -> StagingError {
    move |source| StagingError::Storage { operation, source }
}
