//! The per-user update exclusion shared by platform-specific installers.
use crate::private_store::{LockFileError, PrivateDirectory, PrivateDocument};
use std::{fs::File, path::Path};
const LEASE_FILE: &str = "update-install-v1.lock";
const RECORD_DOCUMENT: PrivateDocument = PrivateDocument {
    subject: "update installation lease",
    file: "update-install-v1.json",
    temporary: ".update-install-v1.tmp",
    maximum_bytes: 4096,
};

/// Held by the installer process from before it unregisters services until the
/// bundles are exchanged. A dashboard refuses to start while it is held, so no
/// instance of the application can re-register services underneath the
/// exchange.
#[derive(Debug)]
pub(crate) struct UpdateInstallLease {
    _file: File,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpdateInstallLeaseError {
    /// Another process holds the lease: an installation is in progress.
    Held,
    Unavailable(String),
}

impl std::fmt::Display for UpdateInstallLeaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held => formatter.write_str("an update installation is in progress"),
            Self::Unavailable(detail) => {
                write!(
                    formatter,
                    "update installation lease is unavailable: {detail}"
                )
            }
        }
    }
}

impl UpdateInstallLease {
    pub(crate) fn acquire(app_home: &Path) -> Result<Self, UpdateInstallLeaseError> {
        PrivateDirectory::open_or_create(app_home, RECORD_DOCUMENT)
            .map_err(UpdateInstallLeaseError::Unavailable)?
            .acquire_lock_file(LEASE_FILE)
            .map(|file| Self { _file: file })
            .map_err(|error| match error {
                LockFileError::Busy => UpdateInstallLeaseError::Held,
                LockFileError::UnsafeMetadata => {
                    UpdateInstallLeaseError::Unavailable("lock file has unsafe metadata".into())
                }
                #[cfg(unix)]
                LockFileError::Open(error) | LockFileError::Inspect(error) => {
                    UpdateInstallLeaseError::Unavailable(error.to_string())
                }
                LockFileError::Lock(error) => {
                    UpdateInstallLeaseError::Unavailable(error.to_string())
                }
            })
    }
}
