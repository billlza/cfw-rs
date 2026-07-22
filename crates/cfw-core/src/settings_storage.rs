use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::SettingsStoreError;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FilePolicy {
    Private,
    LegacyReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
    digest: [u8; 32],
}

pub(crate) struct StoredBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: FileIdentity,
}

pub(crate) struct SecureDirectory {
    file: File,
}

impl SecureDirectory {
    pub(crate) fn open_or_create(path: &Path) -> Result<Self, SettingsStoreError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(SettingsStoreError::UnsafeDirectory);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)?;
            }
            Err(error) => return Err(error.into()),
        }

        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| SettingsStoreError::InvalidPath)?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_dir() || metadata.uid() != current_uid() {
            return Err(SettingsStoreError::UnsafeDirectory);
        }
        let chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o700) };
        if chmod == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { file })
    }

    pub(crate) fn read_optional(
        &self,
        name: &str,
        maximum: usize,
        policy: FilePolicy,
    ) -> Result<Option<StoredBytes>, SettingsStoreError> {
        self.lock(libc::LOCK_SH)?;
        self.read_optional_locked(name, maximum, policy)
    }

    pub(crate) fn write_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), SettingsStoreError> {
        if bytes.len() > maximum {
            return Err(SettingsStoreError::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        self.lock(libc::LOCK_EX)?;
        // Existing state must itself be trusted before it can be replaced.
        self.read_optional_locked(destination, maximum, FilePolicy::Private)?;

        let temporary = format!(".{destination}.tmp");
        if self
            .read_optional_locked(&temporary, maximum, FilePolicy::Private)?
            .is_some()
        {
            self.unlink(&temporary)?;
            self.file.sync_all()?;
        }
        let mut file = self.create_exclusive(&temporary)?;
        let operation = (|| -> Result<(), SettingsStoreError> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            self.rename(&temporary, destination)?;
            self.file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = operation {
            match self.unlink(&temporary) {
                Ok(()) => Err(error),
                Err(SettingsStoreError::Io(cleanup))
                    if cleanup.kind() == std::io::ErrorKind::NotFound =>
                {
                    Err(error)
                }
                Err(cleanup) => Err(SettingsStoreError::CleanupFailed {
                    operation: error.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            }
        } else {
            Ok(())
        }
    }

    pub(crate) fn remove_matching(
        &self,
        name: &str,
        expected: &FileIdentity,
        maximum: usize,
        policy: FilePolicy,
    ) -> Result<(), SettingsStoreError> {
        self.lock(libc::LOCK_EX)?;
        let current = self
            .read_optional_locked(name, maximum, policy)?
            .ok_or(SettingsStoreError::LegacySourceChanged)?;
        if &current.identity != expected {
            return Err(SettingsStoreError::LegacySourceChanged);
        }
        self.unlink(name)?;
        self.file.sync_all()?;
        Ok(())
    }

    fn read_optional_locked(
        &self,
        name: &str,
        maximum: usize,
        policy: FilePolicy,
    ) -> Result<Option<StoredBytes>, SettingsStoreError> {
        let name = relative_name(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(SettingsStoreError::UnsafeFile);
            }
            return Err(error.into());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        validate_file(&metadata, maximum, policy)?;

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(SettingsStoreError::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        let digest = Sha256::digest(&bytes).into();
        Ok(Some(StoredBytes {
            bytes,
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                digest,
            },
        }))
    }

    fn create_exclusive(&self, name: &str) -> Result<File, SettingsStoreError> {
        let name = relative_name(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if chmod == -1 {
            let operation = std::io::Error::last_os_error();
            drop(file);
            let cleanup = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
            if cleanup == -1 {
                return Err(SettingsStoreError::CleanupFailed {
                    operation: operation.to_string(),
                    cleanup: std::io::Error::last_os_error().to_string(),
                });
            }
            return Err(operation.into());
        }
        Ok(file)
    }

    fn rename(&self, source: &str, destination: &str) -> Result<(), SettingsStoreError> {
        let source = relative_name(source)?;
        let destination = relative_name(destination)?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if result == -1 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    fn unlink(&self, name: &str) -> Result<(), SettingsStoreError> {
        let name = relative_name(name)?;
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
        if result == -1 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    fn lock(&self, operation: libc::c_int) -> Result<(), SettingsStoreError> {
        let result = unsafe { libc::flock(self.file.as_raw_fd(), operation) };
        if result == -1 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}

fn validate_file(
    metadata: &fs::Metadata,
    maximum: usize,
    policy: FilePolicy,
) -> Result<(), SettingsStoreError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.uid() != current_uid() {
        return Err(SettingsStoreError::UnsafeFile);
    }
    let mode = metadata.permissions().mode() & 0o777;
    let mode_is_safe = match policy {
        FilePolicy::Private => mode == 0o600,
        FilePolicy::LegacyReadOnly => mode & 0o022 == 0,
    };
    if !mode_is_safe {
        return Err(SettingsStoreError::UnsafeFile);
    }
    if metadata.len() > maximum as u64 {
        return Err(SettingsStoreError::TooLarge {
            actual: metadata.len(),
            maximum,
        });
    }
    Ok(())
}

fn relative_name(name: &str) -> Result<CString, SettingsStoreError> {
    let name = OsStr::new(name);
    if name.as_bytes().contains(&b'/') || name == OsStr::new(".") || name == OsStr::new("..") {
        return Err(SettingsStoreError::InvalidPath);
    }
    CString::new(name.as_bytes()).map_err(|_| SettingsStoreError::InvalidPath)
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}
