use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};

use uuid::Uuid;

use crate::ProfileError;
use crate::storage::{RepositoryDirectory, relative_c_string};

struct CreatedEntryGuard<'a> {
    directory: &'a RepositoryDirectory,
    name: CString,
    armed: bool,
}

impl<'a> CreatedEntryGuard<'a> {
    fn new(directory: &'a RepositoryDirectory, name: CString) -> Self {
        Self {
            directory,
            name,
            armed: true,
        }
    }

    fn cleanup(mut self) -> Result<(), ProfileError> {
        self.armed = false;
        let result =
            unsafe { libc::unlinkat(self.directory.file.as_raw_fd(), self.name.as_ptr(), 0) };
        if result == -1 {
            Err(ProfileError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CreatedEntryGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Panic safety only; ordinary errors explicitly report cleanup.
            unsafe {
                libc::unlinkat(self.directory.file.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

impl RepositoryDirectory {
    pub(crate) fn write_new_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
    ) -> Result<(), ProfileError> {
        if self.entry_exists(destination)? {
            return Err(ProfileError::AlreadyExists(destination.to_string()));
        }
        self.write_atomic(destination, bytes, false)
    }

    pub(crate) fn write_replace_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
    ) -> Result<(), ProfileError> {
        self.write_atomic(destination, bytes, true)
    }

    fn write_atomic(
        &self,
        destination: &str,
        bytes: &[u8],
        replace: bool,
    ) -> Result<(), ProfileError> {
        let temporary = format!(".{}.tmp", Uuid::new_v4().hyphenated());
        let mut file = self.create_exclusive(&temporary)?;
        let operation = (|| -> Result<(), ProfileError> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if replace {
                self.rename_replace(&temporary, destination)
            } else {
                self.rename_new(&temporary, destination)
            }
        })();
        if let Err(error) = operation {
            Err(error_after_cleanup(error, self.unlink(&temporary)))
        } else {
            committed_sync_result(destination, self.file.sync_all())
        }
    }

    fn create_exclusive(&self, name: &str) -> Result<File, ProfileError> {
        self.create_exclusive_with_mode_setter(name, |descriptor| {
            let result = unsafe { libc::fchmod(descriptor, 0o600) };
            if result == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
    }

    pub(super) fn create_exclusive_with_mode_setter(
        &self,
        name: &str,
        set_mode: impl FnOnce(std::os::fd::RawFd) -> std::io::Result<()>,
    ) -> Result<File, ProfileError> {
        let name = relative_c_string(OsStr::new(name))?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(ProfileError::Io(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let guard = CreatedEntryGuard::new(self, name);
        if let Err(error) = set_mode(file.as_raw_fd()) {
            drop(file);
            return Err(error_after_cleanup(
                ProfileError::Io(error),
                guard.cleanup(),
            ));
        }
        guard.disarm();
        Ok(file)
    }

    fn rename_new(&self, source: &str, destination: &str) -> Result<(), ProfileError> {
        let source = relative_c_string(OsStr::new(source))?;
        let destination = relative_c_string(OsStr::new(destination))?;
        let result = unsafe {
            libc::renameatx_np(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(ProfileError::AlreadyExists(
                    destination.to_string_lossy().into_owned(),
                ))
            } else {
                Err(ProfileError::Io(error))
            }
        } else {
            Ok(())
        }
    }

    fn rename_replace(&self, source: &str, destination: &str) -> Result<(), ProfileError> {
        let source = relative_c_string(OsStr::new(source))?;
        let destination = relative_c_string(OsStr::new(destination))?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if result == -1 {
            Err(ProfileError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

pub(super) fn error_after_cleanup(
    operation: ProfileError,
    cleanup: Result<(), ProfileError>,
) -> ProfileError {
    match cleanup {
        Ok(()) => operation,
        Err(ProfileError::Io(cleanup)) if cleanup.kind() == std::io::ErrorKind::NotFound => {
            operation
        }
        Err(cleanup) => ProfileError::AtomicCleanup {
            operation: operation.to_string(),
            cleanup: cleanup.to_string(),
        },
    }
}

pub(super) fn committed_sync_result(
    entry: &str,
    result: std::io::Result<()>,
) -> Result<(), ProfileError> {
    result.map_err(|source| ProfileError::CommitUncertain {
        entry: entry.to_owned(),
        source,
    })
}
