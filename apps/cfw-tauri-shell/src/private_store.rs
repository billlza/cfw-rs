//! Descriptor-relative storage for small private documents that must survive
//! a crash. Every document is one bounded file inside a user-owned 0700
//! directory, replaced by write-fsync-rename, and never reached through a
//! symlink.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// One durable document: its file names, size bound, and the subject used in
/// diagnostics.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrivateDocument {
    pub(crate) subject: &'static str,
    pub(crate) file: &'static str,
    pub(crate) temporary: &'static str,
    pub(crate) maximum_bytes: u64,
}

#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    /// Nothing was renamed into place; the previous document is intact.
    Failed(String),
    /// The rename happened but its durability could not be confirmed.
    CommitUncertain(String),
}

/// Why a stored document was not returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrivateReadError {
    /// What is stored under the document's name is not a document this
    /// process may use: a symlink, something other than a regular file, a
    /// file another user owns or others can reach, or one outside the size
    /// bound. Reading it again changes nothing; only replacing or removing
    /// it does.
    Unusable(String),
    /// The read itself failed; a later attempt may succeed.
    Failed(String),
}

impl std::fmt::Display for PrivateReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable(detail) | Self::Failed(detail) => formatter.write_str(detail),
        }
    }
}

#[derive(Debug)]
pub(crate) enum LockFileError {
    Open(std::io::Error),
    Inspect(std::io::Error),
    UnsafeMetadata,
    Busy,
    Lock(std::io::Error),
}

pub(crate) struct PrivateDirectory {
    file: File,
    document: PrivateDocument,
}

impl PrivateDirectory {
    pub(crate) fn open_or_create(path: &Path, document: PrivateDocument) -> Result<Self, String> {
        let subject = document.subject;
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(format!("{subject} root is not a directory"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)
                    .map_err(|error| format!("failed to create {subject} root: {error}"))?;
            }
            Err(error) => return Err(format!("failed to inspect {subject} root: {error}")),
        }
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("{subject} path contains NUL"))?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to open {subject} root: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(format!("{subject} root has unsafe ownership"));
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } == -1 {
            return Err(format!(
                "failed to secure {subject} root: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file, document })
    }

    /// Serializes one read-modify-write of the document across processes.
    pub(crate) fn lock(&self) -> Result<(), String> {
        const WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(3);
        const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
        let subject = self.document.subject;
        let busy = || {
            format!(
                "{subject} remained busy for 3 seconds; another process still owns its transaction lock"
            )
        };
        let deadline = std::time::Instant::now() + WAIT_LIMIT;
        loop {
            if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                if std::time::Instant::now() >= deadline {
                    return Err(busy());
                }
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(format!("failed to lock {subject}: {error}"));
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(busy());
            }
            std::thread::sleep(RETRY_INTERVAL.min(deadline.saturating_duration_since(now)));
        }
    }

    /// Returns the exact stored bytes, or `None` when the document is absent.
    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, PrivateReadError> {
        let PrivateDocument {
            subject,
            file,
            maximum_bytes,
            ..
        } = self.document;
        let name = CString::new(file).expect("fixed name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                // O_NOFOLLOW refuses a symlink in the document's place.
                Some(libc::ELOOP) => Err(PrivateReadError::Unusable(format!(
                    "{subject} is a symbolic link"
                ))),
                _ => Err(PrivateReadError::Failed(format!(
                    "failed to open {subject}: {error}"
                ))),
            };
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .map_err(|error| PrivateReadError::Failed(error.to_string()))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > maximum_bytes
        {
            return Err(PrivateReadError::Unusable(format!(
                "{subject} has unsafe metadata"
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::by_ref(&mut file)
            .take(maximum_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                PrivateReadError::Failed(format!("failed to read {subject}: {error}"))
            })?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(PrivateReadError::Unusable(format!(
                "{subject} exceeds {maximum_bytes} bytes"
            )));
        }
        Ok(Some(bytes))
    }

    pub(crate) fn write_atomic_with_directory_sync(
        &self,
        bytes: &[u8],
        sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), AtomicWriteError> {
        let subject = self.document.subject;
        self.remove_stale_temporary()
            .map_err(AtomicWriteError::Failed)?;
        let temporary = CString::new(self.document.temporary).expect("fixed name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(AtomicWriteError::Failed(format!(
                "failed to create {subject} temporary: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let before_rename = (|| -> Result<(), String> {
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
                return Err(format!(
                    "failed to secure {subject} temporary: {}",
                    std::io::Error::last_os_error()
                ));
            }
            file.write_all(bytes)
                .map_err(|error| format!("failed to write {subject}: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("failed to fsync {subject}: {error}"))?;
            drop(file);
            let destination = CString::new(self.document.file).expect("fixed name");
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    temporary.as_ptr(),
                    self.file.as_raw_fd(),
                    destination.as_ptr(),
                )
            } == -1
            {
                return Err(format!(
                    "failed to commit {subject}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        if let Err(error) = before_rename {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), temporary.as_ptr(), 0);
            }
            return Err(AtomicWriteError::Failed(error));
        }
        sync_directory(&self.file).map_err(|error| {
            AtomicWriteError::CommitUncertain(format!("directory fsync failed: {error}"))
        })
    }

    /// Removes the document. Absence is success: the caller's intent is that
    /// no document remains.
    pub(crate) fn remove(&self) -> Result<(), String> {
        let subject = self.document.subject;
        let name = CString::new(self.document.file).expect("fixed name");
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("failed to remove {subject}: {error}"));
            }
        }
        self.file
            .sync_all()
            .map_err(|error| format!("failed to fsync {subject} root: {error}"))
    }

    /// Takes a process-lifetime exclusive lock on a private lock file in this
    /// directory. The lock is released when the returned file is dropped.
    pub(crate) fn acquire_lock_file(&self, name: &'static str) -> Result<File, LockFileError> {
        let name = CString::new(name).expect("fixed lock name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(LockFileError::Open(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(LockFileError::Inspect)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(LockFileError::UnsafeMetadata);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            let error = std::io::Error::last_os_error();
            return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                LockFileError::Busy
            } else {
                LockFileError::Lock(error)
            });
        }
        Ok(file)
    }

    fn remove_stale_temporary(&self) -> Result<(), String> {
        let PrivateDocument {
            subject,
            temporary,
            maximum_bytes,
            ..
        } = self.document;
        let temporary = CString::new(temporary).expect("fixed name");
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(format!("failed to inspect {subject} temporary: {error}"))
            };
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_nlink != 1
            || stat.st_mode & 0o077 != 0
            || stat.st_size < 0
            || stat.st_size as u64 > maximum_bytes
        {
            return Err(format!("stale {subject} temporary has unsafe metadata"));
        }
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), temporary.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to remove stale {subject} temporary: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}
