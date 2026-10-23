use super::{HANDOFF_DIRECTORY, MAX_DOCUMENT_BYTES, MAX_HANDOFF_DOCUMENTS, WriteNewFailure};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) struct PrivateDirectory {
    file: File,
}

impl PrivateDirectory {
    pub(super) fn open_or_create(root: &Path) -> Result<Self, String> {
        let root_path = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| "handoff root path contains NUL".to_owned())?;
        let root_descriptor = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_descriptor == -1 {
            return Err(format!(
                "failed to open handoff root: {}",
                std::io::Error::last_os_error()
            ));
        }
        let root_file = unsafe { File::from_raw_fd(root_descriptor) };
        let root_metadata = root_file
            .metadata()
            .map_err(|error| format!("failed to inspect handoff root: {error}"))?;
        if !root_metadata.file_type().is_dir()
            || root_metadata.uid() != unsafe { libc::geteuid() }
            || root_metadata.mode() & 0o077 != 0
        {
            return Err("handoff root is not a private user-owned real directory".into());
        }
        let name = CString::new(HANDOFF_DIRECTORY).expect("fixed handoff directory name");
        let created = if unsafe { libc::mkdirat(root_file.as_raw_fd(), name.as_ptr(), 0o700) } == 0
        {
            true
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                false
            } else {
                return Err(format!("failed to create handoff directory: {error}"));
            }
        };
        let descriptor = unsafe {
            libc::openat(
                root_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to open handoff directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect handoff directory: {error}"))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("handoff directory is not a private user-owned real directory".into());
        }
        if created {
            root_file
                .sync_all()
                .map_err(|error| format!("failed to fsync handoff root: {error}"))?;
        }
        Ok(Self { file })
    }

    pub(super) fn entry_names(&self) -> Result<Vec<String>, String> {
        let current = CString::new(".").expect("fixed current-directory name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                current.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to reopen handoff directory for enumeration: {}",
                std::io::Error::last_os_error()
            ));
        }
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(descriptor);
            }
            return Err(format!(
                "failed to enumerate the handoff directory descriptor: {error}"
            ));
        }
        let operation = (|| -> Result<Vec<String>, String> {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let errno = unsafe { *libc::__error() };
                    return if errno == 0 {
                        Ok(names)
                    } else {
                        Err(format!(
                            "failed while enumerating handoff documents: {}",
                            std::io::Error::from_raw_os_error(errno)
                        ))
                    };
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = name
                    .to_str()
                    .map_err(|_| "handoff directory contains a non-UTF-8 document name".to_owned())?
                    .to_owned();
                names.push(name);
                if names.len() > MAX_HANDOFF_DOCUMENTS {
                    return Err(format!(
                        "handoff directory contains more than {MAX_HANDOFF_DOCUMENTS} documents"
                    ));
                }
            }
        })();
        let closed = unsafe { libc::closedir(stream) };
        match (operation, closed) {
            (Ok(names), 0) => Ok(names),
            (Err(error), 0) => Err(error),
            (Ok(_), _) => Err(format!(
                "failed to close handoff directory enumeration: {}",
                std::io::Error::last_os_error()
            )),
            (Err(error), _) => Err(format!(
                "{error}; handoff directory enumeration close also failed: {}",
                std::io::Error::last_os_error()
            )),
        }
    }

    pub(super) fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.write_new_retaining_ambiguous_failure(name, bytes)
            .map_err(|failure| failure.message)
    }

    pub(super) fn write_new_retaining_ambiguous_failure(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), WriteNewFailure> {
        let name = safe_name(name).map_err(|message| WriteNewFailure {
            message,
            quarantine: None,
        })?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_EXLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(WriteNewFailure {
                message: format!(
                    "failed to create handoff document: {}",
                    std::io::Error::last_os_error()
                ),
                quarantine: None,
            });
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        if let Err(operation) = validate_private_file(&file) {
            let cleanup = self.unlink_created(&name);
            return Err(write_failure_after_cleanup(
                operation,
                "unsafe handoff document cleanup",
                cleanup,
                file,
            ));
        }
        let persisted = file.write_all(bytes).and_then(|()| file.sync_all());
        let operation = match persisted {
            Ok(()) => self
                .file
                .sync_all()
                .map_err(|error| format!("failed to fsync handoff directory: {error}")),
            Err(error) => Err(format!("failed to persist handoff document: {error}")),
        };
        if let Err(operation) = operation {
            let cleanup = self.unlink_created(&name);
            return Err(write_failure_after_cleanup(
                operation,
                "failed handoff document cleanup",
                cleanup,
                file,
            ));
        }
        drop(file);
        Ok(())
    }

    pub(super) fn read_locked_optional(
        &self,
        name: &str,
    ) -> Result<Option<(File, Vec<u8>)>, String> {
        self.read_locked_optional_with_busy(name, false)
    }

    pub(super) fn read_ready_locked_optional(
        &self,
        name: &str,
    ) -> Result<Option<(File, Vec<u8>)>, String> {
        self.read_locked_optional_with_busy(name, true)
    }

    fn read_locked_optional_with_busy(
        &self,
        name: &str,
        writer_busy_is_pending: bool,
    ) -> Result<Option<(File, Vec<u8>)>, String> {
        let name = safe_name(name)?;
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
            return Err(format!("failed to open handoff document: {error}"));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            let error = std::io::Error::last_os_error();
            if writer_busy_is_pending && error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("handoff document is already locked: {error}"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read handoff document: {error}"))?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err("handoff document exceeds 16 KiB".into());
        }
        Ok(Some((file, bytes)))
    }

    pub(super) fn unlink_locked(&self, name: &str, file: File) -> Result<(), String> {
        validate_private_file(&file)?;
        let name = safe_name(name)?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to consume handoff document: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| format!("failed to fsync handoff consumption: {error}"))
    }

    pub(super) fn unlink_optional(&self, name: &str) -> Result<(), String> {
        let Some((file, _)) = self.read_locked_optional(name)? else {
            return Ok(());
        };
        self.unlink_locked(name, file)
    }

    fn unlink_created(&self, name: &CString) -> Result<(), String> {
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to remove an incomplete handoff document: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| format!("failed to fsync incomplete document removal: {error}"))
    }
}

pub(super) fn write_failure_after_cleanup(
    operation: String,
    cleanup_label: &str,
    cleanup: Result<(), String>,
    file: File,
) -> WriteNewFailure {
    match cleanup {
        Ok(()) => WriteNewFailure {
            message: operation,
            quarantine: None,
        },
        Err(cleanup) => WriteNewFailure {
            message: format!("{operation}; {cleanup_label} also failed: {cleanup}"),
            quarantine: Some(file),
        },
    }
}

fn validate_private_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect handoff document: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("handoff document is not a private user-owned single-link file".into());
    }
    Ok(())
}

fn safe_name(name: &str) -> Result<CString, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err("handoff document name is invalid".into());
    }
    CString::new(name).map_err(|_| "handoff document name contains NUL".into())
}
