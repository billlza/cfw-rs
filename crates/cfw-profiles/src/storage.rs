use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use uuid::Uuid;

use crate::envelope::profile_file_name;
use crate::storage_atomic::committed_sync_result;
use crate::{MAX_REPOSITORY_ENTRIES, ProfileError, SELECTION_FILE_NAME};

pub(super) const MAX_ABANDONED_TEMPORARIES: usize = 64;

pub(crate) struct RepositoryDirectory {
    pub(super) file: File,
}

impl RepositoryDirectory {
    pub(crate) fn open_or_create(path: &Path) -> Result<Self, ProfileError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(ProfileError::UnsafeRepositoryDirectory);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)?;
            }
            Err(error) => return Err(ProfileError::Io(error)),
        }
        Self::open(path)
    }

    pub(crate) fn open_if_present(path: &Path) -> Result<Option<Self>, ProfileError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                Err(ProfileError::UnsafeRepositoryDirectory)
            }
            Ok(_) => Self::open(path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ProfileError::Io(error)),
        }
    }

    pub(super) fn open(path: &Path) -> Result<Self, ProfileError> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ProfileError::InvalidRepositoryPath)?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(ProfileError::Io(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        if !repository_directory_is_safe(&metadata, effective_user_id()) {
            return Err(ProfileError::UnsafeRepositoryDirectory);
        }
        // Apply the mode to the opened descriptor so a path replacement cannot
        // redirect permission healing after O_NOFOLLOW succeeds.
        let chmod = unsafe { libc::fchmod(file.as_raw_fd(), 0o700) };
        if chmod == -1 {
            return Err(ProfileError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }

    pub(crate) fn lock_exclusive(&self) -> Result<(), ProfileError> {
        let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX) };
        if result == -1 {
            Err(ProfileError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn entry_names(&self) -> Result<Vec<OsString>, ProfileError> {
        let duplicated = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated == -1 {
            return Err(ProfileError::Io(std::io::Error::last_os_error()));
        }
        let stream = unsafe { libc::fdopendir(duplicated) };
        if stream.is_null() {
            let open_error = std::io::Error::last_os_error();
            let close_result = unsafe { libc::close(duplicated) };
            if close_result == -1 {
                return Err(ProfileError::DirectoryEnumerationCleanup {
                    operation: open_error.to_string(),
                    cleanup: std::io::Error::last_os_error().to_string(),
                });
            }
            return Err(ProfileError::Io(open_error));
        }

        let mut names = Vec::new();
        unsafe { libc::rewinddir(stream) };
        let read_result = loop {
            unsafe { *libc::__error() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = unsafe { *libc::__error() };
                if errno == 0 {
                    break Ok(());
                }
                break Err(ProfileError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                if let Err(error) = ensure_directory_entry_capacity(names.len()) {
                    break Err(error);
                }
                names.push(OsString::from_vec(name.to_vec()));
            }
        };
        let close_result = unsafe { libc::closedir(stream) };
        match (read_result, close_result) {
            (Ok(()), 0) => Ok(names),
            (Err(error), 0) => Err(error),
            (Ok(()), _) => Err(ProfileError::Io(std::io::Error::last_os_error())),
            (Err(error), _) => Err(ProfileError::DirectoryEnumerationCleanup {
                operation: error.to_string(),
                cleanup: std::io::Error::last_os_error().to_string(),
            }),
        }
    }

    pub(crate) fn entry_is_directory(&self, name: &OsStr) -> Result<bool, ProfileError> {
        let metadata = self.entry_metadata(name)?;
        Ok(metadata.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }

    /// Removes only abandoned temporary files created by this repository. The
    /// caller's exclusive directory lock proves no cooperating writer owns one.
    pub(crate) fn recover_owned_temporaries(&self) -> Result<usize, ProfileError> {
        let temporary_names = self
            .entry_names()?
            .into_iter()
            .filter(|name| is_owned_temporary_name(name))
            .collect::<Vec<_>>();
        for name in &temporary_names {
            let metadata = self.entry_metadata(name)?;
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                || metadata.st_uid != effective_user_id()
                || metadata.st_nlink != 1
                || metadata.st_mode & 0o777 != 0o600
            {
                return Err(ProfileError::UnexpectedEntry(
                    name.to_string_lossy().into_owned(),
                ));
            }
        }
        for name in &temporary_names {
            self.unlink_os(name)?;
        }
        if !temporary_names.is_empty() {
            committed_sync_result("abandoned profile temporary recovery", self.file.sync_all())?;
        }
        Ok(temporary_names.len())
    }

    pub(crate) fn open_profile_file(&self, id: &str) -> Result<File, ProfileError> {
        let file_name = profile_file_name(id);
        let name = CString::new(file_name).expect("UUID profile filename never contains NUL");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ELOOP) {
                Err(ProfileError::UnsafeProfileFile(id.to_string()))
            } else {
                Err(ProfileError::Io(error))
            }
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    pub(crate) fn open_selection_file(&self) -> Result<File, ProfileError> {
        let name =
            CString::new(SELECTION_FILE_NAME).expect("selection filename never contains NUL");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ELOOP) {
                Err(ProfileError::UnsafeSelectionFile)
            } else {
                Err(ProfileError::Io(error))
            }
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    pub(crate) fn unlink(&self, name: &str) -> Result<(), ProfileError> {
        self.unlink_os(OsStr::new(name))
    }

    pub(crate) fn unlink_os(&self, name: &OsStr) -> Result<(), ProfileError> {
        let name = relative_c_string(name)?;
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
        if result == -1 {
            Err(ProfileError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn sync_committed(&self, entry: &str) -> Result<(), ProfileError> {
        committed_sync_result(entry, self.file.sync_all())
    }

    pub(super) fn entry_exists(&self, name: &str) -> Result<bool, ProfileError> {
        match self.entry_metadata(OsStr::new(name)) {
            Ok(_) => Ok(true),
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn entry_metadata(&self, name: &OsStr) -> Result<libc::stat, ProfileError> {
        let name = relative_c_string(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            Ok(unsafe { stat.assume_init() })
        } else {
            Err(ProfileError::Io(std::io::Error::last_os_error()))
        }
    }
}

pub(super) fn effective_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

pub(super) fn repository_directory_is_safe(metadata: &fs::Metadata, effective_uid: u32) -> bool {
    metadata.file_type().is_dir() && metadata.uid() == effective_uid
}

pub(crate) fn ensure_entry_capacity(current_entries: usize) -> Result<(), ProfileError> {
    if current_entries >= MAX_REPOSITORY_ENTRIES {
        Err(ProfileError::TooManyEntries)
    } else {
        Ok(())
    }
}

pub(super) fn ensure_directory_entry_capacity(current_entries: usize) -> Result<(), ProfileError> {
    // Selection metadata plus bounded crash temporaries remain enumerable.
    if current_entries >= MAX_REPOSITORY_ENTRIES + 1 + MAX_ABANDONED_TEMPORARIES {
        Err(ProfileError::TooManyEntries)
    } else {
        Ok(())
    }
}

pub(super) fn relative_c_string(name: &OsStr) -> Result<CString, ProfileError> {
    if name.as_bytes().contains(&b'/') || name == OsStr::new(".") || name == OsStr::new("..") {
        return Err(ProfileError::UnexpectedEntry(
            name.to_string_lossy().into_owned(),
        ));
    }
    CString::new(name.as_bytes()).map_err(|_| ProfileError::UnexpectedEntry("NUL byte".into()))
}

pub(super) fn is_owned_temporary_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(id) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
}
