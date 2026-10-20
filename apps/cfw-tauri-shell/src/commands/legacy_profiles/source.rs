//! Owned legacy source files, read relative to one retained directory.
use std::path::Path;
#[cfg(unix)]
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Read as _,
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
};

#[cfg(unix)]
pub(super) type Directory = File;
#[cfg(windows)]
pub(super) type Directory = cfw_windows_storage::LegacyReadDirectory;

#[cfg(windows)]
pub(super) fn open_owned_directory(
    path: &Path,
    require_private: bool,
) -> Result<Directory, String> {
    use cfw_windows_storage::ReadPolicy;
    let policy = if require_private {
        ReadPolicy::Private
    } else {
        ReadPolicy::LegacyReadOnly
    };
    Directory::open_existing(path, policy)
        .map_err(|error| format!("legacy profile directory is unavailable: {error}"))
}

#[cfg(windows)]
pub(super) fn open_directory_at(parent: &Directory, name: &str) -> Result<Directory, String> {
    parent
        .open_child(name, cfw_windows_storage::ReadPolicy::LegacyReadOnly)
        .map_err(|error| format!("legacy profile directory could not be opened safely: {error}"))
}

#[cfg(windows)]
pub(super) fn read_optional_legacy_entry(
    directory: &Directory,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
    directory
        .read(name, maximum)
        .map_err(|error| format!("legacy profile entry could not be read safely: {error}"))
}

#[cfg(unix)]
pub(super) fn open_owned_directory(
    path: &Path,
    require_private: bool,
) -> Result<Directory, String> {
    if !path.is_absolute() {
        return Err("legacy profile directory must be absolute".into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("legacy profile directory is unavailable: {error}"))?;
    validate_directory(&directory, require_private)?;
    Ok(directory)
}

#[cfg(unix)]
pub(super) fn open_directory_at(parent: &Directory, name: &str) -> Result<Directory, String> {
    let name = CString::new(name).map_err(|_| "legacy directory name contains NUL")?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "legacy profile directory could not be opened safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    validate_directory(&directory, false)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_directory(directory: &Directory, require_private: bool) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("legacy profile directory metadata is unavailable: {error}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || (require_private && metadata.mode() & 0o077 != 0)
    {
        return Err(
            "legacy profile directory is not an effective-user-owned real directory".into(),
        );
    }
    Ok(())
}

pub(super) fn read_legacy_entry(
    directory: &Directory,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    read_optional_legacy_entry(directory, name, maximum)?
        .ok_or_else(|| format!("required legacy profile entry is missing: {name}"))
}

#[cfg(unix)]
pub(super) fn read_optional_legacy_entry(
    directory: &Directory,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
    let name = CString::new(name).map_err(|_| "legacy profile entry name contains NUL")?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "legacy profile entry could not be opened safely: {error}"
        ));
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .map_err(|error| format!("legacy profile entry metadata is unavailable: {error}"))?;
    if !before.file_type().is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
    {
        return Err(
            "legacy profile entry is not an effective-user-owned regular non-writable file".into(),
        );
    }
    if before.len() > maximum as u64 {
        return Err(format!(
            "legacy profile entry exceeds the {maximum}-byte migration limit"
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("legacy profile entry read failed: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("legacy profile entry metadata is unavailable: {error}"))?;
    if !after.file_type().is_file()
        || after.uid() != unsafe { libc::geteuid() }
        || after.nlink() != 1
        || after.mode() & 0o022 != 0
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() > maximum
    {
        return Err("legacy profile entry changed while it was being read".into());
    }
    Ok(Some(bytes))
}
