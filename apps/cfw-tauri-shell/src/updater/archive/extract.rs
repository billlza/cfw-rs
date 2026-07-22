use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, ErrorKind, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use tar::Archive;

use super::{
    PlannedEntry, PlannedKind, RELEASE_LIMITS, UpdateArchiveError, bounded_decoder, describe_entry,
    io_error,
};

pub(super) fn extract_archive(
    bytes: &[u8],
    plan: &[PlannedEntry],
    destination: &Path,
) -> Result<(), UpdateArchiveError> {
    let root = open_directory(destination, "open-staging")?;
    let decoder = bounded_decoder(bytes, RELEASE_LIMITS)?;
    let mut archive = Archive::new(decoder);
    let mut entries = archive
        .entries()
        .map_err(|error| io_error("extract-entries", error))?;
    let mut count = 0_usize;
    for expected in plan {
        let entry = entries.next().ok_or(UpdateArchiveError::PlanMismatch)?;
        let mut entry = entry.map_err(|error| io_error("extract-entry", error))?;
        if describe_entry(&entry)? != *expected {
            return Err(UpdateArchiveError::PlanMismatch);
        }
        count += 1;
        match expected.kind {
            PlannedKind::Directory => {
                ensure_directory(root.as_raw_fd(), &expected.relative_path)?;
            }
            PlannedKind::File => {
                let (parent_path, file_name) = split_parent_and_name(&expected.relative_path)?;
                let parent = ensure_directory(root.as_raw_fd(), parent_path)?;
                let file_name = path_component(file_name, UpdateArchiveError::InvalidPath)?;
                // SAFETY: parent is an open directory owned by this extraction,
                // file_name is a live NUL-terminated component, and the returned
                // descriptor is checked before being owned by File.
                let descriptor = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        file_name.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                let descriptor = owned_descriptor(descriptor, "create-file")?;
                let mut file = File::from(descriptor);
                let written = io::copy(&mut entry, &mut file)
                    .map_err(|error| io_error("write-file", error))?;
                if written != expected.size {
                    return Err(UpdateArchiveError::PlanMismatch);
                }
                file.flush()
                    .map_err(|error| io_error("flush-file", error))?;
                // SAFETY: file owns a live descriptor and the validated mode is
                // limited to the portable permission bits.
                if unsafe { libc::fchmod(file.as_raw_fd(), expected.mode as libc::mode_t) } != 0 {
                    return Err(io_error("chmod-file", io::Error::last_os_error()));
                }
                file.sync_all()
                    .map_err(|error| io_error("sync-file", error))?;
            }
            PlannedKind::Symlink => {}
        }
    }
    if count != plan.len() {
        return Err(UpdateArchiveError::PlanMismatch);
    }
    if entries.next().is_some() {
        return Err(UpdateArchiveError::PlanMismatch);
    }

    for entry in plan
        .iter()
        .filter(|entry| entry.kind == PlannedKind::Symlink)
    {
        let target = entry
            .link_target
            .as_ref()
            .ok_or(UpdateArchiveError::InvalidSymlink)?;
        let (parent_path, link_name) = split_parent_and_name(&entry.relative_path)?;
        let parent = open_relative_directory(root.as_raw_fd(), parent_path)?;
        let link_name = path_component(link_name, UpdateArchiveError::InvalidPath)?;
        let target = CString::new(target.as_os_str().as_bytes())
            .map_err(|_| UpdateArchiveError::InvalidSymlink)?;
        // SAFETY: both C strings are live and NUL-terminated, and parent is a
        // no-follow directory descriptor inside the private staging root.
        if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), link_name.as_ptr()) } != 0
        {
            return Err(io_error("create-symlink", io::Error::last_os_error()));
        }
        File::from(parent)
            .sync_all()
            .map_err(|error| io_error("sync-symlink-parent", error))?;
    }

    let mut directories = plan
        .iter()
        .filter(|entry| entry.kind == PlannedKind::Directory)
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| std::cmp::Reverse(entry.relative_path.components().count()));
    for entry in directories {
        let directory = open_relative_directory(root.as_raw_fd(), &entry.relative_path)?;
        // SAFETY: directory is a live no-follow descriptor and the archive mode
        // has already been restricted to portable permission bits.
        if unsafe { libc::fchmod(directory.as_raw_fd(), entry.mode as libc::mode_t) } != 0 {
            return Err(io_error("chmod-directory", io::Error::last_os_error()));
        }
        File::from(directory)
            .sync_all()
            .map_err(|error| io_error("sync-directory", error))?;
    }
    Ok(())
}

fn ensure_directory(root: RawFd, relative: &Path) -> Result<OwnedFd, UpdateArchiveError> {
    let mut current = duplicate_descriptor(root, "duplicate-staging")?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(UpdateArchiveError::InvalidPath);
        };
        let name = path_component(name, UpdateArchiveError::InvalidPath)?;
        // SAFETY: current is a live directory descriptor and name is a single
        // live NUL-terminated path component.
        if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != ErrorKind::AlreadyExists {
                return Err(io_error("create-directory", error));
            }
        }
        current = open_directory_at(current.as_raw_fd(), &name, "open-directory")?;
    }
    Ok(current)
}

fn open_relative_directory(root: RawFd, relative: &Path) -> Result<OwnedFd, UpdateArchiveError> {
    let mut current = duplicate_descriptor(root, "duplicate-staging")?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(UpdateArchiveError::InvalidPath);
        };
        let name = path_component(name, UpdateArchiveError::InvalidPath)?;
        current = open_directory_at(current.as_raw_fd(), &name, "open-directory")?;
    }
    Ok(current)
}

fn open_directory(path: &Path, stage: &'static str) -> Result<OwnedFd, UpdateArchiveError> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| UpdateArchiveError::InvalidPath)?;
    // SAFETY: path is a live NUL-terminated string; the returned descriptor is
    // checked before ownership is transferred.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_descriptor(descriptor, stage)
}

fn open_directory_at(
    parent: RawFd,
    name: &CString,
    stage: &'static str,
) -> Result<OwnedFd, UpdateArchiveError> {
    // SAFETY: parent is a live descriptor and name is a live NUL-terminated
    // single path component; the returned descriptor is checked before use.
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_descriptor(descriptor, stage)
}

fn duplicate_descriptor(
    descriptor: RawFd,
    stage: &'static str,
) -> Result<OwnedFd, UpdateArchiveError> {
    // SAFETY: descriptor is borrowed for the duration of fcntl; the new
    // descriptor is checked and receives independent ownership.
    let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) };
    owned_descriptor(duplicated, stage)
}

fn owned_descriptor(descriptor: RawFd, stage: &'static str) -> Result<OwnedFd, UpdateArchiveError> {
    if descriptor < 0 {
        return Err(io_error(stage, io::Error::last_os_error()));
    }
    // SAFETY: a non-negative descriptor returned by an ownership-transferring
    // libc call is live and not owned elsewhere in Rust.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn split_parent_and_name(path: &Path) -> Result<(&Path, &OsStr), UpdateArchiveError> {
    let parent = path.parent().ok_or(UpdateArchiveError::InvalidPath)?;
    let name = path.file_name().ok_or(UpdateArchiveError::InvalidPath)?;
    Ok((parent, name))
}

fn path_component(value: &OsStr, error: UpdateArchiveError) -> Result<CString, UpdateArchiveError> {
    CString::new(value.as_bytes()).map_err(|_| error)
}
