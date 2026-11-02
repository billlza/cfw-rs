use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use uuid::Uuid;

use super::{GenerationStoreError, MAX_LINEAGE_BYTES};

pub(super) const LINEAGE_FILE: &str = "engine-lineage.json";
const LOCK_FILE: &str = ".engine-lineage.lock";

/// Runs one named filesystem step and reports its failure under that name.
/// The crate's tests can make a named step fail once.
fn io<T>(
    operation: &'static str,
    step: impl FnOnce() -> std::io::Result<T>,
) -> Result<T, GenerationStoreError> {
    let failed = |source| GenerationStoreError::Io { operation, source };
    #[cfg(test)]
    super::failpoint::check(operation).map_err(failed)?;
    step().map_err(failed)
}

pub(super) fn prepare_root(root: &Path) -> Result<(), GenerationStoreError> {
    io("create-lineage-cache-root", || fs::create_dir_all(root))?;
    let metadata = io("inspect-lineage-cache-root", || fs::symlink_metadata(root))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(GenerationStoreError::UnsafeRoot(root.to_path_buf()));
    }
    if metadata.mode() & 0o077 != 0 {
        io("protect-lineage-cache-root", || {
            fs::set_permissions(root, Permissions::from_mode(0o700))
        })?;
    }
    Ok(())
}

pub(super) fn exclusive_lock(root: &Path) -> Result<FileLock, GenerationStoreError> {
    const WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(3);
    const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
    let path = root.join(LOCK_FILE);
    let file = open_regular_file(&path, true)?;
    let deadline = std::time::Instant::now() + WAIT_LIMIT;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(FileLock { _file: file });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            if std::time::Instant::now() >= deadline {
                return Err(GenerationStoreError::Io {
                    operation: "lock-lineage-cache",
                    source: std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "engine lineage cache remained locked for 3 seconds",
                    ),
                });
            }
            continue;
        }
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(GenerationStoreError::Io {
                operation: "lock-lineage-cache",
                source: error,
            });
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(GenerationStoreError::Io {
                operation: "lock-lineage-cache",
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "engine lineage cache remained locked for 3 seconds",
                ),
            });
        }
        std::thread::sleep(RETRY_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

pub(super) fn read(root: &Path) -> Result<Option<Vec<u8>>, GenerationStoreError> {
    let path = root.join(LINEAGE_FILE);
    let exists = io("inspect-lineage-cache", || {
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    })?;
    if exists {
        read_existing(&path).map(Some)
    } else {
        Ok(None)
    }
}

pub(super) fn write(root: &Path, bytes: &[u8]) -> Result<(), GenerationStoreError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
    }
    let temporary = root.join(format!(".{LINEAGE_FILE}.{}.tmp", Uuid::new_v4()));
    let target = root.join(LINEAGE_FILE);
    let write_result: Result<(), GenerationStoreError> = (|| {
        let mut file = io("create-lineage-cache-temporary", || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)
        })?;
        io("write-lineage-cache-temporary", || file.write_all(bytes))?;
        io("sync-lineage-cache-temporary", || file.sync_all())?;
        io("replace-lineage-cache", || fs::rename(&temporary, &target))?;
        io("sync-lineage-cache-directory", || {
            File::open(root).and_then(|directory| directory.sync_all())
        })
    })();

    match write_result {
        Ok(()) => Ok(()),
        Err(write_error) => {
            if temporary.exists()
                && let Err(cleanup_error) = remove_temporary(&temporary)
            {
                return Err(GenerationStoreError::WriteAndCleanupFailed {
                    write_error: write_error.to_string(),
                    cleanup_error,
                });
            }
            Err(write_error)
        }
    }
}

/// Removes a temporary a failed write left behind.
fn remove_temporary(temporary: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    super::failpoint::check("remove-lineage-cache-temporary")?;
    fs::remove_file(temporary)
}

fn read_existing(path: &Path) -> Result<Vec<u8>, GenerationStoreError> {
    let mut file = open_regular_file(path, false)?;
    let length = io("stat-lineage-cache", || file.metadata())?.len();
    if length == 0 || length > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(length));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    io("read-lineage-cache", || {
        Read::by_ref(&mut file)
            .take(MAX_LINEAGE_BYTES + 1)
            .read_to_end(&mut bytes)
    })?;
    if bytes.len() as u64 > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, create: bool) -> Result<File, GenerationStoreError> {
    let file = io("open-lineage-cache-file", || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
    })?;
    let metadata = io("inspect-open-lineage-cache-file", || file.metadata())?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(GenerationStoreError::UnsafeFile(path.to_path_buf()));
    }
    if metadata.mode() & 0o077 != 0 {
        io("protect-lineage-cache-file", || {
            file.set_permissions(Permissions::from_mode(0o600))
        })?;
    }
    Ok(file)
}

pub(super) struct FileLock {
    _file: File,
}

#[cfg(test)]
mod tests;
