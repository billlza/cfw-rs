use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use uuid::Uuid;

use super::{GenerationStoreError, MAX_LINEAGE_BYTES};

pub(super) const LINEAGE_FILE: &str = "engine-lineage.json";
const LOCK_FILE: &str = ".engine-lineage.lock";

pub(super) fn prepare_root(root: &Path) -> Result<(), GenerationStoreError> {
    fs::create_dir_all(root).map_err(|source| GenerationStoreError::Io {
        operation: "create-lineage-cache-root",
        source,
    })?;
    let metadata = fs::symlink_metadata(root).map_err(|source| GenerationStoreError::Io {
        operation: "inspect-lineage-cache-root",
        source,
    })?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(GenerationStoreError::UnsafeRoot(root.to_path_buf()));
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(root, Permissions::from_mode(0o700)).map_err(|source| {
            GenerationStoreError::Io {
                operation: "protect-lineage-cache-root",
                source,
            }
        })?;
    }
    Ok(())
}

pub(super) fn exclusive_lock(root: &Path) -> Result<FileLock, GenerationStoreError> {
    let path = root.join(LOCK_FILE);
    let file = open_regular_file(&path, true)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(GenerationStoreError::Io {
            operation: "lock-lineage-cache",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(FileLock { _file: file })
}

pub(super) fn read(root: &Path) -> Result<Option<Vec<u8>>, GenerationStoreError> {
    let path = root.join(LINEAGE_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_existing(&path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(GenerationStoreError::Io {
            operation: "inspect-lineage-cache",
            source,
        }),
    }
}

pub(super) fn write(root: &Path, bytes: &[u8]) -> Result<(), GenerationStoreError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
    }
    let temporary = root.join(format!(".{LINEAGE_FILE}.{}.tmp", Uuid::new_v4()));
    let target = root.join(LINEAGE_FILE);
    let write_result: Result<(), GenerationStoreError> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|source| GenerationStoreError::Io {
                operation: "create-lineage-cache-temporary",
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| GenerationStoreError::Io {
                operation: "write-lineage-cache-temporary",
                source,
            })?;
        file.sync_all().map_err(|source| GenerationStoreError::Io {
            operation: "sync-lineage-cache-temporary",
            source,
        })?;
        fs::rename(&temporary, &target).map_err(|source| GenerationStoreError::Io {
            operation: "replace-lineage-cache",
            source,
        })?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| GenerationStoreError::Io {
                operation: "sync-lineage-cache-directory",
                source,
            })
    })();

    match write_result {
        Ok(()) => Ok(()),
        Err(write_error) => {
            if temporary.exists()
                && let Err(cleanup_error) = fs::remove_file(&temporary)
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

fn read_existing(path: &Path) -> Result<Vec<u8>, GenerationStoreError> {
    let mut file = open_regular_file(path, false)?;
    let length = file
        .metadata()
        .map_err(|source| GenerationStoreError::Io {
            operation: "stat-lineage-cache",
            source,
        })?
        .len();
    if length == 0 || length > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(length));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_LINEAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| GenerationStoreError::Io {
            operation: "read-lineage-cache",
            source,
        })?;
    if bytes.len() as u64 > MAX_LINEAGE_BYTES {
        return Err(GenerationStoreError::DocumentTooLarge(bytes.len() as u64));
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, create: bool) -> Result<File, GenerationStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| GenerationStoreError::Io {
            operation: "open-lineage-cache-file",
            source,
        })?;
    let metadata = file.metadata().map_err(|source| GenerationStoreError::Io {
        operation: "inspect-open-lineage-cache-file",
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(GenerationStoreError::UnsafeFile(path.to_path_buf()));
    }
    if metadata.mode() & 0o077 != 0 {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|source| GenerationStoreError::Io {
                operation: "protect-lineage-cache-file",
                source,
            })?;
    }
    Ok(file)
}

pub(super) struct FileLock {
    _file: File,
}
