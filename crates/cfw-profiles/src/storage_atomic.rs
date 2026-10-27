use crate::ProfileError;

#[cfg(target_os = "macos")]
#[path = "storage/macos_atomic.rs"]
mod platform;

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
