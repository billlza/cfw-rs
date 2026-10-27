use super::{
    HANDOFF_DIRECTORY, LockedDocument, MAX_DOCUMENT_BYTES, MAX_HANDOFF_DOCUMENTS, WriteNewFailure,
};
use cfw_windows_storage::{Error, PrivateDirectory as NativeDirectory};
use std::{fs::File, path::Path};

pub(super) struct PrivateDirectory {
    native: NativeDirectory,
}

impl PrivateDirectory {
    pub(super) fn open_or_create(root: &Path) -> Result<Self, String> {
        let parent = NativeDirectory::open_existing(root)
            .map_err(|error| format!("failed to open private handoff root: {error}"))?
            .ok_or("private handoff root is absent")?;
        let native = parent
            .open_or_create_child(HANDOFF_DIRECTORY)
            .map_err(|error| format!("failed to open private handoff directory: {error}"))?;
        Ok(Self { native })
    }

    pub(super) fn entry_names(&self) -> Result<Vec<String>, String> {
        self.native
            .read()
            .and_then(|transaction| transaction.entry_names(MAX_HANDOFF_DOCUMENTS))
            .map_err(|error| format!("failed to enumerate handoff documents: {error}"))?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| "handoff directory contains a non-UTF-8 document name".into())
            })
            .collect()
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
        self.native
            .write_new_exclusive_document(name, bytes, maximum(), File::sync_all)
            .map_err(|failure| WriteNewFailure {
                message: format!("failed to publish handoff document: {}", failure.error),
                quarantine: failure.quarantine,
            })
    }

    pub(super) fn read_locked_optional(
        &self,
        name: &str,
    ) -> Result<Option<(LockedDocument, Vec<u8>)>, String> {
        self.read_with_busy(name, false)
    }

    pub(super) fn read_ready_locked_optional(
        &self,
        name: &str,
    ) -> Result<Option<(LockedDocument, Vec<u8>)>, String> {
        self.read_with_busy(name, true)
    }

    fn read_with_busy(
        &self,
        name: &str,
        writer_busy_is_pending: bool,
    ) -> Result<Option<(LockedDocument, Vec<u8>)>, String> {
        match self.native.read_exclusive_document(name, maximum()) {
            Ok(value) => Ok(value),
            Err(Error::Busy) if writer_busy_is_pending => Ok(None),
            Err(error) => Err(format!("failed to read locked handoff document: {error}")),
        }
    }

    pub(super) fn unlink_locked(&self, name: &str, file: LockedDocument) -> Result<(), String> {
        self.native
            .unlink_exclusive_document(name, file)
            .map_err(|error| format!("failed to consume handoff document: {error}"))
    }

    pub(super) fn unlink_optional(&self, name: &str) -> Result<(), String> {
        let Some((file, _)) = self.read_locked_optional(name)? else {
            return Ok(());
        };
        self.unlink_locked(name, file)
    }
}

fn maximum() -> usize {
    const {
        assert!(MAX_DOCUMENT_BYTES <= usize::MAX as u64);
    }
    MAX_DOCUMENT_BYTES as usize
}
