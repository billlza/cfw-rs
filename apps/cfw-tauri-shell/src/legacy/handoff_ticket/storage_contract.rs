pub(crate) const HANDOFF_DIRECTORY: &str = ".migration-handoff-v2";
pub(crate) const MAX_DOCUMENT_BYTES: u64 = 16 * 1024;
pub(crate) const MAX_HANDOFF_DOCUMENTS: usize = 64;

#[cfg(unix)]
pub(crate) type LockedDocument = std::fs::File;
#[cfg(windows)]
pub(crate) type LockedDocument = cfw_windows_storage::ExclusiveDocument;

pub(crate) struct WriteNewFailure {
    pub(crate) message: String,
    pub(crate) quarantine: Option<LockedDocument>,
}
