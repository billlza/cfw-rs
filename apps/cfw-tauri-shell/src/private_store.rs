//! Bounded private documents with explicit transaction and durability results.
//! Platform adapters keep reads, writes and leases on retained native objects.

#[cfg(unix)]
#[path = "private_store/unix.rs"]
mod native;
#[cfg(windows)]
#[path = "private_store/windows.rs"]
mod native;
pub(crate) use native::PrivateDirectory;

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
    #[cfg(unix)]
    Open(std::io::Error),
    #[cfg(unix)]
    Inspect(std::io::Error),
    UnsafeMetadata,
    Busy,
    Lock(std::io::Error),
}
