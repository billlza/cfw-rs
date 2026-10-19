//! Windows Authority metadata and recovery, never a persistent executable lease.
//! No ticket, capability, configuration, credential, endpoint or secret is part
//! of this schema. Even a valid Off record requires fresh OS cleanup evidence.
mod codec;
mod model;
#[cfg(windows)]
mod store;
#[cfg(all(windows, feature = "native-service-validation"))]
pub use store::JournalFaultPoint;
#[cfg(windows)]
pub use store::{JournalRecovery, JournalStoreError, WindowsAuthorityJournal};

pub use codec::{DecodedJournal, EncodedRecord, decode_journal, encode_record};
pub use model::{
    AuthorityCommittedState, JournalAnchor, JournalCursor, JournalOperation, JournalTransition,
    RecordedOwner, RecoveryAction,
};

pub const MAX_RECORD_PAYLOAD: usize = 64 * 1024;
pub const MAX_RECORDS: u64 = 4096;
pub const MAX_JOURNAL_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_HEAD_BYTES: usize = 1024;
pub const MAX_ANCHOR_BYTES: usize = 2048;
pub const LIFECYCLE_FINISH_RESERVE: u64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JournalValidationError {
    #[error("authority journal schema is unsupported")]
    UnsupportedSchema,
    #[error("authority journal state or identity is invalid")]
    InvalidState,
    #[error("authority journal encoding is malformed or noncanonical")]
    Encoding,
    #[error("authority journal exceeds its bound")]
    Capacity,
    #[error("authority journal frame is truncated")]
    Truncated,
    #[error("authority journal checksum, hash chain or cursor does not match")]
    Integrity,
    #[error("authority journal revision or generation moved backwards or out of order")]
    Sequence,
    #[error("authority journal pending anchor is inconsistent")]
    Anchor,
}

#[cfg(test)]
mod tests;
