use thiserror::Error;

use super::archive::UpdateArchiveError;
use super::contract::UpdateContractError;
use super::install_admission::InstallAdmissionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownloadFailureStage {
    ClientBuild,
    MetadataRequest,
    MetadataBody,
    Request,
    ResponseBody,
}

impl std::fmt::Display for DownloadFailureStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ClientBuild => "client-build",
            Self::MetadataRequest => "metadata-request",
            Self::MetadataBody => "metadata-body",
            Self::Request => "request",
            Self::ResponseBody => "response-body",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkFailureCategory {
    Timeout,
    Connect,
    Status,
    Body,
    Decode,
    Request,
    Other,
}

impl std::fmt::Display for NetworkFailureCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Status => "status",
            Self::Body => "body",
            Self::Decode => "decode",
            Self::Request => "request",
            Self::Other => "other",
        })
    }
}

#[derive(Debug, Error)]
pub(super) enum UpdateError {
    #[error(transparent)]
    Archive(#[from] UpdateArchiveError),
    #[error(transparent)]
    Contract(#[from] UpdateContractError),
    #[error("no validated update check authorizes this installation")]
    MissingAuthorization,
    #[error("the update changed after it was presented; check for updates again")]
    AuthorizationChanged,
    #[error("an update download is already active")]
    DownloadAlreadyActive,
    #[error("the update download was cancelled")]
    DownloadCancelled,
    #[error("the update can no longer be cancelled because commit preparation has started")]
    InstallationAlreadyStarted,
    #[error("cannot stop the network engine before update commit")]
    EngineStop,
    #[error("network engine did not reach a proven Off state before update commit")]
    EngineNotOff,
    #[error("the update cannot reserve its exclusive network maintenance barrier")]
    EngineMaintenanceUnavailable,
    #[error(transparent)]
    InstallAdmission(#[from] InstallAdmissionError),
    #[error("updater state lock failed")]
    StateLock,
    #[error("updater state counter is exhausted")]
    StateCounterExhausted,
    #[error("no rustls crypto provider is available for the bounded update client")]
    TlsProviderUnavailable,
    #[error(
        "update network operation failed during {stage} (category: {category}, HTTP status: {status_code:?})"
    )]
    Network {
        stage: DownloadFailureStage,
        category: NetworkFailureCategory,
        status_code: Option<u16>,
    },
    #[error("update server returned HTTP status {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("update metadata Content-Length {declared} exceeds the {maximum}-byte limit")]
    MetadataDeclaredTooLarge { declared: u64, maximum: u64 },
    #[error("update metadata exceeds the {maximum}-byte limit")]
    MetadataTooLarge { maximum: u64 },
    #[error("update metadata is empty")]
    EmptyMetadata,
    #[error("update metadata Content-Length was {declared}, but {actual} bytes were received")]
    MetadataLengthMismatch { declared: u64, actual: u64 },
    #[error("update metadata is not valid strict JSON: {0}")]
    InvalidMetadata(String),
    #[error("update redirect violates the release download policy: {0}")]
    Redirect(String),
    #[error("update Content-Length {declared} exceeds the {maximum}-byte limit")]
    DeclaredArchiveTooLarge { declared: u64, maximum: u64 },
    #[error("update archive exceeds the {maximum}-byte limit")]
    ArchiveTooLarge { maximum: u64 },
    #[error("cannot allocate the bounded update archive buffer")]
    ArchiveAllocation,
    #[error("update archive is empty")]
    EmptyArchive,
    #[error("update Content-Length was {declared}, but {actual} bytes were received")]
    ContentLengthMismatch { declared: u64, actual: u64 },
    #[error("embedded updater public key is invalid")]
    InvalidPublicKey,
    #[error("update signature is invalid")]
    InvalidSignature,
    #[error("update signature trusted comment is invalid")]
    InvalidSignatureComment,
    #[error("update signature is bound to a different archive")]
    SignatureArchiveMismatch,
    #[error("update signature verification failed")]
    SignatureVerification,
    #[error("failed to publish update progress")]
    ProgressEvent,
    #[error("the bounded update installation worker terminated unexpectedly")]
    InstallationWorkerFailed,
}

pub(super) type Result<T> = std::result::Result<T, UpdateError>;
