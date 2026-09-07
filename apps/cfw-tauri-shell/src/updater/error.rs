use thiserror::Error;

use super::contract::UpdateContractError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownloadFailureStage {
    ClientBuild,
    MetadataRequest,
    MetadataBody,
}

impl std::fmt::Display for DownloadFailureStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ClientBuild => "client-build",
            Self::MetadataRequest => "metadata-request",
            Self::MetadataBody => "metadata-body",
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
    Contract(#[from] UpdateContractError),
    #[error("no validated update check authorizes this release page")]
    MissingAuthorization,
    #[error("the update changed after it was presented; check for updates again")]
    AuthorizationChanged,
    #[error("updater state lock failed")]
    StateLock,
    #[error("updater state counter is exhausted")]
    StateCounterExhausted,
    #[error("an update check or release-page authorization is already in progress")]
    Busy,
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
    #[error("update metadata contains a non-canonical release version")]
    InvalidReleaseVersion,
    #[error("failed to publish the update result")]
    ProgressEvent,
    #[error("the official update release page could not be opened")]
    OpenReleasePage,
}

pub(super) type Result<T> = std::result::Result<T, UpdateError>;
