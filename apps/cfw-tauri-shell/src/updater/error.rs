use serde::Serialize;
use thiserror::Error;

use super::admission::InstallAdmissionError;
use super::archive::UpdateArchiveError;
use super::contract::UpdateContractError;
use super::outcome::ReviewError;
use super::services::ServiceStateError;
use super::staged_bundle::StagedBundleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownloadFailureStage {
    ClientBuild,
    MetadataRequest,
    MetadataBody,
    ArchiveRequest,
    ArchiveBody,
}

impl std::fmt::Display for DownloadFailureStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ClientBuild => "client-build",
            Self::MetadataRequest => "metadata-request",
            Self::MetadataBody => "metadata-body",
            Self::ArchiveRequest => "archive-request",
            Self::ArchiveBody => "archive-body",
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

    #[error(transparent)]
    InstallAdmission(#[from] InstallAdmissionError),
    #[error("another update operation is in progress")]
    InstallAlreadyActive,
    #[error("the previous update attempt has not been reviewed")]
    PreviousAttemptUnreviewed,
    #[error(transparent)]
    PreviousAttempt(#[from] ReviewError),
    #[error("this release failed authentication earlier in this run")]
    ReleaseRejected,
    #[error("no verified update is staged for installation")]
    NoStagedUpdate,
    #[error("the update download was cancelled")]
    DownloadCancelled,
    #[error("the update installation can no longer be cancelled")]
    CancellationTooLate,
    #[error("update archive Content-Length {declared} exceeds the {maximum}-byte limit")]
    DeclaredArchiveTooLarge { declared: u64, maximum: u64 },
    #[error("update archive exceeds the {maximum}-byte limit")]
    ArchiveTooLarge { maximum: u64 },
    #[error("update archive is empty")]
    EmptyArchive,
    #[error("update archive Content-Length was {declared}, but {actual} bytes were received")]
    ArchiveLengthMismatch { declared: u64, actual: u64 },
    #[error("update download was redirected outside the release asset origin: {0}")]
    Redirect(String),
    #[error("the embedded update public key is invalid")]
    InvalidPublicKey,
    #[error("the update signature envelope is invalid")]
    InvalidSignature,
    #[error("the update signature trusted comment is invalid")]
    InvalidSignatureComment,
    #[error("the update signature names a different archive")]
    SignatureArchiveMismatch,
    #[error("the update archive does not match its signature")]
    SignatureVerification,
    #[error("update staging failed during {stage} ({kind:?})")]
    Staging {
        stage: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error(transparent)]
    Archive(#[from] UpdateArchiveError),
    #[error(transparent)]
    StagedBundle(#[from] StagedBundleError),
    #[error(transparent)]
    Services(#[from] ServiceStateError),
    #[error("the core did not stop for the update: {0}")]
    EngineStop(String),
    #[error("the update installation record could not be stored: {0}")]
    Journal(String),
    #[error("the update installer did not start: {0}")]
    InstallerStart(String),
    #[error("the update installer's log could not be opened ({0:?})")]
    InstallerLog(std::io::ErrorKind),
    #[error("the application lifecycle did not admit the update: {0}")]
    Lifecycle(String),
    #[error("application data is unavailable: {0}")]
    AppHome(String),
    #[error("this process could not be identified: {0}")]
    ProcessIdentity(String),
    #[error("an updater task ended without a result")]
    TaskFailed,
}

pub(super) type Result<T> = std::result::Result<T, UpdateError>;

/// How much of a tool's own words an error carries into the diagnostic
/// journal.
const DIAGNOSTIC_DETAIL_LIMIT: usize = 1024;

/// Reduces a tool's diagnostic to one bounded line for the journal; the whole
/// output stays in the process log.
pub(super) fn bounded_diagnostic(detail: &str) -> String {
    let joined = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut bounded: String = joined.chars().take(DIAGNOSTIC_DETAIL_LIMIT).collect();
    if joined.chars().count() > DIAGNOSTIC_DETAIL_LIMIT {
        bounded.push('…');
    }
    bounded
}

/// What the user can do about a failed installation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FailureCategory {
    /// The request no longer matches updater state; check again.
    State,
    /// Another update operation holds the updater; nothing was changed.
    Busy,
    /// This installation cannot be replaced in place; use the disk image.
    Environment,
    /// A transfer failed; retrying later may succeed.
    Network,
    /// Local storage refused the staged update.
    Storage,
    /// The download is not the release that was signed. Never retried
    /// automatically and never answered by pointing at another download.
    Authenticity,
    /// A genuine release that this installation must not install.
    Package,
    /// The core could not be stopped safely.
    Engine,
    Internal,
}

/// The stable, renderer-visible description of an installation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct UpdateFailure {
    pub(crate) code: &'static str,
    pub(crate) category: FailureCategory,
}

impl UpdateError {
    pub(super) fn failure(&self) -> UpdateFailure {
        use FailureCategory as Category;
        let (code, category) = match self {
            Self::Contract(_) => ("metadata_contract", Category::Package),
            Self::MissingAuthorization => ("missing_authorization", Category::State),
            Self::AuthorizationChanged => ("authorization_changed", Category::State),
            Self::StateLock | Self::StateCounterExhausted | Self::PreviousAttemptUnreviewed => {
                ("updater_state", Category::Internal)
            }
            Self::Busy => ("busy", Category::Busy),
            Self::TlsProviderUnavailable => ("tls_unavailable", Category::Internal),
            Self::Network { .. } => ("network", Category::Network),
            Self::HttpStatus(_) => ("http_status", Category::Network),
            Self::MetadataDeclaredTooLarge { .. }
            | Self::MetadataTooLarge { .. }
            | Self::EmptyMetadata
            | Self::MetadataLengthMismatch { .. }
            | Self::InvalidMetadata(_)
            | Self::InvalidReleaseVersion => ("metadata_invalid", Category::Package),
            Self::ProgressEvent => ("progress_event", Category::Internal),
            Self::OpenReleasePage => ("open_release_page", Category::Internal),
            Self::InstallAdmission(error) => (error.code(), Category::Environment),
            Self::InstallAlreadyActive => ("install_already_active", Category::Busy),
            Self::PreviousAttempt(error) => (error.code(), error.category()),
            Self::ReleaseRejected => ("release_failed_authentication", Category::Authenticity),
            Self::NoStagedUpdate => ("no_staged_update", Category::State),
            Self::DownloadCancelled => ("download_cancelled", Category::State),
            Self::CancellationTooLate => ("cancellation_too_late", Category::State),
            Self::DeclaredArchiveTooLarge { .. }
            | Self::ArchiveTooLarge { .. }
            | Self::EmptyArchive => ("archive_size", Category::Package),
            Self::ArchiveLengthMismatch { .. } => ("archive_truncated", Category::Network),
            Self::Redirect(_) => ("redirect_rejected", Category::Network),
            Self::InvalidPublicKey => ("public_key_invalid", Category::Internal),
            Self::InvalidSignature | Self::InvalidSignatureComment => {
                ("signature_invalid", Category::Authenticity)
            }
            Self::SignatureArchiveMismatch => {
                ("signature_archive_mismatch", Category::Authenticity)
            }
            Self::SignatureVerification => ("signature_mismatch", Category::Authenticity),
            Self::Staging { .. } => ("staging_io", Category::Storage),
            Self::Archive(error) => (error.code(), Category::Package),
            Self::StagedBundle(error) => (error.code(), error.category()),
            Self::Services(error) => (error.code(), error.category()),
            Self::EngineStop(_) => ("engine_stop_failed", Category::Engine),
            Self::Journal(_) => ("journal_failed", Category::Storage),
            Self::InstallerStart(_) => ("installer_start_failed", Category::Internal),
            Self::InstallerLog(_) => ("installer_log_unavailable", Category::Storage),
            Self::Lifecycle(_) => ("lifecycle_busy", Category::Busy),
            Self::AppHome(_) => ("app_home_unavailable", Category::Storage),
            Self::ProcessIdentity(_) => ("process_identity_unavailable", Category::Internal),
            Self::TaskFailed => ("updater_task_failed", Category::Internal),
        };
        UpdateFailure { code, category }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticity_failures_are_their_own_category() {
        for error in [
            UpdateError::InvalidSignature,
            UpdateError::InvalidSignatureComment,
            UpdateError::SignatureArchiveMismatch,
            UpdateError::SignatureVerification,
            UpdateError::ReleaseRejected,
            UpdateError::StagedBundle(StagedBundleError::SignatureRejected("codesign".into())),
        ] {
            assert_eq!(
                error.failure().category,
                FailureCategory::Authenticity,
                "{error}"
            );
        }
    }

    #[test]
    fn transfer_failures_are_distinct_from_authenticity() {
        for error in [
            UpdateError::Network {
                stage: DownloadFailureStage::ArchiveBody,
                category: NetworkFailureCategory::Timeout,
                status_code: None,
            },
            UpdateError::HttpStatus(reqwest::StatusCode::BAD_GATEWAY),
            UpdateError::ArchiveLengthMismatch {
                declared: 2,
                actual: 1,
            },
        ] {
            assert_eq!(
                error.failure().category,
                FailureCategory::Network,
                "{error}"
            );
        }
    }

    #[test]
    fn a_held_updater_is_reported_as_busy_and_not_as_changed_state() {
        for error in [
            UpdateError::Busy,
            UpdateError::InstallAlreadyActive,
            UpdateError::Lifecycle("shutdown".into()),
            UpdateError::PreviousAttempt(ReviewError::InstallationInProgress),
        ] {
            assert_eq!(error.failure().category, FailureCategory::Busy, "{error}");
        }
        assert_eq!(
            UpdateError::NoStagedUpdate.failure(),
            UpdateFailure {
                code: "no_staged_update",
                category: FailureCategory::State,
            }
        );
        // A review that could not finish is not a storage condition the user
        // can relieve by freeing space.
        for error in [
            UpdateError::PreviousAttempt(ReviewError::Unavailable("detail".into())),
            UpdateError::PreviousAttempt(ReviewError::RecordDiscarded("detail".into())),
        ] {
            assert_eq!(
                error.failure().category,
                FailureCategory::Internal,
                "{error}"
            );
        }
    }

    #[test]
    fn a_tool_diagnostic_is_carried_as_one_bounded_line() {
        assert_eq!(
            bounded_diagnostic("tar: Error\n  opening\tarchive\n"),
            "tar: Error opening archive"
        );
        let long = "x ".repeat(2000);
        let carried = bounded_diagnostic(&long);
        assert_eq!(carried.chars().count(), DIAGNOSTIC_DETAIL_LIMIT + 1);
        assert!(carried.ends_with('…'));
        assert_eq!(
            bounded_diagnostic(&"y".repeat(DIAGNOSTIC_DETAIL_LIMIT))
                .chars()
                .count(),
            DIAGNOSTIC_DETAIL_LIMIT
        );
    }

    #[test]
    fn failure_serialization_exposes_only_the_stable_fields() {
        let encoded = serde_json::to_value(UpdateError::SignatureVerification.failure())
            .expect("serialize failure");
        assert_eq!(
            encoded,
            serde_json::json!({
                "code": "signature_mismatch",
                "category": "authenticity",
            })
        );
        assert_eq!(
            serde_json::to_value(FailureCategory::Busy).expect("serialize category"),
            serde_json::json!("busy")
        );
    }

    #[test]
    fn every_failure_code_is_a_valid_diagnostic_code() {
        for error in [
            UpdateError::MissingAuthorization,
            UpdateError::Busy,
            UpdateError::ReleaseRejected,
            UpdateError::PreviousAttemptUnreviewed,
            UpdateError::PreviousAttempt(ReviewError::Unavailable("detail".into())),
            UpdateError::PreviousAttempt(ReviewError::RecordDiscarded("detail".into())),
            UpdateError::Services(ServiceStateError::Unavailable("detail".into())),
            UpdateError::InstallAdmission(InstallAdmissionError::StagingVolumeMismatch),
            UpdateError::Archive(UpdateArchiveError::EscapingSymlink),
            UpdateError::StagedBundle(StagedBundleError::RequiresNewerSystem),
            UpdateError::InstallerStart("detail".into()),
            UpdateError::InstallerLog(std::io::ErrorKind::PermissionDenied),
            UpdateError::AppHome("detail".into()),
            UpdateError::ProcessIdentity("detail".into()),
            UpdateError::TaskFailed,
        ] {
            let code = error.failure().code;
            assert!(
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "{code}"
            );
        }
    }
}
