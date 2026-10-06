use std::path::Path;

use serde::Serialize;
use thiserror::Error;

use super::error::FailureCategory;
use super::journal::{
    InstallJournal, InstallPhase, InstallRecord, Recorded, UpdateInstallLease,
    UpdateInstallLeaseError,
};
use super::staging::remove_all;
use crate::legacy::ProcessIdentity;

/// What the last installation attempt left behind, reported once to the
/// dashboard that starts after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(super) enum InstallOutcome {
    None,
    Installed { version: String },
    Failed { version: String, code: String },
}

/// Why the previous attempt could not be turned into an outcome.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ReviewError {
    /// An installer process, or the dashboard that started it, is still at
    /// work. Nothing was read or removed.
    #[error("an update installation is in progress")]
    InstallationInProgress,
    /// Storage or process observation failed. Nothing was removed; the next
    /// review tries again.
    #[error("the previous update attempt could not be reviewed: {0}")]
    Unavailable(String),
    /// The stored record was not one this version can interpret. It and its
    /// staging were removed, so later installations are not blocked by it.
    #[error("an update installation record this version cannot interpret was discarded: {0}")]
    RecordDiscarded(String),
}

impl ReviewError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::InstallationInProgress => "install_in_progress",
            Self::Unavailable(_) => "previous_attempt_unreviewable",
            Self::RecordDiscarded(_) => "update_record_discarded",
        }
    }

    pub(super) const fn category(&self) -> FailureCategory {
        match self {
            Self::InstallationInProgress => FailureCategory::Busy,
            // Neither is a lack of space or a volume the user can change: the
            // detail is in the diagnostic journal.
            Self::Unavailable(_) | Self::RecordDiscarded(_) => FailureCategory::Internal,
        }
    }
}

/// Resolves the recorded attempt against the version that is now running,
/// removes every staging directory (after a successful exchange one of them
/// holds the replaced bundle) and clears the record.
///
/// The running version, not the recorded phase, decides whether the exchange
/// happened: the installer may have been interrupted between the exchange and
/// its last record update.
///
/// An attempt that is still in flight is left alone. The installer holds the
/// installation lease while it works, and before it is admitted the dashboard
/// that handed off is still running.
pub(super) fn review_previous_attempt(
    app_home: &Path,
    running_version: &str,
    dashboard_running: impl FnOnce(&ProcessIdentity) -> Result<bool, String>,
) -> Result<InstallOutcome, ReviewError> {
    let _lease = UpdateInstallLease::acquire(app_home).map_err(|error| match error {
        UpdateInstallLeaseError::Held => ReviewError::InstallationInProgress,
        UpdateInstallLeaseError::Unavailable(detail) => ReviewError::Unavailable(detail),
    })?;
    let journal = InstallJournal::new(app_home);
    let staging_removed = || {
        remove_all(app_home).map_err(|error| {
            ReviewError::Unavailable(format!("update staging could not be removed: {error}"))
        })
    };
    let record = match journal.inspect().map_err(ReviewError::Unavailable)? {
        Recorded::Absent => {
            staging_removed()?;
            return Ok(InstallOutcome::None);
        }
        Recorded::Uninterpretable(detail) => {
            staging_removed()?;
            journal
                .discard_uninterpretable()
                .map_err(ReviewError::Unavailable)?;
            return Err(ReviewError::RecordDiscarded(detail));
        }
        Recorded::Valid(record) => record,
    };
    if matches!(
        record.phase,
        InstallPhase::HandedOff | InstallPhase::Decommissioned
    ) && dashboard_running(&record.dashboard).map_err(ReviewError::Unavailable)?
    {
        return Err(ReviewError::InstallationInProgress);
    }
    let outcome = classify(&record, running_version);
    staging_removed()?;
    journal
        .clear(&record.transaction)
        .map_err(ReviewError::Unavailable)?;
    Ok(outcome)
}

fn classify(record: &InstallRecord, running_version: &str) -> InstallOutcome {
    let failed = |code: &str| InstallOutcome::Failed {
        version: record.to.version.clone(),
        code: code.to_owned(),
    };
    if running_version == record.to.version {
        return match record.phase {
            InstallPhase::Aborted => InstallOutcome::None,
            InstallPhase::HandedOff | InstallPhase::Decommissioned | InstallPhase::Swapped => {
                InstallOutcome::Installed {
                    version: record.to.version.clone(),
                }
            }
        };
    }
    if running_version != record.from.version {
        // Another copy was installed by other means; the record is obsolete.
        return InstallOutcome::None;
    }
    match record.phase {
        InstallPhase::Aborted => failed(
            record
                .failure
                .as_deref()
                .expect("a valid aborted record carries its code"),
        ),
        InstallPhase::HandedOff | InstallPhase::Decommissioned => failed("installer_interrupted"),
        InstallPhase::Swapped => failed("installed_version_reverted"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use super::super::journal::tests::record;
    use super::super::staging::StagingArea;
    use super::*;

    struct Attempt {
        home: tempfile::TempDir,
        journal: InstallJournal,
        transaction: Uuid,
        staging: StagingArea,
    }

    fn attempt() -> Attempt {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let transaction = Uuid::from_u128(31);
        let staging = StagingArea::create(home.path(), &transaction, &installed).expect("staging");
        fs::create_dir_all(staging.bundle().join("Contents")).expect("retained bundle");
        let journal = InstallJournal::new(home.path());
        journal.begin(&record(31)).expect("hand-off");
        Attempt {
            home,
            journal,
            transaction,
            staging,
        }
    }

    fn advance(attempt: &Attempt, phases: &[InstallPhase]) {
        let mut current = InstallPhase::HandedOff;
        for next in phases {
            attempt
                .journal
                .advance(&attempt.transaction, current, *next)
                .expect("advance");
            current = *next;
        }
    }

    /// Reviews with the recorded dashboard gone, as after a completed hand-off.
    fn review(home: &Path, running_version: &str) -> Result<InstallOutcome, ReviewError> {
        review_previous_attempt(home, running_version, |_| Ok(false))
    }

    fn installed() -> InstallOutcome {
        InstallOutcome::Installed {
            version: "0.5.0".into(),
        }
    }

    fn failed(code: &str) -> InstallOutcome {
        InstallOutcome::Failed {
            version: "0.5.0".into(),
            code: code.into(),
        }
    }

    #[test]
    fn the_new_version_reports_success_whatever_phase_was_last_recorded() {
        for phases in [
            &[][..],
            &[InstallPhase::Decommissioned][..],
            &[InstallPhase::Decommissioned, InstallPhase::Swapped][..],
        ] {
            let attempt = attempt();
            advance(&attempt, phases);
            assert_eq!(
                review(attempt.home.path(), "0.5.0"),
                Ok(installed()),
                "{phases:?}"
            );
            assert!(
                !attempt.staging.bundle().exists(),
                "the replaced bundle is removed"
            );
            assert_eq!(attempt.journal.load().expect("load"), None);
            assert_eq!(
                review(attempt.home.path(), "0.5.0"),
                Ok(InstallOutcome::None),
                "the outcome is reported once"
            );
        }
    }

    #[test]
    fn the_old_version_reports_why_it_is_still_running() {
        let aborted = attempt();
        aborted
            .journal
            .abort(&aborted.transaction, "application_reopened")
            .expect("abort");
        assert_eq!(
            review(aborted.home.path(), "0.4.0"),
            Ok(failed("application_reopened"))
        );
        assert!(
            !aborted.staging.bundle().exists(),
            "the unused staged bundle is removed"
        );

        for (phases, code) in [
            (&[][..], "installer_interrupted"),
            (&[InstallPhase::Decommissioned][..], "installer_interrupted"),
            (
                &[InstallPhase::Decommissioned, InstallPhase::Swapped][..],
                "installed_version_reverted",
            ),
        ] {
            let attempt = attempt();
            advance(&attempt, phases);
            assert_eq!(
                review(attempt.home.path(), "0.4.0"),
                Ok(failed(code)),
                "{phases:?}"
            );
            assert_eq!(attempt.journal.load().expect("load"), None);
        }
    }

    #[test]
    fn an_attempt_whose_dashboard_is_still_running_is_left_untouched() {
        for phases in [&[][..], &[InstallPhase::Decommissioned][..]] {
            let attempt = attempt();
            advance(&attempt, phases);
            let before = attempt.journal.load().expect("load");
            assert_eq!(
                review_previous_attempt(attempt.home.path(), "0.4.0", |dashboard| {
                    assert_eq!(dashboard, &record(31).dashboard);
                    Ok(true)
                }),
                Err(ReviewError::InstallationInProgress),
                "{phases:?}"
            );
            assert_eq!(attempt.journal.load().expect("load"), before);
            assert!(
                attempt.staging.bundle().exists(),
                "the staged bundle of a live hand-off is kept"
            );

            assert_eq!(
                review_previous_attempt(attempt.home.path(), "0.4.0", |_| {
                    Err("observation failed".into())
                }),
                Err(ReviewError::Unavailable("observation failed".into()))
            );
            assert_eq!(attempt.journal.load().expect("load"), before);
            assert!(attempt.staging.bundle().exists());
        }

        // Once the bundles were exchanged, or the attempt was aborted, the
        // dashboard that handed off no longer matters.
        let swapped = attempt();
        advance(
            &swapped,
            &[InstallPhase::Decommissioned, InstallPhase::Swapped],
        );
        assert_eq!(
            review_previous_attempt(swapped.home.path(), "0.5.0", |_| {
                panic!("an exchanged attempt does not observe its dashboard")
            }),
            Ok(installed())
        );
    }

    #[test]
    fn a_running_installer_keeps_the_record_and_its_staging() {
        let attempt = attempt();
        let installer = UpdateInstallLease::acquire(attempt.home.path()).expect("installer lease");
        assert_eq!(
            review(attempt.home.path(), "0.4.0"),
            Err(ReviewError::InstallationInProgress)
        );
        assert!(attempt.journal.load().expect("load").is_some());
        assert!(attempt.staging.bundle().exists());
        drop(installer);
        assert_eq!(
            review(attempt.home.path(), "0.4.0"),
            Ok(failed("installer_interrupted"))
        );
    }

    #[test]
    fn an_unrelated_running_version_discards_the_obsolete_record_silently() {
        let attempt = attempt();
        assert_eq!(
            review(attempt.home.path(), "0.6.0"),
            Ok(InstallOutcome::None)
        );
        assert_eq!(attempt.journal.load().expect("load"), None);
        assert!(!attempt.staging.bundle().exists());
    }

    #[test]
    fn without_a_record_only_abandoned_staging_is_removed() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let abandoned =
            StagingArea::create(home.path(), &Uuid::from_u128(32), &installed).expect("staging");
        assert_eq!(review(home.path(), "0.4.0"), Ok(InstallOutcome::None));
        assert!(!abandoned.payload().exists());
        assert!(installed.is_dir());
    }

    #[test]
    fn a_record_this_version_cannot_interpret_is_discarded_and_reported_once() {
        let attempt = attempt();
        let path = attempt.home.path().join("update-install-v1.json");
        fs::write(&path, br#"{"schema_version":2}"#).expect("a record of another schema");
        assert!(matches!(
            review(attempt.home.path(), "0.4.0"),
            Err(ReviewError::RecordDiscarded(_))
        ));
        assert!(!path.exists());
        assert!(!attempt.staging.bundle().exists());
        assert_eq!(
            review(attempt.home.path(), "0.4.0"),
            Ok(InstallOutcome::None),
            "later reviews and installations are no longer blocked"
        );
        attempt
            .journal
            .begin(&record(33))
            .expect("a new attempt can be recorded");
    }

    #[test]
    fn staging_that_cannot_be_removed_keeps_the_record_for_the_next_review() {
        let attempt = attempt();
        let updates = attempt.home.path().join("updates");
        let moved = attempt.home.path().join("moved");
        fs::rename(&updates, &moved).expect("move staging aside");
        std::os::unix::fs::symlink(&moved, &updates).expect("a link in place of staging");
        assert!(matches!(
            review(attempt.home.path(), "0.4.0"),
            Err(ReviewError::Unavailable(_))
        ));
        assert!(
            attempt.journal.load().expect("load").is_some(),
            "the record is cleared only after its staging is gone"
        );
        assert!(
            moved
                .join(attempt.transaction.hyphenated().to_string())
                .exists()
        );
    }

    #[test]
    fn outcomes_serialize_as_a_tagged_state() {
        assert_eq!(
            serde_json::to_value(installed()).expect("serialize"),
            serde_json::json!({ "state": "installed", "version": "0.5.0" })
        );
        assert_eq!(
            serde_json::to_value(failed("exchange_failed")).expect("serialize"),
            serde_json::json!({
                "state": "failed",
                "version": "0.5.0",
                "code": "exchange_failed",
            })
        );
        assert_eq!(
            serde_json::to_value(InstallOutcome::None).expect("serialize"),
            serde_json::json!({ "state": "none" })
        );
    }
}
