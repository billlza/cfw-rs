use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

use super::admission::BundleIdentity;
use super::contract::UpdateAuthorization;
use super::error::{Result, UpdateError};
use super::outcome::InstallOutcome;

#[derive(Default)]
pub(crate) struct UpdaterSecurityState {
    inner: Arc<Mutex<Inner>>,
    check_serialization: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    authorization_generation: u64,
    authorization: Option<UpdateAuthorization>,
    /// The release whose download failed authentication in this run.
    rejected: Option<UpdateAuthorization>,
    previous_attempt: PreviousAttempt,
    install: InstallState,
}

/// Whether the attempt an earlier run recorded has been dealt with. Nothing is
/// staged before it has, because the review removes every staging directory.
#[derive(Default)]
enum PreviousAttempt {
    #[default]
    Unreviewed,
    Reviewed {
        /// What the dashboard has not been told yet.
        unreported: InstallOutcome,
    },
}

/// One installation attempt at a time, from the review of the previous one to
/// the hand-off.
#[derive(Default)]
enum InstallState {
    #[default]
    Idle,
    Reviewing,
    Preparing {
        version: String,
        cancellation: Arc<DownloadCancellation>,
    },
    Staged(StagedUpdate),
    Committing {
        version: String,
    },
}

/// An installation this process is holding, as a reloaded dashboard needs it
/// to offer the matching controls again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct PendingInstall {
    pub(super) phase: PendingPhase,
    pub(super) version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PendingPhase {
    Preparing,
    Staged,
    Committing,
}

/// Ownership of the reviewing slot. Dropping it without `complete` leaves the
/// previous attempt unreviewed, so the next request reviews it again.
pub(super) struct ReviewLease {
    state: Arc<Mutex<Inner>>,
    resolved: bool,
}

/// A verified bundle waiting in its staging area for the user to install it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StagedUpdate {
    pub(super) transaction: Uuid,
    pub(super) installed: BundleIdentity,
    pub(super) staged: BundleIdentity,
}

/// Ownership of the preparing slot. Dropping it without `stage` returns the
/// updater to idle, whatever interrupted the preparation.
pub(super) struct PreparationLease {
    state: Arc<Mutex<Inner>>,
    pub(super) cancellation: Arc<DownloadCancellation>,
    resolved: bool,
}

/// Ownership of the committing slot. Dropping it without `handed_off` returns
/// the staged update to the waiting state, whatever ended the hand-off, so the
/// user can install or discard it without downloading it again.
pub(super) struct CommitLease {
    state: Arc<Mutex<Inner>>,
    staged: StagedUpdate,
    handed_off: bool,
}

pub(super) struct DownloadCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

impl DownloadCancellation {
    pub(super) fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) async fn cancelled(&self) {
        loop {
            // Register before reading the flag so a cancellation between the
            // read and the await still wakes this waiter.
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// What a cancellation request found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Cancelled {
    Nothing,
    /// A download or verification was running and has been told to stop.
    Preparation,
    /// A staged update was discarded; its staging area must be removed.
    Staged(Uuid),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedCheck {
    generation: u64,
    authorization: UpdateAuthorization,
}

impl UpdaterSecurityState {
    pub(super) fn try_serialize_checks(&self) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        self.check_serialization
            .try_lock()
            .map_err(|_| UpdateError::Busy)
    }

    pub(super) fn clear_authorization(&self) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        inner.authorization_generation = inner
            .authorization_generation
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        inner.authorization = None;
        Ok(())
    }

    pub(super) fn authorize(&self, authorization: UpdateAuthorization) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        inner.authorization_generation = inner
            .authorization_generation
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        inner.authorization = Some(authorization);
        Ok(())
    }

    pub(super) fn authorization(&self, expected_version: &str) -> Result<AuthorizedCheck> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let authorization = inner
            .authorization
            .clone()
            .ok_or(UpdateError::MissingAuthorization)?;
        if authorization.version != expected_version {
            inner.authorization_generation = inner
                .authorization_generation
                .checked_add(1)
                .ok_or(UpdateError::StateCounterExhausted)?;
            inner.authorization = None;
            return Err(UpdateError::AuthorizationChanged);
        }
        Ok(AuthorizedCheck {
            generation: inner.authorization_generation,
            authorization,
        })
    }

    /// Atomically validates and consumes the presented authorization after the
    /// network recheck. A mismatch consumes it too, so every terminal open
    /// attempt requires a fresh user-visible check.
    pub(super) fn consume_if_current(
        &self,
        checked: &AuthorizedCheck,
        current: &UpdateAuthorization,
    ) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let matches = inner.authorization_generation == checked.generation
            && inner.authorization.as_ref() == Some(&checked.authorization)
            && current == &checked.authorization;
        inner.authorization_generation = inner
            .authorization_generation
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        inner.authorization = None;
        if !matches {
            return Err(UpdateError::AuthorizationChanged);
        }
        Ok(())
    }

    /// Remembers a release whose download failed authentication, so this run
    /// neither installs it nor points the user at its download page again.
    pub(super) fn reject_release(&self, authorization: &UpdateAuthorization) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        inner.rejected = Some(authorization.clone());
        Ok(())
    }

    pub(super) fn is_rejected(&self, authorization: &UpdateAuthorization) -> Result<bool> {
        let inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        Ok(inner.rejected.as_ref() == Some(authorization))
    }

    /// Claims the installation slot to review the previous attempt. Returns
    /// `None` once it has been reviewed: that happens once per process.
    pub(super) fn begin_review(&self) -> Result<Option<ReviewLease>> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        if matches!(inner.previous_attempt, PreviousAttempt::Reviewed { .. }) {
            return Ok(None);
        }
        if !matches!(inner.install, InstallState::Idle) {
            return Err(UpdateError::InstallAlreadyActive);
        }
        inner.install = InstallState::Reviewing;
        Ok(Some(ReviewLease {
            state: self.inner.clone(),
            resolved: false,
        }))
    }

    /// Hands the reviewed outcome to the dashboard exactly once.
    pub(super) fn take_unreported_outcome(&self) -> Result<InstallOutcome> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        Ok(match &mut inner.previous_attempt {
            PreviousAttempt::Unreviewed => InstallOutcome::None,
            PreviousAttempt::Reviewed { unreported } => {
                std::mem::replace(unreported, InstallOutcome::None)
            }
        })
    }

    pub(super) fn pending(&self) -> Result<Option<PendingInstall>> {
        let inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let pending = |phase, version: &str| PendingInstall {
            phase,
            version: version.to_owned(),
        };
        Ok(match &inner.install {
            InstallState::Idle | InstallState::Reviewing => None,
            InstallState::Preparing { version, .. } => {
                Some(pending(PendingPhase::Preparing, version))
            }
            InstallState::Staged(staged) => {
                Some(pending(PendingPhase::Staged, &staged.staged.version))
            }
            InstallState::Committing { version } => {
                Some(pending(PendingPhase::Committing, version))
            }
        })
    }

    /// Claims the single installation slot for a new download.
    pub(super) fn begin_preparation(&self, version: &str) -> Result<PreparationLease> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        if matches!(inner.previous_attempt, PreviousAttempt::Unreviewed) {
            return Err(UpdateError::PreviousAttemptUnreviewed);
        }
        if !matches!(inner.install, InstallState::Idle) {
            return Err(UpdateError::InstallAlreadyActive);
        }
        let cancellation = Arc::new(DownloadCancellation::new());
        inner.install = InstallState::Preparing {
            version: version.to_owned(),
            cancellation: cancellation.clone(),
        };
        Ok(PreparationLease {
            state: self.inner.clone(),
            cancellation,
            resolved: false,
        })
    }

    /// Stops a running preparation or discards a staged update. Once the
    /// hand-off has begun there is nothing left that can be cancelled.
    pub(super) fn cancel_install(&self) -> Result<Cancelled> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        match &inner.install {
            InstallState::Idle | InstallState::Reviewing => Ok(Cancelled::Nothing),
            // The preparing task still owns the slot and releases it.
            InstallState::Preparing { cancellation, .. } => {
                cancellation.cancel();
                Ok(Cancelled::Preparation)
            }
            InstallState::Staged(staged) => {
                let transaction = staged.transaction;
                inner.install = InstallState::Idle;
                Ok(Cancelled::Staged(transaction))
            }
            InstallState::Committing { .. } => Err(UpdateError::CancellationTooLate),
        }
    }

    /// Takes the staged update of exactly this version for installation.
    pub(super) fn begin_commit(&self, expected_version: &str) -> Result<CommitLease> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let staged = match &inner.install {
            InstallState::Staged(staged) if staged.staged.version == expected_version => {
                staged.clone()
            }
            InstallState::Staged(_) => return Err(UpdateError::AuthorizationChanged),
            InstallState::Idle => return Err(UpdateError::NoStagedUpdate),
            InstallState::Reviewing
            | InstallState::Preparing { .. }
            | InstallState::Committing { .. } => return Err(UpdateError::InstallAlreadyActive),
        };
        inner.install = InstallState::Committing {
            version: staged.staged.version.clone(),
        };
        Ok(CommitLease {
            state: self.inner.clone(),
            staged,
            handed_off: false,
        })
    }
}

impl ReviewLease {
    /// Ends the review: the previous attempt is dealt with and `unreported`
    /// is what the dashboard still has to be told.
    pub(super) fn complete(mut self, unreported: InstallOutcome) -> Result<()> {
        let mut inner = self.state.lock().map_err(|_| UpdateError::StateLock)?;
        inner.previous_attempt = PreviousAttempt::Reviewed { unreported };
        inner.install = InstallState::Idle;
        self.resolved = true;
        Ok(())
    }
}

impl Drop for ReviewLease {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        match self.state.lock() {
            Ok(mut inner) => inner.install = InstallState::Idle,
            Err(_) => eprintln!("updater state lock failed while releasing a review"),
        }
    }
}

impl CommitLease {
    pub(super) fn staged(&self) -> &StagedUpdate {
        &self.staged
    }

    /// The installer process owns the update now; this process only exits.
    pub(super) fn handed_off(mut self) {
        self.handed_off = true;
    }
}

impl Drop for CommitLease {
    fn drop(&mut self) {
        if self.handed_off {
            return;
        }
        match self.state.lock() {
            Ok(mut inner) => inner.install = InstallState::Staged(self.staged.clone()),
            Err(_) => eprintln!("updater state lock failed while releasing a hand-off"),
        }
    }
}

impl PreparationLease {
    /// Records the verified bundle as ready to install.
    pub(super) fn stage(mut self, staged: StagedUpdate) -> Result<()> {
        let mut inner = self.state.lock().map_err(|_| UpdateError::StateLock)?;
        // A cancellation that arrived after the last check still wins: the
        // caller discards what it staged.
        if self.cancellation.is_cancelled() {
            return Err(UpdateError::DownloadCancelled);
        }
        inner.install = InstallState::Staged(staged);
        self.resolved = true;
        Ok(())
    }
}

impl Drop for PreparationLease {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        match self.state.lock() {
            Ok(mut inner) => inner.install = InstallState::Idle,
            Err(_) => eprintln!("updater state lock failed while releasing a preparation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(version: &str) -> UpdateAuthorization {
        UpdateAuthorization {
            version: version.into(),
            archive_name: format!("archive-{version}.tar.gz"),
            download_url: format!("https://github.com/release/{version}"),
            signature: format!("signature-{version}"),
        }
    }

    #[test]
    fn renderer_must_request_the_exact_presented_version() {
        let state = UpdaterSecurityState::default();
        state
            .authorize(authorization("1.2.3"))
            .expect("presented check");
        assert!(state.authorization("1.2.3").is_ok());
        assert!(matches!(
            state.authorization("1.2.4"),
            Err(UpdateError::AuthorizationChanged)
        ));
        assert!(matches!(
            state.authorization("1.2.3"),
            Err(UpdateError::MissingAuthorization)
        ));
    }

    #[test]
    fn recheck_must_match_the_exact_presented_authorization() {
        let state = UpdaterSecurityState::default();
        let first = authorization("1.2.3");
        state.authorize(first.clone()).expect("presented check");
        let checked = state.authorization("1.2.3").expect("authorization");
        state
            .consume_if_current(&checked, &first)
            .expect("matching recheck");
        assert!(matches!(
            state.authorization("1.2.3"),
            Err(UpdateError::MissingAuthorization)
        ));

        state.authorize(first.clone()).expect("second check");
        let checked = state.authorization("1.2.3").expect("authorization");
        assert!(matches!(
            state.consume_if_current(&checked, &authorization("1.2.4")),
            Err(UpdateError::AuthorizationChanged)
        ));
        assert!(matches!(
            state.authorization("1.2.3"),
            Err(UpdateError::MissingAuthorization)
        ));
    }

    #[test]
    fn any_intervening_check_invalidates_the_presented_snapshot() {
        let state = UpdaterSecurityState::default();
        let first = authorization("1.2.3");
        state.authorize(first.clone()).expect("first check");
        let checked = state.authorization("1.2.3").expect("authorization");
        state
            .authorize(authorization("1.2.4"))
            .expect("intervening check");
        assert!(matches!(
            state.consume_if_current(&checked, &first),
            Err(UpdateError::AuthorizationChanged)
        ));
    }

    #[test]
    fn consumed_authorization_cannot_be_replayed() {
        let state = UpdaterSecurityState::default();
        state
            .authorize(authorization("1.2.3"))
            .expect("presented check");
        state.clear_authorization().expect("consume authorization");
        assert!(matches!(
            state.authorization("1.2.3"),
            Err(UpdateError::MissingAuthorization)
        ));
    }

    fn staged(version: &str) -> StagedUpdate {
        StagedUpdate {
            transaction: Uuid::from_u128(11),
            installed: BundleIdentity {
                version: "0.4.0".into(),
                build: 40074,
            },
            staged: BundleIdentity {
                version: version.into(),
                build: 50021,
            },
        }
    }

    /// A state whose previous attempt has been reviewed with nothing to report.
    fn reviewed() -> UpdaterSecurityState {
        let state = UpdaterSecurityState::default();
        state
            .begin_review()
            .expect("review slot")
            .expect("first review")
            .complete(InstallOutcome::None)
            .expect("reviewed");
        state
    }

    fn pending(phase: PendingPhase) -> Option<PendingInstall> {
        Some(PendingInstall {
            phase,
            version: "0.5.0".into(),
        })
    }

    #[test]
    fn nothing_is_prepared_before_the_previous_attempt_was_reviewed() {
        let state = UpdaterSecurityState::default();
        assert!(matches!(
            state.begin_preparation("0.5.0"),
            Err(UpdateError::PreviousAttemptUnreviewed)
        ));

        let review = state.begin_review().expect("slot").expect("first review");
        assert!(
            matches!(state.begin_review(), Err(UpdateError::InstallAlreadyActive)),
            "one review at a time"
        );
        assert_eq!(state.pending().expect("pending"), None);
        assert_eq!(
            state.cancel_install().expect("nothing to cancel"),
            Cancelled::Nothing
        );
        drop(review);
        assert!(
            matches!(
                state.begin_preparation("0.5.0"),
                Err(UpdateError::PreviousAttemptUnreviewed)
            ),
            "an abandoned review leaves the attempt unreviewed"
        );

        let outcome = InstallOutcome::Failed {
            version: "0.5.0".into(),
            code: "exchange_failed".into(),
        };
        state
            .begin_review()
            .expect("slot")
            .expect("second review")
            .complete(outcome.clone())
            .expect("reviewed");
        assert!(
            state.begin_review().expect("slot").is_none(),
            "the previous attempt is reviewed once per process"
        );
        assert_eq!(state.take_unreported_outcome().expect("outcome"), outcome);
        assert_eq!(
            state.take_unreported_outcome().expect("outcome"),
            InstallOutcome::None,
            "the outcome is reported once"
        );
        drop(state.begin_preparation("0.5.0").expect("preparation"));
    }

    #[test]
    fn a_release_that_failed_authentication_stays_rejected_until_it_changes() {
        let state = UpdaterSecurityState::default();
        let release = authorization("1.2.3");
        assert!(!state.is_rejected(&release).expect("query"));
        state.reject_release(&release).expect("reject");
        assert!(state.is_rejected(&release).expect("query"));
        state.authorize(release.clone()).expect("fresh check");
        assert!(
            state.is_rejected(&release).expect("query"),
            "a fresh check of the same release does not clear the verdict"
        );
        let mut republished = release.clone();
        republished.signature = "another-signature".into();
        assert!(!state.is_rejected(&republished).expect("query"));
        assert!(!state.is_rejected(&authorization("1.2.4")).expect("query"));
    }

    #[test]
    fn one_installation_occupies_the_slot_until_its_preparation_ends() {
        let state = reviewed();
        let lease = state.begin_preparation("0.5.0").expect("first preparation");
        assert_eq!(
            state.pending().expect("pending"),
            pending(PendingPhase::Preparing)
        );
        assert!(matches!(
            state.begin_preparation("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ));
        assert!(matches!(
            state.begin_commit("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ));
        drop(lease);
        assert!(matches!(
            state.begin_commit("0.5.0"),
            Err(UpdateError::NoStagedUpdate)
        ));
        assert_eq!(state.pending().expect("pending"), None);
        drop(
            state
                .begin_preparation("0.5.0")
                .expect("slot is free after an abandoned preparation"),
        );
    }

    #[test]
    fn cancelling_a_preparation_signals_it_and_refuses_a_late_stage() {
        let state = reviewed();
        assert_eq!(state.cancel_install().expect("idle"), Cancelled::Nothing);
        let lease = state.begin_preparation("0.5.0").expect("preparation");
        assert!(!lease.cancellation.is_cancelled());
        assert_eq!(
            state.cancel_install().expect("cancel"),
            Cancelled::Preparation
        );
        assert!(lease.cancellation.is_cancelled());
        assert!(
            matches!(
                state.begin_preparation("0.5.0"),
                Err(UpdateError::InstallAlreadyActive)
            ),
            "the cancelled task still owns the slot until it stops"
        );
        assert!(matches!(
            lease.stage(staged("0.5.0")),
            Err(UpdateError::DownloadCancelled)
        ));
        drop(
            state
                .begin_preparation("0.5.0")
                .expect("slot is free after the cancelled task ended"),
        );
    }

    #[test]
    fn a_staged_update_is_committed_only_for_its_exact_version() {
        let state = reviewed();
        state
            .begin_preparation("0.5.0")
            .expect("preparation")
            .stage(staged("0.5.0"))
            .expect("staged");
        assert_eq!(
            state.pending().expect("pending"),
            pending(PendingPhase::Staged)
        );
        assert!(matches!(
            state.begin_preparation("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ));
        assert!(matches!(
            state.begin_commit("0.5.1"),
            Err(UpdateError::AuthorizationChanged)
        ));
        let committing = state.begin_commit("0.5.0").expect("commit");
        assert_eq!(committing.staged(), &staged("0.5.0"));
        assert_eq!(
            state.pending().expect("pending"),
            pending(PendingPhase::Committing)
        );
        assert!(matches!(
            state.begin_commit("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ));
        assert!(matches!(
            state.cancel_install(),
            Err(UpdateError::CancellationTooLate)
        ));

        drop(committing);
        assert_eq!(
            state.pending().expect("pending"),
            pending(PendingPhase::Staged),
            "a hand-off that ended without the installer keeps the update staged"
        );
        assert_eq!(
            state.cancel_install().expect("discard"),
            Cancelled::Staged(Uuid::from_u128(11))
        );
        assert_eq!(state.cancel_install().expect("idle"), Cancelled::Nothing);
        assert_eq!(state.pending().expect("pending"), None);
    }

    #[test]
    fn a_completed_hand_off_never_returns_the_update_to_the_waiting_state() {
        let state = reviewed();
        state
            .begin_preparation("0.5.0")
            .expect("preparation")
            .stage(staged("0.5.0"))
            .expect("staged");
        state.begin_commit("0.5.0").expect("commit").handed_off();
        assert_eq!(
            state.pending().expect("pending"),
            pending(PendingPhase::Committing)
        );
        assert!(matches!(
            state.cancel_install(),
            Err(UpdateError::CancellationTooLate)
        ));
        assert!(matches!(
            state.begin_commit("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ));
    }

    #[test]
    fn pending_installations_serialize_as_phase_and_version() {
        assert_eq!(
            serde_json::to_value(pending(PendingPhase::Staged)).expect("serialize"),
            serde_json::json!({ "phase": "staged", "version": "0.5.0" })
        );
        assert_eq!(
            serde_json::to_value(None::<PendingInstall>).expect("serialize"),
            serde_json::Value::Null
        );
        for (phase, name) in [
            (PendingPhase::Preparing, "preparing"),
            (PendingPhase::Committing, "committing"),
        ] {
            assert_eq!(
                serde_json::to_value(phase).expect("serialize"),
                serde_json::json!(name)
            );
        }
    }

    #[tokio::test]
    async fn cancellation_wakes_a_registered_waiter_and_stays_set() {
        let cancellation = Arc::new(DownloadCancellation::new());
        let waiter = {
            let cancellation = cancellation.clone();
            tokio::spawn(async move { cancellation.cancelled().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the waiter is woken")
            .expect("waiter task");
        tokio::time::timeout(std::time::Duration::from_secs(5), cancellation.cancelled())
            .await
            .expect("a later waiter returns immediately");
    }

    #[test]
    fn concurrent_checks_are_rejected_instead_of_queued() {
        let state = UpdaterSecurityState::default();
        let first = state.try_serialize_checks().expect("first check");
        assert!(matches!(
            state.try_serialize_checks(),
            Err(UpdateError::Busy)
        ));
        drop(first);
        let second = state
            .try_serialize_checks()
            .expect("capacity returns after the active check");
        assert!(matches!(
            state.try_serialize_checks(),
            Err(UpdateError::Busy)
        ));
        drop(second);
    }
}
