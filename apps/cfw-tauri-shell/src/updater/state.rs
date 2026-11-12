use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

use super::admission::BundleIdentity;
use super::contract::UpdateAuthorization;
use super::error::{Result, UpdateError};
use super::outcome::InstallOutcome;

pub(crate) struct UpdaterSecurityState<R = super::StagedResources> {
    inner: Arc<Mutex<Inner<R>>>,
    check_serialization: tokio::sync::Mutex<()>,
}

struct Inner<R> {
    authorization_generation: u64,
    authorization: Option<UpdateAuthorization>,
    /// The release whose download failed authentication in this run.
    rejected: Option<UpdateAuthorization>,
    previous_attempt: PreviousAttempt,
    install: InstallState<R>,
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
enum InstallState<R> {
    Idle,
    Reviewing,
    Preparing {
        version: String,
        cancellation: Arc<DownloadCancellation>,
    },
    Staged(StagedUpdate<R>),
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
pub(super) struct ReviewLease<R> {
    state: Arc<Mutex<Inner<R>>>,
    resolved: bool,
}

/// A verified release and its owned platform resources waiting for installation.
/// Resource custody moves through staging, commit and cancellation; it is never
/// reconstructed by cloning a path or a version claim.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct StagedUpdate<R = super::StagedResources> {
    pub(super) transaction: Uuid,
    pub(super) offer_version: String,
    pub(super) installed: BundleIdentity,
    pub(super) staged: BundleIdentity,
    pub(super) resources: R,
}

/// Ownership of the preparing slot. Dropping it without `stage` returns the
/// updater to idle, whatever interrupted the preparation.
pub(super) struct PreparationLease<R> {
    state: Arc<Mutex<Inner<R>>>,
    pub(super) cancellation: Arc<DownloadCancellation>,
    resolved: bool,
}

/// Ownership of the committing slot. Dropping it without `handed_off` returns
/// the staged update to the waiting state, whatever ended the hand-off, so the
/// user can install or discard it without downloading it again.
pub(super) struct CommitLease<R> {
    state: Arc<Mutex<Inner<R>>>,
    staged: Option<StagedUpdate<R>>,
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
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Cancelled<R = super::StagedResources> {
    Nothing,
    /// A download or verification was running and has been told to stop.
    Preparation,
    /// A staged update was discarded; its staging area must be removed.
    Staged(StagedUpdate<R>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedCheck {
    generation: u64,
    authorization: UpdateAuthorization,
}

impl<R> Default for UpdaterSecurityState<R> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                authorization_generation: 0,
                authorization: None,
                rejected: None,
                previous_attempt: PreviousAttempt::default(),
                install: InstallState::Idle,
            })),
            check_serialization: tokio::sync::Mutex::new(()),
        }
    }
}

impl<R> UpdaterSecurityState<R> {
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
    pub(super) fn begin_review(&self) -> Result<Option<ReviewLease<R>>> {
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
                Some(pending(PendingPhase::Staged, &staged.offer_version))
            }
            InstallState::Committing { version } => {
                Some(pending(PendingPhase::Committing, version))
            }
        })
    }

    /// Claims the single installation slot for a new download.
    pub(super) fn begin_preparation(&self, version: &str) -> Result<PreparationLease<R>> {
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
    pub(super) fn cancel_install(&self) -> Result<Cancelled<R>> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        match &inner.install {
            InstallState::Idle | InstallState::Reviewing => Ok(Cancelled::Nothing),
            // The preparing task still owns the slot and releases it.
            InstallState::Preparing { cancellation, .. } => {
                cancellation.cancel();
                Ok(Cancelled::Preparation)
            }
            InstallState::Staged(_) => {
                match std::mem::replace(&mut inner.install, InstallState::Idle) {
                    InstallState::Staged(staged) => Ok(Cancelled::Staged(staged)),
                    _ => Err(UpdateError::StateOwnership),
                }
            }
            InstallState::Committing { .. } => Err(UpdateError::CancellationTooLate),
        }
    }

    /// Takes the staged update of exactly this version for installation.
    pub(super) fn begin_commit(&self, expected_version: &str) -> Result<CommitLease<R>> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let version = match &inner.install {
            InstallState::Staged(staged) if staged.offer_version == expected_version => {
                staged.offer_version.clone()
            }
            InstallState::Staged(_) => return Err(UpdateError::AuthorizationChanged),
            InstallState::Idle => return Err(UpdateError::NoStagedUpdate),
            InstallState::Reviewing
            | InstallState::Preparing { .. }
            | InstallState::Committing { .. } => return Err(UpdateError::InstallAlreadyActive),
        };
        let previous = std::mem::replace(&mut inner.install, InstallState::Committing { version });
        let InstallState::Staged(staged) = previous else {
            return Err(UpdateError::StateOwnership);
        };
        Ok(CommitLease {
            state: self.inner.clone(),
            staged: Some(staged),
            handed_off: false,
        })
    }
}

impl<R> ReviewLease<R> {
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

impl<R> Drop for ReviewLease<R> {
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

impl<R> CommitLease<R> {
    pub(super) fn staged(&self) -> Result<&StagedUpdate<R>> {
        self.staged.as_ref().ok_or(UpdateError::StateOwnership)
    }

    /// The installer process owns the update now; this process only exits.
    pub(super) fn handed_off(mut self) {
        self.handed_off = true;
    }
}

impl<R> Drop for CommitLease<R> {
    fn drop(&mut self) {
        if self.handed_off {
            return;
        }
        match self.state.lock() {
            Ok(mut inner) => match self.staged.take() {
                Some(staged) => inner.install = InstallState::Staged(staged),
                None => eprintln!("updater commit lease lost its staged resources"),
            },
            Err(_) => eprintln!("updater state lock failed while releasing a hand-off"),
        }
    }
}

impl<R> PreparationLease<R> {
    /// Records the verified bundle as ready to install.
    pub(super) fn stage(mut self, staged: StagedUpdate<R>) -> Result<()> {
        let mut inner = self.state.lock().map_err(|_| UpdateError::StateLock)?;
        // A cancellation that arrived after the last check still wins: the
        // caller discards what it staged.
        if self.cancellation.is_cancelled() {
            return Err(UpdateError::DownloadCancelled);
        }
        if !matches!(&inner.install, InstallState::Preparing { version, .. }
            if version == &staged.offer_version)
        {
            return Err(UpdateError::AuthorizationChanged);
        }
        inner.install = InstallState::Staged(staged);
        self.resolved = true;
        Ok(())
    }
}

impl<R> Drop for PreparationLease<R> {
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
mod tests;
