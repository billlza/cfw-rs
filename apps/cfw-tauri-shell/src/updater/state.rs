use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::contract::UpdateAuthorization;
use super::error::{Result, UpdateError};

#[derive(Default)]
pub(crate) struct UpdaterSecurityState {
    inner: Arc<Mutex<Inner>>,
    check_serialization: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    authorization_generation: u64,
    authorization: Option<UpdateAuthorization>,
    next_download_id: u64,
    active: Option<ActiveDownload>,
}

struct ActiveDownload {
    id: u64,
    phase: ActivePhase,
    cancellation: Arc<DownloadCancellation>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActivePhase {
    Downloading,
    Committing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedCheck {
    generation: u64,
    pub(super) authorization: UpdateAuthorization,
}

pub(super) struct DownloadLease {
    state: Arc<Mutex<Inner>>,
    id: u64,
    pub(super) cancellation: Arc<DownloadCancellation>,
}

pub(super) struct DownloadCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

impl UpdaterSecurityState {
    pub(super) async fn serialize_checks(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.check_serialization.lock().await
    }

    pub(super) fn clear_authorization(&self) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        if inner.active.is_some() {
            return Err(UpdateError::DownloadAlreadyActive);
        }
        inner.authorization_generation = inner
            .authorization_generation
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        inner.authorization = None;
        Ok(())
    }

    pub(super) fn authorize(&self, authorization: UpdateAuthorization) -> Result<AuthorizedCheck> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        if inner.active.is_some() {
            return Err(UpdateError::DownloadAlreadyActive);
        }
        inner.authorization_generation = inner
            .authorization_generation
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        inner.authorization = Some(authorization.clone());
        Ok(AuthorizedCheck {
            generation: inner.authorization_generation,
            authorization,
        })
    }

    pub(super) fn authorization(&self, expected_version: &str) -> Result<AuthorizedCheck> {
        let inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let authorization = inner
            .authorization
            .clone()
            .ok_or(UpdateError::MissingAuthorization)?;
        if authorization.version != expected_version {
            return Err(UpdateError::AuthorizationChanged);
        }
        Ok(AuthorizedCheck {
            generation: inner.authorization_generation,
            authorization,
        })
    }

    pub(super) fn begin_download(
        &self,
        checked: &AuthorizedCheck,
        current: &UpdateAuthorization,
    ) -> Result<DownloadLease> {
        let mut inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let authorization_is_current = inner.authorization_generation == checked.generation
            && inner.authorization.as_ref() == Some(&checked.authorization)
            && current == &checked.authorization;
        if !authorization_is_current {
            return Err(UpdateError::AuthorizationChanged);
        }
        if inner.active.is_some() {
            return Err(UpdateError::DownloadAlreadyActive);
        }

        inner.next_download_id = inner
            .next_download_id
            .checked_add(1)
            .ok_or(UpdateError::StateCounterExhausted)?;
        let id = inner.next_download_id;
        let cancellation = Arc::new(DownloadCancellation::new());
        inner.active = Some(ActiveDownload {
            id,
            phase: ActivePhase::Downloading,
            cancellation: cancellation.clone(),
        });
        Ok(DownloadLease {
            state: self.inner.clone(),
            id,
            cancellation,
        })
    }

    pub(super) fn cancel_download(&self) -> Result<bool> {
        let inner = self.inner.lock().map_err(|_| UpdateError::StateLock)?;
        let Some(active) = inner.active.as_ref() else {
            return Ok(false);
        };
        if active.phase == ActivePhase::Committing {
            return Err(UpdateError::InstallationAlreadyStarted);
        }
        active.cancellation.cancel();
        Ok(true)
    }
}

impl DownloadLease {
    pub(super) fn begin_commit(&self) -> Result<()> {
        let mut inner = self.state.lock().map_err(|_| UpdateError::StateLock)?;
        let active = inner
            .active
            .as_mut()
            .filter(|active| active.id == self.id)
            .ok_or(UpdateError::AuthorizationChanged)?;
        if active.cancellation.is_cancelled() {
            return Err(UpdateError::DownloadCancelled);
        }
        active.phase = ActivePhase::Committing;
        Ok(())
    }
}

impl Drop for DownloadLease {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.state.lock()
            && inner.active.as_ref().map(|active| active.id) == Some(self.id)
        {
            inner.active = None;
        }
    }
}

impl DownloadCancellation {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_one();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
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
    fn second_check_must_match_the_presented_authorization() {
        let state = UpdaterSecurityState::default();
        let first = state
            .authorize(authorization("1.2.3"))
            .expect("first check");
        let changed = authorization("1.2.4");
        assert!(matches!(
            state.begin_download(&first, &changed),
            Err(UpdateError::AuthorizationChanged)
        ));
    }

    #[test]
    fn intervening_check_invalidates_an_install_snapshot() {
        let state = UpdaterSecurityState::default();
        let first = state
            .authorize(authorization("1.2.3"))
            .expect("first check");
        state
            .authorize(authorization("1.2.4"))
            .expect("intervening check");
        assert!(matches!(
            state.begin_download(&first, &first.authorization),
            Err(UpdateError::AuthorizationChanged)
        ));
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
    }

    #[test]
    fn exact_second_check_gets_one_exclusive_download_lease() {
        let state = UpdaterSecurityState::default();
        let checked = state.authorize(authorization("1.2.3")).expect("check");
        let lease = state
            .begin_download(&checked, &checked.authorization)
            .expect("matching download");
        assert!(matches!(
            state.begin_download(&checked, &checked.authorization),
            Err(UpdateError::DownloadAlreadyActive)
        ));
        drop(lease);
        assert!(
            state
                .begin_download(&checked, &checked.authorization)
                .is_ok()
        );
    }

    #[test]
    fn cancellation_is_observable_until_installation_starts() {
        let state = UpdaterSecurityState::default();
        let checked = state.authorize(authorization("1.2.3")).expect("check");
        let lease = state
            .begin_download(&checked, &checked.authorization)
            .expect("download");
        assert!(matches!(state.cancel_download(), Ok(true)));
        assert!(lease.cancellation.is_cancelled());
        assert!(matches!(
            lease.begin_commit(),
            Err(UpdateError::DownloadCancelled)
        ));
    }

    #[test]
    fn commit_boundary_atomically_closes_cancellation_before_network_stop() {
        let state = UpdaterSecurityState::default();
        let checked = state.authorize(authorization("1.2.3")).expect("check");
        let lease = state
            .begin_download(&checked, &checked.authorization)
            .expect("download");
        lease.begin_commit().expect("commit phase");
        assert!(matches!(
            state.cancel_download(),
            Err(UpdateError::InstallationAlreadyStarted)
        ));
    }
}
