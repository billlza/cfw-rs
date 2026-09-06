use std::sync::{Arc, Mutex};

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
