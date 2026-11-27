use std::future::Future;
use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineMode;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, oneshot};

pub(super) const MAX_PENDING_MODE_CHANGES: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EngineModeChangeIntent {
    Set(EngineMode),
    ReapplyCurrent,
    /// Storage work that leaves the runtime and its mode as they are. It
    /// takes its turn like the others, so maintenance and mode changes see
    /// it, but it is no new intent: an automatic request or a diagnostic that
    /// observed the current intent stays current.
    KeepRuntime,
}

pub(super) struct EngineMaintenanceGate {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
    mode_serial: Arc<AsyncMutex<()>>,
}

#[derive(Default)]
struct EngineMaintenanceInner {
    active_mode_changes: usize,
    maintenance_active: bool,
    intent_revision: u64,
    /// The latest revision at which a registered intent was asked for, none
    /// until one is. That intent supersedes the leases of that revision or an
    /// earlier one, whose automatic retries end, and an automatic request
    /// that expects such a revision, which is stale. An intent is asked for
    /// as it is registered, and a change of the runtime preferences at its
    /// press, before what it asks is read. Each moves the revision on as it is
    /// asked for, so a revision observed after that is later than the intent.
    superseded_through: Option<u64>,
}

impl EngineMaintenanceInner {
    /// Whether one more change may be counted among the pending ones.
    fn admits_another(&self) -> Result<(), EngineMaintenanceError> {
        if self.maintenance_active {
            return Err(EngineMaintenanceError::AlreadyActive);
        }
        if self.active_mode_changes >= MAX_PENDING_MODE_CHANGES {
            return Err(EngineMaintenanceError::QueueFull);
        }
        Ok(())
    }

    /// Moves the revision on for what is asked for now, and answers the
    /// revision it was asked for at: one observed after this is later.
    fn ask(&mut self) -> Result<u64, EngineMaintenanceError> {
        let asked_at = self.intent_revision;
        self.intent_revision = asked_at
            .checked_add(1)
            .ok_or(EngineMaintenanceError::StateLock)?;
        Ok(asked_at)
    }

    /// Registers a new intent that was asked for at revision `asked_at`: it
    /// supersedes every intent registered by then. The registration moves the
    /// revision on, and its lease takes the revision it moved to.
    fn register_intent(&mut self, asked_at: u64) -> Result<(), EngineMaintenanceError> {
        self.ask()?;
        self.superseded_through = Some(
            self.superseded_through
                .map_or(asked_at, |through| through.max(asked_at)),
        );
        Ok(())
    }

    /// Whether an intent asked for at `revision` or after it was registered:
    /// a lease of that revision, or an expectation of it, is superseded.
    fn superseded(&self, revision: u64) -> bool {
        self.superseded_through
            .is_some_and(|through| through >= revision)
    }
}

pub(crate) struct EngineModeChangeLease {
    _intent: EngineModeChangeIntent,
    revision: u64,
    _serial: OwnedMutexGuard<()>,
    // Declared after the serial guard so Rust drops the guard first. The
    // pending count remains non-zero during ownership handoff to the next
    // waiter, leaving no instant in which maintenance can slip between them.
    _registration: EngineModeChangeRegistration,
}

struct EngineModeChangeRegistration {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
}

pub(crate) struct EngineMaintenanceLease {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
}

/// A change of the runtime preferences counted among the mode changes from
/// its press ([`EngineMaintenanceGate::register_reapply`]), which takes its
/// turn once what it asks has been read. Dropped before then, it gives up its
/// place and was no intent.
pub(super) struct PendingReapply {
    pressed: u64,
    serial: Arc<AsyncMutex<()>>,
    registration: EngineModeChangeRegistration,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EngineMaintenanceError {
    StateLock,
    AlreadyActive,
    ModeChangeActive,
    QueueFull,
    StaleIntent,
}

impl std::fmt::Display for EngineMaintenanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StateLock => "network maintenance state lock failed",
            Self::AlreadyActive => {
                "network mode changes are blocked while exclusive network maintenance is active"
            }
            Self::ModeChangeActive => "a network mode change is already in progress",
            Self::QueueFull => "the bounded network mode change queue is full",
            Self::StaleIntent => "a newer network operation superseded this automatic request",
        })
    }
}

impl EngineMaintenanceGate {
    pub(super) async fn begin_mode_change(
        &self,
        intent: EngineModeChangeIntent,
    ) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        self.begin_mode_change_if_current(intent, None).await
    }

    pub(super) fn intent_revision(&self) -> Result<u64, EngineMaintenanceError> {
        self.inner
            .lock()
            .map(|inner| inner.intent_revision)
            .map_err(|_| EngineMaintenanceError::StateLock)
    }

    pub(super) async fn begin_mode_change_if_current(
        &self,
        intent: EngineModeChangeIntent,
        expected: Option<u64>,
    ) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        let (registration, revision) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| EngineMaintenanceError::StateLock)?;
            inner.admits_another()?;
            if expected.is_some_and(|revision| inner.superseded(revision)) {
                return Err(EngineMaintenanceError::StaleIntent);
            }
            if intent != EngineModeChangeIntent::KeepRuntime {
                let asked_at = inner.intent_revision;
                inner.register_intent(asked_at)?;
            }
            inner.active_mode_changes += 1;
            (
                EngineModeChangeRegistration {
                    inner: self.inner.clone(),
                },
                inner.intent_revision,
            )
        };

        // Register before awaiting the fair single-flight lock. Maintenance
        // therefore sees both queued and executing mutations, including Off.
        // If this future is cancelled while waiting, `registration` drops and
        // removes the pending count instead of leaking a permanent busy state.
        let serial = self.mode_serial.clone().lock_owned().await;
        // An intent asked for after this automatic request supersedes it while
        // it waits, as it would end its retries; a change of the runtime
        // preferences pressed before it does not.
        if expected.is_some()
            && self
                .inner
                .lock()
                .map_err(|_| EngineMaintenanceError::StateLock)?
                .superseded(revision)
        {
            return Err(EngineMaintenanceError::StaleIntent);
        }
        Ok(EngineModeChangeLease {
            _intent: intent,
            revision,
            _serial: serial,
            _registration: registration,
        })
    }

    /// Counts a change of the runtime preferences among the mode changes from
    /// its press, while what it asks is read before its turn: the bound of
    /// the queue refuses it before that read, and maintenance waits for it.
    /// The press moves the revision on, so a revision observed after it, by a
    /// network rule while the change is read for one, is later than the change
    /// and stays current. It is a new intent only once it takes its turn, so
    /// one refused before then is none ([`PendingReapply`]).
    pub(super) fn register_reapply(&self) -> Result<PendingReapply, EngineMaintenanceError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EngineMaintenanceError::StateLock)?;
        inner.admits_another()?;
        let pressed = inner.ask()?;
        inner.active_mode_changes += 1;
        Ok(PendingReapply {
            pressed,
            serial: self.mode_serial.clone(),
            registration: EngineModeChangeRegistration {
                inner: self.inner.clone(),
            },
        })
    }

    pub(super) fn reserve_if_idle(&self) -> Result<EngineMaintenanceLease, EngineMaintenanceError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EngineMaintenanceError::StateLock)?;
        if inner.maintenance_active {
            return Err(EngineMaintenanceError::AlreadyActive);
        }
        if inner.active_mode_changes != 0 {
            return Err(EngineMaintenanceError::ModeChangeActive);
        }
        inner.maintenance_active = true;
        Ok(EngineMaintenanceLease {
            inner: self.inner.clone(),
        })
    }
}

impl PendingReapply {
    /// Takes the turn of the change as a reapplication of the current mode, a
    /// new intent asked for at its press: it supersedes the intents registered,
    /// and the revisions given, before the press, and not an intent asked for
    /// while the change was read, whose automatic retries go on, nor a revision
    /// given since the press.
    pub(super) async fn begin(self) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        let revision = {
            let mut inner = self
                .registration
                .inner
                .lock()
                .map_err(|_| EngineMaintenanceError::StateLock)?;
            inner.register_intent(self.pressed)?;
            inner.intent_revision
        };
        let serial = self.serial.lock_owned().await;
        Ok(EngineModeChangeLease {
            _intent: EngineModeChangeIntent::ReapplyCurrent,
            revision,
            _serial: serial,
            _registration: self.registration,
        })
    }
}

impl EngineModeChangeLease {
    /// A user operation asked for after this one was registered supersedes
    /// its automatic retry even though it cannot take the serial permit until
    /// this accepted attempt has settled. One asked for before, and registered
    /// only once what it asks was read, does not.
    pub(super) fn retry_guard(
        &self,
    ) -> impl Fn() -> Result<(), EngineMaintenanceError> + Send + 'static {
        let inner = self._registration.inner.clone();
        let revision = self.revision;
        move || {
            let current = inner
                .lock()
                .map_err(|_| EngineMaintenanceError::StateLock)?;
            if current.superseded(revision) {
                return Err(EngineMaintenanceError::StaleIntent);
            }
            Ok(())
        }
    }

    /// Detaches an accepted coordinator operation from the renderer's future.
    /// Dropping the returned receiver discards only the response: this task
    /// keeps both the serial permit and maintenance-visible registration until
    /// the operation itself reaches a terminal actor response.
    pub(crate) fn run_to_completion<F, T>(self, operation: F) -> oneshot::Receiver<(T, Self)>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        run_guarded_to_completion(self, operation)
    }
}

impl EngineMaintenanceLease {
    pub(crate) fn run_to_completion<F, T>(self, operation: F) -> oneshot::Receiver<(T, Self)>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        run_guarded_to_completion(self, operation)
    }
}

fn run_guarded_to_completion<G, F, T>(guard: G, operation: F) -> oneshot::Receiver<(T, G)>
where
    G: Send + 'static,
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    std::mem::drop(tokio::spawn(async move {
        let output = operation.await;
        let _receiver_was_dropped = sender.send((output, guard));
    }));
    receiver
}

impl Default for EngineMaintenanceGate {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EngineMaintenanceInner::default())),
            mode_serial: Arc::new(AsyncMutex::new(())),
        }
    }
}

impl Drop for EngineMaintenanceLease {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.maintenance_active = false;
        }
    }
}

impl Drop for EngineModeChangeRegistration {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.active_mode_changes = inner
                .active_mode_changes
                .checked_sub(1)
                .expect("engine mode lease counter invariant");
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProfileControlError {
    MaintenanceBusy,
    EngineNotOff,
    StateUnavailable,
}

impl std::fmt::Display for ProfileControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MaintenanceBusy => {
                "MaintenanceBusy: a network mode change or maintenance operation is in progress"
            }
            Self::EngineNotOff => {
                "EngineNotOff: profile mutation requires the replacement engine to be safely Off"
            }
            Self::StateUnavailable => {
                "ProfileControlUnavailable: replacement engine control state is unavailable"
            }
        })
    }
}
