use std::future::Future;
use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineMode;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, oneshot};

pub(super) const MAX_PENDING_MODE_CHANGES: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EngineModeChangeIntent {
    Set(EngineMode),
    ReapplyCurrent,
}

pub(super) struct EngineMaintenanceGate {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
    mode_serial: Arc<AsyncMutex<()>>,
}

#[derive(Default)]
struct EngineMaintenanceInner {
    active_mode_changes: usize,
    maintenance_active: bool,
}

pub(crate) struct EngineModeChangeLease {
    _intent: EngineModeChangeIntent,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EngineMaintenanceError {
    StateLock,
    AlreadyActive,
    ModeChangeActive,
    QueueFull,
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
        })
    }
}

impl EngineMaintenanceGate {
    pub(super) async fn begin_mode_change(
        &self,
        intent: EngineModeChangeIntent,
    ) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        let registration = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| EngineMaintenanceError::StateLock)?;
            if inner.maintenance_active {
                return Err(EngineMaintenanceError::AlreadyActive);
            }
            if inner.active_mode_changes >= MAX_PENDING_MODE_CHANGES {
                return Err(EngineMaintenanceError::QueueFull);
            }
            inner.active_mode_changes += 1;
            EngineModeChangeRegistration {
                inner: self.inner.clone(),
            }
        };

        // Register before awaiting the fair single-flight lock. Maintenance
        // therefore sees both queued and executing mutations, including Off.
        // If this future is cancelled while waiting, `registration` drops and
        // removes the pending count instead of leaking a permanent busy state.
        let serial = self.mode_serial.clone().lock_owned().await;
        Ok(EngineModeChangeLease {
            _intent: intent,
            _serial: serial,
            _registration: registration,
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

impl EngineModeChangeLease {
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
