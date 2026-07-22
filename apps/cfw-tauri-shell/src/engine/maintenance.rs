use std::sync::{Arc, Mutex};

use cfw_engine_api::EngineMode;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct EngineMaintenanceGate {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
    idle: Arc<Notify>,
}

#[derive(Default)]
struct EngineMaintenanceInner {
    active_mode_changes: u64,
    maintenance_active: bool,
}

pub(super) struct EngineModeChangeLease {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
    idle: Arc<Notify>,
}

pub(crate) struct EngineMaintenanceLease {
    inner: Arc<Mutex<EngineMaintenanceInner>>,
    idle: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EngineMaintenanceError {
    StateLock,
    AlreadyActive,
    ModeChangeActive,
    CounterExhausted,
}

impl std::fmt::Display for EngineMaintenanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StateLock => "network maintenance state lock failed",
            Self::AlreadyActive => {
                "network mode changes are blocked while exclusive network maintenance is active"
            }
            Self::ModeChangeActive => "a network mode change is already in progress",
            Self::CounterExhausted => "network mode change counter is exhausted",
        })
    }
}

impl EngineMaintenanceGate {
    pub(super) fn begin_mode_change(
        &self,
        mode: EngineMode,
    ) -> Result<Option<EngineModeChangeLease>, EngineMaintenanceError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EngineMaintenanceError::StateLock)?;
        // Renderer Off requests are blocked too. Internal maintenance paths
        // hold the lease and call the coordinator directly, which closes the
        // former renderer gap between destructive cleanup and replacement
        // start.
        if inner.maintenance_active {
            return Err(EngineMaintenanceError::AlreadyActive);
        }
        if mode == EngineMode::Off {
            return Ok(None);
        }
        inner.active_mode_changes = inner
            .active_mode_changes
            .checked_add(1)
            .ok_or(EngineMaintenanceError::CounterExhausted)?;
        Ok(Some(EngineModeChangeLease {
            inner: self.inner.clone(),
            idle: self.idle.clone(),
        }))
    }

    pub(super) fn reserve(&self) -> Result<EngineMaintenanceLease, EngineMaintenanceError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EngineMaintenanceError::StateLock)?;
        if inner.maintenance_active {
            return Err(EngineMaintenanceError::AlreadyActive);
        }
        inner.maintenance_active = true;
        Ok(EngineMaintenanceLease {
            inner: self.inner.clone(),
            idle: self.idle.clone(),
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
            idle: self.idle.clone(),
        })
    }
}

impl EngineMaintenanceLease {
    pub(crate) async fn wait_for_idle(&self) -> Result<(), EngineMaintenanceError> {
        loop {
            let notified = self.idle.notified();
            {
                let inner = self
                    .inner
                    .lock()
                    .map_err(|_| EngineMaintenanceError::StateLock)?;
                if inner.active_mode_changes == 0 {
                    return Ok(());
                }
            }
            notified.await;
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

impl Drop for EngineModeChangeLease {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.active_mode_changes = inner
                .active_mode_changes
                .checked_sub(1)
                .expect("engine mode lease counter invariant");
            if inner.active_mode_changes == 0 {
                self.idle.notify_waiters();
            }
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
