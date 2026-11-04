//! Continues a TUN Mode start once the person allows the System Extension.
//!
//! macOS answers an activation request only to the request itself. The start
//! that submitted it has already returned `AwaitingApproval`, so until the
//! person clicked Approve… again nothing acted on the answer. A watcher waits
//! for that answer through the platform's approval wait and then repeats the
//! start exactly as Approve… does: through the shared network controls and
//! bound to the snapshot it watched, so a stop, a failure or any other change
//! in between supersedes it.

use std::sync::{Mutex, MutexGuard};

use cfw_application::EngineModeCoordinator;
use cfw_engine_api::{EngineSnapshot, EngineState, TunnelApprovalBackend, TunnelApprovalWait};
use tauri::{AppHandle, Manager};

use crate::commands::ManagedProfiles;
use crate::engine::ManagedEngine;
use crate::engine_controls::{EngineControl, apply_observed_control};
use crate::platform_maintenance::PlatformMaintenanceGate;

#[cfg(test)]
mod tests;

/// Native waits for one approval. Each lasts at most the native approval wait
/// (270 seconds), so a watcher stops within an hour; Approve… still repeats
/// the start after that.
const MAXIMUM_APPROVAL_WAITS: usize = 12;

/// What the watch of one awaited approval found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalAnswer {
    /// macOS answered the installation's activation request.
    Answered,
    /// The engine moved on, or no activation request waits any more.
    Superseded,
    /// Every native wait ended with the request still waiting.
    Unanswered,
}

/// The generation whose approval a watcher waits for. Every snapshot that the
/// same wait publishes would otherwise start another watcher.
#[derive(Debug, Default)]
pub(crate) struct ApprovalWatch {
    generation: Mutex<Option<u64>>,
}

impl ApprovalWatch {
    /// Claims `generation` unless a watcher already waits for it. A newer
    /// generation replaces an older one, whose watcher is ending.
    pub(crate) fn claim(&self, generation: u64) -> Result<bool, String> {
        let mut watched = self.lock()?;
        if *watched == Some(generation) {
            return Ok(false);
        }
        *watched = Some(generation);
        Ok(true)
    }

    pub(crate) fn release(&self, generation: u64) -> Result<(), String> {
        let mut watched = self.lock()?;
        if *watched == Some(generation) {
            *watched = None;
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<u64>>, String> {
        self.generation
            .lock()
            .map_err(|_| "tunnel approval watch lock is poisoned".to_owned())
    }
}

/// Waits until macOS answers the System Extension approval that `observed`
/// awaits, for as long as the coordinator's state is still `observed`.
pub(crate) async fn awaited_approval(
    coordinator: &EngineModeCoordinator,
    backend: &dyn TunnelApprovalBackend,
    observed: &EngineSnapshot,
) -> Result<ApprovalAnswer, String> {
    for _ in 0..MAXIMUM_APPROVAL_WAITS {
        let Some(context) = coordinator
            .pending_tunnel_approval(observed.clone())
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(ApprovalAnswer::Superseded);
        };
        match backend
            .await_tunnel_approval(context)
            .await
            .map_err(|error| error.to_string())?
        {
            TunnelApprovalWait::Resolved => return Ok(ApprovalAnswer::Answered),
            TunnelApprovalWait::StillAwaiting => {}
            TunnelApprovalWait::NoPendingRequest => return Ok(ApprovalAnswer::Superseded),
        }
    }
    Ok(ApprovalAnswer::Unanswered)
}

/// Starts one watcher for every published Tunnel installation that awaits the
/// System Extension approval. Nothing runs where no installation awaits one.
pub(crate) fn start(app: AppHandle) -> Result<(), String> {
    if app.state::<ManagedEngine>().tunnel_approval().is_none() {
        return Ok(());
    }
    if !app.manage(ApprovalWatch::default()) {
        return Err("the tunnel approval watch was registered twice".into());
    }
    let mut snapshots = app.state::<ManagedEngine>().coordinator.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            let snapshot = snapshots.borrow_and_update().clone();
            watch_snapshot(&app, snapshot);
            if snapshots.changed().await.is_err() {
                break;
            }
        }
    });
    Ok(())
}

fn watch_snapshot(app: &AppHandle, snapshot: EngineSnapshot) {
    let EngineState::AwaitingApproval { generation } = snapshot.state else {
        return;
    };
    match app.state::<ApprovalWatch>().claim(generation) {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => return record_failure(app, &error),
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let outcome = continue_when_allowed(&app, snapshot).await;
        let released = app.state::<ApprovalWatch>().release(generation);
        if let Err(error) = outcome.and(released) {
            record_failure(&app, &error);
        }
    });
}

async fn continue_when_allowed(app: &AppHandle, observed: EngineSnapshot) -> Result<(), String> {
    let engine = app.state::<ManagedEngine>();
    let Some(backend) = engine.tunnel_approval() else {
        return Ok(());
    };
    if awaited_approval(&engine.coordinator, backend.as_ref(), &observed).await?
        != ApprovalAnswer::Answered
    {
        return Ok(());
    }
    match apply_observed_control(
        &engine,
        &app.state::<PlatformMaintenanceGate>(),
        &app.state::<ManagedProfiles>(),
        EngineControl::Tunnel,
        true,
        observed.clone(),
    )
    .await
    {
        Ok(_) => Ok(()),
        // A stop or another change in between refuses the repeat, and a start
        // that failed is published as the engine's Failed state; neither is a
        // failure of this watcher.
        Err(_) if engine.coordinator.snapshot() != observed => Ok(()),
        Err(error) => Err(error),
    }
}

fn record_failure(app: &AppHandle, error: &str) {
    crate::diagnostics::record(
        app,
        cfw_core::DiagnosticTopic::Network,
        "tunnel_approval_wait_failed",
        error,
    );
}
