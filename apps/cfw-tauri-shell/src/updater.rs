mod archive;
mod contract;
mod download;
mod error;
mod install_admission;
mod metadata;
mod state;

use std::time::Duration;

use cfw_engine_api::{EngineEvent, EngineMode, EngineSnapshot, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::engine::ManagedEngine;
use archive::install_verified_archive;
use download::download_verified_update;
use error::{Result, UpdateError};
use install_admission::validate_install_environment;
use metadata::check_bounded_update;
pub(crate) use state::UpdaterSecurityState;

#[tauri::command]
pub(crate) async fn check_for_updates(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, String> {
    check_for_updates_inner(app)
        .await
        .map_err(|error| error.to_string())
}

async fn check_for_updates_inner(app: AppHandle) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let _serialized_check = security.serialize_checks().await;
    security.clear_authorization()?;
    let update = check_bounded_update().await?;
    let payload = match update {
        Some(update) => {
            security.authorize(update.authorization.clone())?;
            serde_json::json!({
                "available": true,
                "current": env!("CARGO_PKG_VERSION"),
                "version": update.authorization.version,
                "notes": update.notes,
                "date": update.publication_date,
            })
        }
        None => serde_json::json!({
            "available": false,
            "current": env!("CARGO_PKG_VERSION"),
        }),
    };
    if let Err(error) = app.emit("cfw://update-available", payload.clone()) {
        security.clear_authorization()?;
        let _ = error;
        return Err(UpdateError::ProgressEvent);
    }
    Ok(payload)
}

#[tauri::command]
pub(crate) async fn install_available_update(
    app: AppHandle,
    expected_version: String,
) -> std::result::Result<serde_json::Value, String> {
    install_available_update_inner(app, expected_version)
        .await
        .map_err(|error| error.to_string())
}

async fn install_available_update_inner(
    app: AppHandle,
    expected_version: String,
) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let _serialized_check = security.serialize_checks().await;
    let authorized = security.authorization(&expected_version)?;
    let update = match check_bounded_update().await {
        Ok(Some(update)) => update,
        Ok(None) => {
            security.clear_authorization()?;
            return Err(UpdateError::AuthorizationChanged);
        }
        Err(error) => {
            security.clear_authorization()?;
            return Err(error);
        }
    };
    let current = update.authorization;
    validate_install_environment()?;
    let lease = security.begin_download(&authorized, &current)?;
    let version = current.version.clone();
    emit_progress(&app, &version, "downloading", 0, None, None)?;

    let mut last_percent = None;
    let mut next_unknown_length_event = 0_u64;
    let bytes = download_verified_update(
        &current,
        &lease.cancellation,
        |downloaded, total, percent| {
            let should_emit = match percent {
                Some(value) => last_percent.replace(value) != Some(value),
                None => {
                    if downloaded >= next_unknown_length_event {
                        next_unknown_length_event = downloaded.saturating_add(512 * 1024);
                        true
                    } else {
                        false
                    }
                }
            };
            if should_emit {
                emit_progress(&app, &version, "downloading", downloaded, total, percent)?;
            }
            Ok(())
        },
    )
    .await?;

    // This mutex-protected phase change is the cancellation linearization
    // point. A cancellation that wins here returns before any network change;
    // once commit wins, later cancellation is rejected explicitly.
    lease.begin_commit()?;
    emit_progress(
        &app,
        &version,
        "stopping-network",
        bytes.len() as u64,
        Some(bytes.len() as u64),
        Some(100),
    )?;
    let (coordinator, maintenance) = {
        let engine = app.state::<ManagedEngine>();
        let maintenance = engine
            .reserve_maintenance()
            .map_err(|_| UpdateError::EngineMaintenanceUnavailable)?;
        (engine.coordinator.clone(), maintenance)
    };
    maintenance
        .wait_for_idle()
        .await
        .map_err(|_| UpdateError::EngineMaintenanceUnavailable)?;
    let stopped = coordinator
        .set_mode(
            EngineMode::Off,
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .map_err(|_| UpdateError::EngineStop)?;
    require_engine_off(&stopped)?;

    // Revalidate immediately before the non-cancellable synchronous commit.
    validate_install_environment()?;
    emit_progress(
        &app,
        &version,
        "installing",
        bytes.len() as u64,
        Some(bytes.len() as u64),
        Some(100),
    )?;
    let install_version = version.clone();
    let outcome =
        tokio::task::spawn_blocking(move || install_verified_archive(&bytes, &install_version))
            .await
            .map_err(|_| UpdateError::InstallationWorkerFailed)??;
    if let Some(kind) = outcome.cleanup_warning
        && let Err(error) = app.emit(
            "cfw://engine-event",
            EngineEvent::boundary_failure(
                "update_cleanup_failed",
                format!("the new app was committed but post-commit cleanup failed ({kind:?})"),
            ),
        )
    {
        eprintln!("failed to publish post-commit update cleanup warning: {error}");
    }

    tokio::time::sleep(Duration::from_millis(350)).await;
    app.restart();
}

#[tauri::command]
pub(crate) fn cancel_update_install(
    security: State<'_, UpdaterSecurityState>,
) -> std::result::Result<serde_json::Value, String> {
    security
        .cancel_download()
        .map(|cancelled| serde_json::json!({ "cancelled": cancelled }))
        .map_err(|error| error.to_string())
}

fn emit_progress(
    app: &AppHandle,
    version: &str,
    phase: &str,
    downloaded: u64,
    total: Option<u64>,
    percent: Option<u64>,
) -> Result<()> {
    app.emit(
        "cfw://update-progress",
        serde_json::json!({
            "phase": phase,
            "version": version,
            "downloaded": downloaded,
            "total": total,
            "percent": percent,
        }),
    )
    .map_err(|_| UpdateError::ProgressEvent)
}

fn require_engine_off(snapshot: &EngineSnapshot) -> Result<()> {
    if snapshot.state != EngineState::Off
        || snapshot.desired_mode != EngineMode::Off
        || snapshot.config_digest.is_some()
    {
        return Err(UpdateError::EngineNotOff);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_commit_requires_a_proven_off_engine_snapshot() {
        require_engine_off(&EngineSnapshot::default()).expect("default Off snapshot");
        let invalid = EngineSnapshot {
            desired_mode: EngineMode::Tunnel,
            ..EngineSnapshot::default()
        };
        assert!(matches!(
            require_engine_off(&invalid),
            Err(UpdateError::EngineNotOff)
        ));
    }
}
