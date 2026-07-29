mod cutover;
mod maintenance;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Duration, Instant};

use cfw_apple_network::{
    AppleNetworkBackend, KeychainEngineGenerationStore, NativeFrameworkBridge,
};
use cfw_application::{EngineControllerAccess, EngineModeCoordinator};
use cfw_engine_api::{
    CutoverPreflightBackend, EngineBackend, EngineEvent, EngineMode, EngineSnapshot,
};
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::ManagedProfiles;
use crate::legacy::{LegacyRetirementGate, LegacyRetirementStatus};
use crate::settings_store;
use cutover::CutoverPreparationGate;
pub(crate) use maintenance::{EngineMaintenanceError, EngineMaintenanceLease, ProfileControlError};
use maintenance::{EngineMaintenanceGate, EngineModeChangeLease};

pub(crate) use cutover::{
    CutoverAuthority, prepare_legacy_cutover, run_native_preflight, validate_outcome_binding,
};

/// Maps an independent 0.3.5-style on/off switch onto the mutually exclusive
/// 0.4.0 engine modes.
///
/// `None` means "no transition": turning a switch off that does not own the
/// current desired mode must not stop the other mode's data plane, and turning
/// on a mode that is already desired must not restart it.
pub(crate) fn switch_transition(
    desired_mode: EngineMode,
    switch: EngineMode,
    enabled: bool,
) -> Option<EngineMode> {
    debug_assert_ne!(switch, EngineMode::Off, "a switch owns a real mode");
    match (enabled, desired_mode == switch) {
        (true, false) => Some(switch),
        (false, true) => Some(EngineMode::Off),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct EngineCapabilities {
    system_proxy: bool,
    tunnel: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EngineStatusPayload {
    snapshot: EngineSnapshot,
    capabilities: EngineCapabilities,
    cutover_ready: bool,
    cutover_unavailable_reason: Option<String>,
    unavailable_reason: Option<String>,
}

impl EngineStatusPayload {
    /// Why the replacement network is unavailable, when it is. Callers report
    /// it verbatim; it never carries an endpoint or a secret.
    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }
}

pub(crate) struct ManagedEngine {
    pub(crate) coordinator: EngineModeCoordinator,
    capabilities: EngineCapabilities,
    unavailable_reason: Option<String>,
    pub(crate) preflight_backend: Arc<dyn CutoverPreflightBackend>,
    cutover: CutoverPreparationGate,
    maintenance: EngineMaintenanceGate,
    /// Engine settings plus the loopback controller they open. The per-run
    /// controller secret lives here in memory only: it is never persisted, never
    /// logged, and never published in an engine snapshot.
    controller: EngineControllerAccess,
}

impl ManagedEngine {
    /// The single engine-settings value this process starts modes with, so the
    /// running engine's controller is exactly the one held in memory here.
    pub(crate) fn engine_settings(&self) -> &EngineSettings {
        self.controller.settings()
    }

    /// The app-owned controller of the engine this process starts. Command
    /// handlers build their client endpoint from here, so a controller host,
    /// port, or secret can never come from user settings or from a profile.
    pub(crate) fn controller_access(&self) -> &EngineControllerAccess {
        &self.controller
    }

    fn begin_mode_change(
        &self,
        mode: EngineMode,
    ) -> Result<Option<EngineModeChangeLease>, EngineMaintenanceError> {
        self.maintenance.begin_mode_change(mode)
    }

    pub(crate) fn reserve_maintenance(
        &self,
    ) -> Result<EngineMaintenanceLease, EngineMaintenanceError> {
        self.maintenance.reserve()
    }

    pub(crate) fn reserve_profile_mutation(
        &self,
    ) -> Result<EngineMaintenanceLease, ProfileControlError> {
        let lease = self
            .maintenance
            .reserve_if_idle()
            .map_err(|error| match error {
                EngineMaintenanceError::AlreadyActive
                | EngineMaintenanceError::ModeChangeActive => ProfileControlError::MaintenanceBusy,
                EngineMaintenanceError::StateLock | EngineMaintenanceError::CounterExhausted => {
                    ProfileControlError::StateUnavailable
                }
            })?;
        let snapshot = self.coordinator.snapshot();
        if snapshot.desired_mode != EngineMode::Off
            || snapshot.state != cfw_engine_api::EngineState::Off
        {
            return Err(ProfileControlError::EngineNotOff);
        }
        Ok(lease)
    }

    pub(crate) fn require_capability(&self, mode: EngineMode) -> Result<(), String> {
        let available = match mode {
            EngineMode::Off => false,
            EngineMode::SystemProxy => self.capabilities.system_proxy,
            EngineMode::Tunnel => self.capabilities.tunnel,
        };
        if available {
            Ok(())
        } else {
            Err(self
                .unavailable_reason
                .clone()
                .unwrap_or_else(|| format!("engine mode {mode:?} is unavailable in this build")))
        }
    }

    pub(crate) fn take_cutover_authority(
        &self,
        receipt_id: &str,
    ) -> Result<CutoverAuthority, String> {
        self.cutover.take(receipt_id, Instant::now())
    }

    pub(crate) fn status_payload(
        &self,
        retirement: &LegacyRetirementGate,
    ) -> Result<EngineStatusPayload, String> {
        let retirement_status = retirement.status()?;
        let (capabilities, retirement_reason) = match retirement_status {
            LegacyRetirementStatus::Cleared => (self.capabilities, None),
            LegacyRetirementStatus::PostCutoverCleanupRequired { message } => (
                self.capabilities,
                Some(format!(
                    "replacement networking is active; post-cutover data cleanup must be retried: {message}"
                )),
            ),
            LegacyRetirementStatus::AwaitingConfirmation => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                },
                Some(
                    "legacy network remains unchanged while replacement configuration is staged"
                        .to_owned(),
                ),
            ),
            LegacyRetirementStatus::Cleaning => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                },
                Some("the explicitly confirmed legacy network cutover is running".to_owned()),
            ),
            LegacyRetirementStatus::RecoveryStartRequired { message, .. } => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                },
                Some(format!(
                    "an interrupted cutover requires explicit replacement recovery: {message}"
                )),
            ),
            LegacyRetirementStatus::ManualCleanupRequired { message, .. } => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                },
                Some(format!(
                    "legacy network cleanup requires manual intervention: {message}"
                )),
            ),
        };
        let (cutover_ready, mut cutover_reason) = self.cutover.readiness(Instant::now())?;
        if self.unavailable_reason.is_some() {
            cutover_reason = self.unavailable_reason.clone();
        }
        Ok(EngineStatusPayload {
            snapshot: self.coordinator.snapshot(),
            capabilities,
            cutover_ready: cutover_ready
                && (self.capabilities.system_proxy || self.capabilities.tunnel),
            cutover_unavailable_reason: (!cutover_ready).then_some(cutover_reason).flatten(),
            unavailable_reason: retirement_reason.or_else(|| self.unavailable_reason.clone()),
        })
    }
}

pub(crate) fn build_managed_engine(bridge: NativeFrameworkBridge) -> Result<ManagedEngine, String> {
    let controller = EngineControllerAccess::resolve(EngineSettings::default())
        .map_err(|error| format!("engine settings are unusable: {error}"))?;
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let native_available = bridge.is_available();
    let native_failure = bridge.unavailable_reason().map(ToOwned::to_owned);
    let concrete_backend = Arc::new(AppleNetworkBackend::new(bridge));
    let engine_backend: Arc<dyn EngineBackend> = concrete_backend.clone();
    let preflight_backend: Arc<dyn CutoverPreflightBackend> = concrete_backend;
    let generation_store =
        KeychainEngineGenerationStore::new(store.paths().app_home.join("engine"));
    let persisted = match generation_store {
        Ok(generation_store) => EngineModeCoordinator::spawn_persisted_with(
            engine_backend.clone(),
            Arc::new(generation_store),
            Duration::from_secs(15),
            spawn_coordinator_task,
        ),
        Err(error) => Err(cfw_application::EngineCoordinatorError::Journal(
            error.to_string(),
        )),
    };
    let (coordinator, lineage_failure) = match persisted {
        Ok(coordinator) => (coordinator, None),
        Err(error) => {
            let message = format!("authoritative engine lineage is unavailable: {error}");
            let coordinator = EngineModeCoordinator::spawn_journal_unavailable_with(
                engine_backend,
                message.clone(),
                Duration::from_secs(15),
                spawn_coordinator_task,
            );
            (coordinator, Some(message))
        }
    };

    Ok(ManagedEngine {
        coordinator,
        capabilities: EngineCapabilities {
            system_proxy: native_available && lineage_failure.is_none(),
            tunnel: native_available && lineage_failure.is_none(),
        },
        unavailable_reason: lineage_failure.or(native_failure),
        preflight_backend,
        cutover: CutoverPreparationGate::default(),
        maintenance: EngineMaintenanceGate::default(),
        controller,
    })
}

fn spawn_coordinator_task(task: cfw_application::CoordinatorTask) {
    std::mem::drop(tauri::async_runtime::spawn(task));
}

pub(crate) fn start_engine_event_forwarder(app: AppHandle) {
    let mut snapshots = app.state::<ManagedEngine>().coordinator.subscribe();
    tauri::async_runtime::spawn(async move {
        while snapshots.changed().await.is_ok() {
            let event = EngineEvent::SnapshotChanged {
                snapshot: snapshots.borrow().clone(),
            };
            if let Err(error) = app.emit("cfw://engine-event", event) {
                eprintln!("failed to publish engine state event: {error}");
            }
        }
    });
}

#[tauri::command]
pub(crate) fn engine_snapshot(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
) -> Result<EngineStatusPayload, String> {
    engine.status_payload(&retirement)
}

#[tauri::command]
pub(crate) async fn set_engine_mode(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    mode: EngineMode,
) -> Result<EngineStatusPayload, String> {
    apply_engine_mode(&engine, &retirement, &profiles, mode).await
}

/// The single in-process path to a mode transition.
///
/// Every renderer entry point that changes what the data plane is doing — the
/// explicit mode command, the restored System Proxy and TUN switches, and the
/// profile reapply commands — funnels through here, so the maintenance lease,
/// the legacy-retirement gate, the capability check, the selected-profile
/// requirement, and the app-owned engine settings are applied exactly once and
/// cannot be skipped by adding another command later.
pub(crate) async fn apply_engine_mode(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    mode: EngineMode,
) -> Result<EngineStatusPayload, String> {
    let _mode_lease = engine
        .begin_mode_change(mode)
        .map_err(|error| error.to_string())?;
    if mode != EngineMode::Off {
        retirement.require_cleared()?;
        engine.require_capability(mode)?;
    }
    let (profile_id, profile) = selected_profile_for_mode(profiles.repository(), mode)
        .map_err(|error| error.to_string())?;
    engine
        .coordinator
        .set_mode(mode, profile_id, profile, engine.engine_settings().clone())
        .await
        .map_err(|error| error.to_string())?;
    engine.status_payload(retirement)
}

fn selected_profile_for_mode(
    repository: &ProfileRepository,
    mode: EngineMode,
) -> Result<(String, ValidatedSingBoxProfile), ProfileError> {
    if mode == EngineMode::Off {
        Ok((
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
        ))
    } else {
        repository
            .require_selected()
            .map(|stored| (stored.record.id, stored.profile))
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProductInfo {
    name: &'static str,
    version: &'static str,
    license: &'static str,
    minimum_macos: &'static str,
    architecture: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BootPayload {
    product: ProductInfo,
    /// Whether this process is the explicit `--migration-handoff` instance. The
    /// dashboard uses it to decide whether to offer the controlled restart that
    /// enters the handoff, or the prepare/confirm/recover cutover controls that
    /// only the handoff instance may drive.
    migration_handoff: bool,
}

#[tauri::command]
pub(crate) fn boot_payload(launch: State<'_, crate::LaunchContext>) -> BootPayload {
    BootPayload {
        product: ProductInfo {
            name: "Clash for Mac",
            version: env!("CARGO_PKG_VERSION"),
            license: "GPL-3.0-or-later",
            minimum_macos: "15.0",
            architecture: "arm64",
        },
        migration_handoff: launch.migration_handoff,
    }
}
