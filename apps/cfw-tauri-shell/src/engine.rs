mod cutover;
mod endpoints;
mod maintenance;
#[cfg(feature = "physical-release-evidence")]
pub mod packet_evidence;

#[cfg(test)]
mod tests;

use std::sync::{Arc, RwLock};
use std::time::Instant;

use cfw_apple_network::{
    AppleNetworkBackend, KeychainEngineGenerationStore, NATIVE_BRIDGE_OUTER_WATCHDOG,
    NativeFrameworkBridge,
};
use cfw_application::{EngineControllerAccess, EngineCoordinatorError, EngineModeCoordinator};
use cfw_engine_api::{
    BackendErrorKind, CutoverPreflightBackend, EngineBackend, EngineEvent, EngineMode, EngineOwner,
    EngineSnapshot, EngineState,
};
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::ManagedProfiles;
use crate::legacy::{
    LegacyRetirementGate, LegacyRetirementStatus, load_replacement_engine_settings,
};
use crate::settings_store;
use cutover::CutoverPreparationGate;
use endpoints::{EndpointCandidateCursor, EndpointRole, select_process_engine_settings};
pub(crate) use maintenance::{EngineMaintenanceError, EngineMaintenanceLease, ProfileControlError};
use maintenance::{EngineMaintenanceGate, EngineModeChangeIntent, EngineModeChangeLease};

pub(crate) use cutover::{
    CutoverAuthority, prepare_legacy_cutover, run_native_preflight, validate_outcome_binding,
};

/// Maps an independent 0.3.5-style on/off switch onto the mutually exclusive
/// 0.4.0 engine modes.
///
/// `None` means "no transition": turning a switch off that does not own the
/// current desired mode must not stop the other mode's data plane, and an
/// in-flight or proven-active mode must not be restarted. An explicit retry is
/// admitted only from a terminal/retryable state for that same desired mode.
pub(crate) fn switch_transition(
    snapshot: &EngineSnapshot,
    switch: EngineMode,
    enabled: bool,
) -> Option<EngineMode> {
    debug_assert_ne!(switch, EngineMode::Off, "a switch owns a real mode");
    if !enabled {
        return (snapshot.desired_mode == switch).then_some(EngineMode::Off);
    }
    if snapshot.desired_mode != switch {
        return Some(switch);
    }
    match &snapshot.state {
        EngineState::Off => Some(switch),
        EngineState::AwaitingApproval { .. } if switch == EngineMode::Tunnel => Some(switch),
        EngineState::Failed { target, .. } if *target == switch => Some(switch),
        EngineState::ProxyActive { runtime }
            if switch == EngineMode::SystemProxy && !runtime.ready =>
        {
            Some(switch)
        }
        EngineState::TunnelActive { runtime } if switch == EngineMode::Tunnel && !runtime.ready => {
            Some(switch)
        }
        _ => None,
    }
}

/// Revalidates a switch intent after it reaches the front of the serialized
/// mutation queue. An enabled intent is generation-sensitive: if an earlier
/// request changed any part of the observed snapshot, this request must be
/// retried explicitly instead of allocating another start generation. A
/// disable intent that originally owned its switch may still supersede an
/// earlier retry and converge that same desired mode to Off.
pub(crate) fn serialized_switch_transition(
    observed: &EngineSnapshot,
    current: &EngineSnapshot,
    switch: EngineMode,
    enabled: bool,
) -> Result<Option<EngineMode>, &'static str> {
    if !enabled && observed.desired_mode != switch {
        return Ok(None);
    }
    if enabled && observed != current {
        return Err(
            "network mode changed while this enable request was queued; retry against the current state",
        );
    }
    Ok(switch_transition(current, switch, enabled))
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct EngineCapabilities {
    system_proxy: bool,
    tunnel: bool,
    provider_management: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EngineStatusPayload {
    snapshot: EngineSnapshot,
    capabilities: EngineCapabilities,
    cutover_ready: bool,
    cutover_unavailable_reason: Option<String>,
    unavailable_reason: Option<String>,
}

pub(crate) struct EngineShutdownOutcome {
    result: Result<EngineSnapshot, String>,
    maintenance: EngineMaintenanceLease,
}

impl EngineShutdownOutcome {
    pub(crate) fn into_parts(self) -> (Result<EngineSnapshot, String>, EngineMaintenanceLease) {
        (self.result, self.maintenance)
    }
}

pub struct ManagedEngine {
    pub(crate) coordinator: EngineModeCoordinator,
    capabilities: EngineCapabilities,
    unavailable_reason: Option<String>,
    pub(crate) preflight_backend: Arc<dyn CutoverPreflightBackend>,
    cutover: CutoverPreparationGate,
    maintenance: EngineMaintenanceGate,
    endpoints: Arc<RwLock<EngineEndpointBinding>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EngineEndpointBinding {
    controller: EngineControllerAccess,
    cursor: EndpointCandidateCursor,
    active: Option<ActiveControllerBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveControllerBinding {
    generation: u64,
    config_digest: String,
}

pub(crate) struct StagedEndpointRebind {
    expected: EngineEndpointBinding,
    replacement: EngineEndpointBinding,
}

impl StagedEndpointRebind {
    pub(crate) fn settings(&self) -> &EngineSettings {
        self.replacement.controller.settings()
    }
}

impl ManagedEngine {
    /// The single engine-settings value this process starts modes with, so the
    /// running engine's controller is exactly the one held in memory here.
    pub(crate) fn engine_settings(&self) -> Result<EngineSettings, String> {
        read_engine_settings(&self.endpoints)
    }

    /// The app-owned controller of the engine this process starts. Command
    /// handlers build their client endpoint from here, so a controller host,
    /// port, or secret can never come from user settings or from a profile.
    pub(crate) fn controller_access(&self) -> Result<EngineControllerAccess, String> {
        read_controller_access(&self.endpoints)
    }

    pub(crate) fn active_controller_access(
        &self,
        generation: u64,
        config_digest: &str,
    ) -> Result<EngineControllerAccess, String> {
        read_active_controller_access(&self.endpoints, generation, config_digest)
    }

    pub(crate) fn record_endpoint_runtime(&self, snapshot: &EngineSnapshot) -> Result<(), String> {
        record_endpoint_runtime(&self.endpoints, snapshot)
    }

    pub(crate) fn stage_endpoint_rebind(
        &self,
        conflict: BackendErrorKind,
    ) -> Result<StagedEndpointRebind, String> {
        stage_endpoint_rebind(&self.endpoints, &self.coordinator, conflict)
    }

    pub(crate) fn commit_endpoint_rebind(
        &self,
        staged: StagedEndpointRebind,
    ) -> Result<(), String> {
        commit_endpoint_rebind(&self.endpoints, staged)
    }

    pub(crate) async fn begin_mode_change(
        &self,
        mode: EngineMode,
    ) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        self.maintenance
            .begin_mode_change(EngineModeChangeIntent::Set(mode))
            .await
    }

    /// Serializes a "reapply whatever is current" intent before reading the
    /// desired mode. An Off queued ahead of this call is therefore observed as
    /// Off and can never be undone by a stale pre-queue snapshot.
    pub(crate) async fn begin_current_mode_change(
        &self,
    ) -> Result<(EngineMode, EngineModeChangeLease), EngineMaintenanceError> {
        let lease = self
            .maintenance
            .begin_mode_change(EngineModeChangeIntent::ReapplyCurrent)
            .await?;
        Ok((self.coordinator.snapshot().desired_mode, lease))
    }

    pub(crate) fn reserve_maintenance(
        &self,
    ) -> Result<EngineMaintenanceLease, EngineMaintenanceError> {
        self.maintenance.reserve_if_idle()
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
                EngineMaintenanceError::StateLock | EngineMaintenanceError::QueueFull => {
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

    /// Converges the engine to Off under an exclusive maintenance reservation.
    /// No mode intent can queue behind shutdown and restart networking during
    /// process exit. The returned reservation remains held until lifecycle code
    /// stores it for the remainder of the process or explicitly abandons exit.
    pub(crate) async fn shutdown_to_completion(&self) -> Result<EngineShutdownOutcome, String> {
        let maintenance = self
            .reserve_maintenance()
            .map_err(|error| error.to_string())?;
        let coordinator = self.coordinator.clone();
        let (result, maintenance) = maintenance
            .run_to_completion(async move {
                coordinator
                    .shutdown()
                    .await
                    .map_err(|error| error.to_string())
            })
            .await
            .map_err(|_| "network shutdown task ended without a response".to_owned())?;
        Ok(EngineShutdownOutcome {
            result,
            maintenance,
        })
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
                    provider_management: false,
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
                    provider_management: false,
                },
                Some("the explicitly confirmed legacy network cutover is running".to_owned()),
            ),
            LegacyRetirementStatus::RecoveryStartRequired { message, .. } => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                    provider_management: false,
                },
                Some(format!(
                    "an interrupted cutover requires explicit replacement recovery: {message}"
                )),
            ),
            LegacyRetirementStatus::ManualCleanupRequired { message, .. } => (
                EngineCapabilities {
                    system_proxy: false,
                    tunnel: false,
                    provider_management: false,
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
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let (settings, cursor) = match load_replacement_engine_settings(&store.paths().app_home)? {
        Some(settings) => {
            let cursor = EndpointCandidateCursor::from_persisted(settings.clone())
                .map_err(|error| format!("persisted engine endpoints are unusable: {error}"))?;
            (settings, cursor)
        }
        None => select_process_engine_settings(EngineSettings::default())
            .map_err(|error| format!("engine loopback endpoints are unavailable: {error}"))?,
    };
    let controller = EngineControllerAccess::resolve(settings)
        .map_err(|error| format!("engine settings are unusable: {error}"))?;
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
            NATIVE_BRIDGE_OUTER_WATCHDOG,
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
                NATIVE_BRIDGE_OUTER_WATCHDOG,
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
            // The pinned sing-box 1.13.15 schema cannot construct proxy or
            // rule providers. Keep the controller commands as explicit
            // fail-closed backstops, but do not advertise or probe them.
            provider_management: false,
        },
        unavailable_reason: lineage_failure.or(native_failure),
        preflight_backend,
        cutover: CutoverPreparationGate::default(),
        maintenance: EngineMaintenanceGate::default(),
        endpoints: Arc::new(RwLock::new(EngineEndpointBinding {
            controller,
            cursor,
            active: None,
        })),
    })
}

fn spawn_coordinator_task(task: cfw_application::CoordinatorTask) {
    std::mem::drop(tauri::async_runtime::spawn(task));
}

pub(crate) fn start_engine_event_forwarder(app: AppHandle) {
    let engine = app.state::<ManagedEngine>();
    let coordinator = engine.coordinator.clone();
    let mut snapshots = coordinator.subscribe();
    let default_ipv6_enabled = match engine.engine_settings() {
        Ok(settings) => settings.enable_ipv6,
        Err(error) => {
            eprintln!("failed to read engine endpoint state: {error}");
            return;
        }
    };
    if let Err(error) = crate::release_observation::emit_engine_snapshot(
        &snapshots.borrow().clone(),
        default_ipv6_enabled,
    ) {
        eprintln!("failed to publish initial release observation: {error}");
    }
    tauri::async_runtime::spawn(async move {
        while snapshots.changed().await.is_ok() {
            let snapshot = snapshots.borrow().clone();
            // Evidence transactions may temporarily use a source-owned settings
            // variant (notably IPv6-disabled and exact Off). Ask the serialized
            // actor for the settings it accepted for this exact snapshot instead
            // of publishing the dashboard's ordinary settings for every state.
            let ipv6_enabled = coordinator
                .restart_spec()
                .await
                .ok()
                .flatten()
                .filter(|spec| spec.matches_ready_snapshot(&snapshot))
                .map_or(default_ipv6_enabled, |spec| spec.settings().enable_ipv6);
            if let Err(error) =
                crate::release_observation::emit_engine_snapshot(&snapshot, ipv6_enabled)
            {
                eprintln!("failed to publish release observation: {error}");
            }
            let event = EngineEvent::SnapshotChanged { snapshot };
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

/// The single in-process execution path after a caller transfers its
/// single-flight transition permit.
///
/// Every renderer mutation first acquires an exact target or current-mode
/// admission, then funnels through here so the legacy-retirement gate,
/// capability check, selected profile, and app-owned settings cannot be
/// skipped. The permit outlives renderer cancellation until the coordinator
/// actor responds, so accepted native work cannot escape maintenance.
pub(crate) async fn apply_admitted_engine_mode(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    mode: EngineMode,
    mode_lease: EngineModeChangeLease,
) -> Result<EngineStatusPayload, String> {
    if mode != EngineMode::Off {
        retirement.require_cleared()?;
        engine.require_capability(mode)?;
    }
    let (profile_id, profile) = selected_profile_for_mode(profiles.repository(), mode)
        .map_err(|error| error.to_string())?;
    let coordinator = engine.coordinator.clone();
    let endpoints = engine.endpoints.clone();
    let completion = mode_lease.run_to_completion(async move {
        set_mode_with_endpoint_rebind(
            &coordinator,
            &endpoints,
            mode,
            &profile_id,
            &profile,
            |conflict| {
                let staged = stage_endpoint_rebind(&endpoints, &coordinator, conflict)?;
                commit_endpoint_rebind(&endpoints, staged)
            },
        )
        .await
    });
    let (result, mode_lease) = completion
        .await
        .map_err(|_| "network mode coordinator task ended without a response".to_owned())?;
    drop(mode_lease);
    result?;
    engine.status_payload(retirement)
}

async fn set_mode_with_endpoint_rebind(
    coordinator: &EngineModeCoordinator,
    endpoints: &RwLock<EngineEndpointBinding>,
    mode: EngineMode,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    mut rebind: impl FnMut(BackendErrorKind) -> Result<(), String>,
) -> Result<EngineSnapshot, String> {
    loop {
        let settings = read_engine_settings(endpoints)?;
        match coordinator
            .set_mode(mode, profile_id.to_owned(), profile.clone(), settings)
            .await
        {
            Ok(snapshot) => {
                record_endpoint_runtime(endpoints, &snapshot)?;
                return Ok(snapshot);
            }
            Err(EngineCoordinatorError::StartEndpointConflictAfterOff { conflict, .. }) => {
                rebind(conflict)?;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_engine_settings(
    endpoints: &RwLock<EngineEndpointBinding>,
) -> Result<EngineSettings, String> {
    endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())
        .map(|binding| binding.controller.settings().clone())
}

fn read_controller_access(
    endpoints: &RwLock<EngineEndpointBinding>,
) -> Result<EngineControllerAccess, String> {
    endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())
        .map(|binding| binding.controller.clone())
}

fn read_active_controller_access(
    endpoints: &RwLock<EngineEndpointBinding>,
    generation: u64,
    config_digest: &str,
) -> Result<EngineControllerAccess, String> {
    let binding = endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())?;
    let expected = ActiveControllerBinding {
        generation,
        config_digest: config_digest.to_owned(),
    };
    if binding.active.as_ref() != Some(&expected) {
        return Err("active engine identity does not match the controller binding".into());
    }
    Ok(binding.controller.clone())
}

fn record_endpoint_runtime(
    endpoints: &RwLock<EngineEndpointBinding>,
    snapshot: &EngineSnapshot,
) -> Result<(), String> {
    let active = match &snapshot.state {
        EngineState::Off if snapshot.desired_mode == EngineMode::Off => None,
        EngineState::AwaitingApproval { .. } if snapshot.desired_mode == EngineMode::Tunnel => None,
        EngineState::ProxyActive { runtime }
            if snapshot.desired_mode == EngineMode::SystemProxy
                && runtime.owner == EngineOwner::ProxyAgent
                && runtime.ready
                && runtime.context.generation == snapshot.generation
                && snapshot.config_digest.as_deref() == Some(runtime.config_digest.as_str()) =>
        {
            Some(ActiveControllerBinding {
                generation: runtime.context.generation,
                config_digest: runtime.config_digest.clone(),
            })
        }
        EngineState::TunnelActive { runtime }
            if snapshot.desired_mode == EngineMode::Tunnel
                && runtime.owner == EngineOwner::PacketTunnelSystemExtension
                && runtime.ready
                && runtime.context.generation == snapshot.generation
                && snapshot.config_digest.as_deref() == Some(runtime.config_digest.as_str()) =>
        {
            Some(ActiveControllerBinding {
                generation: runtime.context.generation,
                config_digest: runtime.config_digest.clone(),
            })
        }
        _ => {
            return Err(
                "coordinator returned a state that cannot bind controller access".to_owned(),
            );
        }
    };
    endpoints
        .write()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())?
        .active = active;
    Ok(())
}

fn stage_endpoint_rebind(
    endpoints: &RwLock<EngineEndpointBinding>,
    coordinator: &EngineModeCoordinator,
    conflict: BackendErrorKind,
) -> Result<StagedEndpointRebind, String> {
    let role = match conflict {
        BackendErrorKind::MixedEndpointInUse => EndpointRole::Mixed,
        BackendErrorKind::ControllerEndpointInUse => EndpointRole::Controller,
        _ => return Err("non-endpoint failure cannot advance the endpoint cursor".into()),
    };
    if coordinator.snapshot().state != EngineState::Off {
        return Err("endpoint rebind requires a proven Off coordinator snapshot".into());
    }
    let expected = endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())?
        .clone();
    let (settings, cursor) = expected
        .cursor
        .advance(role)
        .map_err(|error| error.to_string())?;
    let controller = EngineControllerAccess::resolve(settings)
        .map_err(|error| format!("replacement engine settings are unusable: {error}"))?;
    Ok(StagedEndpointRebind {
        expected,
        replacement: EngineEndpointBinding {
            controller,
            cursor,
            active: None,
        },
    })
}

fn commit_endpoint_rebind(
    endpoints: &RwLock<EngineEndpointBinding>,
    staged: StagedEndpointRebind,
) -> Result<(), String> {
    let mut current = endpoints
        .write()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())?;
    if *current != staged.expected {
        return Err("engine endpoint state changed before rebind commit".into());
    }
    *current = staged.replacement;
    Ok(())
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
