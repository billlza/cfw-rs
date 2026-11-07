#[cfg(target_os = "macos")]
mod cutover;
mod endpoints;
mod maintenance;
mod mode_switch;
mod preparation;
mod runtime_access;
mod runtime_settings;
pub(crate) use mode_switch::{apply_admitted_engine_mode, apply_profile_change};
pub(crate) use preparation::{
    EngineCapabilities, EngineShutdownOutcome, EngineStatusPayload, StagedEndpointRebind,
    prepare_managed_engine,
};
pub(crate) use runtime_access::{ready_runtime, start_engine_event_forwarder};
pub(crate) use runtime_settings::change_runtime_preferences;
#[cfg(feature = "physical-release-evidence")]
pub mod packet_evidence;

/// A start that finds its own loopback endpoint in use right after the
/// coordinator stopped the previous runtime tries the same endpoint once more
/// after this pause before the endpoint cursor moves on. Connections a stopped
/// root-owned tunnel engine leaves in TIME_WAIT do not cause such a conflict:
/// the engine's loopback listeners share their port across users (the
/// endpoint-conflict sing-box patch), so the user agent rebinds the same port
/// and an automatic port stays put across mode switches.
pub(crate) const ENDPOINT_CONFLICT_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(500);

#[cfg(test)]
mod tests;

use std::sync::{Arc, RwLock};
#[cfg(target_os = "macos")]
use std::time::Instant;

use cfw_application::{EngineControllerAccess, EngineCoordinatorError, EngineModeCoordinator};
use cfw_engine_api::{
    BackendErrorKind, CutoverPreflightBackend, EngineEvent, EngineMode, EngineRuntimePlatform,
    EngineSnapshot, EngineState, RuntimeIdentity, SystemProxyAuthorization,
};
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::ManagedProfiles;
#[cfg(target_os = "macos")]
use crate::legacy::load_replacement_engine_settings;
use crate::platform_maintenance::PlatformMaintenanceGate;
use crate::settings_store;
#[cfg(target_os = "macos")]
use cutover::CutoverPreparationGate;
use endpoints::{EndpointCandidateCursor, EndpointRole};
pub(crate) use maintenance::{EngineMaintenanceError, EngineMaintenanceLease, ProfileControlError};
use maintenance::{EngineMaintenanceGate, EngineModeChangeIntent, EngineModeChangeLease};
use preparation::{ActiveControllerBinding, EngineEndpointBinding};
use runtime_access::{
    commit_endpoint_rebind, engine_snapshot_is_off, read_active_controller_access,
    read_controller_access, read_engine_settings, record_endpoint_runtime,
    selected_profile_for_mode, stage_endpoint_rebind,
};

#[cfg(target_os = "macos")]
pub(crate) use cutover::{
    CutoverAuthority, prepare_legacy_cutover, run_native_preflight, validate_outcome_binding,
};

/// Changes one OS integration switch while preserving the other switch.
/// Both enabled integrations share the Packet Tunnel's single libbox instance.
pub(crate) fn switch_transition(
    snapshot: &EngineSnapshot,
    switch: EngineMode,
    enabled: bool,
) -> Option<EngineMode> {
    let desired = snapshot.desired_mode;
    let mut target = match switch {
        EngineMode::SystemProxy => EngineMode::from_switches(enabled, desired.tunnel_enabled()),
        EngineMode::Tunnel => EngineMode::from_switches(desired.system_proxy_enabled(), enabled),
        EngineMode::Off | EngineMode::LocalProxy | EngineMode::TunnelSystemProxy => return None,
    };
    // Removing the last integration preserves a ready core. Cancelling a
    // pending/failed start is a stop, and must never start a new local runtime.
    let ready = matches!(&snapshot.state,
        EngineState::LocalProxyActive { runtime }
        | EngineState::ProxyActive { runtime }
        | EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime } if runtime.ready
    );
    if !enabled && target == EngineMode::LocalProxy && !ready {
        target = EngineMode::Off;
    }
    if target != desired {
        return Some(target);
    }
    if !enabled {
        return None;
    }
    match &snapshot.state {
        EngineState::Off => Some(target),
        EngineState::Failed {
            target: failed_target,
            ..
        } if *failed_target == target => Some(target),
        EngineState::AwaitingApproval { .. } if target.tunnel_enabled() => Some(target),
        EngineState::LocalProxyActive { runtime }
        | EngineState::ProxyActive { runtime }
        | EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime }
            if !runtime.ready =>
        {
            Some(target)
        }
        _ => None,
    }
}

fn mode_owns_switch(mode: EngineMode, switch: EngineMode) -> bool {
    match switch {
        EngineMode::SystemProxy => mode.system_proxy_enabled(),
        EngineMode::Tunnel => mode.tunnel_enabled(),
        EngineMode::Off | EngineMode::LocalProxy | EngineMode::TunnelSystemProxy => false,
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
    if !enabled
        && (!mode_owns_switch(observed.desired_mode, switch)
            || !mode_owns_switch(current.desired_mode, switch))
    {
        return Ok(None);
    }
    if enabled && observed != current {
        return Err(
            "network mode changed while this enable request was queued; retry against the current state",
        );
    }
    Ok(switch_transition(current, switch, enabled))
}

pub struct ManagedEngine {
    pub(crate) coordinator: EngineModeCoordinator,
    capabilities: EngineCapabilities,
    unavailable_reason: Option<String>,
    preflight_backend: Option<Arc<dyn CutoverPreflightBackend>>,
    system_proxy_authorization: Arc<dyn SystemProxyAuthorization>,
    pub(crate) profile_delay_backend: Arc<dyn cfw_engine_api::ProfileDelayBackend>,
    tunnel_approval: Option<Arc<dyn cfw_engine_api::TunnelApprovalBackend>>,
    #[cfg(target_os = "macos")]
    cutover: CutoverPreparationGate,
    maintenance: EngineMaintenanceGate,
    endpoints: Arc<RwLock<EngineEndpointBinding>>,
}

impl ManagedEngine {
    #[cfg(target_os = "macos")]
    pub(crate) fn legacy_preflight(&self) -> Result<&dyn CutoverPreflightBackend, String> {
        self.preflight_backend
            .as_deref()
            .ok_or_else(|| "legacy service cutover is unavailable on this platform".into())
    }

    /// The platform's wait for a Tunnel installation's approval; `None` where
    /// an installation never awaits one.
    pub(crate) fn tunnel_approval(
        &self,
    ) -> Option<&Arc<dyn cfw_engine_api::TunnelApprovalBackend>> {
        self.tunnel_approval.as_ref()
    }

    pub(crate) fn mode_intent_revision(&self) -> Result<u64, EngineMaintenanceError> {
        self.maintenance.intent_revision()
    }
    pub(crate) async fn begin_automatic_mode_change(
        &self,
        mode: EngineMode,
        revision: u64,
    ) -> Result<EngineModeChangeLease, EngineMaintenanceError> {
        self.maintenance
            .begin_mode_change_if_current(EngineModeChangeIntent::Set(mode), Some(revision))
            .await
    }
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

    #[cfg(target_os = "macos")]
    pub(crate) fn record_endpoint_runtime(&self, snapshot: &EngineSnapshot) -> Result<(), String> {
        record_endpoint_runtime(
            &self.endpoints,
            self.coordinator.runtime_platform(),
            snapshot,
        )
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn stage_endpoint_rebind(
        &self,
        conflict: BackendErrorKind,
    ) -> Result<StagedEndpointRebind, String> {
        stage_endpoint_rebind(&self.endpoints, &self.coordinator, conflict)
    }

    #[cfg(target_os = "macos")]
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
                | EngineMaintenanceError::ModeChangeActive
                | EngineMaintenanceError::StaleIntent => ProfileControlError::MaintenanceBusy,
                EngineMaintenanceError::StateLock | EngineMaintenanceError::QueueFull => {
                    ProfileControlError::StateUnavailable
                }
            })?;
        if !self.is_off_under(&lease) {
            return Err(ProfileControlError::EngineNotOff);
        }
        Ok(lease)
    }

    /// Whether the engine is Off. While `_held` lives no mode or profile
    /// change can start, so the answer holds until the lease drops.
    pub(crate) fn is_off_under(&self, _held: &EngineMaintenanceLease) -> bool {
        engine_snapshot_is_off(&self.coordinator.snapshot())
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
        let authorization = self.system_proxy_authorization.clone();
        let (result, maintenance) = maintenance
            .run_to_completion(async move {
                authorize_proxy_transition(authorization.as_ref(), true).await?;
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

    /// Runs background service `recovery` once macOS granted the rights to
    /// restore the System Proxy settings an ended session left; see
    /// `recover_after_settings_restoration`.
    pub(crate) fn recover_with_restoration_rights<R>(
        &self,
        recovery: R,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'static + use<R>
    where
        R: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let authorization = self.system_proxy_authorization.clone();
        recover_after_settings_restoration(
            move |restoration_only| async move {
                authorization.authorize_system_proxy(restoration_only).await
            },
            recovery,
        )
    }

    pub(crate) fn require_capability(&self, mode: EngineMode) -> Result<(), String> {
        let available = match mode {
            EngineMode::Off => false,
            EngineMode::LocalProxy => self.capabilities.local_proxy,
            EngineMode::SystemProxy => self.capabilities.system_proxy,
            EngineMode::Tunnel => self.capabilities.tunnel,
            EngineMode::TunnelSystemProxy => self.capabilities.tunnel_system_proxy,
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

    #[cfg(target_os = "macos")]
    pub(crate) fn take_cutover_authority(
        &self,
        receipt_id: &str,
    ) -> Result<CutoverAuthority, String> {
        self.cutover.take(receipt_id, Instant::now())
    }

    pub(crate) fn status_payload(
        &self,
        retirement: &PlatformMaintenanceGate,
    ) -> Result<EngineStatusPayload, String> {
        let retirement_reason = crate::platform_maintenance::start_block_reason(retirement)?;
        let capabilities = if retirement_reason.is_some() {
            EngineCapabilities {
                local_proxy: false,
                system_proxy: false,
                tunnel: false,
                tunnel_system_proxy: false,
                provider_management: true,
            }
        } else {
            self.capabilities
        };
        #[cfg(target_os = "macos")]
        let (cutover_ready, mut cutover_reason) = self.cutover.readiness(Instant::now())?;
        #[cfg(windows)]
        let (cutover_ready, mut cutover_reason) = (
            false,
            Some("legacy maintenance does not apply to this Windows release".into()),
        );
        let cutover_ready = cutover_ready && self.preflight_backend.is_some();
        if self.preflight_backend.is_none() {
            cutover_reason = Some("legacy service cutover is unavailable on this platform".into());
        }
        if self.unavailable_reason.is_some() {
            cutover_reason = self.unavailable_reason.clone();
        }
        Ok(EngineStatusPayload {
            snapshot: self.coordinator.snapshot(),
            capabilities,
            startup_recovery_available: self.unavailable_reason.is_none()
                && retirement_reason.is_none()
                && self.coordinator.can_reconcile_startup(),
            cutover_ready: cutover_ready
                && (self.capabilities.system_proxy || self.capabilities.tunnel),
            cutover_unavailable_reason: (!cutover_ready).then_some(cutover_reason).flatten(),
            unavailable_reason: retirement_reason.or_else(|| self.unavailable_reason.clone()),
        })
    }
}

#[tauri::command]
pub(crate) fn engine_snapshot(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
) -> Result<EngineStatusPayload, String> {
    engine.status_payload(&retirement)
}

/// What became of the macOS prompt behind a System Proxy rights request that
/// did not go through. macOS asks for consent in its own prompt, so these are
/// the two outcomes a user can cause; every other failure is no answer of the
/// user's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RightsPromptOutcome {
    /// No answer came in time: the prompt went unanswered, or, which the Host
    /// cannot tell apart, the ProxyAgent that shows it did not reply.
    Unanswered,
    Refused,
}

impl RightsPromptOutcome {
    fn of(code: BackendErrorKind) -> Option<Self> {
        match code {
            BackendErrorKind::Timeout => Some(Self::Unanswered),
            BackendErrorKind::ApprovalDenied | BackendErrorKind::PermissionDenied => {
                Some(Self::Refused)
            }
            _ => None,
        }
    }
}

/// What the page shows when System Proxy authorization does not go through:
/// either outcome the user caused gets the way back.
fn authorization_failure_message(code: BackendErrorKind, message: &str) -> String {
    if cfg!(windows) {
        return format!(
            "System Proxy authorization failed: {code:?}: {message}. Check Windows proxy policy and the user session before trying again."
        );
    }
    match RightsPromptOutcome::of(code) {
        Some(RightsPromptOutcome::Unanswered) => "System Proxy authorization timed out: macOS did \
             not get an answer to its prompt. Turn System Proxy on again and approve the prompt."
            .into(),
        Some(RightsPromptOutcome::Refused) => "System Proxy authorization was cancelled or \
             denied. Turn System Proxy on again and approve the prompt."
            .into(),
        None => format!("System Proxy authorization failed: {code:?}: {message}"),
    }
}

async fn authorize_proxy_transition(
    authorization: &dyn SystemProxyAuthorization,
    restoration_only: bool,
) -> Result<(), String> {
    authorization
        .authorize_system_proxy(restoration_only)
        .await
        .map_err(|error| authorization_failure_message(error.kind, &error.message))
}

/// Recovers background services once macOS granted the rights to restore the
/// System Proxy settings an ended session left. `authorize` asks for those
/// rights alone, restoration only, so with no settings left macOS shows no
/// prompt. The user's refusal, or a prompt left unanswered, ends the recovery
/// before it starts, because those settings stay until the user approves.
/// Any other failure comes from the services this recovery repairs, so the
/// recovery runs: one that proves Off had no settings left to restore, since
/// a ProxyAgent holding them never reports Off, and one that fails reports
/// both causes.
async fn recover_after_settings_restoration<A>(
    authorize: impl FnOnce(bool) -> A,
    recovery: impl std::future::Future<Output = Result<(), String>>,
) -> Result<(), String>
where
    A: std::future::Future<Output = Result<(), cfw_engine_api::BackendError>>,
{
    let unrequested = match authorize(true).await {
        Ok(()) => None,
        #[cfg(windows)]
        Err(error) if RightsPromptOutcome::of(error.kind).is_some() => {
            return Err(format!(
                "Restoring System Proxy settings was not authorized: {}. Check Windows proxy policy and the user session, then recover background services again.",
                error.message
            ));
        }
        Err(error) => match RightsPromptOutcome::of(error.kind) {
            Some(RightsPromptOutcome::Unanswered) => {
                return Err(
                    "Restoring System Proxy settings timed out: macOS did not get an \
                     answer to its prompt, or the ProxyAgent did not reply. Recover background \
                     services again and approve the prompt."
                        .into(),
                );
            }
            Some(RightsPromptOutcome::Refused) => {
                return Err(
                    "Restoring System Proxy settings was cancelled or denied. Recover \
                     background services again and approve the prompt."
                        .into(),
                );
            }
            None => Some(format!("{:?}: {}", error.kind, error.message)),
        },
    };
    recovery.await.map_err(|error| match unrequested {
        Some(cause) => format!(
            "{error}; the rights to restore System Proxy settings could not be requested: {cause}"
        ),
        None => error,
    })
}
