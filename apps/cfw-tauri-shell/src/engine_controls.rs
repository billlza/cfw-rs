//! UI-independent network controls shared by the Tauri and native shells.
//!
//! Each caller enters the same engine mutation queue and admission path. These
//! functions retain snapshot-sensitive enables and superseding owned stops;
//! neither shell owns an alternate native transition or authorization path.

use cfw_engine_api::{EngineMode, EngineSnapshot};

use crate::commands::ManagedProfiles;
use crate::engine::{
    EngineStatusPayload, ManagedEngine, apply_admitted_engine_mode, serialized_switch_transition,
};
use crate::legacy::LegacyRetirementGate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineControl {
    Core,
    SystemProxy,
    Tunnel,
}

/// Explicitly rechecks a failed startup through the existing native service
/// reconciliation path. It never carries a requested start or a profile.
pub(crate) async fn reconcile_startup_services(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
) -> Result<EngineStatusPayload, String> {
    // Capture the actor's current recovery offer before waiting in the Host
    // queue; a queued click cannot adopt a newer offer after another attempt.
    let recovery = engine.coordinator.reconcile_startup();
    let mode_lease = engine
        .begin_mode_change(EngineMode::Off)
        .await
        .map_err(|error| error.to_string())?;
    // Recovery may register the current services, so retain the same exclusion
    // against a live legacy runtime or an unfinished maintenance transaction.
    crate::legacy::require_network_start_allowed(retirement)?;
    let completion = mode_lease
        .run_to_completion(async move { recovery.await.map_err(|error| error.to_string()) });
    let (result, mode_lease) = completion
        .await
        .map_err(|_| "background service recovery task ended without a response".to_owned())?;
    drop(mode_lease);
    result?;
    engine.status_payload(retirement)
}

/// Enables or removes System Proxy while preserving the core and Packet Tunnel.
pub(crate) async fn set_system_proxy_enabled(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    let observed = engine.coordinator.snapshot();
    apply_observed_control(
        engine,
        retirement,
        profiles,
        EngineControl::SystemProxy,
        enabled,
        observed,
    )
    .await
}

/// Starts or removes the Packet Tunnel through the existing Authority path.
pub(crate) async fn set_tun_enabled(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    let observed = engine.coordinator.snapshot();
    apply_observed_control(
        engine,
        retirement,
        profiles,
        EngineControl::Tunnel,
        enabled,
        observed,
    )
    .await
}

/// Starts a local listener without OS integration, or explicitly stops every
/// app-owned runtime. A delayed enable cannot undo a more recent stop.
pub(crate) async fn set_core_enabled(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    enabled: bool,
) -> Result<EngineStatusPayload, String> {
    let observed = engine.coordinator.snapshot();
    apply_observed_control(
        engine,
        retirement,
        profiles,
        EngineControl::Core,
        enabled,
        observed,
    )
    .await
}

/// Applies a control against the snapshot observed by its caller. Native
/// windows can supply their last delivered snapshot; it is not replaced with a
/// newer observation before this request enters the serialized mutation queue.
pub(crate) async fn apply_observed_control(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    control: EngineControl,
    enabled: bool,
    observed: EngineSnapshot,
) -> Result<EngineStatusPayload, String> {
    let requested_mode = match (control, enabled) {
        (_, false) => EngineMode::Off,
        (EngineControl::Core, true) => EngineMode::LocalProxy,
        (EngineControl::SystemProxy, true) => EngineMode::SystemProxy,
        (EngineControl::Tunnel, true) => EngineMode::Tunnel,
    };
    // Queue every intent, including Off, before reading current state. The
    // permit serializes this check with earlier retries and stops; maintenance
    // sees the queued registration throughout.
    let mode_lease = engine
        .begin_mode_change(requested_mode)
        .await
        .map_err(|error| error.to_string())?;
    let current = engine.coordinator.snapshot();
    match control_transition(&observed, &current, control, enabled)? {
        Some(mode) => {
            apply_admitted_engine_mode(engine, retirement, profiles, mode, mode_lease).await
        }
        None => engine.status_payload(retirement),
    }
}

fn control_transition(
    observed: &EngineSnapshot,
    current: &EngineSnapshot,
    control: EngineControl,
    enabled: bool,
) -> Result<Option<EngineMode>, &'static str> {
    match control {
        EngineControl::Core => {
            if enabled && current != observed {
                return Err(
                    "engine state changed while this start was queued; retry against the current state",
                );
            }
            let target = if !enabled {
                EngineMode::Off
            } else if current.desired_mode == EngineMode::Off {
                EngineMode::LocalProxy
            } else {
                current.desired_mode
            };
            Ok(Some(target))
        }
        EngineControl::SystemProxy => {
            serialized_switch_transition(observed, current, EngineMode::SystemProxy, enabled)
        }
        EngineControl::Tunnel => {
            serialized_switch_transition(observed, current, EngineMode::Tunnel, enabled)
        }
    }
}

#[cfg(test)]
mod tests;
