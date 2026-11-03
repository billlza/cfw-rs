//! Reading the running engine: its event forwarder, settings, controller
//! access and readiness, and the endpoint rebind it stages and commits.

use super::*;

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
            if let EngineState::Failed {
                generation,
                target,
                error,
                recheck_pending,
            } = &snapshot.state
            {
                let recheck = if *recheck_pending {
                    " recheck=pending"
                } else {
                    ""
                };
                crate::diagnostics::record(
                    &app,
                    cfw_core::DiagnosticTopic::Network,
                    "engine_failed",
                    &format!("generation={generation} target={target:?}{recheck}: {error}"),
                );
            }
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

pub(super) fn read_engine_settings(
    endpoints: &RwLock<EngineEndpointBinding>,
) -> Result<EngineSettings, String> {
    endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())
        .map(|binding| binding.controller.settings().clone())
}

pub(super) fn read_controller_access(
    endpoints: &RwLock<EngineEndpointBinding>,
) -> Result<EngineControllerAccess, String> {
    endpoints
        .read()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())
        .map(|binding| binding.controller.clone())
}

pub(super) fn read_active_controller_access(
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

/// Shared desktop identity policy for endpoints, controller commands and tray
/// state. The platform must come from the coordinator's pinned backend choice.
pub(crate) fn ready_runtime(
    platform: EngineRuntimePlatform,
    snapshot: &EngineSnapshot,
) -> Option<&RuntimeIdentity> {
    let (runtime, owner) = match &snapshot.state {
        EngineState::LocalProxyActive { runtime } | EngineState::ProxyActive { runtime } => {
            (runtime, platform.proxy_owner())
        }
        EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime } => (runtime, platform.tunnel_owner()),
        _ => return None,
    };
    (snapshot.desired_mode == snapshot.state.active_mode()
        && runtime.owner == owner
        && runtime.ready
        && runtime.context.generation == snapshot.generation
        && snapshot.config_digest.as_deref() == Some(runtime.config_digest.as_str()))
    .then_some(runtime)
}

pub(super) fn record_endpoint_runtime(
    endpoints: &RwLock<EngineEndpointBinding>,
    platform: EngineRuntimePlatform,
    snapshot: &EngineSnapshot,
) -> Result<(), String> {
    let active = match &snapshot.state {
        EngineState::Off if snapshot.desired_mode == EngineMode::Off => None,
        EngineState::AwaitingApproval { .. } if snapshot.desired_mode.tunnel_enabled() => None,
        _ => {
            let runtime = ready_runtime(platform, snapshot).ok_or_else(|| {
                "coordinator returned a state that cannot bind controller access".to_owned()
            })?;
            Some(ActiveControllerBinding {
                generation: runtime.context.generation,
                config_digest: runtime.config_digest.clone(),
            })
        }
    };
    endpoints
        .write()
        .map_err(|_| "engine endpoint state lock is poisoned".to_owned())?
        .active = active;
    Ok(())
}

pub(super) fn stage_endpoint_rebind(
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

pub(super) fn commit_endpoint_rebind(
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

/// Off both as requested and as observed; a pending, failed or stopping
/// engine is not Off.
pub(super) fn engine_snapshot_is_off(snapshot: &EngineSnapshot) -> bool {
    snapshot.desired_mode == EngineMode::Off && snapshot.state == EngineState::Off
}

pub(super) fn selected_profile_for_mode(
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
