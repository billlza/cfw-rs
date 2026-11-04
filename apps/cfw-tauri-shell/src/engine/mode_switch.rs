//! Applying an admitted engine mode or profile change, and the endpoint
//! rebind a mode switch may need.

use super::*;

/// The single in-process execution path after a caller transfers its
/// single-flight transition permit.
///
/// Every renderer mutation first acquires an exact target or current-mode
/// admission, then funnels through here so the live legacy-runtime admission,
/// capability check, selected profile, and app-owned settings cannot be
/// skipped. The permit outlives renderer cancellation until the coordinator
/// actor responds, so accepted native work cannot escape maintenance.
pub(crate) async fn apply_admitted_engine_mode(
    engine: &ManagedEngine,
    retirement: &PlatformMaintenanceGate,
    profiles: &ManagedProfiles,
    mode: EngineMode,
    mode_lease: EngineModeChangeLease,
) -> Result<EngineStatusPayload, String> {
    if mode != EngineMode::Off {
        crate::platform_maintenance::require_start_allowed(retirement)?;
        engine.require_capability(mode)?;
    }
    let (profile_id, profile) = selected_profile_for_mode(profiles.repository(), mode)
        .map_err(|error| error.to_string())?;
    let coordinator = engine.coordinator.clone();
    let endpoints = engine.endpoints.clone();
    let authorization = engine.system_proxy_authorization.clone();
    let retry_guard = mode_lease.retry_guard();
    let completion = mode_lease.run_to_completion(async move {
        // Authorization precedes the runtime transition, including restoration
        // after a long session. The existing runtime stays active while macOS
        // waits; no cleanup deadline or new engine generation has begun.
        authorize_proxy_transition(authorization.as_ref(), mode != EngineMode::SystemProxy).await?;
        set_mode_with_endpoint_rebind(
            &coordinator,
            &endpoints,
            mode,
            &profile_id,
            &profile,
            || retry_guard().map_err(|error| error.to_string()),
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

/// A profile transaction owns the same queue as explicit mode changes. Native
/// preparation runs in the actor, so status polling cannot mistake bridge Busy
/// for a crashed active runtime. The owned task survives a dropped UI waiter.
pub(crate) async fn apply_profile_change<T, F, P>(
    engine: &ManagedEngine,
    retirement: &PlatformMaintenanceGate,
    prepare: P,
) -> Result<T, String>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<cfw_application::ProfileChange<T>, String>>
        + Send
        + 'static,
    P: FnOnce(EngineSettings) -> F + Send + 'static,
{
    let (mode, lease) = engine
        .begin_current_mode_change()
        .await
        .map_err(|error| error.to_string())?;
    let start_admission = if mode != EngineMode::Off {
        crate::platform_maintenance::require_start_allowed(retirement)
            .and_then(|()| engine.require_capability(mode))
    } else {
        Ok(())
    };
    let settings = engine.engine_settings()?;
    let coordinator = engine.coordinator.clone();
    let endpoints = engine.endpoints.clone();
    let authorization = engine.system_proxy_authorization.clone();
    let (result, lease) = lease
        .run_to_completion(async move {
            let before = coordinator.snapshot();
            let preparation_settings = settings.clone();
            let result = coordinator
                .change_profile(settings, async move {
                    let candidate = prepare(preparation_settings)
                        .await
                        .map_err(EngineCoordinatorError::ProfilePreparation)?;
                    if candidate.activate && mode != EngineMode::Off {
                        start_admission.map_err(EngineCoordinatorError::ProfilePreparation)?;
                        authorize_proxy_transition(
                            authorization.as_ref(),
                            mode != EngineMode::SystemProxy,
                        )
                        .await
                        .map_err(EngineCoordinatorError::ProfilePreparation)?;
                    }
                    Ok(candidate)
                })
                .await;
            // Failed replacements may have restored a new generation of the old
            // source. Always refresh controller identity from the resulting state.
            let after = coordinator.snapshot();
            let binding = if after == before {
                Ok(())
            } else {
                record_endpoint_runtime(&endpoints, coordinator.runtime_platform(), &after)
            };
            match (result, binding) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), Ok(())) => Err(error.to_string()),
                (Ok(_), Err(binding)) => Err(format!(
                    "profile committed, but controller identity refresh failed: {binding}"
                )),
                (Err(error), Err(binding)) => Err(format!(
                    "{error}; controller identity refresh also failed: {binding}"
                )),
            }
        })
        .await
        .map_err(|_| "profile transaction task ended without a response".to_owned())?;
    drop(lease);
    result
}

pub(super) async fn set_mode_with_endpoint_rebind(
    coordinator: &EngineModeCoordinator,
    endpoints: &RwLock<EngineEndpointBinding>,
    mode: EngineMode,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    ensure_retry_current: impl Fn() -> Result<(), String>,
    mut rebind: impl FnMut(BackendErrorKind) -> Result<(), String>,
) -> Result<EngineSnapshot, String> {
    let mut ticket_retry_used = false;
    let mut conflict_retry_used = false;
    loop {
        let settings = read_engine_settings(endpoints)?;
        match coordinator
            .set_mode(mode, profile_id.to_owned(), profile.clone(), settings)
            .await
        {
            Ok(snapshot) => {
                record_endpoint_runtime(endpoints, coordinator.runtime_platform(), &snapshot)?;
                return Ok(snapshot);
            }
            Err(EngineCoordinatorError::StartEndpointConflictAfterOff { conflict, .. }) => {
                ensure_retry_current()?;
                if !conflict_retry_used {
                    // The coordinator has cleaned the failed attempt and proven
                    // Off; the endpoint it could not bind was most likely the
                    // listener it just stopped. Try the same endpoint once more
                    // before the cursor moves on.
                    conflict_retry_used = true;
                    tokio::time::sleep(ENDPOINT_CONFLICT_RETRY_DELAY).await;
                    continue;
                }
                rebind(conflict)?;
            }
            Err(EngineCoordinatorError::StartTicketExpiredAfterOff) if !ticket_retry_used => {
                ensure_retry_current()?;
                ticket_retry_used = true;
                // The coordinator has already cleaned the failed attempt and
                // independently proven Off. The next call allocates a fresh
                // generation/ticket; it never reuses or extends the old ticket.
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
