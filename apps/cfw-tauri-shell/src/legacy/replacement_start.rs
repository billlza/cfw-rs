//! Starting the replacement engine at the end of a cutover or a recovery, and
//! proving that it is the exact Active runtime the journal bound.

use super::*;

pub(super) async fn start_replacement_with_endpoint_rebind(
    engine: &ManagedEngine,
    journal_store: &CutoverJournalStore,
    mut journal: CutoverJournal,
    profile_id: &str,
    profile_digest: &str,
    profile: &cfw_singbox_config::ValidatedSingBoxProfile,
) -> Result<
    (
        EngineSnapshot,
        cfw_engine_api::CutoverPreflightRequest,
        CutoverJournal,
    ),
    String,
> {
    if !matches!(
        journal.phase,
        CutoverPhase::NetworkRetiring | CutoverPhase::LegacyRetired
    ) {
        return Err(format!(
            "replacement endpoint binding cannot start from cutover phase {:?}",
            journal.phase
        ));
    }

    let mut conflict_retry_used = false;
    loop {
        let settings = engine.engine_settings()?;
        if settings != journal.replacement_settings {
            return Err(
                "in-memory replacement endpoints do not match the durable cutover journal".into(),
            );
        }
        let request = engine
            .coordinator
            .prepare_cutover(
                journal.target,
                profile_id.to_owned(),
                profile.clone(),
                settings.clone(),
            )
            .await
            .map_err(|error| format!("replacement projection failed: {error}"))?;
        if journal.context != request.system_proxy_request().context
            || journal.system_proxy_digest != request.system_proxy_request().config_digest
            || journal.tunnel_digest != request.tunnel_request().config_digest
        {
            journal = journal_store.rebind_recovery_request(
                journal.phase,
                profile_id,
                profile_digest,
                &request,
                &settings,
            )?;
        }

        let outcome = run_native_preflight(engine.legacy_preflight()?, request.clone()).await?;
        validate_outcome_binding(&request, &outcome)?;
        if !matches!(outcome, CutoverPreflightOutcome::Ready { .. }) {
            return Err(
                "System Extension approval is still pending; replacement was not started".into(),
            );
        }
        let final_request = engine
            .coordinator
            .prepare_cutover(
                journal.target,
                profile_id.to_owned(),
                profile.clone(),
                settings.clone(),
            )
            .await
            .map_err(|error| format!("final replacement Off validation failed: {error}"))?;
        if final_request != request {
            return Err("replacement projection changed after native preflight".into());
        }

        match engine
            .coordinator
            .set_mode(
                journal.target,
                profile_id.to_owned(),
                profile.clone(),
                settings,
            )
            .await
        {
            Ok(snapshot) => {
                require_replacement_active(
                    snapshot.clone(),
                    journal.target,
                    target_digest(&request),
                    &request.system_proxy_request().context,
                )?;
                engine.record_endpoint_runtime(&snapshot)?;
                return Ok((snapshot, request, journal));
            }
            Err(EngineCoordinatorError::StartEndpointConflictAfterOff { conflict, .. }) => {
                if !conflict_retry_used {
                    // Same bounded retry as the dashboard mode switch: the
                    // listener the coordinator just stopped may still be closing.
                    conflict_retry_used = true;
                    tokio::time::sleep(crate::engine::ENDPOINT_CONFLICT_RETRY_DELAY).await;
                    continue;
                }
                let staged = engine.stage_endpoint_rebind(conflict)?;
                let replacement_settings = staged.settings().clone();
                let rebound_request = engine
                    .coordinator
                    .prepare_cutover(
                        journal.target,
                        profile_id.to_owned(),
                        profile.clone(),
                        replacement_settings.clone(),
                    )
                    .await
                    .map_err(|error| {
                        format!("replacement endpoint re-projection failed: {error}")
                    })?;
                journal = journal_store.rebind_endpoint_request(
                    &journal,
                    &rebound_request,
                    &replacement_settings,
                )?;
                engine.commit_endpoint_rebind(staged)?;
            }
            Err(error) => return Err(format!("replacement start failed: {error}")),
        }
    }
}

fn target_digest(request: &cfw_engine_api::CutoverPreflightRequest) -> &str {
    match request.target() {
        EngineMode::SystemProxy => &request.system_proxy_request().config_digest,
        EngineMode::Tunnel => &request.tunnel_request().config_digest,
        EngineMode::Off | EngineMode::LocalProxy | EngineMode::TunnelSystemProxy => {
            unreachable!("cutover requests reject unsupported replacement modes")
        }
    }
}

pub(super) fn require_replacement_active(
    snapshot: EngineSnapshot,
    target: EngineMode,
    expected_digest: &str,
    expected_context: &cfw_engine_api::EngineCommandContext,
) -> Result<(), String> {
    let runtime = match (&snapshot.state, target) {
        (EngineState::ProxyActive { runtime }, EngineMode::SystemProxy)
        | (EngineState::TunnelActive { runtime }, EngineMode::Tunnel) => runtime,
        _ => {
            return Err(format!(
                "target {target:?} returned non-Active state {:?}",
                snapshot.state
            ));
        }
    };
    if snapshot.desired_mode == target
        && snapshot.generation == expected_context.generation
        && snapshot.config_digest.as_deref() == Some(expected_digest)
        && runtime.owner
            == match target {
                EngineMode::SystemProxy => cfw_engine_api::EngineOwner::ProxyAgent,
                EngineMode::Tunnel | EngineMode::TunnelSystemProxy => {
                    cfw_engine_api::EngineOwner::PacketTunnelSystemExtension
                }
                EngineMode::Off | EngineMode::LocalProxy => {
                    unreachable!("validated replacement target requires an OS integration")
                }
            }
        && &runtime.context == expected_context
        && runtime.config_digest == expected_digest
        && runtime.ready
    {
        Ok(())
    } else {
        Err("replacement runtime identity does not match the preflighted digest".into())
    }
}
