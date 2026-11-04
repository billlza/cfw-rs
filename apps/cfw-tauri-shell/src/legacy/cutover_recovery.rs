//! Recovering an interrupted cutover from its journal. The network-side steps
//! the recovery runs are in `recovery`.

use super::*;

#[tauri::command]
pub(crate) async fn recover_legacy_cutover(
    app: AppHandle,
    retirement: State<'_, LegacyRetirementGate>,
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    launch: State<'_, crate::LaunchContext>,
) -> Result<(), String> {
    if !launch.is_migration_handoff() {
        return Err(
            "replacement recovery is accepted only by an explicit --migration-handoff instance"
                .into(),
        );
    }
    launch.require_renderer_ready_published()?;
    launch.require_handoff_parent_absent()?;
    let _maintenance = engine
        .reserve_maintenance()
        .map_err(|error| error.to_string())?;
    let store = crate::settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let journal_store = CutoverJournalStore::new(store.paths().app_home.clone());
    let mut journal = journal_store
        .load()?
        .ok_or_else(|| "no interrupted legacy cutover journal exists".to_owned())?;

    if matches!(
        journal.phase,
        CutoverPhase::Prepared | CutoverPhase::GuiStopped
    ) {
        migration::require_explicit_pre_network_recovery(
            launch.is_migration_handoff(),
            admission::require_canonical_handoff_candidate,
            || recovery::seal_pre_network_cutover_for_recovery(&journal, &store),
        )
        .map_err(|failure| {
            migration::emit_launch_recovery_diagnostic(journal.phase, &failure);
            failure.user_message().to_owned()
        })?;
        journal = journal_store
            .load()?
            .ok_or_else(|| "sealed legacy cutover journal disappeared".to_owned())?;
    } else {
        admission::require_canonical_handoff_candidate()?;
    }
    if journal.phase == CutoverPhase::CleanupComplete {
        migration::run_launch_preflight(&app)?;
        return Ok(());
    }
    let Some(mut attempt) = retirement.begin_attempt()? else {
        return Err("legacy cutover recovery is already complete".into());
    };
    let locked_profile = profiles
        .repository()
        .lock_selected()
        .map_err(|error| format!("selected recovery profile could not be locked: {error}"))?;
    let selected = locked_profile.stored();
    if selected.record.id != journal.profile_id || selected.record.digest != journal.profile_digest
    {
        let message = "selected profile no longer matches the interrupted cutover; recovery did not change networking";
        attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, message)?;
        return Err(message.into());
    }
    engine.require_capability(journal.target)?;
    let settings = journal.replacement_settings.clone();
    if settings != engine.engine_settings()? {
        let message = "recovery engine settings do not match the journal-bound replacement; recovery did not change networking";
        attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, message)?;
        return Err(message.into());
    }

    let active_digest = match journal.target {
        EngineMode::SystemProxy => journal.system_proxy_digest.as_str(),
        EngineMode::Tunnel => journal.tunnel_digest.as_str(),
        EngineMode::Off
        | EngineMode::LocalProxy
        | cfw_engine_api::EngineMode::TunnelSystemProxy => {
            unreachable!("journal rejects unsupported replacement modes")
        }
    };
    let mut replacement_active = require_replacement_active(
        engine.coordinator.snapshot(),
        journal.target,
        active_digest,
        &journal.context,
    )
    .is_ok();

    if !replacement_active {
        if journal.phase == CutoverPhase::ReplacementActive {
            let message = "a ReplacementActive journal no longer has its exact active runtime; endpoint or generation rebinding is forbidden in this phase";
            attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, message)?;
            return Err(message.into());
        }
        if journal.phase == CutoverPhase::NetworkRetiring {
            recovery::ensure_network_retiring_gui_terminated(&journal)?;
        }
        normalize_recovery_engine_off(&engine, &selected.record.id, &selected.profile, &settings)
            .await?;
        let request = engine
            .coordinator
            .prepare_cutover(
                journal.target,
                selected.record.id.clone(),
                selected.profile.clone(),
                settings.clone(),
            )
            .await
            .map_err(|error| format!("replacement recovery projection failed: {error}"))?;
        journal = journal_store.rebind_recovery_request(
            journal.phase,
            &selected.record.id,
            &selected.record.digest,
            &request,
            &settings,
        )?;
        let outcome = run_native_preflight(engine.legacy_preflight()?, request.clone()).await?;
        validate_outcome_binding(&request, &outcome)?;
        if !matches!(outcome, CutoverPreflightOutcome::Ready { .. }) {
            let message = "System Extension approval is still pending; replacement recovery made no further network change";
            attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, message)?;
            return Err(message.into());
        }

        if journal.phase == CutoverPhase::NetworkRetiring {
            recovery::finish_network_retirement(&journal, &store).await?;
            journal = journal_store
                .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)?;
        }
        if journal.phase != CutoverPhase::LegacyRetired
            && journal.phase != CutoverPhase::ReplacementActive
        {
            return Err(format!(
                "replacement cannot start from recovery phase {:?}",
                journal.phase
            ));
        }
        let (_, _, rebound_journal) = start_replacement_with_endpoint_rebind(
            &engine,
            &journal_store,
            journal,
            &selected.record.id,
            &selected.record.digest,
            &selected.profile,
        )
        .await
        .map_err(|error| format!("replacement recovery start failed: {error}"))?;
        journal = rebound_journal;
        replacement_active = true;
        if journal.phase == CutoverPhase::LegacyRetired {
            journal = journal_store
                .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
        }
    } else if journal.phase == CutoverPhase::NetworkRetiring {
        recovery::verify_network_retirement_completed_with_active_replacement(&journal, &store)?;
        require_replacement_active(
            engine.coordinator.snapshot(),
            journal.target,
            active_digest,
            &journal.context,
        )?;
        journal_store.advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)?;
        journal =
            journal_store.advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
    } else if journal.phase == CutoverPhase::LegacyRetired {
        journal =
            journal_store.advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
    }

    debug_assert!(replacement_active);
    let active_digest = match journal.target {
        EngineMode::SystemProxy => journal.system_proxy_digest.as_str(),
        EngineMode::Tunnel => journal.tunnel_digest.as_str(),
        EngineMode::Off
        | EngineMode::LocalProxy
        | cfw_engine_api::EngineMode::TunnelSystemProxy => {
            unreachable!("journal rejects unsupported replacement modes")
        }
    };
    require_replacement_active(
        engine.coordinator.snapshot(),
        journal.target,
        active_digest,
        &journal.context,
    )?;
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::terminate_persisted_after_replacement_active(legacy_gui)?;
    }
    match migration::finalize_recovered_legacy_data(&app) {
        Ok(()) => {
            if journal.phase == CutoverPhase::ReplacementActive {
                journal_store.advance(
                    CutoverPhase::ReplacementActive,
                    CutoverPhase::CleanupComplete,
                )?;
            }
            attempt.mark_cleared()?;
            migration::emit_engine_snapshot_refresh(&app)
        }
        Err(error) => {
            let message = format!(
                "replacement is Active, but non-network legacy data cleanup remains: {error}"
            );
            attempt.mark_post_cutover_cleanup_required(&message)?;
            emit_cutover_failure(&app, "post_cutover_cleanup_required", &message);
            migration::emit_engine_snapshot_refresh(&app)?;
            Err(message)
        }
    }
}

async fn normalize_recovery_engine_off(
    engine: &ManagedEngine,
    profile_id: &str,
    profile: &cfw_singbox_config::ValidatedSingBoxProfile,
    settings: &cfw_singbox_config::EngineSettings,
) -> Result<(), String> {
    let snapshot = engine.coordinator.snapshot();
    if snapshot.desired_mode == EngineMode::Off && snapshot.state == EngineState::Off {
        return Ok(());
    }
    if !matches!(snapshot.state, EngineState::Failed { .. }) {
        return Err(format!(
            "recovery refuses to stop an unrecognized live engine state {:?}",
            snapshot.state
        ));
    }
    let off = engine
        .coordinator
        .set_mode(
            EngineMode::Off,
            profile_id.to_owned(),
            profile.clone(),
            settings.clone(),
        )
        .await
        .map_err(|error| format!("failed to normalize replacement recovery to Off: {error}"))?;
    if off.desired_mode == EngineMode::Off && off.state == EngineState::Off {
        Ok(())
    } else {
        Err("replacement recovery did not reach exact Off".into())
    }
}
