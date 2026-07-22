mod admission;
mod cutover_plan;
mod gui_handoff;
mod journal;
mod migration;
mod network_fingerprint;
mod process_cleanup;
mod recovery;
mod state_gate;

#[cfg(test)]
mod tests;

use cfw_engine_api::{
    CutoverPreflightOutcome, EngineEvent, EngineMode, EngineSnapshot, EngineState,
};
use tauri::{AppHandle, Emitter, State};

use crate::commands::ManagedProfiles;
use crate::engine::{ManagedEngine, run_native_preflight, validate_outcome_binding};
use cutover_plan::LegacyCutoverPlan;
use gui_handoff::LegacyGuiHandoff;
use journal::{
    CutoverJournal, CutoverJournalStore, CutoverPhase, LegacyNetworkJournalInput,
    LegacySessionJournalIdentity,
};

pub(crate) use admission::require_canonical_handoff_candidate;
pub(crate) use journal::MigrationHandoffLease;

pub(crate) use state_gate::{LegacyRetirementGate, LegacyRetirementStatus};

#[tauri::command]
pub(crate) fn legacy_retirement_status(
    retirement: State<'_, LegacyRetirementGate>,
) -> Result<LegacyRetirementStatus, String> {
    retirement.status()
}

#[tauri::command]
pub(crate) async fn disable_service_mode(
    app: AppHandle,
    retirement: State<'_, LegacyRetirementGate>,
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    launch: State<'_, crate::LaunchContext>,
    receipt_id: String,
    cutover_confirmed: bool,
    dns_review_confirmed: bool,
) -> Result<(), String> {
    if !launch.migration_handoff {
        return Err(
            "destructive legacy cutover is accepted only by an explicit --migration-handoff instance"
                .into(),
        );
    }
    admission::require_canonical_handoff_candidate()?;
    require_explicit_cutover_confirmation(cutover_confirmed)?;
    // Immediate exclusive admission requires exact Off and rejects any prior
    // mode change. The lease remains held through retirement and replacement
    // Active verification, so no renderer command can enter the handoff gap.
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let authority = engine.take_cutover_authority(&receipt_id)?;

    // Potentially slow or interactive legacy checks happen while the old VPN
    // is intact and before the retirement state changes to Cleaning.
    let plan =
        LegacyCutoverPlan::prepare(dns_review_confirmed).map_err(|error| error.to_string())?;
    let locked_profile = profiles
        .repository()
        .lock_selected()
        .map_err(|error| format!("selected replacement profile could not be locked: {error}"))?;
    let selected = locked_profile.stored();
    if selected.record.id != authority.profile_id()
        || selected.record.digest != authority.profile_digest()
        || authority.settings() != &cfw_singbox_config::EngineSettings::default()
    {
        return Err(
            "CutoverReceiptStale: selected profile or engine settings changed; the legacy VPN was not changed"
                .into(),
        );
    }
    validate_outcome_binding(
        authority.request(),
        &CutoverPreflightOutcome::Ready {
            attestation: authority.attestation().clone(),
        },
    )?;
    let current_request = engine
        .coordinator
        .prepare_cutover(
            authority.target(),
            selected.profile.clone(),
            authority.settings().clone(),
        )
        .await
        .map_err(|error| format!("cutover live projection failed: {error}"))?;
    if &current_request != authority.request() {
        return Err(
            "CutoverReceiptStale: projection identity changed; the legacy VPN was not changed"
                .into(),
        );
    }

    // This is the last operation before mutation. Native re-resolves every
    // credential, validates both libbox configs, proves global Off, and for a
    // Tunnel target proves the System Extension is ready.
    let live_outcome =
        run_native_preflight(engine.preflight_backend.as_ref(), current_request.clone()).await?;
    validate_outcome_binding(&current_request, &live_outcome)?;
    if !matches!(live_outcome, CutoverPreflightOutcome::Ready { .. }) {
        return Err(
            "System Extension approval is still pending; the legacy VPN was not changed".into(),
        );
    }
    let final_request = engine
        .coordinator
        .prepare_cutover(
            authority.target(),
            selected.profile.clone(),
            authority.settings().clone(),
        )
        .await
        .map_err(|error| format!("final replacement Off validation failed: {error}"))?;
    if final_request != current_request {
        return Err(
            "replacement identity changed after native validation; the legacy VPN was not changed"
                .into(),
        );
    }
    let mut legacy_gui = LegacyGuiHandoff::capture()?;

    let journal_store = CutoverJournalStore::new(plan.store.paths().app_home.clone());
    let journal = CutoverJournal::prepared(
        selected.record.id.clone(),
        selected.record.digest.clone(),
        &current_request,
        LegacyNetworkJournalInput {
            interface: plan.legacy_interface().map(ToOwned::to_owned),
            process: plan.legacy_process().cloned(),
            session: plan.legacy_session_identity().map(
                |(mixed_port, controller_port, generation)| LegacySessionJournalIdentity {
                    mixed_port,
                    controller_port,
                    generation,
                },
            ),
            proxy_services: plan.legacy_proxy_services().to_vec(),
            proxy_port: plan.legacy_proxy_port(),
        },
        legacy_gui.identity().clone(),
    )?;
    // This fsync-backed Prepared record is the last barrier before any
    // destructive operation. Failure here leaves the old VPN untouched.
    journal_store.write_prepared(&journal)?;

    let Some(mut attempt) = retirement.begin_attempt()? else {
        return Err("legacy network is already retired; the cutover receipt was not used".into());
    };
    legacy_gui.stop()?;
    if let Err(error) = journal_store.advance(CutoverPhase::Prepared, CutoverPhase::GuiStopped) {
        return Err(format!(
            "legacy GUI was resumed because its stopped phase could not be persisted: {error}"
        ));
    }
    if let Err(error) =
        journal_store.advance(CutoverPhase::GuiStopped, CutoverPhase::NetworkRetiring)
    {
        return Err(format!(
            "legacy GUI was resumed because network-retirement intent could not be persisted: {error}"
        ));
    }
    legacy_gui.seal_legacy_retired();
    let retired = match plan.retire_network().await {
        Ok(retired) => retired,
        Err(failure) => {
            debug_assert!(!failure.can_resume_old_gui);
            attempt.mark_failed(failure.error.action(), failure.error.to_string())?;
            migration::emit_engine_snapshot_refresh(&app)?;
            return Err(failure.error.to_string());
        }
    };
    let mut journal_warnings = Vec::new();
    if let Err(error) =
        journal_store.advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
    {
        journal_warnings.push(format!(
            "network was retired but LegacyRetired journal persistence failed: {error}"
        ));
    }

    let start = engine
        .coordinator
        .set_mode(
            authority.target(),
            selected.profile.clone(),
            authority.settings().clone(),
        )
        .await;
    let active = match start {
        Ok(snapshot) => require_replacement_active(
            snapshot,
            authority.target(),
            target_digest(&current_request),
            &current_request.system_proxy_request().context,
        ),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = active {
        let message = format!(
            "legacy network retirement completed, but the replacement failed to become Active: {error}. There is no legacy helper fallback; keep this app open, inspect the engine failure, and reconnect with the staged mode"
        );
        attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, &message)?;
        emit_cutover_failure(&app, "cutover_start_failed", &message);
        migration::emit_engine_snapshot_refresh(&app)?;
        return Err(message);
    }

    if let Err(error) = legacy_gui.terminate_after_replacement_active() {
        journal_warnings.push(format!(
            "replacement is Active but the stopped legacy GUI could not be terminated safely: {error}"
        ));
    }

    if let Err(error) = advance_journal_after_active(&journal_store) {
        journal_warnings.push(error);
    }
    let mut warnings = journal_warnings;
    if let Err(error) = migration::finalize_legacy_data(&app, &retired) {
        warnings.push(error);
    } else if let Err(error) = journal_store.advance(
        CutoverPhase::ReplacementActive,
        CutoverPhase::CleanupComplete,
    ) {
        warnings.push(format!(
            "legacy data cleanup completed but CleanupComplete journal persistence failed: {error}"
        ));
    }
    if warnings.is_empty() {
        attempt.mark_cleared()?;
        migration::emit_engine_snapshot_refresh(&app)
    } else {
        let message = format!(
            "replacement network is Active, but non-network legacy data cleanup must be retried: {}",
            warnings.join("; ")
        );
        attempt.mark_post_cutover_cleanup_required(&message)?;
        emit_cutover_failure(&app, "post_cutover_cleanup_required", &message);
        migration::emit_engine_snapshot_refresh(&app)?;
        Err(message)
    }
}

#[tauri::command]
pub(crate) async fn recover_legacy_cutover(
    app: AppHandle,
    retirement: State<'_, LegacyRetirementGate>,
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    launch: State<'_, crate::LaunchContext>,
) -> Result<(), String> {
    if !launch.migration_handoff {
        return Err(
            "replacement recovery is accepted only by an explicit --migration-handoff instance"
                .into(),
        );
    }
    admission::require_canonical_handoff_candidate()?;
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
        recovery::resume_pre_network_cutover_if_intact(&journal, &store)?;
        retirement.apply_launch_preflight(LegacyRetirementStatus::AwaitingConfirmation)?;
        migration::emit_engine_snapshot_refresh(&app)?;
        return Ok(());
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
    let settings = cfw_singbox_config::EngineSettings::default();

    let active_digest = match journal.target {
        EngineMode::SystemProxy => journal.system_proxy_digest.as_str(),
        EngineMode::Tunnel => journal.tunnel_digest.as_str(),
        EngineMode::Off => unreachable!("journal rejects Off"),
    };
    let mut replacement_active = require_replacement_active(
        engine.coordinator.snapshot(),
        journal.target,
        active_digest,
        &journal.context,
    )
    .is_ok();

    if !replacement_active {
        normalize_recovery_engine_off(&engine, &selected.profile, &settings).await?;
        let request = engine
            .coordinator
            .prepare_cutover(journal.target, selected.profile.clone(), settings.clone())
            .await
            .map_err(|error| format!("replacement recovery projection failed: {error}"))?;
        journal = journal_store.rebind_recovery_request(
            journal.phase,
            &selected.record.id,
            &selected.record.digest,
            &request,
        )?;
        let outcome =
            run_native_preflight(engine.preflight_backend.as_ref(), request.clone()).await?;
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
        let snapshot = engine
            .coordinator
            .set_mode(journal.target, selected.profile.clone(), settings.clone())
            .await
            .map_err(|error| format!("replacement recovery start failed: {error}"))?;
        require_replacement_active(
            snapshot,
            journal.target,
            target_digest(&request),
            &request.system_proxy_request().context,
        )?;
        replacement_active = true;
        if journal.phase == CutoverPhase::LegacyRetired {
            journal = journal_store
                .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
        }
    } else if journal.phase == CutoverPhase::NetworkRetiring {
        recovery::finish_network_retirement(&journal, &store).await?;
        journal_store.advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)?;
        journal =
            journal_store.advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
    } else if journal.phase == CutoverPhase::LegacyRetired {
        journal =
            journal_store.advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)?;
    }

    debug_assert!(replacement_active);
    LegacyGuiHandoff::terminate_persisted_after_replacement_active(&journal.legacy_gui)?;
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
        .set_mode(EngineMode::Off, profile.clone(), settings.clone())
        .await
        .map_err(|error| format!("failed to normalize replacement recovery to Off: {error}"))?;
    if off.desired_mode == EngineMode::Off && off.state == EngineState::Off {
        Ok(())
    } else {
        Err("replacement recovery did not reach exact Off".into())
    }
}

fn advance_journal_after_active(store: &CutoverJournalStore) -> Result<(), String> {
    let phase = store
        .load()?
        .ok_or_else(|| "cutover journal disappeared after network retirement".to_owned())?
        .phase;
    let phase = match phase {
        CutoverPhase::NetworkRetiring => {
            store
                .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)?
                .phase
        }
        other => other,
    };
    match phase {
        CutoverPhase::LegacyRetired => store
            .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
            .map(|_| ()),
        CutoverPhase::ReplacementActive => Ok(()),
        other => Err(format!(
            "cutover journal cannot record replacement Active from phase {other:?}"
        )),
    }
}

fn target_digest(request: &cfw_engine_api::CutoverPreflightRequest) -> &str {
    match request.target() {
        EngineMode::SystemProxy => &request.system_proxy_request().config_digest,
        EngineMode::Tunnel => &request.tunnel_request().config_digest,
        EngineMode::Off => unreachable!("cutover requests reject Off"),
    }
}

fn require_replacement_active(
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
                EngineMode::Tunnel => cfw_engine_api::EngineOwner::PacketTunnelSystemExtension,
                EngineMode::Off => unreachable!("active target cannot be Off"),
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

fn emit_cutover_failure(app: &AppHandle, code: &str, message: &str) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(code, message),
    ) {
        eprintln!("failed to publish cutover failure: {error}");
    }
}

fn require_explicit_cutover_confirmation(confirmed: bool) -> Result<(), String> {
    if confirmed {
        Ok(())
    } else {
        Err(
            "legacy network was left unchanged because the one-way cutover was not explicitly confirmed"
                .into(),
        )
    }
}

pub(crate) fn run_launch_preflight(app: &AppHandle) -> Result<(), String> {
    migration::run_launch_preflight(app)
}
