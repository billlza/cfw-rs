//! The one-way cutover from the legacy network to the replacement, which only
//! a migration hand-off instance runs.

use super::*;

// Tauri commands receive each renderer argument as a separate parameter, so the
// injected handles plus the explicit confirmation flags exceed the default
// argument threshold without any of them being removable.
#[allow(clippy::too_many_arguments)]
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
    if !launch.is_migration_handoff() {
        return Err(
            "destructive legacy cutover is accepted only by an explicit --migration-handoff instance"
                .into(),
        );
    }
    launch.require_renderer_ready_published()?;
    admission::require_canonical_handoff_candidate()?;
    launch.require_handoff_parent_absent()?;
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
        || authority.settings() != &engine.engine_settings()?
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
            selected.record.id.clone(),
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
        run_native_preflight(engine.legacy_preflight()?, current_request.clone()).await?;
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
            selected.record.id.clone(),
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
    let parent = launch
        .handoff_parent_identity()
        .ok_or_else(|| "migration handoff has no ticket-bound parent identity".to_owned())?;
    let mut legacy_gui = LegacyGuiHandoff::capture(parent, plan.runtime_kind())?;

    let journal_store = CutoverJournalStore::new(plan.store.paths().app_home.clone());
    let journal = CutoverJournal::prepared(
        selected.record.id.clone(),
        selected.record.digest.clone(),
        &current_request,
        authority.settings().clone(),
        plan.runtime_kind(),
        LegacyNetworkJournalInput {
            tunnel: plan.legacy_tunnel_identity(),
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
        legacy_gui.identity().cloned(),
    )?;
    // This fsync-backed Prepared record is the last barrier before any
    // destructive operation. Failure here leaves the old VPN untouched.
    journal_store.write_prepared(&journal)?;

    let Some(mut attempt) = retirement.begin_attempt()? else {
        return Err("legacy network is already retired; the cutover receipt was not used".into());
    };
    legacy_gui.verify_before_network_retirement_seal()?;
    if let Err(error) = journal_store.advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
    {
        if error.commit_is_uncertain() {
            return Err(format!(
                "NetworkRetiring journal commit is durability-uncertain; the legacy GUI and network were not intentionally changed, and explicit recovery is required: {error}"
            ));
        }
        return Err(format!(
            "network-retirement intent could not be persisted; the legacy GUI and network remain unchanged: {error}"
        ));
    }
    legacy_gui.seal_network_retirement();
    legacy_gui.terminate_for_network_retirement()?;
    if let Err(error) = legacy_gui.revalidate_for_network_mutation() {
        attempt.mark_failed(
            state_gate::LegacyCleanupAction::Retry,
            format!("legacy GUI state changed at the network-retirement boundary: {error}"),
        )?;
        migration::emit_engine_snapshot_refresh(&app)?;
        return Err(error);
    }
    let retired = match plan
        .retire_network(|| legacy_gui.revalidate_for_network_mutation())
        .await
    {
        Ok(retired) => retired,
        Err(failure) => {
            attempt.mark_failed(failure.error.action(), failure.error.to_string())?;
            migration::emit_engine_snapshot_refresh(&app)?;
            return Err(failure.error.to_string());
        }
    };
    if let Err(error) = legacy_gui.revalidate_for_network_mutation() {
        let message = format!(
            "legacy service was retired, but the journal-bound GUI absence changed before replacement start: {error}"
        );
        attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, &message)?;
        migration::emit_engine_snapshot_refresh(&app)?;
        return Err(message);
    }
    let mut journal_warnings = Vec::new();
    if let Err(error) =
        journal_store.advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
    {
        journal_warnings.push(format!(
            "network was retired but LegacyRetired journal persistence failed: {error}"
        ));
    }

    let start_journal = journal_store
        .load()?
        .ok_or_else(|| "cutover journal disappeared before replacement start".to_owned())?;
    let active = start_replacement_with_endpoint_rebind(
        &engine,
        &journal_store,
        start_journal,
        &selected.record.id,
        &selected.record.digest,
        &selected.profile,
    )
    .await
    .map(|_| ());
    if let Err(error) = active {
        let message = format!(
            "legacy network retirement completed, but the replacement failed to become Active: {error}. There is no legacy helper fallback; keep this app open, inspect the engine failure, and reconnect with the staged mode"
        );
        attempt.mark_failed(state_gate::LegacyCleanupAction::Retry, &message)?;
        emit_cutover_failure(&app, "cutover_start_failed", &message);
        migration::emit_engine_snapshot_refresh(&app)?;
        return Err(message);
    }

    if let Err(error) = legacy_gui.verify_terminated_after_replacement_active() {
        journal_warnings.push(format!(
            "replacement is Active but the legacy GUI exit could not be reverified safely: {error}"
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
            .map(|_| ())
            .map_err(String::from),
        CutoverPhase::ReplacementActive => Ok(()),
        other => Err(format!(
            "cutover journal cannot record replacement Active from phase {other:?}"
        )),
    }
}

pub(super) fn require_explicit_cutover_confirmation(confirmed: bool) -> Result<(), String> {
    if confirmed {
        Ok(())
    } else {
        Err(
            "legacy network was left unchanged because the one-way cutover was not explicitly confirmed"
                .into(),
        )
    }
}
