mod admission;
mod cutover;
mod cutover_plan;
mod cutover_recovery;
mod gui_handoff;
mod handoff_launch;
mod handoff_ticket;
mod journal;
mod migration;
mod network_fingerprint;
mod normal_start;
mod process_cleanup;
mod recovery;
mod replacement_start;
mod runtime_plan;
mod state_gate;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::path::Path;

use cfw_application::EngineCoordinatorError;
use cfw_engine_api::{
    CutoverPreflightOutcome, EngineEvent, EngineMode, EngineSnapshot, EngineState,
};
use cfw_singbox_config::EngineSettings;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::oneshot;

use crate::commands::ManagedProfiles;
use crate::engine::{ManagedEngine, run_native_preflight, validate_outcome_binding};
use crate::lifecycle::MigrationHandoffFailure;
use cutover_plan::LegacyCutoverPlan;
use gui_handoff::LegacyGuiHandoff;
use journal::{
    CutoverJournal, CutoverJournalStore, CutoverPhase, LegacyNetworkJournalInput,
    LegacySessionJournalIdentity,
};
use replacement_start::{require_replacement_active, start_replacement_with_endpoint_rebind};

pub(crate) use crate::process_identity::ProcessIdentity;
pub(crate) use admission::require_canonical_handoff_candidate;
pub(crate) use cutover::disable_service_mode;
pub(crate) use cutover_recovery::recover_legacy_cutover;
pub(crate) use handoff_launch::begin_migration_handoff;
pub(crate) use handoff_ticket::{ConsumedHandoffTicket, RendererReadyChallenge};
#[cfg(target_os = "macos")]
pub(crate) use handoff_ticket::{LaunchArguments, parse_launch_arguments};
pub(crate) use journal::MigrationHandoffLease;
#[cfg(test)]
pub(crate) use journal::write_journal_governing_startup;
pub(crate) use normal_start::{
    load_replacement_engine_settings, require_network_start_allowed,
    require_runtime_preferences_changeable,
};

pub use state_gate::LegacyRetirementGate;
pub(crate) use state_gate::LegacyRetirementStatus;

#[tauri::command]
pub(crate) fn legacy_retirement_status(
    retirement: State<'_, LegacyRetirementGate>,
) -> Result<LegacyRetirementStatus, String> {
    retirement.status()
}

fn emit_cutover_failure(app: &AppHandle, code: &str, message: &str) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(code, message),
    ) {
        eprintln!("failed to publish cutover failure: {error}");
    }
}

pub(crate) fn run_launch_preflight(app: &AppHandle) -> Result<(), String> {
    migration::run_launch_preflight(app)
}
