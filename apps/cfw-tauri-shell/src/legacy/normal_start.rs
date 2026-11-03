//! What a normal start and a runtime preference change require while a
//! legacy cutover journal may govern startup.

use super::*;

/// Normal networking does not depend on deleting legacy data. The existing
/// mode/maintenance permit serializes this observation with explicit cleanup.
pub(crate) fn require_network_start_allowed(
    retirement: &LegacyRetirementGate,
) -> Result<(), String> {
    require_network_start_with(
        retirement,
        &crate::settings_store()?,
        process_cleanup::require_legacy_runtime_inactive,
    )
}

pub(super) fn require_network_start_with(
    retirement: &LegacyRetirementGate,
    store: &cfw_core::SettingsStore,
    observe_runtime: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    retirement.require_start_allowed()?;
    let phase = CutoverJournalStore::new(store.paths().app_home.clone())
        .load()?
        .map(|journal| journal.phase);
    require_normal_start_phase(phase, &retirement.status()?)?;
    observe_runtime(&store.paths().legacy_cores_dir)
}

pub(super) fn require_normal_start_phase(
    phase: Option<CutoverPhase>,
    status: &LegacyRetirementStatus,
) -> Result<(), String> {
    match phase {
        None | Some(CutoverPhase::CleanupComplete) => Ok(()),
        Some(CutoverPhase::ReplacementActive)
            if matches!(
                status,
                LegacyRetirementStatus::PostCutoverCleanupRequired { .. }
            ) =>
        {
            Ok(())
        }
        Some(phase) => Err(format!(
            "an interrupted legacy network transaction in phase {phase:?} requires explicit recovery; no network start was attempted"
        )),
    }
}

/// Returns the exact non-secret replacement settings bound to an interrupted
/// cutover. A completed journal no longer governs a future engine start; a
/// live recovery phase does, so a restarted process cannot silently choose a
/// different loopback endpoint or projection input.
pub(crate) fn load_replacement_engine_settings(
    app_home: &Path,
) -> Result<Option<EngineSettings>, String> {
    let journal = CutoverJournalStore::new(app_home.to_owned()).load()?;
    Ok(journal.and_then(|journal| {
        (journal.phase != CutoverPhase::CleanupComplete).then_some(journal.replacement_settings)
    }))
}

/// Why runtime preferences cannot change now.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RuntimePreferencesLocked {
    /// A cutover journal governs startup until its legacy cleanup completes:
    /// the cleanup verifies the running engine against the journal's
    /// replacement settings, which the journal keeps immutable in that phase,
    /// and a relaunch starts from them. A changed preference would block the
    /// cleanup, and the next launch would revert it while the saved
    /// preferences, and the settings page, still showed it.
    #[error(
        "settings cannot change until the legacy cleanup completes: the unfinished migration fixed the engine settings until then, so finish the legacy cleanup first"
    )]
    CutoverCleanupPending,
    /// Whether a journal governs startup could not be read.
    #[error("whether settings can change is unknown: {0}")]
    JournalUnavailable(String),
}

/// Refuses a runtime preference change while a cutover journal governs
/// startup ([`load_replacement_engine_settings`]).
pub(crate) fn require_runtime_preferences_changeable(
    app_home: &Path,
) -> Result<(), RuntimePreferencesLocked> {
    match load_replacement_engine_settings(app_home) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(RuntimePreferencesLocked::CutoverCleanupPending),
        Err(error) => Err(RuntimePreferencesLocked::JournalUnavailable(error)),
    }
}
