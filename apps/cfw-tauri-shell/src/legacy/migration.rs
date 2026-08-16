use std::fs;
use std::path::{Path, PathBuf};

use cfw_core::{LegacyNetworkState, SettingsStore, UiPreferences};
use cfw_platform::{MacOsPlatformService, ServiceModeStatus};
use cfw_profiles::ProfileRepository;
use tauri::{AppHandle, Emitter, Manager};

use super::cutover_plan::RetiredLegacyNetwork;
use super::journal::{CutoverJournalStore, CutoverPhase};
use super::process_cleanup::{require_path_absent, verify_privileged_artifacts_are_gone};
use super::state_gate::{LegacyCleanupAction, LegacyCleanupError, LegacyRetirementStatus};
use crate::commands::sanitize_legacy_preferences;
use crate::settings_store;

const MAX_LAUNCH_RECOVERY_DIAGNOSTIC_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchRecoveryFailureCategory {
    Role,
    Admission,
    Recovery,
    ActiveProof,
}

impl LaunchRecoveryFailureCategory {
    const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Admission => "admission",
            Self::Recovery => "recovery",
            Self::ActiveProof => "active-proof",
        }
    }

    pub(super) const fn user_message(self) -> &'static str {
        match self {
            Self::Role => {
                "Recovery must run in the signed migration session. Select Open Recovery to start that session; no recovery action ran in this dashboard."
            }
            Self::Admission => {
                "The migration session could not verify the installed, signed, notarized 0.4.0 app. Reinstall the release in /Applications and ensure Gatekeeper is enabled, then reopen Recovery; no recovery action ran."
            }
            Self::Recovery => {
                "The interrupted pre-network cutover could not prove the legacy network intact, durably seal NetworkRetiring, or safely finish the journal-bound legacy GUI exit. Do not relaunch the legacy app or change network settings; review the local migration log, then retry Recovery."
            }
            Self::ActiveProof => {
                "The journal says the replacement was active, but the current native owner, context, digest, and readiness proof does not match. Keep the app open, review the local migration log, then select Recover Replacement."
            }
        }
    }
}

pub(super) struct LaunchRecoveryFailure {
    category: LaunchRecoveryFailureCategory,
    cause: String,
}

impl std::fmt::Debug for LaunchRecoveryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchRecoveryFailure")
            .field("category", &self.category)
            .field(
                "cause",
                &"[available only at the bounded diagnostic boundary]",
            )
            .finish()
    }
}

impl LaunchRecoveryFailure {
    fn new(category: LaunchRecoveryFailureCategory, cause: impl Into<String>) -> Self {
        Self {
            category,
            cause: cause.into(),
        }
    }

    pub(super) const fn category(&self) -> LaunchRecoveryFailureCategory {
        self.category
    }

    pub(super) const fn user_message(&self) -> &'static str {
        self.category.user_message()
    }
}

pub(super) fn require_pre_network_launch_recovery<Admission, Recovery>(
    migration_handoff: bool,
    require_admission: Admission,
    seal_recovery: Recovery,
) -> Result<(), LaunchRecoveryFailure>
where
    Admission: FnOnce() -> Result<(), String>,
    Recovery: FnOnce() -> Result<(), String>,
{
    if !migration_handoff {
        return Err(LaunchRecoveryFailure::new(
            LaunchRecoveryFailureCategory::Role,
            "the current process is not the explicit migration handoff",
        ));
    }
    require_admission().map_err(|cause| {
        LaunchRecoveryFailure::new(LaunchRecoveryFailureCategory::Admission, cause)
    })?;
    seal_recovery()
        .map_err(|cause| LaunchRecoveryFailure::new(LaunchRecoveryFailureCategory::Recovery, cause))
}

pub(super) fn classify_replacement_active_proof(
    proof: Result<(), String>,
) -> Result<(), LaunchRecoveryFailure> {
    proof.map_err(|cause| {
        LaunchRecoveryFailure::new(LaunchRecoveryFailureCategory::ActiveProof, cause)
    })
}

pub(super) fn run_launch_preflight(app: &AppHandle) -> Result<(), String> {
    let store = settings_store()?;
    if let Some(journal) = CutoverJournalStore::new(store.paths().app_home.clone()).load()? {
        let status = match journal.phase {
            CutoverPhase::Prepared | CutoverPhase::GuiStopped => {
                let launch = app.state::<crate::LaunchContext>();
                match require_pre_network_launch_recovery(
                    launch.is_migration_handoff(),
                    super::admission::require_canonical_handoff_candidate,
                    || {
                        super::recovery::seal_pre_network_cutover_for_recovery(&journal, &store)
                    },
                ) {
                    Ok(()) => LegacyRetirementStatus::RecoveryStartRequired {
                        target: journal.target,
                        message: "the confirmed one-way cutover was safely sealed as NetworkRetiring and the journal-bound legacy GUI exited; use Recover Replacement to finish without relaunching the legacy app"
                            .into(),
                    },
                    Err(failure) => {
                        recovery_required_status(journal.phase, journal.target, failure)
                    }
                }
            }
            CutoverPhase::NetworkRetiring | CutoverPhase::LegacyRetired => {
                LegacyRetirementStatus::RecoveryStartRequired {
                    target: journal.target,
                    message: format!(
                        "cutover was interrupted in phase {:?}; use Recover Replacement. The old helper is never restarted automatically",
                        journal.phase
                    ),
                }
            }
            CutoverPhase::ReplacementActive => {
                let engine = app.state::<crate::engine::ManagedEngine>();
                let digest = match journal.target {
                    cfw_engine_api::EngineMode::SystemProxy => &journal.system_proxy_digest,
                    cfw_engine_api::EngineMode::Tunnel => &journal.tunnel_digest,
                    cfw_engine_api::EngineMode::Off => unreachable!("journal rejects Off"),
                };
                let proof = super::require_replacement_active(
                    engine.coordinator.snapshot(),
                    journal.target,
                    digest,
                    &journal.context,
                );
                if let Err(failure) = classify_replacement_active_proof(proof) {
                    recovery_required_status(journal.phase, journal.target, failure)
                } else {
                    LegacyRetirementStatus::PostCutoverCleanupRequired {
                        message: "native state proves the journal-bound replacement is Active; finish non-network legacy data cleanup"
                            .into(),
                    }
                }
            }
            CutoverPhase::CleanupComplete => launch_preflight_with(
                || {
                    store
                        .legacy_retirement_completed()
                        .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))
                },
                || verify_privileged_artifacts_are_gone(&store.paths().legacy_cores_dir),
                || require_retired_managed_paths_absent(&store),
            ),
        };
        app.state::<super::LegacyRetirementGate>()
            .apply_launch_preflight(status)?;
        return emit_engine_snapshot_refresh(app);
    }
    let status = launch_preflight_with(
        || {
            store
                .legacy_retirement_completed()
                .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))
        },
        || verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path()),
        || require_retired_managed_paths_absent(&store),
    );
    app.state::<super::LegacyRetirementGate>()
        .apply_launch_preflight(status)?;
    emit_engine_snapshot_refresh(app)
}

fn recovery_required_status(
    phase: CutoverPhase,
    target: cfw_engine_api::EngineMode,
    failure: LaunchRecoveryFailure,
) -> LegacyRetirementStatus {
    emit_launch_recovery_diagnostic(phase, &failure);
    LegacyRetirementStatus::RecoveryStartRequired {
        target,
        message: failure.user_message().to_owned(),
    }
}

/// Raw launch-recovery causes never cross the IPC/event boundary. This local
/// diagnostic boundary removes log-control characters and caps the rendered
/// cause before it reaches the application log.
fn emit_launch_recovery_diagnostic(phase: CutoverPhase, failure: &LaunchRecoveryFailure) {
    eprintln!(
        "legacy launch recovery failed (phase={phase:?}, category={}): {}",
        failure.category().diagnostic_code(),
        bounded_diagnostic_cause(&failure.cause)
    );
}

pub(super) fn bounded_diagnostic_cause(cause: &str) -> String {
    const TRUNCATED: &str = " [truncated]";
    let content_limit = MAX_LAUNCH_RECOVERY_DIAGNOSTIC_BYTES - TRUNCATED.len();
    let mut rendered = String::with_capacity(cause.len().min(MAX_LAUNCH_RECOVERY_DIAGNOSTIC_BYTES));
    let mut truncated = false;
    for character in cause.chars() {
        let safe = if character.is_control() {
            ' '
        } else {
            character
        };
        if rendered.len() + safe.len_utf8() > content_limit {
            truncated = true;
            break;
        }
        rendered.push(safe);
    }
    if truncated {
        rendered.push_str(TRUNCATED);
    }
    rendered
}

pub(super) fn launch_preflight_with<Marker, VerifyNetwork, VerifyData>(
    read_completed_marker: Marker,
    verify_network_retired: VerifyNetwork,
    verify_data_removed: VerifyData,
) -> LegacyRetirementStatus
where
    Marker: FnOnce() -> Result<bool, String>,
    VerifyNetwork: FnOnce() -> Result<(), String>,
    VerifyData: FnOnce() -> Result<(), String>,
{
    match read_completed_marker() {
        Ok(false) => LegacyRetirementStatus::AwaitingConfirmation,
        Ok(true) => match verify_network_retired() {
            Err(message) => LegacyRetirementStatus::ManualCleanupRequired {
                action: LegacyCleanupAction::Retry,
                message: format!(
                    "completed legacy retirement could not verify the network boundary: {message}"
                ),
            },
            Ok(()) => match verify_data_removed() {
                Ok(()) => LegacyRetirementStatus::Cleared,
                Err(message) => LegacyRetirementStatus::PostCutoverCleanupRequired {
                    message: format!(
                        "network retirement is verified, but managed data cleanup remains: {message}"
                    ),
                },
            },
        },
        Err(message) => LegacyRetirementStatus::ManualCleanupRequired {
            action: LegacyCleanupAction::Retry,
            message,
        },
    }
}

/// Runs only after the replacement runtime has been verified Active. Failures
/// here never stop or roll back the new network and remain idempotently
/// retryable from the persistent retirement marker.
pub(super) fn finalize_legacy_data(
    app: &AppHandle,
    retired: &RetiredLegacyNetwork,
) -> Result<(), String> {
    let plan = &retired.plan;
    finalize_legacy_data_state(
        app,
        &plan.store,
        plan.retirement_completed,
        plan.legacy_settings.as_ref(),
        &plan.preferences,
    )
}

pub(super) fn finalize_recovered_legacy_data(app: &AppHandle) -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let retirement_completed = store
        .legacy_retirement_completed()
        .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))?;
    let legacy_settings = cfw_core::LegacySettingsMigration::read(store.paths())
        .map_err(|error| format!("legacy settings are unreadable during recovery: {error}"))?;
    let preferences = legacy_settings
        .as_ref()
        .map(|migration| migration.preferences.clone())
        .unwrap_or(store.read_or_default().map_err(|error| error.to_string())?);
    finalize_legacy_data_state(
        app,
        &store,
        retirement_completed,
        legacy_settings.as_ref(),
        &preferences,
    )
}

fn finalize_legacy_data_state(
    app: &AppHandle,
    store: &SettingsStore,
    retirement_completed: bool,
    legacy_settings: Option<&cfw_core::LegacySettingsMigration>,
    preferences: &UiPreferences,
) -> Result<(), String> {
    let snapshot = complete_legacy_data_retirement(
        retirement_completed,
        || {
            ProfileRepository::new(store.paths().legacy_profiles_dir.clone())
                .clear_managed_profiles()
                .map_err(|error| format!("failed to clear managed legacy profiles: {error}"))?;
            reconcile_main_app_login_item(preferences)?;
            sanitize_legacy_preferences(store, preferences.clone())
        },
        || {
            if let Some(migration) = legacy_settings {
                migration
                    .remove_source(store.paths())
                    .map_err(|error| format!("failed to remove migrated legacy settings: {error}"))
            } else {
                require_path_absent(&store.paths().legacy_settings_file, "legacy settings file")
            }
        },
        || {
            store
                .commit_legacy_retirement()
                .map_err(|error| format!("failed to persist legacy retirement marker: {error}"))
        },
        || {
            remove_managed_path(&store.paths().legacy_cores_dir)?;
            remove_managed_path(&store.paths().legacy_helpers_dir)?;
            remove_managed_path(&store.paths().legacy_profiles_dir)?;
            for path in legacy_managed_files(store) {
                remove_managed_path(&path)?;
            }
            verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
            require_retired_managed_paths_absent(store)
        },
    )?;
    app.emit("cfw://settings-changed", snapshot)
        .map_err(|error| format!("failed to publish migrated settings: {error}"))
}

/// Completes the durable data-retirement transaction in dependency order.
///
/// The source removal is the irreversible migration boundary and must be
/// directory-durable before the completion marker is committed. Everything
/// before and after that marker is intentionally idempotent: this also repairs
/// installations created by older builds that wrote the marker before cleanup.
fn complete_legacy_data_retirement<Snapshot, Prepare, RemoveSource, CommitMarker, FinishCleanup>(
    retirement_completed: bool,
    prepare: Prepare,
    remove_source: RemoveSource,
    commit_marker: CommitMarker,
    finish_cleanup: FinishCleanup,
) -> Result<Snapshot, String>
where
    Prepare: FnOnce() -> Result<Snapshot, String>,
    RemoveSource: FnOnce() -> Result<(), String>,
    CommitMarker: FnOnce() -> Result<(), String>,
    FinishCleanup: FnOnce() -> Result<(), String>,
{
    let snapshot = prepare()?;
    remove_source()?;
    if !retirement_completed {
        commit_marker()?;
    }
    finish_cleanup()?;
    Ok(snapshot)
}

pub(super) fn require_retired_managed_paths_absent(store: &SettingsStore) -> Result<(), String> {
    require_path_absent(&store.paths().legacy_settings_file, "legacy settings file")?;
    require_path_absent(
        &store.paths().legacy_cores_dir,
        "legacy managed core directory",
    )?;
    require_path_absent(
        &store.paths().legacy_helpers_dir,
        "legacy managed helper directory",
    )?;
    require_path_absent(
        &store.paths().legacy_profiles_dir,
        "legacy managed profile directory",
    )?;
    for path in legacy_managed_files(store) {
        require_path_absent(&path, "legacy managed file")?;
    }
    Ok(())
}

fn legacy_managed_files(store: &SettingsStore) -> Vec<PathBuf> {
    let home = &store.paths().app_home;
    vec![
        store.paths().legacy_config_file.clone(),
        home.join("proxy.pac"),
        home.join("mixin.yaml"),
        home.join("mixin.yml"),
        home.join("profile-parser.js"),
        home.join("tray-script.js"),
        home.join("child-process.json"),
        home.join("cache.db"),
        home.join("cache.db-shm"),
        home.join("cache.db-wal"),
    ]
}

pub(super) fn restore_legacy_dns(
    network: &LegacyNetworkState,
    dns_review_confirmed: bool,
) -> Result<(), LegacyCleanupError> {
    let Some(_dns_servers) = network.restore_dns_servers.as_ref() else {
        return Ok(());
    };
    if dns_review_confirmed {
        Ok(())
    } else {
        Err(LegacyCleanupError::ReviewDns(
            "legacy restore-dns-servers has no per-service ownership identity. Before cutover, review DNS for every active service in System Settings; no DNS setting is changed automatically"
                .into(),
        ))
    }
}

fn reconcile_main_app_login_item(preferences: &UiPreferences) -> Result<(), String> {
    let platform = MacOsPlatformService;
    if !preferences.launch_at_login {
        return platform
            .disable_login_item()
            .map_err(|error| format!("failed to keep Start at Login disabled: {error}"));
    }
    let status = match platform.login_item_status() {
        ServiceModeStatus::Enabled => ServiceModeStatus::Enabled,
        ServiceModeStatus::RequiresApproval => ServiceModeStatus::RequiresApproval,
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => {
            platform.enable_login_item().map_err(|error| {
                format!("failed to register the signed main app Login Item: {error}")
            })?
        }
        ServiceModeStatus::Unknown => ServiceModeStatus::Unknown,
    };
    require_enabled_login_item(status)
}

pub(super) fn require_enabled_login_item(status: ServiceModeStatus) -> Result<(), String> {
    match status {
        ServiceModeStatus::Enabled => Ok(()),
        ServiceModeStatus::RequiresApproval => Err(
            "the preserved Start at Login preference requires approval in System Settings; replacement networking remains active and cleanup can be retried after approval"
                .into(),
        ),
        other => Err(format!(
            "the signed main app Login Item is not enabled after migration: {other:?}"
        )),
    }
}

pub(super) fn remove_managed_path(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(|error| {
            format!(
                "failed to remove managed directory {}: {error}",
                path.display()
            )
        })
    } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to remove managed file {}: {error}", path.display()))
    } else {
        Err(format!(
            "refusing to remove unsupported managed path type: {}",
            path.display()
        ))
    }
}

pub(super) fn emit_engine_snapshot_refresh(app: &AppHandle) -> Result<(), String> {
    app.emit("cfw://engine-snapshot", serde_json::Value::Null)
        .map_err(|error| format!("failed to publish engine snapshot refresh: {error}"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::complete_legacy_data_retirement;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FaultAfter {
        Prepare(usize),
        SourceRemoval,
        MarkerCommit,
        Cleanup(usize),
    }

    #[derive(Debug)]
    struct DurableCleanupState {
        prepared: [bool; 3],
        source_present: bool,
        marker_present: bool,
        cleanup_present: [bool; 4],
        marker_commits: usize,
    }

    impl Default for DurableCleanupState {
        fn default() -> Self {
            Self {
                prepared: [false; 3],
                source_present: true,
                marker_present: false,
                cleanup_present: [true; 4],
                marker_commits: 0,
            }
        }
    }

    fn run_cleanup_transaction(
        state: &RefCell<DurableCleanupState>,
        fault: Option<FaultAfter>,
    ) -> Result<(), String> {
        let marker_present = state.borrow().marker_present;
        complete_legacy_data_retirement(
            marker_present,
            || {
                for index in 0..3 {
                    state.borrow_mut().prepared[index] = true;
                    if fault == Some(FaultAfter::Prepare(index)) {
                        return Err(format!("fault after prepare step {index}"));
                    }
                }
                Ok(())
            },
            || {
                state.borrow_mut().source_present = false;
                if fault == Some(FaultAfter::SourceRemoval) {
                    Err("fault after source removal".into())
                } else {
                    Ok(())
                }
            },
            || {
                let mut state = state.borrow_mut();
                state.marker_present = true;
                state.marker_commits += 1;
                if fault == Some(FaultAfter::MarkerCommit) {
                    Err("fault after marker commit".into())
                } else {
                    Ok(())
                }
            },
            || {
                for index in 0..4 {
                    state.borrow_mut().cleanup_present[index] = false;
                    if fault == Some(FaultAfter::Cleanup(index)) {
                        return Err(format!("fault after cleanup step {index}"));
                    }
                }
                Ok(())
            },
        )
    }

    #[test]
    fn retirement_marker_is_committed_only_after_legacy_source_removal() {
        let operations = RefCell::new(Vec::new());
        complete_legacy_data_retirement(
            false,
            || {
                operations.borrow_mut().push("prepare");
                Ok(())
            },
            || {
                operations.borrow_mut().push("remove-source");
                Ok(())
            },
            || {
                operations.borrow_mut().push("commit-marker");
                Ok(())
            },
            || {
                operations.borrow_mut().push("finish-cleanup");
                Ok(())
            },
        )
        .expect("retirement sequence");
        assert_eq!(
            operations.into_inner(),
            [
                "prepare",
                "remove-source",
                "commit-marker",
                "finish-cleanup"
            ]
        );
    }

    #[test]
    fn every_cleanup_fault_converges_on_retry_without_marker_source_split_brain() {
        let faults = [
            FaultAfter::Prepare(0),
            FaultAfter::Prepare(1),
            FaultAfter::Prepare(2),
            FaultAfter::SourceRemoval,
            FaultAfter::MarkerCommit,
            FaultAfter::Cleanup(0),
            FaultAfter::Cleanup(1),
            FaultAfter::Cleanup(2),
            FaultAfter::Cleanup(3),
        ];

        for fault in faults {
            let state = RefCell::new(DurableCleanupState::default());
            assert!(
                run_cleanup_transaction(&state, Some(fault)).is_err(),
                "{fault:?} must interrupt the first attempt"
            );
            {
                let durable = state.borrow();
                assert!(
                    !durable.marker_present || !durable.source_present,
                    "the marker must never be committed ahead of source removal after {fault:?}"
                );
            }

            run_cleanup_transaction(&state, None)
                .unwrap_or_else(|error| panic!("retry after {fault:?} failed: {error}"));
            let durable = state.borrow();
            assert_eq!(durable.prepared, [true; 3], "{fault:?}");
            assert!(!durable.source_present, "{fault:?}");
            assert!(durable.marker_present, "{fault:?}");
            assert_eq!(durable.cleanup_present, [false; 4], "{fault:?}");
            assert_eq!(durable.marker_commits, 1, "{fault:?}");
        }
    }

    #[test]
    fn marker_present_retry_repairs_legacy_source_and_remaining_cleanup() {
        let state = RefCell::new(DurableCleanupState {
            marker_present: true,
            ..DurableCleanupState::default()
        });

        run_cleanup_transaction(&state, None).expect("repair old marker-first state");
        let durable = state.borrow();
        assert_eq!(durable.prepared, [true; 3]);
        assert!(!durable.source_present);
        assert!(durable.marker_present);
        assert_eq!(durable.cleanup_present, [false; 4]);
        assert_eq!(durable.marker_commits, 0);
    }
}
