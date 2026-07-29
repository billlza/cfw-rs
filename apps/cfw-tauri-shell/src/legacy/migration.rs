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
                "The interrupted pre-network cutover could not safely restore the recorded legacy process/network state or durably clear its journal. Do not change either app or network settings; review the local migration log, then retry Recovery."
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
    resume_recovery: Recovery,
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
    resume_recovery()
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
                    launch.migration_handoff,
                    super::admission::require_canonical_handoff_candidate,
                    || super::recovery::resume_pre_network_cutover_if_intact(&journal, &store),
                ) {
                    Ok(()) => LegacyRetirementStatus::AwaitingConfirmation,
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
    if !retirement_completed {
        store
            .commit_legacy_retirement()
            .map_err(|error| format!("failed to persist legacy retirement marker: {error}"))?;
    }

    let snapshot = if retirement_completed {
        store.snapshot().map_err(|error| error.to_string())?
    } else {
        ProfileRepository::new(store.paths().legacy_profiles_dir.clone())
            .clear_managed_profiles()
            .map_err(|error| format!("failed to clear managed legacy profiles: {error}"))?;
        reconcile_main_app_login_item(preferences)?;
        let snapshot = sanitize_legacy_preferences(store, preferences.clone())?;
        if let Some(migration) = legacy_settings {
            migration
                .remove_source(store.paths())
                .map_err(|error| format!("failed to remove migrated legacy settings: {error}"))?;
        }
        snapshot
    };

    remove_managed_path(&store.paths().legacy_cores_dir)?;
    remove_managed_path(&store.paths().legacy_helpers_dir)?;
    remove_managed_path(&store.paths().legacy_profiles_dir)?;
    for path in legacy_managed_files(store) {
        remove_managed_path(&path)?;
    }
    verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
    require_retired_managed_paths_absent(store)?;
    app.emit("cfw://settings-changed", snapshot)
        .map_err(|error| format!("failed to publish migrated settings: {error}"))
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
