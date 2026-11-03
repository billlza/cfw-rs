use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cfw_core::{AppPaths, LegacyNetworkState, SettingsStore};
use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineSnapshot, EngineState, RuntimeIdentity,
};
use cfw_platform::{LegacyServiceJobObservation, LegacyServiceJobProgram, ServiceModeStatus};
use cfw_profiles::ProfileRepository;

use super::cutover::require_explicit_cutover_confirmation;
use super::handoff_launch::spawn_supervised_app_result;
use super::migration::{
    LaunchRecoveryFailureCategory, bounded_diagnostic_cause, classify_replacement_active_proof,
    launch_preflight_with, remove_managed_path, require_enabled_login_item,
    require_explicit_pre_network_recovery, restore_legacy_dns,
};
use super::normal_start::{
    RuntimePreferencesLocked, require_network_start_with, require_normal_start_phase,
};
use super::process_cleanup::{
    ProcessRecord, parse_loopback_listener_owners, parse_managed_process,
    require_no_launchable_legacy_helper, require_no_legacy_runtime_processes, require_path_absent,
    validate_unique_root_managed_process,
};
use super::state_gate::{LegacyCleanupAction, LegacyRetirementGate, LegacyRetirementStatus};
use super::{require_replacement_active, require_runtime_preferences_changeable};

mod artifact_cleanup;
mod handoff_and_cutover;
mod launch_recovery;
mod retirement;
mod start_gates;
