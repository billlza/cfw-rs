use std::time::{Duration, Instant};

use cfw_core::{LegacyControlSession, LegacyControlSessionObservation, SettingsStore};
use cfw_engine_api::EngineMode;
use cfw_platform::{
    LegacyProxyCutoverPlan, LegacyServiceJobObservation, LegacyServiceRetirement,
    MacOsPlatformService, ServiceModeStatus,
};

use super::cutover_plan::LegacyProxyAbsence;
use super::gui_handoff::LegacyGuiHandoff;
use super::journal::{CutoverJournal, CutoverJournalStore, CutoverPhase};
use super::migration::require_retired_managed_paths_absent;
use super::network_fingerprint::LegacyNetworkFingerprint;
use super::process_cleanup::{
    managed_processes, validate_unique_root_managed_process, verify_privileged_artifacts_are_gone,
    verify_process_listens_on_ports, wait_for_managed_process_to_exit,
};
use super::runtime_plan::{
    LegacyRuntimePlanKind, complete_service_retirement, observe_service_retirement_boundary,
};

const NETWORK_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn seal_pre_network_cutover_for_recovery(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    if !matches!(
        journal.phase,
        CutoverPhase::Prepared | CutoverPhase::GuiStopped
    ) {
        return Err("cutover journal is not in a recoverable pre-network phase".into());
    }
    verify_legacy_network_intact(journal, store)?;
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::verify_persisted_identity_or_missing(legacy_gui)?;
    } else {
        LegacyGuiHandoff::verify_no_persisted_legacy_gui()?;
    }
    let retiring = CutoverJournalStore::new(store.paths().app_home.clone())
        .advance(journal.phase, CutoverPhase::NetworkRetiring)?;
    ensure_network_retiring_gui_terminated(&retiring)
}

pub(super) fn verify_legacy_network_intact(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    match journal.runtime_kind {
        LegacyRuntimePlanKind::LiveOwned { service_job } => {
            let (Some(expected), Some(expected_session)) =
                (&journal.legacy_process, &journal.legacy_session)
            else {
                return Err("live legacy journal has no process/session identity".into());
            };
            if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled {
                return Err("legacy Service Mode is no longer enabled".into());
            }
            if MacOsPlatformService
                .legacy_service_job_observation()
                .map_err(|error| error.to_string())?
                != service_job
            {
                return Err("legacy launchd job identity or activity changed".into());
            }
            let observed = LegacyControlSession::observe().map_err(|error| error.to_string())?;
            validate_session(&observed, journal, store)?;
            if !observed.wants_core() {
                return Err("legacy core retirement has already begun".into());
            }
            let current = managed_processes(store.paths().legacy_cores_dir.as_path())?;
            let validated = validate_unique_root_managed_process(
                &current,
                &store.paths().app_home,
                &store.paths().legacy_config_file,
            )?;
            if &validated != expected {
                return Err("legacy root core PID/start/command identity changed".into());
            }
            verify_process_listens_on_ports(
                expected,
                &[
                    expected_session.mixed_port,
                    expected_session.controller_port,
                ],
            )?;
        }
        LegacyRuntimePlanKind::DormantRegistered { service_job } => {
            if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled
                || MacOsPlatformService
                    .legacy_service_job_observation()
                    .map_err(|error| error.to_string())?
                    != service_job
            {
                return Err("dormant legacy service/job state changed".into());
            }
            verify_inactive_runtime_absence(store, journal.runtime_kind)?;
        }
        LegacyRuntimePlanKind::OfflineUpgrade | LegacyRuntimePlanKind::FreshInstall => {
            verify_unregistered_service()?;
            verify_inactive_runtime_absence(store, journal.runtime_kind)?;
        }
    }

    if let Some(tunnel) = &journal.legacy_tunnel {
        LegacyNetworkFingerprint::for_recovery(tunnel.clone())?.verify_still_present()?;
    } else {
        LegacyNetworkFingerprint::verify_absent()?;
    }
    if journal.legacy_proxy_services.is_empty() {
        if journal.runtime_kind != LegacyRuntimePlanKind::FreshInstall {
            // FreshInstall completed the mandatory inactive-resource proof
            // above and has no recorded proxy endpoint to verify again.
            LegacyProxyAbsence::resolve(store, journal.runtime_kind)?.verify(
                store,
                "the retired installation's system proxy is still applied",
            )?;
        }
    } else {
        MacOsPlatformService
            .verify_legacy_proxy_still_applied(&proxy_plan(journal)?)
            .map_err(|error| error.to_string())?;
    }
    if !journal.runtime_kind.requires_legacy_gui() {
        LegacyGuiHandoff::verify_no_persisted_legacy_gui()?;
    }
    Ok(())
}

pub(super) async fn finish_network_retirement(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    if journal.phase != CutoverPhase::NetworkRetiring {
        return Err("network retirement recovery requires NetworkRetiring phase".into());
    }

    ensure_network_retiring_gui_terminated(journal)?;

    match journal.runtime_kind {
        LegacyRuntimePlanKind::LiveOwned { .. } => {
            let (Some(expected), Some(_)) = (&journal.legacy_process, &journal.legacy_session)
            else {
                return Err("live legacy journal has no process/session identity".into());
            };
            let current = managed_processes(store.paths().legacy_cores_dir.as_path())?;
            match current.as_slice() {
                [] => {
                    ensure_network_retiring_gui_terminated(journal)?;
                    request_stop_if_session_remains(journal, store)?;
                }
                [actual] if actual == expected => {
                    ensure_network_retiring_gui_terminated(journal)?;
                    request_stop_if_session_remains(journal, store)?;
                    wait_for_managed_process_to_exit(
                        store.paths().legacy_cores_dir.as_path(),
                        expected,
                    )
                    .await?;
                }
                _ => {
                    return Err(
                        "legacy core identity changed or respawned during recovery; no process was signaled"
                            .into(),
                    );
                }
            }
        }
        LegacyRuntimePlanKind::DormantRegistered { .. }
        | LegacyRuntimePlanKind::OfflineUpgrade
        | LegacyRuntimePlanKind::FreshInstall => {
            verify_inactive_runtime_absence(store, journal.runtime_kind)?;
        }
    }

    if let Some(tunnel) = &journal.legacy_tunnel {
        ensure_network_retiring_gui_terminated(journal)?;
        wait_for_network_fingerprint_removal(&LegacyNetworkFingerprint::for_recovery(
            tunnel.clone(),
        )?)
        .await?;
    }
    if !journal.legacy_proxy_services.is_empty() {
        ensure_network_retiring_gui_terminated(journal)?;
        MacOsPlatformService
            .recover_legacy_proxy(&proxy_plan(journal)?)
            .map_err(|error| format!("legacy proxy recovery failed: {error}"))?;
    }
    if journal.legacy_session.is_some() {
        ensure_network_retiring_gui_terminated(journal)?;
        LegacyControlSession::remove()
            .map_err(|error| format!("failed to remove retired control session: {error}"))?;
    }
    verify_pre_service_retirement_absence(journal, store, true)?;
    match journal.runtime_kind {
        LegacyRuntimePlanKind::LiveOwned { .. }
        | LegacyRuntimePlanKind::DormantRegistered { .. } => complete_service_retirement(
            observe_service_retirement_boundary,
            || {
                ensure_network_retiring_gui_terminated(journal)?;
                MacOsPlatformService
                    .retire_legacy_service()
                    .map_err(|error| format!("failed to unregister retired Service Mode: {error}"))
            },
            || verify_post_unregister_absence(journal, store, true),
        ),
        LegacyRuntimePlanKind::OfflineUpgrade | LegacyRuntimePlanKind::FreshInstall => {
            verify_unregistered_service()?;
            verify_post_unregister_absence(journal, store, true)
        }
    }
}

/// An exact Active replacement is already authoritative. Recovery may safely
/// finish the journal-bound legacy GUI exit, but must not replay any legacy
/// network mutation from a stale `NetworkRetiring` journal. System Proxy
/// ownership belongs to the replacement, so that target deliberately omits the
/// legacy "all proxies disabled" postcondition.
pub(super) fn verify_network_retirement_completed_with_active_replacement(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    if journal.phase != CutoverPhase::NetworkRetiring {
        return Err("active replacement retirement proof requires NetworkRetiring phase".into());
    }
    ensure_network_retiring_gui_terminated(journal)?;
    verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
    if let Some(tunnel) = &journal.legacy_tunnel {
        LegacyNetworkFingerprint::for_recovery(tunnel.clone())?.verify_removed()?;
    }
    LegacyNetworkFingerprint::verify_absent()?;
    verify_active_replacement_proxy_postcondition(
        journal.target,
        journal.runtime_kind,
        || require_retired_managed_paths_absent(store),
        || {
            LegacyProxyAbsence::resolve(store, journal.runtime_kind)?
                .verify(store, "legacy proxy retirement is incomplete")
        },
    )?;
    verify_network_retiring_gui_terminated(journal)
}

pub(super) fn ensure_network_retiring_gui_terminated(
    journal: &CutoverJournal,
) -> Result<(), String> {
    if journal.phase != CutoverPhase::NetworkRetiring {
        return Err("GUI exit recovery requires NetworkRetiring phase".into());
    }
    // NetworkRetiring is a one-way intent record. Before any legacy network
    // mutation, bind the persisted identity to one NSRunningApplication
    // instance and finish its exit. A crash can only retry that same identity
    // or accept its absence; a replacement PID or second same-path app fails.
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::terminate_persisted_for_network_retirement(legacy_gui)?;
    } else {
        LegacyGuiHandoff::verify_no_persisted_legacy_gui()?;
    }
    Ok(())
}

fn verify_network_retiring_gui_terminated(journal: &CutoverJournal) -> Result<(), String> {
    if journal.phase != CutoverPhase::NetworkRetiring {
        return Err("GUI retirement proof requires NetworkRetiring phase".into());
    }
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::verify_persisted_terminated(legacy_gui)
    } else {
        LegacyGuiHandoff::verify_no_persisted_legacy_gui()
    }
}

fn verify_unregistered_service() -> Result<(), String> {
    if !matches!(
        MacOsPlatformService.service_mode_status(),
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
    ) {
        return Err("legacy Service Mode remains registered".into());
    }
    if MacOsPlatformService
        .legacy_service_job_observation()
        .map_err(|error| error.to_string())?
        != LegacyServiceJobObservation::Unloaded
    {
        return Err("legacy launchd job remains loaded after service unregister".into());
    }
    Ok(())
}

fn verify_inactive_runtime_absence(
    store: &SettingsStore,
    runtime_kind: LegacyRuntimePlanKind,
) -> Result<(), String> {
    if LegacyControlSession::exists().map_err(|error| error.to_string())?
        || !managed_processes(store.paths().legacy_cores_dir.as_path())?.is_empty()
    {
        return Err("a legacy session or managed core exists in an inactive upgrade plan".into());
    }
    LegacyNetworkFingerprint::verify_absent()?;
    LegacyProxyAbsence::resolve(store, runtime_kind)?
        .verify(store, "a legacy proxy remains in an inactive upgrade plan")
}

fn verify_pre_service_retirement_absence(
    journal: &CutoverJournal,
    store: &SettingsStore,
    require_proxy_absence: bool,
) -> Result<(), String> {
    if LegacyControlSession::exists().map_err(|error| error.to_string())?
        || !managed_processes(store.paths().legacy_cores_dir.as_path())?.is_empty()
    {
        return Err("a legacy session or managed core remains before helper unregister".into());
    }
    if let Some(tunnel) = &journal.legacy_tunnel {
        LegacyNetworkFingerprint::for_recovery(tunnel.clone())?.verify_removed()?;
    }
    LegacyNetworkFingerprint::verify_absent()?;
    if require_proxy_absence {
        LegacyProxyAbsence::resolve(store, journal.runtime_kind)?
            .verify(store, "legacy proxy remains before helper unregister")?;
    }
    ensure_network_retiring_gui_terminated(journal)
}

fn verify_post_unregister_absence(
    journal: &CutoverJournal,
    store: &SettingsStore,
    require_proxy_absence: bool,
) -> Result<(), String> {
    // Fresh proxy-absence verification below already checks privileged resources.
    if journal.runtime_kind != LegacyRuntimePlanKind::FreshInstall || !require_proxy_absence {
        verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
    }
    verify_pre_service_retirement_absence(journal, store, require_proxy_absence)
}

fn verify_active_replacement_proxy_postcondition(
    target: EngineMode,
    runtime_kind: LegacyRuntimePlanKind,
    verify_fresh_resources_absent: impl FnOnce() -> Result<(), String>,
    verify_legacy_proxy_absent: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    match (target, runtime_kind) {
        (EngineMode::Off, _) => {
            Err("an Off target cannot own an Active replacement retirement proof".into())
        }
        (EngineMode::SystemProxy | EngineMode::Tunnel, LegacyRuntimePlanKind::FreshInstall) => {
            verify_fresh_resources_absent()
        }
        (EngineMode::SystemProxy, _) => Ok(()),
        (EngineMode::Tunnel, _) => verify_legacy_proxy_absent(),
    }
}

fn request_stop_if_session_remains(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    if !LegacyControlSession::exists().map_err(|error| error.to_string())? {
        return Ok(());
    }
    let observed = LegacyControlSession::observe().map_err(|error| error.to_string())?;
    validate_session(&observed, journal, store)?;
    if observed.wants_core() {
        LegacyControlSession::request_stop(&observed).map_err(|error| {
            format!("failed to continue the exact legacy stop request: {error}")
        })?;
    }
    Ok(())
}

fn validate_session(
    observed: &LegacyControlSessionObservation,
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    let expected = journal
        .legacy_session
        .as_ref()
        .ok_or_else(|| "journal has no legacy session identity".to_owned())?;
    if observed.app_home() != store.paths().app_home
        || observed.config_file() != store.paths().legacy_config_file
        || observed.mixed_port() != expected.mixed_port
        || observed.controller_port() != expected.controller_port
        || observed.generation() != expected.generation
    {
        return Err("legacy control session no longer matches its journal identity".into());
    }
    Ok(())
}

fn proxy_plan(journal: &CutoverJournal) -> Result<LegacyProxyCutoverPlan, String> {
    LegacyProxyCutoverPlan::for_recovery(
        journal.legacy_proxy_services.clone(),
        journal
            .legacy_proxy_port
            .ok_or_else(|| "journal has no legacy proxy port".to_owned())?,
    )
    .map_err(|error| error.to_string())
}

async fn wait_for_network_fingerprint_removal(
    fingerprint: &LegacyNetworkFingerprint,
) -> Result<(), String> {
    let deadline = Instant::now() + NETWORK_REMOVAL_TIMEOUT;
    loop {
        match fingerprint.verify_removed() {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;

    use cfw_core::MacOsAppPaths;

    use super::*;

    #[test]
    fn active_system_proxy_never_replays_the_legacy_proxy_postcondition() {
        let legacy_proxy_calls = Cell::new(0);
        verify_active_replacement_proxy_postcondition(
            EngineMode::SystemProxy,
            LegacyRuntimePlanKind::OfflineUpgrade,
            || Err("an upgrade must not use fresh-install evidence".into()),
            || {
                legacy_proxy_calls.set(legacy_proxy_calls.get() + 1);
                Err("legacy proxy mutation or absence check must not run".into())
            },
        )
        .expect("replacement System Proxy remains authoritative");
        assert_eq!(legacy_proxy_calls.get(), 0);
    }

    #[test]
    fn active_non_proxy_replacements_require_legacy_proxy_absence() {
        let legacy_proxy_calls = Cell::new(0);
        verify_active_replacement_proxy_postcondition(
            EngineMode::Tunnel,
            LegacyRuntimePlanKind::OfflineUpgrade,
            || Err("an upgrade must not use fresh-install evidence".into()),
            || {
                legacy_proxy_calls.set(legacy_proxy_calls.get() + 1);
                Ok(())
            },
        )
        .expect("Tunnel requires proxy absence");
        assert_eq!(legacy_proxy_calls.get(), 1);
        assert!(
            verify_active_replacement_proxy_postcondition(
                EngineMode::Off,
                LegacyRuntimePlanKind::OfflineUpgrade,
                || panic!("Off must not inspect fresh resources"),
                || panic!("Off must not inspect legacy proxies"),
            )
            .is_err()
        );
    }

    #[test]
    fn active_fresh_replacements_verify_real_resources_without_proxy_queries() {
        let temporary = tempfile::tempdir().expect("fresh recovery fixture");
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(temporary.path().join("app")));
        store.ensure_layout().expect("new settings layout");
        store
            .commit_legacy_retirement()
            .expect("late recovery marker");
        for target in [EngineMode::SystemProxy, EngineMode::Tunnel] {
            let fresh_calls = Cell::new(0);
            let legacy_proxy_calls = Cell::new(0);
            verify_active_replacement_proxy_postcondition(
                target,
                LegacyRuntimePlanKind::FreshInstall,
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    require_retired_managed_paths_absent(&store)
                },
                || {
                    legacy_proxy_calls.set(legacy_proxy_calls.get() + 1);
                    Err("replacement or foreign proxy must not be inspected".into())
                },
            )
            .expect("fresh absence does not depend on an unrecorded endpoint");
            assert_eq!(fresh_calls.get(), 1);
            assert_eq!(legacy_proxy_calls.get(), 0);
        }
    }

    #[test]
    fn active_fresh_system_proxy_cannot_skip_new_legacy_resources() {
        let temporary = tempfile::tempdir().expect("fresh recovery fixture");
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(temporary.path().join("app")));
        store.ensure_layout().expect("new settings layout");
        for path in [
            store.paths().legacy_settings_file.clone(),
            store.paths().app_home.join("proxy.pac"),
        ] {
            fs::write(&path, b"late legacy resource").expect("reappeared legacy resource");
            let fresh_calls = Cell::new(0);
            let error = verify_active_replacement_proxy_postcondition(
                EngineMode::SystemProxy,
                LegacyRuntimePlanKind::FreshInstall,
                || {
                    fresh_calls.set(fresh_calls.get() + 1);
                    require_retired_managed_paths_absent(&store)
                },
                || panic!("the active replacement's proxy must remain untouched"),
            )
            .expect_err("fresh resource absence must run outside the legacy proxy closure");
            assert!(error.contains("remains at"), "{error}");
            assert_eq!(fresh_calls.get(), 1);
            fs::remove_file(path).expect("remove fixture resource");
        }
    }

    #[test]
    fn off_never_acquires_fresh_or_recorded_proxy_postconditions() {
        for kind in [
            LegacyRuntimePlanKind::FreshInstall,
            LegacyRuntimePlanKind::OfflineUpgrade,
        ] {
            let error = verify_active_replacement_proxy_postcondition(
                EngineMode::Off,
                kind,
                || panic!("Off must not inspect fresh resources"),
                || panic!("Off must not inspect legacy proxies"),
            )
            .expect_err("Off is never an active replacement");
            assert!(error.contains("an Off target"), "{error}");
        }
    }
}
