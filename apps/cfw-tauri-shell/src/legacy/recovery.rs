use std::time::{Duration, Instant};

use cfw_core::{LegacyControlSession, LegacyControlSessionObservation, SettingsStore};
use cfw_platform::{
    LegacyProxyCutoverPlan, LegacyServiceRetirement, MacOsPlatformService, ServiceModeStatus,
};

use super::gui_handoff::LegacyGuiHandoff;
use super::journal::{CutoverJournal, CutoverJournalStore, CutoverPhase};
use super::network_fingerprint::LegacyNetworkFingerprint;
use super::process_cleanup::{
    managed_processes, validate_unique_root_managed_process, verify_privileged_artifacts_are_gone,
    verify_process_listens_on_ports, wait_for_managed_process_to_exit,
};

const NETWORK_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn resume_pre_network_cutover_if_intact(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    if !matches!(
        journal.phase,
        CutoverPhase::Prepared | CutoverPhase::GuiStopped
    ) {
        return Err("cutover journal is not in a resumable pre-network phase".into());
    }
    verify_legacy_network_intact(journal, store)?;
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::resume_persisted_if_stopped(legacy_gui)?;
    }
    CutoverJournalStore::new(store.paths().app_home.clone()).abandon_pre_network(journal.phase)
}

pub(super) fn verify_legacy_network_intact(
    journal: &CutoverJournal,
    store: &SettingsStore,
) -> Result<(), String> {
    match (&journal.legacy_process, &journal.legacy_session) {
        (Some(expected), Some(expected_session)) => {
            if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled {
                return Err("legacy Service Mode is no longer enabled".into());
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
        (None, None) => {
            if !matches!(
                MacOsPlatformService.service_mode_status(),
                ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
            ) || LegacyControlSession::exists().map_err(|error| error.to_string())?
                || !managed_processes(store.paths().legacy_cores_dir.as_path())?.is_empty()
            {
                return Err("legacy helper/session/core state changed".into());
            }
        }
        _ => return Err("legacy journal helper identity is inconsistent".into()),
    }

    if let Some(interface) = &journal.legacy_interface {
        LegacyNetworkFingerprint::for_recovery(interface.clone())?.verify_still_present()?;
    }
    if journal.legacy_proxy_services.is_empty() {
        MacOsPlatformService
            .verify_all_legacy_proxies_disabled()
            .map_err(|error| error.to_string())?;
    } else {
        MacOsPlatformService
            .verify_legacy_proxy_still_applied(&proxy_plan(journal)?)
            .map_err(|error| error.to_string())?;
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

    ensure_network_retiring_gui_stopped(journal)?;

    match (&journal.legacy_process, &journal.legacy_session) {
        (Some(expected), Some(_)) => {
            let current = managed_processes(store.paths().legacy_cores_dir.as_path())?;
            match current.as_slice() {
                [] => {
                    request_stop_if_session_remains(journal, store)?;
                }
                [actual] if actual == expected => {
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
        (None, None) => {}
        _ => return Err("legacy journal helper identity is inconsistent".into()),
    }

    if let Some(interface) = &journal.legacy_interface {
        wait_for_network_fingerprint_removal(&LegacyNetworkFingerprint::for_recovery(
            interface.clone(),
        )?)
        .await?;
    }
    if !journal.legacy_proxy_services.is_empty() {
        MacOsPlatformService
            .recover_legacy_proxy(&proxy_plan(journal)?)
            .map_err(|error| format!("legacy proxy recovery failed: {error}"))?;
    }
    if journal.legacy_session.is_some() {
        LegacyControlSession::remove()
            .map_err(|error| format!("failed to remove retired control session: {error}"))?;
    }
    if !managed_processes(store.paths().legacy_cores_dir.as_path())?.is_empty() {
        return Err("a managed legacy core respawned before helper unregister".into());
    }
    MacOsPlatformService
        .retire_legacy_service()
        .map_err(|error| format!("failed to unregister retired Service Mode: {error}"))?;
    verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())
}

pub(super) fn ensure_network_retiring_gui_stopped(journal: &CutoverJournal) -> Result<(), String> {
    if journal.phase != CutoverPhase::NetworkRetiring {
        return Err("GUI stop recovery requires NetworkRetiring phase".into());
    }
    // NetworkRetiring is a one-way intent record. Before any replacement or
    // legacy network mutation, bind the persisted GUI identity to the live
    // kernel incarnation and prove it is stopped. A crash between journal
    // commit and stop confirmation can only re-stop that exact process or fail.
    if let Some(legacy_gui) = journal.legacy_gui.as_ref() {
        LegacyGuiHandoff::ensure_persisted_stopped_for_network_retirement(legacy_gui)?;
    }
    Ok(())
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
        LegacyControlSession::request_stop(&observed)
            .map_err(|error| format!("failed to resume the exact legacy stop request: {error}"))?;
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
