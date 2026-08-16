use cfw_core::{
    LegacyControlSession, LegacyControlSessionObservation, LegacySettingsMigration, SettingsStore,
    UiPreferences,
};
use cfw_platform::{
    LegacyProxyCutoverPlan, LegacyProxyServiceIdentity, LegacyServiceJobObservation,
    LegacyServiceRetirement, MacOsPlatformService, ServiceModeStatus,
};

use super::migration::require_retired_managed_paths_absent;
use super::migration::restore_legacy_dns;
use super::network_fingerprint::{LegacyNetworkFingerprint, LegacyNetworkJournalIdentity};
use super::process_cleanup::{
    ProcessRecord, managed_processes, validate_unique_root_managed_process,
    verify_privileged_artifacts_are_gone, verify_process_listens_on_ports,
    wait_for_managed_process_to_exit,
};
use super::runtime_plan::{
    LegacyRuntimeEvidence, LegacyRuntimePlanKind, classify_legacy_runtime,
    complete_service_retirement, observe_service_retirement_boundary,
};
use super::state_gate::LegacyCleanupError;
use crate::settings_store;

#[derive(Debug)]
pub(super) struct LegacyCutoverPlan {
    pub(super) store: SettingsStore,
    pub(super) retirement_completed: bool,
    pub(super) legacy_settings: Option<LegacySettingsMigration>,
    pub(super) preferences: UiPreferences,
    proxy: Option<LegacyProxyCutoverPlan>,
    tunnel: Option<LegacyNetworkFingerprint>,
    control_session: Option<LegacyControlSessionObservation>,
    managed_process: Option<ProcessRecord>,
    runtime_kind: LegacyRuntimePlanKind,
}

#[derive(Debug)]
pub(super) struct RetiredLegacyNetwork {
    pub(super) plan: LegacyCutoverPlan,
}

#[derive(Debug)]
pub(super) struct LegacyRetirementFailure {
    pub(super) error: LegacyCleanupError,
}

impl LegacyCutoverPlan {
    /// Builds the complete read-only ownership plan. No launchd, process,
    /// proxy, DNS, route, interface, preference, or filesystem mutation occurs
    /// before this returns successfully.
    pub(super) fn prepare(dns_review_confirmed: bool) -> Result<Self, LegacyCleanupError> {
        let store = settings_store()?;
        store.ensure_layout().map_err(|error| error.to_string())?;
        let retirement_completed = store
            .legacy_retirement_completed()
            .map_err(|error| format!("legacy retirement marker is untrusted: {error}"))?;
        let legacy_settings = LegacySettingsMigration::read(store.paths()).map_err(|error| {
            format!("legacy settings are unreadable; cutover ownership cannot be proven: {error}")
        })?;
        if retirement_completed && legacy_settings.is_some() {
            return Err(
                "legacy settings reappeared after the one-way retirement marker; refusing to trust them"
                    .into(),
            );
        }
        let preferences = match legacy_settings.as_ref() {
            Some(migration) => migration.preferences.clone(),
            None => store.read_or_default().map_err(|error| error.to_string())?,
        };
        let network = legacy_settings
            .as_ref()
            .map(|migration| migration.network.clone())
            .unwrap_or_default();
        restore_legacy_dns(&network, dns_review_confirmed)?;

        let service_status = MacOsPlatformService.service_mode_status();
        let service_job = MacOsPlatformService
            .legacy_service_job_observation()
            .map_err(|error| {
                format!(
                    "the fixed legacy launchd job could not be observed authoritatively: {error}"
                )
            })?;
        let control_session_present =
            LegacyControlSession::exists().map_err(|error| error.to_string())?;
        let observed_processes = managed_processes(store.paths().legacy_cores_dir.as_path())?;
        let runtime_kind = classify_legacy_runtime(LegacyRuntimeEvidence {
            retirement_completed,
            legacy_settings_present: legacy_settings.is_some(),
            service_status,
            service_job,
            control_session_present,
            managed_process_count: observed_processes.len(),
        })?;

        let (control_session, managed_process) = match runtime_kind {
            LegacyRuntimePlanKind::LiveOwned { .. } => {
                let session = LegacyControlSession::observe().map_err(|error| {
                    format!(
                        "legacy Service Mode is enabled but its exact control session is not trustworthy: {error}"
                    )
                })?;
                if !session.wants_core()
                    || session.app_home() != store.paths().app_home
                    || session.config_file() != store.paths().legacy_config_file
                    || Some(session.mixed_port()) != network.mixed_port
                {
                    return Err(
                        "legacy control session does not bind the fixed app home, config, active mixed port, and want_core=true; the existing VPN was not changed"
                            .into(),
                    );
                }
                let process = validate_unique_root_managed_process(
                    &observed_processes,
                    &store.paths().app_home,
                    &store.paths().legacy_config_file,
                )?;
                verify_process_listens_on_ports(
                    &process,
                    &[session.mixed_port(), session.controller_port()],
                )?;
                (Some(session), Some(process))
            }
            LegacyRuntimePlanKind::DormantRegistered { .. }
            | LegacyRuntimePlanKind::OfflineUpgrade
            | LegacyRuntimePlanKind::FreshInstall => (None, None),
        };
        let tunnel = match runtime_kind {
            LegacyRuntimePlanKind::LiveOwned { .. } if network.tun_mode => {
                Some(LegacyNetworkFingerprint::capture()?)
            }
            _ => {
                LegacyNetworkFingerprint::verify_absent()?;
                None
            }
        };

        let proxy = if matches!(runtime_kind, LegacyRuntimePlanKind::LiveOwned { .. })
            && network.system_proxy
        {
            let expected_port = network.mixed_port.ok_or_else(|| {
                "legacy system proxy is enabled but mixed_port ownership is missing; the existing proxy was not changed"
                    .to_owned()
            })?;
            Some(
                MacOsPlatformService
                    .prepare_legacy_proxy_cutover(expected_port)
                    .map_err(|error| {
                        format!(
                            "legacy system proxy ownership could not be proven; the existing proxy was not changed: {error}"
                        )
                    })?,
            )
        } else {
            MacOsPlatformService
                .verify_all_legacy_proxies_disabled()
                .map_err(|error| {
                    format!(
                        "legacy settings report no owned proxy, but an enabled proxy remains. Disable it manually before cutover: {error}"
                    )
                })?;
            None
        };

        if runtime_kind == LegacyRuntimePlanKind::FreshInstall {
            verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path())?;
            require_retired_managed_paths_absent(&store)?;
        }

        Ok(Self {
            store,
            retirement_completed,
            legacy_settings,
            preferences,
            proxy,
            tunnel,
            control_session,
            managed_process,
            runtime_kind,
        })
    }

    pub(super) async fn retire_network(
        self,
        mut revalidate_gui: impl FnMut() -> Result<(), String>,
    ) -> Result<RetiredLegacyNetwork, LegacyRetirementFailure> {
        // Everything below is mutation-capable. All fallible ownership checks
        // above have already completed while the legacy data plane was intact.
        self.revalidate_before_mutation()
            .map_err(|error| LegacyRetirementFailure {
                error: error.into(),
            })?;

        // This is the first network mutation. From this point onward the old
        // GUI has already exited and must never be relaunched: the supervisor
        // may already be stopping its child even if a later operation fails.
        let result = async {
            if let (Some(session), Some(process)) = (&self.control_session, &self.managed_process) {
                revalidate_gui()?;
                LegacyControlSession::request_stop(session).map_err(|error| {
                    format!("failed to publish the exact legacy core stop request: {error}")
                })?;
                wait_for_managed_process_to_exit(
                    self.store.paths().legacy_cores_dir.as_path(),
                    process,
                )
                .await?;
            }
            if let Some(tunnel) = &self.tunnel {
                revalidate_gui()?;
                tunnel.verify_removed()?;
            }
            if let Some(proxy) = &self.proxy {
                revalidate_gui()?;
                MacOsPlatformService
                    .disable_legacy_proxy(proxy)
                    .map_err(|error| {
                        format!("failed to clear the exact product-owned proxy fields: {error}")
                    })?;
                MacOsPlatformService
                    .verify_legacy_proxy_disabled(proxy)
                    .map_err(|error| {
                        format!("legacy proxy cleanup could not be verified: {error}")
                    })?;
            }
            if self.control_session.is_some() {
                revalidate_gui()?;
                LegacyControlSession::remove().map_err(|error| {
                    format!("failed to remove the fixed legacy control session: {error}")
                })?;
            }
            self.verify_pre_service_retirement_absence()?;
            match self.runtime_kind {
                LegacyRuntimePlanKind::LiveOwned { .. }
                | LegacyRuntimePlanKind::DormantRegistered { .. } => {
                    complete_service_retirement(
                        observe_service_retirement_boundary,
                        || {
                            revalidate_gui()?;
                            MacOsPlatformService.retire_legacy_service().map_err(|error| {
                                format!("failed to unregister retired Service Mode: {error}")
                            })
                        },
                        || {
                            self.verify_post_retirement_absence()
                        },
                    )?;
                    revalidate_gui()?;
                }
                LegacyRuntimePlanKind::OfflineUpgrade | LegacyRuntimePlanKind::FreshInstall => {
                    let (status, job) = observe_service_retirement_boundary()?;
                    if !matches!(status, ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound)
                        || job != LegacyServiceJobObservation::Unloaded
                    {
                        return Err(
                            "an inactive upgrade acquired a legacy service registration before the retirement boundary"
                                .into(),
                        );
                    }
                    self.verify_post_retirement_absence()?;
                    revalidate_gui()?;
                }
            }
            Ok::<(), LegacyCleanupError>(())
        }
        .await;
        match result {
            Ok(()) => Ok(RetiredLegacyNetwork { plan: self }),
            Err(error) => Err(LegacyRetirementFailure { error }),
        }
    }

    pub(super) fn legacy_tunnel_identity(&self) -> Option<LegacyNetworkJournalIdentity> {
        self.tunnel
            .as_ref()
            .map(LegacyNetworkFingerprint::journal_identity)
    }

    pub(super) fn runtime_kind(&self) -> LegacyRuntimePlanKind {
        self.runtime_kind
    }

    pub(super) fn legacy_process(&self) -> Option<&ProcessRecord> {
        self.managed_process.as_ref()
    }

    pub(super) fn legacy_proxy_services(&self) -> &[LegacyProxyServiceIdentity] {
        self.proxy
            .as_ref()
            .map_or(&[], LegacyProxyCutoverPlan::services)
    }

    pub(super) fn legacy_proxy_port(&self) -> Option<u16> {
        self.proxy
            .as_ref()
            .map(LegacyProxyCutoverPlan::expected_port)
    }

    pub(super) fn legacy_session_identity(&self) -> Option<(u16, u16, u64)> {
        self.control_session.as_ref().map(|session| {
            (
                session.mixed_port(),
                session.controller_port(),
                session.generation(),
            )
        })
    }

    fn revalidate_before_mutation(&self) -> Result<(), String> {
        match self.runtime_kind {
            LegacyRuntimePlanKind::LiveOwned { service_job } => {
                let (Some(session), Some(process)) = (&self.control_session, &self.managed_process)
                else {
                    return Err("live legacy runtime plan has no session/process identity".into());
                };
                if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled {
                    return Err("legacy Service Mode is no longer Enabled".into());
                }
                if MacOsPlatformService
                    .legacy_service_job_observation()
                    .map_err(|error| error.to_string())?
                    != service_job
                {
                    return Err("legacy launchd job identity or activity changed".into());
                }
                if LegacyControlSession::observe().map_err(|error| error.to_string())? != *session {
                    return Err("legacy control session changed after preparation".into());
                }
                let current = managed_processes(self.store.paths().legacy_cores_dir.as_path())?;
                if current.len() != 1 || current.first() != Some(process) {
                    return Err("legacy managed process identity changed".into());
                }
                verify_process_listens_on_ports(
                    process,
                    &[session.mixed_port(), session.controller_port()],
                )?;
            }
            LegacyRuntimePlanKind::DormantRegistered { service_job } => {
                if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled {
                    return Err("dormant legacy Service Mode registration changed".into());
                }
                if MacOsPlatformService
                    .legacy_service_job_observation()
                    .map_err(|error| error.to_string())?
                    != service_job
                {
                    return Err("dormant legacy launchd job identity or activity changed".into());
                }
                self.verify_inactive_runtime_absence()?;
            }
            LegacyRuntimePlanKind::OfflineUpgrade | LegacyRuntimePlanKind::FreshInstall => {
                if !matches!(
                    MacOsPlatformService.service_mode_status(),
                    ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
                ) {
                    return Err("legacy Service Mode registration changed".into());
                }
                if MacOsPlatformService
                    .legacy_service_job_observation()
                    .map_err(|error| error.to_string())?
                    != LegacyServiceJobObservation::Unloaded
                {
                    return Err("an unregistered legacy launchd job appeared".into());
                }
                self.verify_inactive_runtime_absence()?;
                if self.runtime_kind == LegacyRuntimePlanKind::FreshInstall {
                    verify_privileged_artifacts_are_gone(
                        self.store.paths().legacy_cores_dir.as_path(),
                    )?;
                    require_retired_managed_paths_absent(&self.store)?;
                }
            }
        }
        if let Some(proxy) = &self.proxy {
            MacOsPlatformService
                .verify_legacy_proxy_still_applied(proxy)
                .map_err(|error| error.to_string())?;
        } else {
            MacOsPlatformService
                .verify_all_legacy_proxies_disabled()
                .map_err(|error| format!("an unplanned legacy proxy appeared: {error}"))?;
        }
        if let Some(tunnel) = &self.tunnel {
            tunnel.verify_still_present()?;
        } else {
            LegacyNetworkFingerprint::verify_absent()?;
        }
        Ok(())
    }

    fn verify_inactive_runtime_absence(&self) -> Result<(), String> {
        if LegacyControlSession::exists().map_err(|error| error.to_string())?
            || !managed_processes(self.store.paths().legacy_cores_dir.as_path())?.is_empty()
        {
            return Err("a legacy control session or managed core appeared".into());
        }
        LegacyNetworkFingerprint::verify_absent()?;
        MacOsPlatformService
            .verify_all_legacy_proxies_disabled()
            .map_err(|error| format!("a legacy proxy appeared: {error}"))
    }

    fn verify_post_retirement_absence(&self) -> Result<(), String> {
        verify_privileged_artifacts_are_gone(self.store.paths().legacy_cores_dir.as_path())?;
        self.verify_pre_service_retirement_absence()
    }

    fn verify_pre_service_retirement_absence(&self) -> Result<(), String> {
        if LegacyControlSession::exists().map_err(|error| error.to_string())?
            || !managed_processes(self.store.paths().legacy_cores_dir.as_path())?.is_empty()
        {
            return Err("legacy session or managed core remains before helper unregister".into());
        }
        LegacyNetworkFingerprint::verify_absent()?;
        MacOsPlatformService
            .verify_all_legacy_proxies_disabled()
            .map_err(|error| format!("legacy proxy retirement is incomplete: {error}"))
    }
}
