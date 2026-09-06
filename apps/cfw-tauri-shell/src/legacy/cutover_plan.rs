use cfw_core::{
    LegacyControlSession, LegacyControlSessionObservation, LegacyNetworkState,
    LegacySettingsMigration, SettingsStore, UiPreferences,
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
    proxy_absence: LegacyProxyAbsence,
}

/// The existing runtime classification selects the absence question. A fresh
/// installation must keep proving that no legacy resources exist; an upgrade
/// must prove absence at the endpoint its own settings recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LegacyProxyAbsence {
    FreshInstall,
    RecordedEndpoint { owned_port: u16, pac_present: bool },
}

impl LegacyProxyAbsence {
    /// The plan or journal owns the runtime kind. Missing settings never turn an
    /// upgrade into a fresh installation, and unreadable settings remain errors.
    pub(super) fn resolve(
        store: &SettingsStore,
        runtime_kind: LegacyRuntimePlanKind,
    ) -> Result<Self, String> {
        let legacy_settings = LegacySettingsMigration::read(store.paths()).map_err(|error| {
            format!(
                "legacy settings are unreadable; legacy proxy absence cannot be proven: {error}"
            )
        })?;
        Self::from_network(
            legacy_settings.as_ref().map(|migration| &migration.network),
            store,
            runtime_kind,
        )
    }

    fn from_network(
        network: Option<&LegacyNetworkState>,
        store: &SettingsStore,
        runtime_kind: LegacyRuntimePlanKind,
    ) -> Result<Self, String> {
        if runtime_kind == LegacyRuntimePlanKind::FreshInstall {
            if network.is_some() {
                return Err(
                    "legacy settings appeared in a fresh installation; the existing network was not changed"
                        .into(),
                );
            }
            return Ok(Self::FreshInstall);
        }
        let owned_port = network.and_then(|network| network.mixed_port).ok_or_else(|| {
            "legacy settings do not record the retired mixed port, so legacy proxy absence cannot be proven; the existing proxy was not changed"
                .to_owned()
        })?;
        Ok(Self::RecordedEndpoint {
            owned_port,
            pac_present: store.paths().app_home.join("proxy.pac").exists(),
        })
    }

    pub(super) fn verify(&self, store: &SettingsStore, context: &str) -> Result<(), String> {
        self.verify_with(
            store,
            context,
            || verify_privileged_artifacts_are_gone(store.paths().legacy_cores_dir.as_path()),
            |owned_port, pac_present| {
                MacOsPlatformService
                    .verify_no_legacy_owned_proxy(&[owned_port], pac_present)
                    .map_err(|error| error.to_string())
            },
        )
    }

    fn verify_with(
        &self,
        store: &SettingsStore,
        context: &str,
        verify_privileged_absence: impl FnOnce() -> Result<(), String>,
        verify_recorded_proxy_absence: impl FnOnce(u16, bool) -> Result<(), String>,
    ) -> Result<(), String> {
        let result = match self {
            Self::FreshInstall => verify_privileged_absence()
                .and_then(|()| require_retired_managed_paths_absent(store)),
            Self::RecordedEndpoint {
                owned_port,
                pac_present,
            } => verify_recorded_proxy_absence(*owned_port, *pac_present),
        };
        result.map_err(|error| format!("{context}: {error}"))
    }
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

        let proxy_absence = LegacyProxyAbsence::from_network(
            legacy_settings.as_ref().map(|migration| &migration.network),
            &store,
            runtime_kind,
        )?;
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
            // The retired installation is not holding a proxy it claims to own,
            // so prove that nothing remains on the endpoint it recorded as its
            // own. A proxy belonging to a different product on a different
            // endpoint says nothing about this installation and is not consulted;
            // the address range and the loopback host are shared across the whole
            // tool family. Fail closed when the recorded endpoint is unknown.
            proxy_absence.verify(
                &store,
                "the retired installation's system proxy is still applied; it must be off before cutover",
            )?;
            None
        };

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
            proxy_absence,
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
            }
        }
        if let Some(proxy) = &self.proxy {
            MacOsPlatformService
                .verify_legacy_proxy_still_applied(proxy)
                .map_err(|error| error.to_string())?;
        } else if self.runtime_kind != LegacyRuntimePlanKind::FreshInstall {
            // The inactive FreshInstall branch above already proved its full
            // resource absence; it has no recorded proxy endpoint to recheck.
            self.proxy_absence
                .verify(&self.store, "an unplanned legacy proxy appeared")?;
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
        self.proxy_absence
            .verify(&self.store, "a legacy proxy appeared")
    }

    fn verify_post_retirement_absence(&self) -> Result<(), String> {
        if self.runtime_kind != LegacyRuntimePlanKind::FreshInstall {
            verify_privileged_artifacts_are_gone(self.store.paths().legacy_cores_dir.as_path())?;
        }
        self.verify_pre_service_retirement_absence()
    }

    fn verify_pre_service_retirement_absence(&self) -> Result<(), String> {
        if LegacyControlSession::exists().map_err(|error| error.to_string())?
            || !managed_processes(self.store.paths().legacy_cores_dir.as_path())?.is_empty()
        {
            return Err("legacy session or managed core remains before helper unregister".into());
        }
        LegacyNetworkFingerprint::verify_absent()?;
        self.proxy_absence
            .verify(&self.store, "legacy proxy retirement is incomplete")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;

    use cfw_core::MacOsAppPaths;
    use cfw_platform::LegacyServiceJobProgram;

    use super::*;

    const LEGACY_WRITER_BASE: &str = "retain_window_bounds: true\nlaunch_at_login: false\nsilent_start: false\nsystem_proxy: false\n";

    fn fresh_store() -> (tempfile::TempDir, SettingsStore) {
        let temporary = tempfile::tempdir().expect("fresh installation fixture");
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(temporary.path().join("app")));
        store.ensure_layout().expect("new settings layout");
        (temporary, store)
    }

    fn upgrade_kinds() -> [LegacyRuntimePlanKind; 3] {
        [
            LegacyRuntimePlanKind::OfflineUpgrade,
            LegacyRuntimePlanKind::DormantRegistered {
                service_job: LegacyServiceJobObservation::LoadedInactive {
                    program: LegacyServiceJobProgram::RetirementTombstone,
                },
            },
            LegacyRuntimePlanKind::LiveOwned {
                service_job: LegacyServiceJobObservation::LoadedActive {
                    program: LegacyServiceJobProgram::LegacyHelper,
                },
            },
        ]
    }

    #[test]
    fn fresh_install_without_legacy_settings_has_no_recorded_proxy_endpoint() {
        let (_temporary, store) = fresh_store();
        assert!(
            LegacySettingsMigration::read(store.paths())
                .expect("read absent legacy settings")
                .is_none()
        );
        let runtime_kind = classify_legacy_runtime(LegacyRuntimeEvidence {
            retirement_completed: false,
            legacy_settings_present: false,
            service_status: ServiceModeStatus::NotRegistered,
            service_job: LegacyServiceJobObservation::Unloaded,
            control_session_present: false,
            managed_process_count: 0,
        })
        .expect("authoritatively absent legacy runtime");
        assert_eq!(runtime_kind, LegacyRuntimePlanKind::FreshInstall);

        let absence = LegacyProxyAbsence::resolve(&store, runtime_kind)
            .expect("a fresh installation never recorded a legacy proxy endpoint");
        assert_eq!(absence, LegacyProxyAbsence::FreshInstall);
        let privileged_calls = Cell::new(0);
        for _ in 0..2 {
            absence
                .verify_with(
                    &store,
                    "fresh installation",
                    || {
                        privileged_calls.set(privileged_calls.get() + 1);
                        Ok(())
                    },
                    |_, _| panic!("fresh installation must not inspect or clear foreign proxies"),
                )
                .expect("current legacy resources remain absent");
        }
        assert_eq!(
            privileged_calls.get(),
            2,
            "absence results are never cached"
        );
    }

    #[test]
    fn fresh_install_rechecks_real_managed_paths_after_resolution() {
        let (_temporary, store) = fresh_store();
        let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect("fresh strategy");
        for path in [
            store.paths().legacy_settings_file.clone(),
            store.paths().legacy_config_file.clone(),
            store.paths().legacy_cores_dir.clone(),
            store.paths().legacy_helpers_dir.clone(),
            store.paths().legacy_profiles_dir.clone(),
            store.paths().app_home.join("proxy.pac"),
        ] {
            fs::write(&path, b"late legacy resource").expect("create late resource");
            let error = absence
                .verify_with(
                    &store,
                    "fresh installation recheck",
                    || Ok(()),
                    |_, _| panic!("fresh failure must not inspect foreign proxies"),
                )
                .expect_err("a previously selected fresh strategy is not an absence receipt");
            assert!(error.contains("remains at"), "{error}");
            fs::remove_file(path).expect("remove fixture resource");
        }
        let pac = store.paths().app_home.join("proxy.pac");
        std::os::unix::fs::symlink("missing-pac-target", &pac).expect("broken PAC symlink");
        let error = absence
            .verify_with(&store, "fresh recheck", || Ok(()), |_, _| unreachable!())
            .expect_err("a broken symlink is still a legacy resource");
        assert!(error.contains("remains at"), "{error}");
    }

    #[test]
    fn fresh_install_requires_each_privileged_absence_observation() {
        let (_temporary, store) = fresh_store();
        let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect("fresh strategy");
        for failure in [
            "legacy helper remains",
            "legacy service observation is unavailable",
            "legacy control session remains",
            "legacy managed process appeared",
        ] {
            let error = absence
                .verify_with(
                    &store,
                    "fresh recheck",
                    || Err(failure.to_owned()),
                    |_, _| panic!("failed absence must not fall back to proxy inspection"),
                )
                .expect_err("unverified runtime absence must fail");
            assert_eq!(error, format!("fresh recheck: {failure}"));
        }
    }

    #[test]
    fn upgrade_kinds_never_become_fresh_when_settings_or_the_port_are_missing() {
        let (_temporary, store) = fresh_store();
        for kind in upgrade_kinds() {
            let error = LegacyProxyAbsence::resolve(&store, kind)
                .expect_err("missing settings do not change the journal's runtime kind");
            assert!(
                error.contains("do not record the retired mixed port"),
                "{error}"
            );
        }
        fs::write(&store.paths().legacy_settings_file, LEGACY_WRITER_BASE)
            .expect("valid legacy settings without a port");
        for kind in upgrade_kinds() {
            let error = LegacyProxyAbsence::resolve(&store, kind)
                .expect_err("a recorded installation must identify its owned endpoint");
            assert!(
                error.contains("do not record the retired mixed port"),
                "{error}"
            );
        }
    }

    #[test]
    fn fresh_install_rejects_settings_with_or_without_a_recorded_port() {
        let (_temporary, store) = fresh_store();
        for port_field in ["", "mixed_port: 7902\n"] {
            fs::write(
                &store.paths().legacy_settings_file,
                format!("{LEGACY_WRITER_BASE}{port_field}"),
            )
            .expect("legacy settings");
            let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
                .expect_err("new legacy settings must not select a different absence strategy");
            assert!(
                error.contains("settings appeared in a fresh installation"),
                "{error}"
            );
        }
    }

    #[test]
    fn unreadable_legacy_settings_never_become_fresh_absence() {
        let (_temporary, store) = fresh_store();
        fs::write(&store.paths().legacy_settings_file, [0xff]).expect("invalid UTF-8 settings");
        let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect_err("invalid content is not missing content");
        assert!(error.contains("legacy settings are unreadable"), "{error}");
        fs::remove_file(&store.paths().legacy_settings_file).expect("remove invalid fixture");
        std::os::unix::fs::symlink(
            "missing-settings-target",
            &store.paths().legacy_settings_file,
        )
        .expect("broken settings symlink");
        let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect_err("an unreadable settings path is not absent");
        assert!(error.contains("legacy settings are unreadable"), "{error}");
    }

    #[test]
    fn recorded_endpoint_keeps_its_exact_proxy_boundary() {
        let (_temporary, store) = fresh_store();
        fs::write(
            &store.paths().legacy_settings_file,
            format!("{LEGACY_WRITER_BASE}mixed_port: 7902\n"),
        )
        .expect("recorded legacy port");
        fs::write(store.paths().app_home.join("proxy.pac"), b"fixture PAC")
            .expect("recorded PAC presence");
        let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::OfflineUpgrade)
            .expect("recorded strategy");
        assert_eq!(
            absence,
            LegacyProxyAbsence::RecordedEndpoint {
                owned_port: 7902,
                pac_present: true
            }
        );
        let proxy_calls = Cell::new(0);
        let error = absence
            .verify_with(
                &store,
                "recorded endpoint",
                || panic!("an upgrade must not acquire fresh-install absence"),
                |port, pac_present| {
                    proxy_calls.set(proxy_calls.get() + 1);
                    assert_eq!(port, 7902);
                    assert!(pac_present);
                    Err("recorded proxy remains".into())
                },
            )
            .expect_err("recorded proxy failure remains explicit");
        assert_eq!(proxy_calls.get(), 1);
        assert_eq!(error, "recorded endpoint: recorded proxy remains");
    }

    #[test]
    fn fresh_absence_remains_valid_after_the_completion_marker() {
        let (_temporary, store) = fresh_store();
        store
            .commit_legacy_retirement()
            .expect("completed data retirement marker");
        let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect("recovery preserves the original journal kind");
        absence
            .verify_with(
                &store,
                "completed fresh installation",
                || Ok(()),
                |_, _| panic!("completed fresh installation has no retired proxy endpoint"),
            )
            .expect("the marker does not invalidate current absence");
    }
}
