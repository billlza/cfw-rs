use cfw_core::{
    LegacyControlSession, LegacyControlSessionObservation, LegacySettingsMigration, SettingsStore,
    UiPreferences,
};
use cfw_platform::{
    LegacyProxyCutoverPlan, LegacyProxyServiceIdentity, LegacyServiceRetirement,
    MacOsPlatformService, ServiceModeStatus,
};

use super::migration::restore_legacy_dns;
use super::network_fingerprint::LegacyNetworkFingerprint;
use super::process_cleanup::{
    ProcessRecord, managed_processes, require_unique_root_managed_process,
    verify_privileged_artifacts_are_gone, verify_process_listens_on_ports,
    wait_for_managed_process_to_exit,
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
}

#[derive(Debug)]
pub(super) struct RetiredLegacyNetwork {
    pub(super) plan: LegacyCutoverPlan,
}

#[derive(Debug)]
pub(super) struct LegacyRetirementFailure {
    pub(super) error: LegacyCleanupError,
    pub(super) can_resume_old_gui: bool,
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
        let (control_session, managed_process) = match service_status {
            ServiceModeStatus::Enabled => {
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
                let process = require_unique_root_managed_process(
                    store.paths().legacy_cores_dir.as_path(),
                    &store.paths().app_home,
                    &store.paths().legacy_config_file,
                )?;
                verify_process_listens_on_ports(
                    &process,
                    &[session.mixed_port(), session.controller_port()],
                )?;
                (Some(session), Some(process))
            }
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => {
                if LegacyControlSession::exists().map_err(|error| error.to_string())?
                    || !managed_processes(store.paths().legacy_cores_dir.as_path())?.is_empty()
                {
                    return Err(
                        "legacy Service Mode is not registered but its session or managed core remains; the existing network was not changed"
                            .into(),
                    );
                }
                (None, None)
            }
            status => {
                return Err(format!(
                    "legacy Service Mode has non-authoritative status {status:?}; the existing VPN was not changed"
                )
                .into());
            }
        };
        let tunnel = if network.tun_mode {
            if managed_process.is_none() {
                return Err(
                    "legacy TUN is enabled but no unique root managed core was proven; the existing VPN was not changed"
                        .into(),
                );
            }
            Some(LegacyNetworkFingerprint::capture()?)
        } else {
            None
        };

        let proxy = if network.system_proxy {
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

        Ok(Self {
            store,
            retirement_completed,
            legacy_settings,
            preferences,
            proxy,
            tunnel,
            control_session,
            managed_process,
        })
    }

    pub(super) async fn retire_network(
        self,
    ) -> Result<RetiredLegacyNetwork, LegacyRetirementFailure> {
        // Everything below is mutation-capable. All fallible ownership checks
        // above have already completed while the legacy data plane was intact.
        self.revalidate_before_mutation()
            .map_err(|error| LegacyRetirementFailure {
                error: error.into(),
                can_resume_old_gui: false,
            })?;

        // This is the first network mutation. From this point onward the old
        // GUI must never be resumed: the supervisor may already be stopping its
        // child even if a later filesystem or verification operation fails.
        let result = async {
            if let (Some(session), Some(process)) = (&self.control_session, &self.managed_process) {
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
                tunnel.verify_removed()?;
            }
            if let Some(proxy) = &self.proxy {
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
                LegacyControlSession::remove().map_err(|error| {
                    format!("failed to remove the fixed legacy control session: {error}")
                })?;
            }
            MacOsPlatformService
                .retire_legacy_service()
                .map_err(|error| format!("failed to unregister retired Service Mode: {error}"))?;
            verify_privileged_artifacts_are_gone(self.store.paths().legacy_cores_dir.as_path())?;
            Ok::<(), LegacyCleanupError>(())
        }
        .await;
        match result {
            Ok(()) => Ok(RetiredLegacyNetwork { plan: self }),
            Err(error) => Err(LegacyRetirementFailure {
                error,
                can_resume_old_gui: false,
            }),
        }
    }

    pub(super) fn legacy_interface(&self) -> Option<&str> {
        self.tunnel
            .as_ref()
            .map(LegacyNetworkFingerprint::interface)
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
        match (&self.control_session, &self.managed_process) {
            (Some(session), Some(process)) => {
                if MacOsPlatformService.service_mode_status() != ServiceModeStatus::Enabled {
                    return Err("legacy Service Mode is no longer Enabled".into());
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
            (None, None) => {
                if !matches!(
                    MacOsPlatformService.service_mode_status(),
                    ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound
                ) {
                    return Err("legacy Service Mode registration changed".into());
                }
            }
            _ => return Err("legacy helper/process ownership plan is inconsistent".into()),
        }
        if let Some(proxy) = &self.proxy {
            MacOsPlatformService
                .verify_legacy_proxy_still_applied(proxy)
                .map_err(|error| error.to_string())?;
        }
        if let Some(tunnel) = &self.tunnel {
            tunnel.verify_still_present()?;
        }
        Ok(())
    }
}
