//! Preparing the managed engine and the values it reports: its capabilities,
//! status, shutdown outcome and endpoint bindings.

use super::*;

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct EngineCapabilities {
    pub(super) local_proxy: bool,
    pub(super) system_proxy: bool,
    pub(super) tunnel: bool,
    /// Both integrations in one run; never true unless each alone is.
    pub(super) tunnel_system_proxy: bool,
    pub(super) provider_management: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EngineStatusPayload {
    pub(crate) snapshot: EngineSnapshot,
    pub(super) capabilities: EngineCapabilities,
    pub(super) startup_recovery_available: bool,
    pub(super) cutover_ready: bool,
    pub(super) cutover_unavailable_reason: Option<String>,
    pub(super) unavailable_reason: Option<String>,
}

pub(crate) struct EngineShutdownOutcome {
    pub(super) result: Result<EngineSnapshot, String>,
    pub(super) maintenance: EngineMaintenanceLease,
}

impl EngineShutdownOutcome {
    pub(crate) fn into_parts(self) -> (Result<EngineSnapshot, String>, EngineMaintenanceLease) {
        (self.result, self.maintenance)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EngineEndpointBinding {
    pub(super) controller: EngineControllerAccess,
    pub(super) cursor: EndpointCandidateCursor,
    pub(super) active: Option<ActiveControllerBinding>,
    /// How many times this process has set out to replace the saved runtime
    /// preferences. A write that succeeds replaces the settings file and the
    /// settings held here together, and one that fails may have been the
    /// file for a moment, so whoever reads the file takes this count before
    /// and after it and knows whether the file belongs to these settings.
    pub(super) preference_writes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ActiveControllerBinding {
    pub(super) generation: u64,
    pub(super) config_digest: String,
}

pub(crate) struct StagedEndpointRebind {
    pub(super) expected: EngineEndpointBinding,
    pub(super) replacement: EngineEndpointBinding,
}

#[cfg(target_os = "macos")]
impl StagedEndpointRebind {
    pub(crate) fn settings(&self) -> &EngineSettings {
        self.replacement.controller.settings()
    }
}

/// Preparing filesystem / platform state never starts the coordinator. The
/// startup owner admits this task only after checking for an intervening quit.
pub(crate) struct PreparedEngine {
    pub(crate) engine: ManagedEngine,
    pub(crate) task: cfw_application::CoordinatorTask,
}

/// The engine settings and endpoints of a start: those of a cutover journal
/// that governs it, or those the saved preferences make of the defaults, with
/// endpoints selected clear of the LAN listener and of the ports that
/// `reserved` observes as taken.
pub(super) fn configured_engine_settings(
    store: &cfw_core::SettingsStore,
    reserved: impl FnOnce()
        -> Result<std::collections::BTreeSet<u16>, endpoints::EndpointSelectionError>,
) -> Result<(EngineSettings, EndpointCandidateCursor), String> {
    #[cfg(target_os = "macos")]
    if let Some(settings) = load_replacement_engine_settings(&store.paths().app_home)? {
        let cursor = EndpointCandidateCursor::from_persisted(settings.clone())
            .map_err(|error| format!("persisted engine endpoints are unusable: {error}"))?;
        return Ok((settings, cursor));
    }
    let preferences = store
        .runtime_settings::<cfw_singbox_config::RuntimePreferences>()
        .map_err(|error| error.to_string())?
        .settings;
    // The endpoints are selected away from the LAN listener: a port the
    // preferences leave to the engine, and the port of the controller. Only a
    // port they name is checked against the listener first.
    let settings = preferences
        .apply_before_endpoint_selection(EngineSettings::default())
        .map_err(|error| error.to_string())?;
    endpoints::select_configured_engine_settings(
        settings,
        preferences.preferred_mixed_port,
        reserved,
    )
    .map_err(|error| format!("engine loopback endpoints are unavailable: {error}"))
}

pub(crate) fn prepare_managed_engine(
    services: crate::platform_runtime::PlatformRuntime,
) -> Result<PreparedEngine, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    let (settings, cursor) = configured_engine_settings(&store, endpoints::observe_reserved_ports)?;
    let controller = EngineControllerAccess::resolve(settings)
        .map_err(|error| format!("engine settings are unusable: {error}"))?;
    let crate::platform_runtime::PreparedRuntime {
        services,
        coordinator,
        task,
    } = services.prepare()?;

    let engine = ManagedEngine {
        coordinator,
        capabilities: EngineCapabilities {
            local_proxy: services.proxy_available,
            system_proxy: services.proxy_available,
            tunnel: services.tunnel_available,
            tunnel_system_proxy: services.tunnel_system_proxy_available
                && services.tunnel_available
                && services.proxy_available,
            // Providers are application-owned resources (commands::providers).
            // The pinned sing-box 1.14.4 schema has no proxy or rule providers,
            // so the controller's provider methods stay fail-closed backstops
            // that nothing probes.
            provider_management: true,
        },
        unavailable_reason: services.unavailable_reason,
        preflight_backend: services.legacy_preflight,
        system_proxy_authorization: services.authorization,
        profile_delay_backend: services.probes,
        tunnel_approval: services.tunnel_approval,
        #[cfg(target_os = "macos")]
        cutover: CutoverPreparationGate::default(),
        maintenance: EngineMaintenanceGate::default(),
        endpoints: Arc::new(RwLock::new(EngineEndpointBinding {
            controller,
            cursor,
            active: None,
            preference_writes: 0,
        })),
    };
    Ok(PreparedEngine { engine, task })
}
