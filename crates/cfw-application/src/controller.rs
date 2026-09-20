use std::fmt;
use std::net::Ipv4Addr;

use cfw_controller::ControllerEndpoint;
use cfw_singbox_config::{ClashApiEndpoint, ConfigError, EngineSettings, ProjectedConfig};

/// The engine settings this process starts libbox with, together with the
/// loopback clash-compatible controller those settings open.
///
/// This is the application-layer carrier for the controller endpoint: the host
/// application resolves it once, keeps it in memory beside its engine state, and
/// builds a client endpoint from it when it needs to drive the running engine.
///
/// The per-run secret lives only in bounded process/XPC memory. It appears in
/// the exact runtime start configuration but is never persisted, written to
/// settings, logged, or included in an engine snapshot; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineControllerAccess {
    settings: EngineSettings,
    endpoint: ClashApiEndpoint,
}

impl EngineControllerAccess {
    /// Resolves the controller these settings open, rejecting an unusable port
    /// before any engine mode can be started with them.
    pub fn resolve(settings: EngineSettings) -> Result<Self, ConfigError> {
        let endpoint = settings.clash_api_endpoint()?;
        Ok(Self { settings, endpoint })
    }

    /// The settings every mode change must use, so the running engine's
    /// controller is exactly the one described here.
    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    pub fn address(&self) -> Ipv4Addr {
        self.endpoint.address()
    }

    pub fn port(&self) -> u16 {
        self.endpoint.port()
    }

    /// True when the configuration handed to the engine exposes exactly this
    /// controller.
    pub fn matches_projection(&self, projected: &ProjectedConfig) -> bool {
        projected.clash_api() == self.endpoint
    }

    /// Builds the authenticated loopback endpoint a controller client uses. The
    /// returned value carries the secret, so it must not be logged or persisted.
    pub fn client_endpoint(&self) -> ControllerEndpoint {
        ControllerEndpoint::new(
            self.endpoint.address().to_string(),
            self.endpoint.port(),
            Some(self.endpoint.expose_secret().to_owned()),
        )
    }
}

impl fmt::Debug for EngineControllerAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineControllerAccess")
            .field("settings", &self.settings)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Explicit saved choices override libbox's previous controller cache. Apply
/// them before publishing Active and require readback through the same client.
pub(crate) async fn restore_proxy_selections(
    profile: &cfw_singbox_config::ValidatedSingBoxProfile,
    settings: &EngineSettings,
) -> Result<(), crate::EngineCoordinatorError> {
    if profile.proxy_selections().is_empty() {
        return Ok(());
    }
    let endpoint = EngineControllerAccess::resolve(settings.clone())?.client_endpoint();
    let operation = async {
        let client =
            cfw_controller::ControllerClient::new(endpoint).map_err(|error| error.to_string())?;
        for (group, selected) in profile.proxy_selections() {
            client
                .select_proxy(group, selected)
                .await
                .map_err(|error| error.to_string())?;
        }
        let observed = client.proxies().await.map_err(|error| error.to_string())?;
        for (group, selected) in profile.proxy_selections() {
            if !observed
                .groups
                .iter()
                .any(|entry| &entry.name == group && entry.now.as_ref() == Some(selected))
            {
                return Err("controller did not confirm the saved node choice".to_owned());
            }
        }
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), operation)
        .await
        .map_err(|_| {
            crate::EngineCoordinatorError::ProxySelectionInitialization(
                "controller initialization timed out".into(),
            )
        })?
        .map_err(crate::EngineCoordinatorError::ProxySelectionInitialization)
}
