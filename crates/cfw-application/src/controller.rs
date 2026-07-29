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
