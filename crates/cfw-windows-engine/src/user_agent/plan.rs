use super::{Result, UserAgentError};
use crate::{
    PreparedConfig,
    authority::{
        LeaseContext,
        wire::{BindRequest, validate_context},
    },
};
use cfw_engine_api::authority_v1::AuthorityMode;
use cfw_singbox_config::ProjectionMode;

/// A checked input, not a start capability. Only the native Authority channel
/// can bind its ticket, and the runtime must keep that channel alive.
pub struct UserAgentPlan {
    pub(super) binding: BindRequest,
    pub(super) config: PlannedConfiguration,
}
pub(super) enum PlannedConfiguration {
    Prepared(PreparedConfig),
    #[cfg(windows)]
    Requested {
        request: crate::CheckedStartConfiguration,
        vault: cfw_windows_credentials::WindowsCredentialStore,
    },
}
impl PlannedConfiguration {
    #[cfg(windows)]
    pub(super) fn prepare_after_binding(self) -> Result<PreparedConfig> {
        match self {
            Self::Prepared(config) => Ok(config),
            Self::Requested { request, vault } => {
                let references = request.credential_references();
                let material =
                    vault.resolve_for_engine(request.credential_audience(), &references)?;
                Ok(match request.mode() {
                    ProjectionMode::Tunnel => {
                        request.prepare_tunnel_data_plane(material.expose_to_engine())?
                    }
                    _ => request.prepare_proxy(material.expose_to_engine())?,
                })
            }
        }
    }
    /// The digest-bound network options of a Tunnel request, which SYSTEM's
    /// tunnel network is opened with before the engine starts.
    #[cfg(windows)]
    pub(super) fn tunnel_options(&self) -> Option<cfw_engine_api::TunnelNetworkOptions> {
        match self {
            Self::Prepared(_) => None,
            Self::Requested { request, .. } => request.shared_request().tunnel_options,
        }
    }
}
impl UserAgentPlan {
    /// A pre-resolved configuration carries no network options, so it can
    /// only plan a listener data plane; Tunnel runs use the start request.
    pub fn new(binding: BindRequest, config: PreparedConfig) -> Result<Self> {
        if config.mode().has_tunnel() {
            return Err(UserAgentError::Mode);
        }
        Self::check(
            &binding,
            config.mode(),
            config.configuration_digest(),
            config.digest(),
        )?;
        Ok(Self {
            binding,
            config: PlannedConfiguration::Prepared(config),
        })
    }
    /// The product path accepts the application's existing request. Its vault
    /// is installation-owned; validation never reads credentials. Resolution
    /// occurs only after this exact native Authority binding is acknowledged.
    #[cfg(windows)]
    pub fn from_start_request(
        binding: BindRequest,
        request: cfw_engine_api::EngineStartRequest,
        vault: cfw_windows_credentials::WindowsCredentialStore,
    ) -> Result<Self> {
        let request = crate::CheckedStartConfiguration::new(request)?;
        Self::from_checked_request(binding, request, vault)
    }
    #[cfg(windows)]
    pub(super) fn from_checked_request(
        binding: BindRequest,
        request: crate::CheckedStartConfiguration,
        vault: cfw_windows_credentials::WindowsCredentialStore,
    ) -> Result<Self> {
        Self::check_request(&binding, &request)?;
        Ok(Self {
            binding,
            config: PlannedConfiguration::Requested { request, vault },
        })
    }
    pub(super) fn check_request(
        binding: &BindRequest,
        request: &crate::CheckedStartConfiguration,
    ) -> Result<()> {
        Self::check(
            binding,
            request.mode(),
            request.configuration_digest(),
            request.digest(),
        )?;
        let root = &binding.context.operation.root;
        let context = request.context();
        if context.installation_id != root.installation_id.to_string()
            || context.config_epoch != root.epoch
            || context.generation != root.generation
        {
            return Err(UserAgentError::ConfigurationMismatch);
        }
        Ok(())
    }
    fn check(
        binding: &BindRequest,
        mode: ProjectionMode,
        configuration_digest: &str,
        identity_digest: &str,
    ) -> Result<()> {
        validate_context(&binding.context)?;
        let mode = match mode {
            ProjectionMode::LocalProxy => AuthorityMode::LocalProxy,
            ProjectionMode::SystemProxy => AuthorityMode::SystemProxy,
            ProjectionMode::Tunnel => AuthorityMode::Tunnel,
            // The combined mode's system proxy is not yet owned on Windows.
            ProjectionMode::TunnelSystemProxy => return Err(UserAgentError::Mode),
        };
        if binding.context.operation.mode != mode {
            return Err(UserAgentError::Mode);
        }
        if configuration_digest != hex(&binding.context.operation.config_sha256)
            || identity_digest != hex(&binding.context.operation.identity_sha256)
        {
            return Err(UserAgentError::ConfigurationMismatch);
        }
        Ok(())
    }
    pub fn context(&self) -> &LeaseContext {
        &self.binding.context
    }
    pub fn mode(&self) -> ProjectionMode {
        match &self.config {
            PlannedConfiguration::Prepared(config) => config.mode(),
            #[cfg(windows)]
            PlannedConfiguration::Requested { request, .. } => request.mode(),
        }
    }
}
pub(crate) fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
