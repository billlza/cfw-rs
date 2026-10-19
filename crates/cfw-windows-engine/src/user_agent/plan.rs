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
    pub(super) config: PreparedConfig,
}
impl UserAgentPlan {
    pub fn new(binding: BindRequest, config: PreparedConfig) -> Result<Self> {
        validate_context(&binding.context)?;
        let mode = match config.mode() {
            ProjectionMode::LocalProxy => AuthorityMode::LocalProxy,
            ProjectionMode::SystemProxy => AuthorityMode::SystemProxy,
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => {
                return Err(UserAgentError::Mode);
            }
        };
        if binding.context.operation.mode != mode {
            return Err(UserAgentError::Mode);
        }
        if config.configuration_digest() != hex(&binding.context.operation.config_sha256)
            || config.digest() != hex(&binding.context.operation.identity_sha256)
        {
            return Err(UserAgentError::ConfigurationMismatch);
        }
        Ok(Self { binding, config })
    }
    pub fn context(&self) -> &LeaseContext {
        &self.binding.context
    }
    pub fn configuration(&self) -> &PreparedConfig {
        &self.config
    }
}
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
