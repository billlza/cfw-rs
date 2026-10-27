//! One bounded launch frame for an inherited private channel. A decoded frame
//! is not an executable lease: the receiving process must still bind natively.
use super::{UserAgentError, UserAgentPlan};
use crate::{
    CheckedStartConfiguration,
    authority::{LeaseContext, wire::BindRequest},
};
use cfw_engine_api::{EngineCommandContext, EngineStartRequest, TunnelNetworkOptions};
use cfw_singbox_config::{CredentialAudience, CredentialSlot, ProjectionMode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL: &str = "cfw.windows.user-agent.start";
const VERSION: u16 = 1;
// Includes JSON escaping of the 512 KiB template plus all 2,048 bounded
// credential-slot descriptors. This is separate from the small Authority RPC.
pub const MAX_START_BYTES: usize = 2 * cfw_engine_api::authority_v1::MAX_ENVELOPE_BYTES;
pub const MAX_FRAME_BYTES: usize = MAX_START_BYTES + 4;

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("Windows user-agent launch frame has an invalid length")]
    Length,
    #[error("Windows user-agent launch frame is malformed or noncanonical")]
    Malformed,
    #[error("Windows user-agent launch protocol/version is unsupported")]
    Version,
    #[error("Windows user-agent launch configuration: {0}")]
    Configuration(#[from] crate::Error),
    #[error("Windows user-agent launch binding: {0}")]
    Binding(#[from] UserAgentError),
}
type Result<T> = std::result::Result<T, HandoffError>;

pub struct LaunchMessage {
    bytes: Zeroizing<Vec<u8>>,
    length: usize,
}
impl LaunchMessage {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
pub struct UserAgentLaunch {
    binding: BindRequest,
    request: CheckedStartConfiguration,
}
impl UserAgentLaunch {
    pub fn new(binding: BindRequest, request: EngineStartRequest) -> Result<Self> {
        Self::checked(binding, CheckedStartConfiguration::new(request)?)
    }
    pub(super) fn checked(
        binding: BindRequest,
        request: CheckedStartConfiguration,
    ) -> Result<Self> {
        UserAgentPlan::check_request(&binding, &request)?;
        Ok(Self { binding, request })
    }
    pub fn context(&self) -> &LeaseContext {
        &self.binding.context
    }
    pub fn mode(&self) -> ProjectionMode {
        self.request.mode()
    }
    #[cfg(all(windows, feature = "native-service-validation"))]
    pub(super) fn rejected_copy_for_validation(&self) -> Result<Self> {
        let ticket = self
            .binding
            .ticket
            .with_bytes(|bytes| {
                let mut changed = Zeroizing::new([0; 32]);
                changed.copy_from_slice(bytes);
                changed[0] ^= 1;
                crate::authority::wire::TicketMaterial::from_slice(changed.as_ref())
            })
            .map_err(UserAgentError::from)?;
        Self::new(
            BindRequest {
                context: self.binding.context.clone(),
                ticket,
            },
            self.request.shared_request().clone(),
        )
    }
    pub fn encode(&self) -> Result<LaunchMessage> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            protocol: &'a str,
            version: u16,
            binding: &'a BindRequest,
            request: &'a EngineStartRequest,
        }
        let mut bytes = Zeroizing::new(vec![0; MAX_FRAME_BYTES]);
        let length = {
            let mut output = &mut bytes[4..];
            serde_json::to_writer(
                &mut output,
                &Envelope {
                    protocol: PROTOCOL,
                    version: VERSION,
                    binding: &self.binding,
                    request: self.request.shared_request(),
                },
            )
            .map_err(|_| HandoffError::Length)?;
            MAX_START_BYTES - output.len()
        };
        let prefix = u32::try_from(length)
            .map_err(|_| HandoffError::Length)?
            .to_le_bytes();
        bytes[..4].copy_from_slice(&prefix);
        Ok(LaunchMessage {
            bytes,
            length: length + 4,
        })
    }
    /// Decode only a complete, externally bounded frame. The caller owns I/O
    /// deadlines, cancellation and wiping the input buffer; parsing performs no
    /// file/credential access and cannot select executable or storage paths.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        if frame.len() < 4 || frame.len() > MAX_FRAME_BYTES {
            return Err(HandoffError::Length);
        }
        let length =
            u32::from_le_bytes(frame[..4].try_into().map_err(|_| HandoffError::Length)?) as usize;
        if length == 0 || length > MAX_START_BYTES || frame.len() != length + 4 {
            return Err(HandoffError::Length);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header<'a> {
            protocol: &'a str,
            version: u16,
            binding: &'a RawValue,
            request: &'a RawValue,
        }
        let header: Header<'_> =
            serde_json::from_slice(&frame[4..]).map_err(|_| HandoffError::Malformed)?;
        if header.protocol != PROTOCOL || header.version != VERSION {
            return Err(HandoffError::Version);
        }
        let binding =
            serde_json::from_str(header.binding.get()).map_err(|_| HandoffError::Malformed)?;
        let request: RequestWire =
            serde_json::from_str(header.request.get()).map_err(|_| HandoffError::Malformed)?;
        let launch = Self::new(binding, request.into_request())?;
        // Also closes nested request/context fields and duplicate aliases, not
        // just the envelope. Sender and receiver share the exact existing DTO.
        if launch.encode()?.as_bytes() != frame {
            return Err(HandoffError::Malformed);
        }
        Ok(launch)
    }
    #[cfg(windows)]
    pub fn into_plan(
        self,
        vault: cfw_windows_credentials::WindowsCredentialStore,
    ) -> super::Result<UserAgentPlan> {
        UserAgentPlan::from_checked_request(self.binding, self.request, vault)
    }
}

struct Template(String);
impl<'de> Deserialize<'de> for Template {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}
impl Template {
    fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}
impl Drop for Template {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Same EngineStartRequest fields, with a wiping owner for the template even
// if a later field fails deserialization. No new configuration schema is used.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    context: EngineCommandContext,
    mode: ProjectionMode,
    credential_audience: CredentialAudience,
    config_json: Template,
    config_content_digest: String,
    config_digest: String,
    credential_slots: Vec<CredentialSlot>,
    tunnel_options: Option<TunnelNetworkOptions>,
}
impl RequestWire {
    fn into_request(self) -> EngineStartRequest {
        EngineStartRequest {
            context: self.context,
            mode: self.mode,
            credential_audience: self.credential_audience,
            config_json: self.config_json.take(),
            config_content_digest: self.config_content_digest,
            config_digest: self.config_digest,
            credential_slots: self.credential_slots,
            tunnel_options: self.tunnel_options,
        }
    }
}

#[cfg(test)]
mod tests;
