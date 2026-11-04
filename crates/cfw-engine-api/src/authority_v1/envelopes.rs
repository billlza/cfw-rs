//! Request and response envelopes and the events the Authority pushes.

use super::*;

pub enum Command {
    Handshake(HandshakeRequest),
    PrepareStart(PrepareStartRequest),
    BindProxyOwner(BindProxyOwnerRequest),
    RedeemTunnelTicket(RedeemTunnelTicketRequest),
    AttestReady(ReadyAttestation),
    BeginStop(BeginStopRequest),
    AttestStopped(StoppedAttestation),
    CancelPrepared(CancelPreparedRequest),
    Snapshot(SnapshotRequest),
}
impl Command {
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Handshake(_) | Self::Snapshot(_))
    }

    pub(super) fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Handshake(value) => value.validate(),
            Self::PrepareStart(value) => value.validate(),
            Self::BindProxyOwner(value) => {
                value.operation.validate()?;
                if matches!(
                    value.operation.mode,
                    AuthorityMode::LocalProxy | AuthorityMode::SystemProxy
                ) {
                    Ok(())
                } else {
                    Err(CodecError::BoundViolation)
                }
            }
            Self::RedeemTunnelTicket(value) => {
                value.operation.validate()?;
                if value.operation.mode == AuthorityMode::Tunnel {
                    Ok(())
                } else {
                    Err(CodecError::BoundViolation)
                }
            }
            Self::AttestReady(value) => value.validate(),
            Self::BeginStop(value) => value.validate(),
            Self::AttestStopped(value) => value.validate(),
            Self::CancelPrepared(value) => value.validate(),
            Self::Snapshot(value) => value.validate(),
        }
    }
}

pub struct RequestEnvelope {
    pub major: u16,
    pub minor: u16,
    pub required_feature_bits: u64,
    pub request_id: Uuid,
    pub command: Command,
}
impl RequestEnvelope {
    pub fn new(
        request_id: Uuid,
        required_feature_bits: u64,
        command: Command,
    ) -> Result<Self, CodecError> {
        let unsupported = required_feature_bits & !SUPPORTED_FEATURE_BITS;
        if unsupported != 0 {
            return Err(CodecError::UnsupportedRequiredFeatures(unsupported));
        }
        command.validate()?;
        Ok(Self {
            major: MAJOR,
            minor: MINOR,
            required_feature_bits,
            request_id,
            command,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum AuthorityEvent {
    Snapshot(AuthoritySnapshot),
    Revoke(StopDirective),
    Stop(StopDirective),
}
impl WireValidate for AuthorityEvent {
    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Snapshot(value) => value.validate(),
            Self::Revoke(value) | Self::Stop(value) => value.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope<T> {
    pub major: u16,
    pub minor: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Uuid>,
    pub request_id: Uuid,
    pub result: T,
}
impl<T> ResponseEnvelope<T> {
    pub fn new(request_id: Uuid, operation_id: Option<Uuid>, result: T) -> Self {
        Self {
            major: MAJOR,
            minor: MINOR,
            operation_id,
            request_id,
            result,
        }
    }
}
impl<T: WireValidate> WireValidate for ResponseEnvelope<T> {
    fn validate(&self) -> Result<(), CodecError> {
        if self.major != MAJOR {
            return Err(CodecError::UnsupportedMajor(self.major));
        }
        if self.minor != MINOR {
            return Err(CodecError::UnsupportedMinor(self.minor));
        }
        self.result.validate()
    }
}

#[cfg(test)]
mod tests;
