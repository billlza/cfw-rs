use super::wire::{self, Request, Response, WireError};
use crate::{
    NativePeerProcess, ServiceChannel, ServiceClientRole, ServiceTransportError,
    VerifiedExecutable, authority_journal::RecordedOwner,
};
use std::{sync::Arc, time::Instant};

/// One authenticated connection and its native user identity. A malformed,
/// unrelated or timed-out reply closes it; no delivery-uncertain command is
/// replayed. A typed domain rejection keeps the same live connection available.
pub struct AuthorityChannel {
    channel: Option<ServiceChannel>,
    identity: NativePeerProcess,
}
impl AuthorityChannel {
    pub fn connect(
        service: &str,
        role: ServiceClientRole,
        image: impl Into<Arc<VerifiedExecutable>>,
    ) -> Result<Self, WireError> {
        let identity = NativePeerProcess::open(std::process::id())?;
        let channel = ServiceChannel::connect(service, role, image)?;
        Ok(Self {
            channel: Some(channel),
            identity,
        })
    }
    pub fn request(&mut self, request: Request, deadline: Instant) -> Result<Response, WireError> {
        let message = request.encode()?;
        let mut channel = self.channel.take().ok_or(ServiceTransportError::Closed)?;
        self.identity.revalidate()?;
        let owner = RecordedOwner::from_native(self.identity.identity().user_session())?;
        let reply = channel.request(message.as_bytes(), deadline)?;
        self.identity.revalidate()?;
        let response = wire::response(&request, reply.as_bytes(), &owner);
        if response.is_ok() || matches!(&response, Err(WireError::Rejected(_))) {
            self.channel = Some(channel);
        }
        response
    }
}
