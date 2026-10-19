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
        self.request_inner(request, deadline, true)
    }
    fn request_inner(
        &mut self,
        request: Request,
        deadline: Instant,
        confirm_keeper: bool,
    ) -> Result<Response, WireError> {
        let message = request.encode()?;
        let mut channel = self.channel.take().ok_or(ServiceTransportError::Closed)?;
        self.identity.revalidate()?;
        let owner = RecordedOwner::from_native(self.identity.identity().user_session())?;
        let reply = channel.request(message.as_bytes(), deadline)?;
        self.identity.revalidate()?;
        let mut response = wire::response(&request, reply.as_bytes(), &owner);
        if confirm_keeper && let Ok(Response::Bound(grant)) = &mut response {
            // Wire validation and native service/request correlation precede
            // any interpretation of a numeric value as a receiver-owned handle.
            self.confirm_keeper(&mut channel, grant, deadline)?;
        }
        if response.is_ok() || matches!(&response, Err(WireError::Rejected(_))) {
            self.channel = Some(channel);
        }
        response
    }
    fn confirm_keeper(
        &self,
        channel: &mut ServiceChannel,
        grant: &mut wire::BoundGrant,
        deadline: Instant,
    ) -> Result<(), WireError> {
        let owner = RecordedOwner::from_native(self.identity.identity().user_session())?;
        let context = grant.context().clone();
        grant.adopt_keeper(&self.identity, |handle| {
            let confirmation =
                Request::new(wire::Command::ConfirmRuntimeKeeper(wire::KeeperRequest {
                    context,
                    handle,
                }))?;
            let message = confirmation.encode()?;
            self.identity.revalidate()?;
            let reply = channel.request(message.as_bytes(), deadline)?;
            self.identity.revalidate()?;
            match wire::response(&confirmation, reply.as_bytes(), &owner)? {
                Response::Status(_) => Ok(()),
                _ => Err(WireError::Correlation),
            }
        })
    }
    /// Native fixture only: observe the actual Ready rejection in the interval
    /// between Bind and keeper confirmation. This receipt cannot start an engine.
    #[cfg(feature = "native-service-validation")]
    pub fn unconfirmed_bind_for_validation(
        &mut self,
        request: Request,
        deadline: Instant,
    ) -> Result<Response, WireError> {
        if !matches!(request.command(), wire::Command::BindUserAgent(_)) {
            return Err(WireError::Correlation);
        }
        self.request_inner(request, deadline, false)
    }
    #[cfg(feature = "native-service-validation")]
    pub fn confirm_binding_for_validation(
        &mut self,
        mut grant: wire::BoundGrant,
        deadline: Instant,
    ) -> Result<wire::BoundGrant, WireError> {
        let mut channel = self.channel.take().ok_or(ServiceTransportError::Closed)?;
        self.confirm_keeper(&mut channel, &mut grant, deadline)?;
        self.channel = Some(channel);
        Ok(grant)
    }
}
