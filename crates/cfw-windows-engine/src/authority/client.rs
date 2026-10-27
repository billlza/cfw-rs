use super::wire::{self, Request, Response, WireError};
use crate::{
    NativePeerProcess, ServiceChannel, ServiceClientRole, ServiceTransportError,
    VerifiedExecutable, authority_journal::RecordedOwner,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Each tunnel progress request has the ordinary command bound; the whole
/// open is bounded by its caller's deadline.
const TUNNEL_POLL_REQUEST: Duration =
    Duration::from_millis(cfw_engine_api::authority_v1::COMMAND_TIMEOUT_MS);
const TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
        if let Ok(Response::RuntimeRetained(grant)) = &mut response {
            self.confirm_runtime_reference(&mut channel, grant, deadline)?;
        }
        if response.is_ok() || matches!(&response, Err(WireError::Rejected(_))) {
            self.channel = Some(channel);
        }
        response
    }
    /// Open SYSTEM's tunnel network for the bound Tunnel lease, polling the
    /// same request until SYSTEM offers its endpoint by `deadline`, then adopt
    /// the endpoint SYSTEM placed in this process. SYSTEM compares this
    /// process's own copy before the transferred value is closed. Any failure
    /// after the offer closes this connection, which revokes the lease.
    pub fn open_tunnel(
        &mut self,
        request: wire::TunnelOpenRequest,
        deadline: Instant,
    ) -> Result<crate::tunnel::PacketClient, WireError> {
        let context = request.context.clone();
        let offer = loop {
            let attempt = Request::new(wire::Command::OpenTunnel(request.clone()))?;
            match self.request(attempt, deadline.min(Instant::now() + TUNNEL_POLL_REQUEST))? {
                Response::TunnelOffered(offer) => break offer,
                Response::TunnelPending => {
                    if Instant::now() + TUNNEL_POLL_INTERVAL >= deadline {
                        return Err(ServiceTransportError::Deadline.into());
                    }
                    std::thread::sleep(TUNNEL_POLL_INTERVAL);
                }
                _ => return Err(WireError::Correlation),
            }
        };
        let mut channel = self.channel.take().ok_or(ServiceTransportError::Closed)?;
        let owner = RecordedOwner::from_native(self.identity.identity().user_session())?;
        let authority = channel.packet_authority()?;
        let identity = &self.identity;
        let client = crate::tunnel::PacketClient::adopt(&offer, &authority, |handle| {
            let confirmation =
                Request::new(wire::Command::ConfirmTunnelEndpoint(wire::KeeperRequest {
                    context,
                    handle,
                }))?;
            let message = confirmation.encode()?;
            identity.revalidate()?;
            let reply = channel.request(message.as_bytes(), deadline)?;
            identity.revalidate()?;
            match wire::response(&confirmation, reply.as_bytes(), &owner)? {
                Response::Status(_) => Ok(()),
                _ => Err(WireError::Correlation),
            }
        })?;
        self.channel = Some(channel);
        Ok(client)
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
    fn confirm_runtime_reference(
        &self,
        channel: &mut ServiceChannel,
        grant: &mut wire::RuntimeReferenceGrant,
        deadline: Instant,
    ) -> Result<(), WireError> {
        let owner = RecordedOwner::from_native(self.identity.identity().user_session())?;
        let context = grant.context().clone();
        grant.adopt(&self.identity, |handle| {
            let confirmation = Request::new(wire::Command::ConfirmRuntimeReference(
                wire::KeeperRequest { context, handle },
            ))?;
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
