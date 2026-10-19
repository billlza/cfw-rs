use super::{
    AuthorityError, WindowsAuthority,
    wire::{self, Command, Message, Request, Response, WireError},
};
use crate::{
    AuthenticatedServiceRequest, LocalServiceConnection, ServiceAuthorizationError,
    ServiceClientRole, ServicePeerAuthorization, ServiceTransportError, UserAgentLeaseRequirement,
    authorize_service_request,
};
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("Windows authority request: {0}")]
    Wire(#[from] WireError),
    #[error("Windows authority request admission: {0}")]
    Authorization(#[from] ServiceAuthorizationError),
}
/// Owns the exact admitted request until its only reply. Publication errors are
/// retained for the service supervisor as well as reported with a closed wire
/// code. A send failure is delivery-uncertain; it never retries or undoes a grant.
pub struct AuthorizedReply {
    authorization: ServicePeerAuthorization,
    message: Message,
    rejection: Option<AuthorityError>,
}
impl AuthorizedReply {
    pub fn rejection(&self) -> Option<&AuthorityError> {
        self.rejection.as_ref()
    }
    pub fn send(
        self,
        connection: &mut LocalServiceConnection,
        deadline: Instant,
    ) -> Result<Option<AuthorityError>, ServiceTransportError> {
        connection.reply(
            self.authorization.request(),
            self.message.as_bytes(),
            deadline,
        )?;
        Ok(self.rejection)
    }
}
impl WindowsAuthority {
    /// Call under the service lifecycle guard, and retain that guard until the
    /// returned reply is sent. This binds dispatch to the actual message bytes;
    /// callers cannot substitute a second command for an admitted request.
    pub fn handle(
        &mut self,
        connection: &mut LocalServiceConnection,
        request: AuthenticatedServiceRequest,
        deadline: Instant,
    ) -> Result<AuthorizedReply, DispatchError> {
        let command = Request::decode(request.body())?;
        let requirement = if matches!(command.command, Command::Observe) {
            UserAgentLeaseRequirement::OwnedLeaseOrNone
        } else {
            UserAgentLeaseRequirement::OwnedLease
        };
        let authorization = authorize_service_request(
            connection,
            request,
            self.lease_owner(),
            requirement,
            deadline,
        )?;
        let admitted_role = authorization.request().role();
        let allowed = match admitted_role {
            ServiceClientRole::Desktop => matches!(
                command.command,
                Command::Observe
                    | Command::Prepare(_)
                    | Command::BeginStop(_)
                    | Command::AbortPrepared(_)
                    | Command::OwnedLease
            ),
            ServiceClientRole::UserAgent => matches!(
                command.command,
                Command::Observe
                    | Command::BindUserAgent(_)
                    | Command::Ready(_)
                    | Command::Heartbeat(_)
                    | Command::Stopped(_)
                    | Command::OwnedLease
            ),
        };
        let outcome = if allowed {
            self.execute(&authorization, command.command)
        } else {
            Err(AuthorityError::Identity)
        };
        let (message, rejection) = match outcome {
            Ok(response) => (response.encode(command.id)?, None),
            Err(error) => (wire::rejection(command.id, &error)?, Some(error)),
        };
        Ok(AuthorizedReply {
            authorization,
            message,
            rejection,
        })
    }
    fn execute(
        &mut self,
        authorization: &ServicePeerAuthorization,
        command: Command,
    ) -> Result<Response, AuthorityError> {
        Ok(match command {
            Command::Observe => Response::Observed(self.poll()?),
            Command::Prepare(input) => {
                let ticket = self.prepare(authorization, input)?;
                let material = ticket
                    .with_ticket(wire::TicketMaterial::from_slice)
                    .map_err(|_| AuthorityError::Invalid)?;
                Response::Prepared(wire::PreparedGrant {
                    context: ticket.context().clone(),
                    ticket: material,
                })
            }
            Command::BindUserAgent(input) => {
                let grant = input.ticket.with_bytes(|ticket| {
                    self.bind_user_agent(authorization, input.context.clone(), ticket)
                })?;
                Response::Bound(wire::BoundGrant {
                    context: grant.context().clone(),
                    committed_revision: grant.committed_revision(),
                })
            }
            Command::Ready(input) => Response::Status(self.ready(authorization, input)?),
            Command::Heartbeat(context) => {
                Response::Status(self.heartbeat(authorization, &context)?)
            }
            Command::BeginStop(input) => Response::Status(self.begin_stop(
                authorization,
                &input.context,
                input.expected_revision,
            )?),
            Command::AbortPrepared(input) => Response::Status(self.abort_prepared(
                authorization,
                &input.context,
                input.expected_revision,
            )?),
            Command::Stopped(input) => Response::Status(self.stopped(authorization, input)?),
            Command::OwnedLease => Response::Lease(self.owned_lease(authorization)?),
        })
    }
}
