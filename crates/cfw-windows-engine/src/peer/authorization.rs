//! Live console-user admission after native message/installed-image admission.
//! This preserves the CFM console-owner policy. It does not grant a runtime
//! lease, attest OS cleanup, or claim remote-session/sleep-wake qualification.
use super::{NativePeerProcess, NativeUserSession, PeerIdentityError, observe_user_session};
use crate::{
    AuthenticatedServiceRequest, LocalServiceConnection, ServiceClientRole, ServicePeerError,
    ServiceTransportError, service_peer::require_system_service_identity,
    service_transport::check_deadline,
};
use std::{
    io,
    mem::size_of,
    os::windows::io::{FromRawHandle, OwnedHandle},
    ptr::null_mut,
    time::Instant,
};
use windows_sys::Win32::{
    Security::TokenPrimary,
    System::RemoteDesktop::{
        WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSConnectState,
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
        WTSQueryUserToken,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ServiceAuthorizationError {
    #[error("Windows service authorization observer: {0}")]
    Observer(#[from] ServicePeerError),
    #[error("Windows service authorization identity: {0}")]
    Identity(#[from] PeerIdentityError),
    #[error("Windows service authorization message: {0}")]
    Transport(#[from] ServiceTransportError),
    #[error("Windows service authorization {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows service authorization has no active console user")]
    NoActiveConsole,
    #[error("Windows service authorization console session changed during observation")]
    ConsoleChanged,
    #[error("Windows service caller is not the current console logon")]
    NotConsoleOwner,
    #[error("Windows user-agent operation requires an owned lease")]
    LeaseRequired,
    #[error("Windows user-agent operation belongs to a different lease owner")]
    LeaseOwnerMismatch,
}

fn native(operation: &'static str) -> ServiceAuthorizationError {
    ServiceAuthorizationError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

/// Resolves the physical console's current logon in the SYSTEM service. Token
/// handles are private, never impersonated/duplicated to the caller, and closed
/// before return. Permission or WTS failures remain errors, not absent users.
pub struct LiveConsoleSession {
    identity: NativeUserSession,
}
impl LiveConsoleSession {
    pub fn observe() -> Result<Self, ServiceAuthorizationError> {
        let _observer = require_system_service_identity()?;
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == 0 || session == u32::MAX {
            return Err(ServiceAuthorizationError::NoActiveConsole);
        }
        require_active(session)?;
        let first = query_user(session)?;
        // Session numbers and account SIDs can be reused. A second native token
        // observation must also agree on the logon LUID, not only the number.
        if unsafe { WTSGetActiveConsoleSessionId() } != session {
            return Err(ServiceAuthorizationError::ConsoleChanged);
        }
        require_active(session)?;
        let second = query_user(session)?;
        if first != second || unsafe { WTSGetActiveConsoleSessionId() } != session {
            return Err(ServiceAuthorizationError::ConsoleChanged);
        }
        Ok(Self { identity: first })
    }

    pub fn identity(&self) -> &NativeUserSession {
        &self.identity
    }
}

fn query_user(session: u32) -> Result<NativeUserSession, ServiceAuthorizationError> {
    let mut raw = null_mut();
    if unsafe { WTSQueryUserToken(session, &mut raw) } == 0 {
        return Err(native("query console user token"));
    }
    if raw.is_null() {
        return Err(PeerIdentityError::InvalidIdentity.into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let identity = observe_user_session(&token, TokenPrimary)?;
    if !identity.is_interactive() || identity.session_id() != session {
        return Err(ServiceAuthorizationError::ConsoleChanged);
    }
    Ok(identity)
}

fn require_active(session: u32) -> Result<(), ServiceAuthorizationError> {
    let mut raw = null_mut();
    let mut size = 0;
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSConnectState,
            &mut raw,
            &mut size,
        )
    } == 0
    {
        return Err(native("query console session state"));
    }
    struct Buffer(*mut u16);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
    let buffer = Buffer(raw);
    if buffer.0.is_null() || size as usize != size_of::<WTS_CONNECTSTATE_CLASS>() {
        return Err(PeerIdentityError::InvalidIdentity.into());
    }
    let state = unsafe { buffer.0.cast::<WTS_CONNECTSTATE_CLASS>().read_unaligned() };
    if state != WTSActive {
        return Err(ServiceAuthorizationError::NoActiveConsole);
    }
    Ok(())
}

/// Selected by the trusted dispatcher for its method, never by a wire field.
/// Only connection/bound-lease observation can use OwnedLeaseOrNone. Starting,
/// readiness, renewal and cleanup acknowledgements require the owned lease.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserAgentLeaseRequirement {
    OwnedLease,
    OwnedLeaseOrNone,
}

/// One observed request, with a retained process object. This is peer admission,
/// not a reusable runtime permit. The authority must serialize lease mutation,
/// validate the command/context and supervise subsequent owner/session loss.
pub struct ServicePeerAuthorization {
    request: AuthenticatedServiceRequest,
    process: NativePeerProcess,
}
impl ServicePeerAuthorization {
    pub fn request(&self) -> &AuthenticatedServiceRequest {
        &self.request
    }
    pub fn process(&self) -> &NativePeerProcess {
        &self.process
    }
    pub fn owner(&self) -> &NativeUserSession {
        self.process.identity().user_session()
    }
}

/// Call under the authority's lifecycle/lease guard immediately before dispatch.
/// WTS observation can block on the native session service; a late observation
/// is rejected by the deadline. Failure closes this message connection.
pub fn authorize_service_request(
    connection: &mut LocalServiceConnection,
    request: AuthenticatedServiceRequest,
    lease_owner: Option<&NativeUserSession>,
    agent_requirement: UserAgentLeaseRequirement,
    deadline: Instant,
) -> Result<ServicePeerAuthorization, ServiceAuthorizationError> {
    let result = (|| {
        check_deadline(deadline)?;
        let console = LiveConsoleSession::observe()?;
        authorize_identity(
            request.role(),
            request.identity().user_session(),
            console.identity(),
            lease_owner,
            agent_requirement,
        )?;
        // Session queries may outlast or race the original peer observation.
        // Revalidate this exact pending request/image before retaining its peer.
        let process = connection.retain_request_peer(&request, deadline)?;
        Ok(ServicePeerAuthorization { request, process })
    })();
    if result.is_err() {
        connection.close();
    }
    result
}

fn authorize_identity(
    role: ServiceClientRole,
    peer: &NativeUserSession,
    console: &NativeUserSession,
    lease_owner: Option<&NativeUserSession>,
    agent_requirement: UserAgentLeaseRequirement,
) -> Result<(), ServiceAuthorizationError> {
    if !console.is_interactive() || peer != console {
        return Err(ServiceAuthorizationError::NotConsoleOwner);
    }
    if role == ServiceClientRole::UserAgent {
        match lease_owner {
            Some(owner) if owner != peer => {
                return Err(ServiceAuthorizationError::LeaseOwnerMismatch);
            }
            None if agent_requirement == UserAgentLeaseRequirement::OwnedLease => {
                return Err(ServiceAuthorizationError::LeaseRequired);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
