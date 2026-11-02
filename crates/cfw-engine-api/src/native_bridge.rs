//! Commands, results and envelopes of the Rust/Swift host bridge.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    BackendErrorKind, CredentialGarbageCollectionCommitRequest, CredentialGarbageCollectionPreview,
    CredentialGarbageCollectionReceipt, CredentialGarbageCollectionRequest, CredentialPresence,
    CredentialPresenceWireRequest, CredentialRebindRequest, CredentialVaultReceipt,
    CutoverPreflightOutcome, CutoverPreflightRequest, ENGINE_PROTOCOL_VERSION,
    EngineCommandContext, EngineStartRequest, NativeEngineStatus, NativeServiceMaintenanceAction,
    NativeServiceMaintenanceResult, ProfileDelayTestRequest, ProfileProxyDelay, RuntimeIdentity,
    TunnelApprovalWait, TunnelInstallOutcome,
};

/// Versioned command sent over the narrow Rust/Swift host boundary.
///
/// This is the only product-level native wire command. Swift maps it onto the
/// already-versioned ProxyAgent and Packet Tunnel command envelopes; it does
/// not expose an independent product state machine.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "opcode", content = "payload", rename_all = "snake_case")]
pub enum NativeBridgeCommand {
    QueryStatus,
    CheckConfiguration {
        request: EngineStartRequest,
    },
    AuthorizeSystemProxy,
    AuthorizeSystemProxyRestoration,
    StartLocalProxy {
        request: EngineStartRequest,
    },
    StopLocalProxy {
        context: EngineCommandContext,
    },
    MaintainCurrentServices {
        action: NativeServiceMaintenanceAction,
    },
    StartSystemProxy {
        request: EngineStartRequest,
    },
    StopSystemProxy {
        context: EngineCommandContext,
    },
    InstallTunnel {
        context: EngineCommandContext,
    },
    AwaitTunnelApproval {
        context: EngineCommandContext,
    },
    CancelTunnelInstall {
        context: EngineCommandContext,
    },
    AuthorizeTunnelConfiguration {
        request: EngineStartRequest,
    },
    StartTunnel {
        request: EngineStartRequest,
    },
    StopTunnel {
        context: EngineCommandContext,
    },
    QueryCredentialPresence {
        request: CredentialPresenceWireRequest,
    },
    RebindProfileCredentials {
        request: CredentialRebindRequest,
    },
    PreflightCutover {
        request: Box<CutoverPreflightRequest>,
    },
    TestProfileDelays {
        request: ProfileDelayTestRequest,
    },
    PreviewCredentialGarbageCollection {
        request: CredentialGarbageCollectionRequest,
    },
    CommitCredentialGarbageCollection {
        request: CredentialGarbageCollectionCommitRequest,
    },
}

impl fmt::Debug for NativeBridgeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryStatus => formatter.write_str("QueryStatus"),
            Self::CheckConfiguration { request } => formatter
                .debug_struct("CheckConfiguration")
                .field("request", request)
                .finish(),
            Self::StartLocalProxy { request } => formatter
                .debug_struct("StartLocalProxy")
                .field("request", request)
                .finish(),
            Self::StopLocalProxy { context } => formatter
                .debug_struct("StopLocalProxy")
                .field("context", context)
                .finish(),
            Self::AuthorizeSystemProxy => formatter.write_str("AuthorizeSystemProxy"),
            Self::AuthorizeSystemProxyRestoration => {
                formatter.write_str("AuthorizeSystemProxyRestoration")
            }
            Self::MaintainCurrentServices { action } => formatter
                .debug_struct("MaintainCurrentServices")
                .field("action", action)
                .finish(),
            Self::StartSystemProxy { request } => formatter
                .debug_struct("StartSystemProxy")
                .field("request", request)
                .finish(),
            Self::StopSystemProxy { context } => formatter
                .debug_struct("StopSystemProxy")
                .field("context", context)
                .finish(),
            Self::InstallTunnel { context } => formatter
                .debug_struct("InstallTunnel")
                .field("context", context)
                .finish(),
            Self::AwaitTunnelApproval { context } => formatter
                .debug_struct("AwaitTunnelApproval")
                .field("context", context)
                .finish(),
            Self::CancelTunnelInstall { context } => formatter
                .debug_struct("CancelTunnelInstall")
                .field("context", context)
                .finish(),
            Self::AuthorizeTunnelConfiguration { request } => formatter
                .debug_struct("AuthorizeTunnelConfiguration")
                .field("request", request)
                .finish(),
            Self::StartTunnel { request } => formatter
                .debug_struct("StartTunnel")
                .field("request", request)
                .finish(),
            Self::StopTunnel { context } => formatter
                .debug_struct("StopTunnel")
                .field("context", context)
                .finish(),
            Self::QueryCredentialPresence { request } => formatter
                .debug_struct("QueryCredentialPresence")
                .field("request", request)
                .finish(),
            Self::RebindProfileCredentials { request } => formatter
                .debug_struct("RebindProfileCredentials")
                .field("request", request)
                .finish(),
            Self::TestProfileDelays { request } => formatter
                .debug_struct("TestProfileDelays")
                .field("request", request)
                .finish(),
            Self::PreflightCutover { request } => formatter
                .debug_struct("PreflightCutover")
                .field("request", request)
                .finish(),
            Self::PreviewCredentialGarbageCollection { request } => formatter
                .debug_struct("PreviewCredentialGarbageCollection")
                .field("request", request)
                .finish(),
            Self::CommitCredentialGarbageCollection { request } => formatter
                .debug_struct("CommitCredentialGarbageCollection")
                .field("request", request)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRequestEnvelope {
    pub schema_version: u16,
    pub request_id: uuid::Uuid,
    pub command: NativeBridgeCommand,
}

impl NativeRequestEnvelope {
    pub fn new(command: NativeBridgeCommand) -> Self {
        Self {
            schema_version: ENGINE_PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4(),
            command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NativeBridgeResult {
    Status(NativeEngineStatus),
    Runtime(RuntimeIdentity),
    TunnelInstall(TunnelInstallOutcome),
    TunnelApproval(TunnelApprovalWait),
    Acknowledged,
    CredentialReceipt(CredentialVaultReceipt),
    CredentialPresence(Vec<CredentialPresence>),
    CredentialGarbageCollectionPreview(CredentialGarbageCollectionPreview),
    CredentialGarbageCollectionReceipt(CredentialGarbageCollectionReceipt),
    CutoverPreflight(CutoverPreflightOutcome),
    ServiceMaintenance(NativeServiceMaintenanceResult),
    ProfileDelays(Vec<ProfileProxyDelay>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBridgeFailure {
    pub code: BackendErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeResponseEnvelope {
    pub schema_version: u16,
    pub request_id: Option<uuid::Uuid>,
    pub result: Option<NativeBridgeResult>,
    pub failure: Option<NativeBridgeFailure>,
}

#[cfg(test)]
mod tests;
