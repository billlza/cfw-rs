//! How long one native command may run: the operation and authorization
//! budgets, the cleanup grace and the outer watchdog the C header shares.

use std::time::Duration;

use cfw_engine_api::NativeBridgeCommand;

const NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS: u64 = 30_000;
pub(crate) const NATIVE_BRIDGE_AUTHORIZATION_BUDGET_MILLISECONDS: u64 = 300_000;
const NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS: u64 = 20_000;

/// Commands that wait for a person to answer macOS get the authorization
/// budget; every other command gets the operation budget.
pub(crate) fn waits_for_person(command: &NativeBridgeCommand) -> bool {
    match command {
        NativeBridgeCommand::AuthorizeSystemProxy
        | NativeBridgeCommand::AuthorizeSystemProxyRestoration
        | NativeBridgeCommand::AuthorizeTunnelConfiguration { .. }
        | NativeBridgeCommand::AwaitTunnelApproval { .. } => true,
        NativeBridgeCommand::QueryStatus
        | NativeBridgeCommand::CheckConfiguration { .. }
        | NativeBridgeCommand::StartLocalProxy { .. }
        | NativeBridgeCommand::StopLocalProxy { .. }
        | NativeBridgeCommand::MaintainCurrentServices { .. }
        | NativeBridgeCommand::StartSystemProxy { .. }
        | NativeBridgeCommand::StopSystemProxy { .. }
        | NativeBridgeCommand::InstallTunnel { .. }
        | NativeBridgeCommand::CancelTunnelInstall { .. }
        | NativeBridgeCommand::StartTunnel { .. }
        | NativeBridgeCommand::StopTunnel { .. }
        | NativeBridgeCommand::QueryCredentialPresence { .. }
        | NativeBridgeCommand::RebindProfileCredentials { .. }
        | NativeBridgeCommand::PreflightCutover { .. }
        | NativeBridgeCommand::TestProfileDelays { .. }
        | NativeBridgeCommand::PreviewCredentialGarbageCollection { .. }
        | NativeBridgeCommand::CommitCredentialGarbageCollection { .. } => false,
    }
}

const NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS: u64 = 55_000;

const _: () = assert!(
    NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS
        > NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS + NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS
);

const NATIVE_BRIDGE_OPERATION_BUDGET: Duration =
    Duration::from_millis(NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS);
pub(crate) const NATIVE_BRIDGE_CLEANUP_GRACE: Duration =
    Duration::from_millis(NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS);
pub const NATIVE_BRIDGE_OUTER_WATCHDOG: Duration =
    Duration::from_millis(NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS);

#[derive(Clone, Copy)]
pub(crate) struct InvocationTiming {
    pub(super) operation_budget: Duration,
    pub(super) cleanup_grace: Duration,
}

impl InvocationTiming {
    pub(super) const PRODUCTION: Self = Self {
        operation_budget: NATIVE_BRIDGE_OPERATION_BUDGET,
        cleanup_grace: NATIVE_BRIDGE_CLEANUP_GRACE,
    };
}

#[cfg(test)]
mod tests;
