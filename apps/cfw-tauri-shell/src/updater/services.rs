//! The installed application's background services, observed and unregistered
//! through the Host's own maintenance modes: the entry points the release
//! tooling uses to make an installation dormant before it is replaced.

use std::time::Duration;

use cfw_engine_api::{
    NativeServiceMaintenanceAction, NativeServiceMaintenanceResult, NativeServiceRegistrationStatus,
};
use cfw_platform::run_installed_host;
use thiserror::Error;

use super::error::FailureCategory;
use crate::launch::SERVICE_MAINTENANCE_FLAG;
use crate::service_maintenance::MaintenanceReceipt;

const STATUS: &str = "status";
const UNREGISTER_PROXY_AGENT: &str = "unregister-proxy-agent";
const UNREGISTER_GLOBAL_AUTHORITY: &str = "unregister-global-authority";
/// The native bridge bounds one maintenance action at 55 s; the child also
/// needs to start and to report.
const MAINTENANCE_TIMEOUT: Duration = Duration::from_secs(70);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServicePair {
    pub(super) proxy_agent: NativeServiceRegistrationStatus,
    pub(super) global_authority: NativeServiceRegistrationStatus,
}

impl ServicePair {
    /// Neither service is registered: there is nothing to unregister.
    pub(super) fn dormant(self) -> bool {
        use NativeServiceRegistrationStatus::NotRegistered;
        self.proxy_agent == NotRegistered && self.global_authority == NotRegistered
    }

    /// Whether the maintenance modes can bring both services to
    /// NotRegistered. Unregistering needs the authority enabled, because it
    /// is the authority that proves the engine Off.
    pub(super) fn removable(self) -> bool {
        use NativeServiceRegistrationStatus::{Enabled, NotRegistered};
        self.dormant()
            || (self.global_authority == Enabled
                && matches!(self.proxy_agent, Enabled | NotRegistered))
    }
}

/// Why an installation is refused before anything is stopped.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ServiceStateError {
    #[error("the registration of the background services could not be read: {0}")]
    Unavailable(String),
    #[error("the background services cannot be unregistered from their state: {0:?}")]
    NotRemovable(ServicePair),
}

impl ServiceStateError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "service_status_unavailable",
            Self::NotRemovable(_) => "services_not_in_a_removable_state",
        }
    }

    pub(super) const fn category(&self) -> FailureCategory {
        match self {
            Self::Unavailable(_) => FailureCategory::Internal,
            Self::NotRemovable(_) => FailureCategory::Environment,
        }
    }
}

/// Refuses an installation the installer process would have to abort after
/// the core was already stopped. The installer decides again from its own
/// observation; this only spares the user a pointless interruption.
pub(super) fn require_removable_services() -> Result<(), ServiceStateError> {
    let pair = status().map_err(ServiceStateError::Unavailable)?;
    if pair.removable() {
        Ok(())
    } else {
        Err(ServiceStateError::NotRemovable(pair))
    }
}

pub(super) fn status() -> Result<ServicePair, String> {
    let result = run(STATUS, NativeServiceMaintenanceAction::Status)?;
    Ok(ServicePair {
        proxy_agent: result.proxy_agent,
        global_authority: result.global_authority,
    })
}

pub(super) fn unregister_proxy_agent() -> Result<(), String> {
    run(
        UNREGISTER_PROXY_AGENT,
        NativeServiceMaintenanceAction::UnregisterProxyAgent,
    )
    .map(|_| ())
}

pub(super) fn unregister_global_authority() -> Result<(), String> {
    run(
        UNREGISTER_GLOBAL_AUTHORITY,
        NativeServiceMaintenanceAction::UnregisterGlobalAuthority,
    )
    .map(|_| ())
}

/// Runs one maintenance mode of the installed Host in its own process and
/// accepts only the receipt that proves the action's postcondition.
fn run(
    argument: &'static str,
    action: NativeServiceMaintenanceAction,
) -> Result<NativeServiceMaintenanceResult, String> {
    let output = run_installed_host(&[SERVICE_MAINTENANCE_FLAG, argument], MAINTENANCE_TIMEOUT)
        .map_err(|error| format!("service maintenance {argument} failed: {error}"))?;
    MaintenanceReceipt::proven(&output.stdout, action).map_err(|error| {
        format!("service maintenance {argument} returned an unusable receipt: {error}")
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::launch::{LaunchMode, ServiceMaintenanceAction, parse_launch_mode};

    #[test]
    fn each_mode_is_an_argument_the_host_parses_as_exactly_that_action() {
        for (argument, action) in [
            (STATUS, ServiceMaintenanceAction::Status),
            (
                UNREGISTER_PROXY_AGENT,
                ServiceMaintenanceAction::UnregisterProxyAgent,
            ),
            (
                UNREGISTER_GLOBAL_AUTHORITY,
                ServiceMaintenanceAction::UnregisterGlobalAuthority,
            ),
        ] {
            let arguments = [SERVICE_MAINTENANCE_FLAG, argument].map(OsString::from);
            assert_eq!(
                parse_launch_mode(&arguments),
                Ok(LaunchMode::ServiceMaintenance(action)),
                "{argument}"
            );
        }
    }

    #[test]
    fn only_states_the_maintenance_modes_can_unwind_are_removable() {
        use NativeServiceRegistrationStatus::{
            Enabled, NotFound, NotRegistered, RequiresApproval, Unknown,
        };
        let pair = |proxy_agent, global_authority| ServicePair {
            proxy_agent,
            global_authority,
        };

        assert!(pair(NotRegistered, NotRegistered).dormant());
        for removable in [
            pair(NotRegistered, NotRegistered),
            pair(Enabled, Enabled),
            pair(NotRegistered, Enabled),
        ] {
            assert!(removable.removable(), "{removable:?}");
        }
        for stuck in [
            pair(Enabled, NotRegistered),
            pair(Enabled, RequiresApproval),
            pair(NotRegistered, RequiresApproval),
            pair(RequiresApproval, Enabled),
            pair(NotFound, Enabled),
            pair(Unknown, Unknown),
        ] {
            assert!(!stuck.removable(), "{stuck:?}");
            assert!(!stuck.dormant(), "{stuck:?}");
        }
    }
}
