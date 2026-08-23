use std::ffi::OsString;

use crate::legacy::{LaunchArguments, parse_launch_arguments};

pub(crate) const STARTUP_USAGE_EXIT_CODE: i32 = 64;
pub(crate) const STARTUP_ADMISSION_EXIT_CODE: i32 = 78;
pub(crate) const SERVICE_MAINTENANCE_FLAG: &str = "--service-maintenance-v2";

#[cfg(feature = "physical-release-evidence")]
pub(crate) const PACKET_EVIDENCE_FLAG: &str = "--physical-packet-evidence-v5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceMaintenanceAction {
    ProveOff,
    ProveInstalled40019Off,
    Status,
    UnregisterProxyAgent,
    UnregisterInstalled40019ProxyAgent,
    UnregisterGlobalAuthority,
    UnregisterInstalled40019GlobalAuthority,
    RecoverInstalled40019GlobalAuthority,
    RegisterGlobalAuthority,
    RegisterProxyAgent,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LaunchMode {
    Dashboard,
    MigrationHandoff {
        token: String,
    },
    ServiceMaintenance(ServiceMaintenanceAction),
    #[cfg(feature = "physical-release-evidence")]
    PacketEvidence,
}

impl std::fmt::Debug for LaunchMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dashboard => formatter.write_str("Dashboard"),
            Self::MigrationHandoff { .. } => formatter
                .debug_struct("MigrationHandoff")
                .field("token", &"[redacted]")
                .finish(),
            Self::ServiceMaintenance(action) => formatter
                .debug_tuple("ServiceMaintenance")
                .field(action)
                .finish(),
            #[cfg(feature = "physical-release-evidence")]
            Self::PacketEvidence => formatter.write_str("PacketEvidence"),
        }
    }
}

pub(crate) fn parse_launch_mode(arguments: &[OsString]) -> Result<LaunchMode, String> {
    if arguments.is_empty() {
        return Ok(LaunchMode::Dashboard);
    }
    if let [flag, action] = arguments
        && flag == SERVICE_MAINTENANCE_FLAG
    {
        let action = match action.to_str() {
            Some("prove-off") => ServiceMaintenanceAction::ProveOff,
            Some("prove-installed-40019-off") => ServiceMaintenanceAction::ProveInstalled40019Off,
            Some("status") => ServiceMaintenanceAction::Status,
            Some("unregister-proxy-agent") => ServiceMaintenanceAction::UnregisterProxyAgent,
            Some("unregister-installed-40019-proxy-agent") => {
                ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent
            }
            Some("unregister-global-authority") => {
                ServiceMaintenanceAction::UnregisterGlobalAuthority
            }
            Some("unregister-installed-40019-global-authority") => {
                ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority
            }
            Some("recover-installed-40019-global-authority") => {
                ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority
            }
            Some("register-global-authority") => ServiceMaintenanceAction::RegisterGlobalAuthority,
            Some("register-proxy-agent") => ServiceMaintenanceAction::RegisterProxyAgent,
            _ => return Err("service maintenance action is not one fixed v2 operation".into()),
        };
        return Ok(LaunchMode::ServiceMaintenance(action));
    }
    #[cfg(feature = "physical-release-evidence")]
    if arguments == [OsString::from(PACKET_EVIDENCE_FLAG)] {
        return Ok(LaunchMode::PacketEvidence);
    }
    match parse_launch_arguments(arguments)? {
        LaunchArguments::MigrationHandoff { token } => Ok(LaunchMode::MigrationHandoff { token }),
        LaunchArguments::Dashboard => {
            Err("startup arguments are not a supported exact mode".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_modes_are_closed_and_unknown_arguments_never_become_dashboard() {
        assert_eq!(
            parse_launch_mode(&[]).expect("dashboard"),
            LaunchMode::Dashboard
        );
        for invalid in [
            vec![OsString::from("--unknown")],
            vec![OsString::from("profile.json")],
            vec![OsString::from("--migration-handoff")],
            vec![OsString::from(SERVICE_MAINTENANCE_FLAG)],
            vec![
                OsString::from(SERVICE_MAINTENANCE_FLAG),
                OsString::from("unknown"),
            ],
        ] {
            assert!(parse_launch_mode(&invalid).is_err());
        }
    }

    #[test]
    fn service_maintenance_modes_are_exact_and_closed() {
        let cases = [
            ("prove-off", ServiceMaintenanceAction::ProveOff),
            (
                "prove-installed-40019-off",
                ServiceMaintenanceAction::ProveInstalled40019Off,
            ),
            ("status", ServiceMaintenanceAction::Status),
            (
                "unregister-proxy-agent",
                ServiceMaintenanceAction::UnregisterProxyAgent,
            ),
            (
                "unregister-installed-40019-proxy-agent",
                ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent,
            ),
            (
                "unregister-global-authority",
                ServiceMaintenanceAction::UnregisterGlobalAuthority,
            ),
            (
                "unregister-installed-40019-global-authority",
                ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority,
            ),
            (
                "recover-installed-40019-global-authority",
                ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority,
            ),
            (
                "register-global-authority",
                ServiceMaintenanceAction::RegisterGlobalAuthority,
            ),
            (
                "register-proxy-agent",
                ServiceMaintenanceAction::RegisterProxyAgent,
            ),
        ];
        for (argument, expected) in cases {
            assert_eq!(
                parse_launch_mode(&[
                    OsString::from(SERVICE_MAINTENANCE_FLAG),
                    OsString::from(argument),
                ])
                .expect("fixed maintenance mode"),
                LaunchMode::ServiceMaintenance(expected)
            );
        }
        assert!(
            parse_launch_mode(&[
                OsString::from(SERVICE_MAINTENANCE_FLAG),
                OsString::from("status"),
                OsString::from("extra"),
            ])
            .is_err()
        );
    }

    #[cfg(feature = "physical-release-evidence")]
    #[test]
    fn packet_evidence_mode_has_one_exact_secret_free_shape() {
        assert_eq!(
            parse_launch_mode(&[OsString::from(PACKET_EVIDENCE_FLAG)]).expect("packet"),
            LaunchMode::PacketEvidence,
        );
        assert!(
            parse_launch_mode(&[
                OsString::from(PACKET_EVIDENCE_FLAG),
                OsString::from("--extra"),
            ])
            .is_err()
        );
    }
}
