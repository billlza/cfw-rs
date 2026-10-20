use std::ffi::OsString;

#[cfg(target_os = "macos")]
use crate::legacy::{LaunchArguments, parse_launch_arguments};

pub(crate) const STARTUP_USAGE_EXIT_CODE: i32 = 64;
pub(crate) const STARTUP_ADMISSION_EXIT_CODE: i32 = 78;
#[cfg(target_os = "macos")]
use crate::service_maintenance::SERVICE_MAINTENANCE_FLAG;
pub(crate) const FINISH_UPDATE_FLAG: &str = "--finish-update-v1";

#[cfg(all(target_os = "macos", feature = "physical-release-evidence"))]
pub(crate) const PACKET_EVIDENCE_FLAG: &str = "--physical-packet-evidence-v5";

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceMaintenanceAction {
    ProveOff,
    ProveInstalled40019Off,
    Status,
    RetireOrphanedServices,
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
    #[cfg(target_os = "macos")]
    MigrationHandoff {
        token: String,
    },
    #[cfg(target_os = "macos")]
    ServiceMaintenance(ServiceMaintenanceAction),
    /// The installer process of one recorded update transaction.
    FinishUpdate {
        transaction: String,
    },
    #[cfg(all(target_os = "macos", feature = "physical-release-evidence"))]
    PacketEvidence,
}

impl std::fmt::Debug for LaunchMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dashboard => formatter.write_str("Dashboard"),
            #[cfg(target_os = "macos")]
            Self::MigrationHandoff { .. } => formatter
                .debug_struct("MigrationHandoff")
                .field("token", &"[redacted]")
                .finish(),
            #[cfg(target_os = "macos")]
            Self::ServiceMaintenance(action) => formatter
                .debug_tuple("ServiceMaintenance")
                .field(action)
                .finish(),
            Self::FinishUpdate { transaction } => formatter
                .debug_struct("FinishUpdate")
                .field("transaction", transaction)
                .finish(),
            #[cfg(all(target_os = "macos", feature = "physical-release-evidence"))]
            Self::PacketEvidence => formatter.write_str("PacketEvidence"),
        }
    }
}

pub(crate) fn parse_launch_mode(arguments: &[OsString]) -> Result<LaunchMode, String> {
    if arguments.is_empty() {
        return Ok(LaunchMode::Dashboard);
    }
    #[cfg(target_os = "macos")]
    if let [flag, action] = arguments
        && flag == SERVICE_MAINTENANCE_FLAG
    {
        let action = match action.to_str() {
            Some("prove-off") => ServiceMaintenanceAction::ProveOff,
            Some("prove-installed-40019-off") => ServiceMaintenanceAction::ProveInstalled40019Off,
            Some("status") => ServiceMaintenanceAction::Status,
            Some("retire-orphaned-services") => ServiceMaintenanceAction::RetireOrphanedServices,
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
    if let [flag, transaction] = arguments
        && flag == FINISH_UPDATE_FLAG
    {
        let transaction = transaction
            .to_str()
            .ok_or_else(|| "update installer transaction is not UTF-8".to_owned())?;
        return Ok(LaunchMode::FinishUpdate {
            transaction: transaction.to_owned(),
        });
    }
    #[cfg(all(target_os = "macos", feature = "physical-release-evidence"))]
    if arguments == [OsString::from(PACKET_EVIDENCE_FLAG)] {
        return Ok(LaunchMode::PacketEvidence);
    }
    #[cfg(target_os = "macos")]
    {
        match parse_launch_arguments(arguments)? {
            LaunchArguments::MigrationHandoff { token } => {
                Ok(LaunchMode::MigrationHandoff { token })
            }
            LaunchArguments::Dashboard => {
                Err("startup arguments are not a supported exact mode".into())
            }
        }
    }
    #[cfg(windows)]
    {
        // Windows 0.5 is the first release of this implementation. CFM's
        // historical migration and Apple service commands carry no Windows
        // authority and must fail before startup performs any I/O.
        Err("startup arguments are not a supported exact Windows mode".into())
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
            vec![OsString::from("--service-maintenance-v2")],
            vec![
                OsString::from("--service-maintenance-v2"),
                OsString::from("unknown"),
            ],
        ] {
            assert!(parse_launch_mode(&invalid).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn service_maintenance_modes_are_exact_and_closed() {
        let cases = [
            (
                "retire-orphaned-services",
                ServiceMaintenanceAction::RetireOrphanedServices,
            ),
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

    #[test]
    fn update_installer_mode_takes_exactly_one_transaction() {
        let flag = OsString::from(FINISH_UPDATE_FLAG);
        assert_eq!(
            parse_launch_mode(&[
                flag.clone(),
                OsString::from("00000000-0000-4000-8000-000000000001"),
            ])
            .expect("installer mode"),
            LaunchMode::FinishUpdate {
                transaction: "00000000-0000-4000-8000-000000000001".into(),
            }
        );
        assert!(parse_launch_mode(std::slice::from_ref(&flag)).is_err());
        assert!(parse_launch_mode(&[flag, OsString::from("one"), OsString::from("two")]).is_err());
    }

    #[cfg(all(target_os = "macos", feature = "physical-release-evidence"))]
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

    #[cfg(windows)]
    #[test]
    fn windows_rejects_every_apple_service_action_and_migration_handoff() {
        for action in [
            "prove-off",
            "prove-installed-40019-off",
            "status",
            "retire-orphaned-services",
            "unregister-proxy-agent",
            "unregister-installed-40019-proxy-agent",
            "unregister-global-authority",
            "unregister-installed-40019-global-authority",
            "recover-installed-40019-global-authority",
            "register-global-authority",
            "register-proxy-agent",
        ] {
            assert!(
                parse_launch_mode(&[
                    OsString::from("--service-maintenance-v2"),
                    OsString::from(action),
                ])
                .is_err(),
                "{action}"
            );
        }
        for arguments in [
            vec![
                OsString::from("--migration-handoff"),
                OsString::from("--migration-ticket"),
                OsString::from("00000000-0000-4000-8000-000000000001"),
            ],
            vec![OsString::from("--physical-packet-evidence-v5")],
        ] {
            assert!(parse_launch_mode(&arguments).is_err());
        }
        assert_ne!(STARTUP_USAGE_EXIT_CODE, 0);
        assert_ne!(STARTUP_ADMISSION_EXIT_CODE, 0);
        assert_ne!(STARTUP_USAGE_EXIT_CODE, STARTUP_ADMISSION_EXIT_CODE);
    }

    #[cfg(windows)]
    #[test]
    fn windows_non_unicode_arguments_never_become_dashboard_or_update_authority() {
        use std::os::windows::ffi::OsStringExt;
        let unpaired_surrogate = OsString::from_wide(&[0xd800]);
        assert!(parse_launch_mode(std::slice::from_ref(&unpaired_surrogate)).is_err());
        assert!(
            parse_launch_mode(&[OsString::from(FINISH_UPDATE_FLAG), unpaired_surrogate]).is_err()
        );
    }
}
