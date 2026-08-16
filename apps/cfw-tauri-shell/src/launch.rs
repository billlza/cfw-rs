use std::ffi::OsString;

use crate::legacy::{LaunchArguments, parse_launch_arguments};

#[cfg(feature = "physical-release-evidence")]
pub(crate) const PACKET_EVIDENCE_FLAG: &str = "--physical-packet-evidence-v5";

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LaunchMode {
    Dashboard,
    MigrationHandoff {
        token: String,
    },
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
            #[cfg(feature = "physical-release-evidence")]
            Self::PacketEvidence => formatter.write_str("PacketEvidence"),
        }
    }
}

pub(crate) fn parse_launch_mode(arguments: &[OsString]) -> Result<LaunchMode, String> {
    if arguments.is_empty() {
        return Ok(LaunchMode::Dashboard);
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
        ] {
            assert!(parse_launch_mode(&invalid).is_err());
        }
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
