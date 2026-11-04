//! The engine mode, profile and settings a packet evidence case is tested
//! with.

use super::*;

pub(super) struct PacketTestPlan {
    pub(super) mode: EngineMode,
    pub(super) profile_id: &'static str,
    pub(super) profile: ValidatedSingBoxProfile,
    pub(super) settings: EngineSettings,
    pub(super) expected_digest: Option<String>,
}

impl PacketTestPlan {
    pub(super) fn matches(
        &self,
        baseline: &PacketEvidenceSnapshotReceipt,
        test: &PacketEvidenceSnapshotReceipt,
    ) -> bool {
        test.desired_mode() == self.mode
            && test.generation() > baseline.generation()
            && test.config_digest() == self.expected_digest.as_deref()
            && test.config_digest() != baseline.config_digest()
            && test.ipv6_enabled() == self.settings.enable_ipv6
            && match self.mode {
                EngineMode::Off => {
                    test.phase() == PacketEvidencePhase::Off
                        && test.owner().is_none()
                        && !test.ready()
                }
                EngineMode::Tunnel => {
                    test.phase() == PacketEvidencePhase::TunnelActive
                        && test.owner() == Some(EngineOwner::PacketTunnelSystemExtension)
                        && test.ready()
                }
                EngineMode::LocalProxy
                | EngineMode::SystemProxy
                | EngineMode::TunnelSystemProxy => false,
            }
    }
}

pub(super) fn test_plan(
    case: ReleasePacketEvidenceCase,
    baseline: &EngineRestartSpec,
) -> Result<PacketTestPlan, ConfigError> {
    let profile_id = profile_id(case);
    let profile = ValidatedSingBoxProfile::release_packet_evidence(case);
    let mut settings = baseline.settings().clone();
    let mode = if case == ReleasePacketEvidenceCase::StopCleanup {
        settings.enable_ipv6 = false;
        EngineMode::Off
    } else {
        if case == ReleasePacketEvidenceCase::Ipv6DisabledAbsence {
            settings.enable_ipv6 = false;
        }
        EngineMode::Tunnel
    };
    let expected_digest = match mode {
        EngineMode::Off => None,
        EngineMode::Tunnel => Some(
            profile
                .project(profile_id, ProjectionMode::Tunnel, &settings)?
                .digest()
                .to_owned(),
        ),
        EngineMode::LocalProxy | EngineMode::SystemProxy | EngineMode::TunnelSystemProxy => {
            unreachable!("Packet evidence only uses pure TUN or Off")
        }
    };
    Ok(PacketTestPlan {
        mode,
        profile_id,
        profile,
        settings,
        expected_digest,
    })
}

pub(super) fn profile_id(case: ReleasePacketEvidenceCase) -> &'static str {
    match case {
        ReleasePacketEvidenceCase::TcpIpv4 => "f1300001-0000-4000-8000-000000000001",
        ReleasePacketEvidenceCase::TcpIpv6 => "f1300001-0000-4000-8000-000000000002",
        ReleasePacketEvidenceCase::Udp => "f1300001-0000-4000-8000-000000000003",
        ReleasePacketEvidenceCase::Quic => "f1300001-0000-4000-8000-000000000004",
        ReleasePacketEvidenceCase::DnsAPrimary => "f1300001-0000-4000-8000-000000000005",
        ReleasePacketEvidenceCase::DnsASecondary => "f1300001-0000-4000-8000-000000000006",
        ReleasePacketEvidenceCase::DnsAaaaPrimary => "f1300001-0000-4000-8000-000000000007",
        ReleasePacketEvidenceCase::DnsAaaaSecondary => "f1300001-0000-4000-8000-000000000008",
        ReleasePacketEvidenceCase::LanBypass => "f1300001-0000-4000-8000-000000000009",
        ReleasePacketEvidenceCase::IncludedRoutes => "f1300001-0000-4000-8000-00000000000a",
        ReleasePacketEvidenceCase::ExcludedRoutes => "f1300001-0000-4000-8000-00000000000b",
        ReleasePacketEvidenceCase::StopCleanup => "f1300001-0000-4000-8000-00000000000c",
        ReleasePacketEvidenceCase::Ipv6DisabledAbsence => "f1300001-0000-4000-8000-00000000000d",
    }
}
