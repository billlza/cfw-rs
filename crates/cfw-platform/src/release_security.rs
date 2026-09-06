use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::bounded_command::{BoundedCommandError, BoundedCommandOutput, run_bounded_command};

const CODESIGN: &str = "/usr/bin/codesign";
const SPCTL: &str = "/usr/sbin/spctl";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseSignedComponent {
    Application,
    MainExecutable,
    NativeBridge,
    GlobalAuthority,
    ProxyAgent,
    PacketTunnel,
    LegacyHelperTombstone,
}

impl ReleaseSignedComponent {
    pub const NESTED: [Self; 6] = [
        Self::MainExecutable,
        Self::NativeBridge,
        Self::GlobalAuthority,
        Self::ProxyAgent,
        Self::PacketTunnel,
        Self::LegacyHelperTombstone,
    ];

    pub fn path(self) -> &'static Path {
        Path::new(match self {
            Self::Application => "/Applications/Clash for Mac.app",
            Self::MainExecutable => "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
            Self::NativeBridge => {
                "/Applications/Clash for Mac.app/Contents/Frameworks/CFWNativeBridge.framework"
            }
            Self::GlobalAuthority => {
                "/Applications/Clash for Mac.app/Contents/Library/HelperTools/CFWGlobalAuthority"
            }
            Self::ProxyAgent => {
                "/Applications/Clash for Mac.app/Contents/Library/LoginItems/CFWProxyAgent.app"
            }
            Self::PacketTunnel => {
                "/Applications/Clash for Mac.app/Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension"
            }
            Self::LegacyHelperTombstone => {
                "/Applications/Clash for Mac.app/Contents/Library/HelperTools/cfw-helper-tombstone"
            }
        })
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Application => "application bundle",
            Self::MainExecutable => "Contents/MacOS/clash-for-mac",
            Self::NativeBridge => "Contents/Frameworks/CFWNativeBridge.framework",
            Self::GlobalAuthority => "Contents/Library/HelperTools/CFWGlobalAuthority",
            Self::ProxyAgent => "Contents/Library/LoginItems/CFWProxyAgent.app",
            Self::PacketTunnel => {
                "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension"
            }
            Self::LegacyHelperTombstone => "Contents/Library/HelperTools/cfw-helper-tombstone",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSecurityCommandOutput {
    success: bool,
    combined: String,
}

impl ReleaseSecurityCommandOutput {
    pub const fn success(&self) -> bool {
        self.success
    }

    pub fn combined(&self) -> &str {
        &self.combined
    }
}

pub fn verify_release_signature(
    component: ReleaseSignedComponent,
) -> Result<ReleaseSecurityCommandOutput> {
    let path = component.path().to_str().expect("fixed path is UTF-8");
    run_security_command(
        "code signature verification",
        CODESIGN,
        &["--verify", "--strict", "--verbose=4", path],
    )
}

pub fn inspect_release_signature(
    component: ReleaseSignedComponent,
) -> Result<ReleaseSecurityCommandOutput> {
    let path = component.path().to_str().expect("fixed path is UTF-8");
    run_security_command(
        "code signature identity inspection",
        CODESIGN,
        &["--display", "--verbose=4", path],
    )
}

pub fn observe_gatekeeper_status() -> Result<ReleaseSecurityCommandOutput> {
    run_security_command("Gatekeeper status", SPCTL, &["--status"])
}

pub fn assess_release_application() -> Result<ReleaseSecurityCommandOutput> {
    let path = ReleaseSignedComponent::Application
        .path()
        .to_str()
        .expect("fixed path is UTF-8");
    run_security_command(
        "Gatekeeper assessment",
        SPCTL,
        &["--assess", "--type", "execute", "--verbose=4", path],
    )
}

fn run_security_command(
    label: &str,
    program: &str,
    args: &[&str],
) -> Result<ReleaseSecurityCommandOutput> {
    finish_security_command(
        label,
        run_bounded_command(
            program,
            args,
            COMMAND_TIMEOUT,
            MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
        ),
    )
}

fn finish_security_command(
    label: &str,
    result: Result<BoundedCommandOutput, BoundedCommandError>,
) -> Result<ReleaseSecurityCommandOutput> {
    let output = result.map_err(|error| anyhow::anyhow!("failed to run {label}: {error}"))?;
    let mut combined = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("{label} stdout is not UTF-8"))?;
    combined.push_str(
        &String::from_utf8(output.stderr)
            .map_err(|_| anyhow::anyhow!("{label} stderr is not UTF-8"))?,
    );
    Ok(ReleaseSecurityCommandOutput {
        success: output.status.success(),
        combined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_component_paths_are_closed_and_canonical() {
        for component in [ReleaseSignedComponent::Application]
            .into_iter()
            .chain(ReleaseSignedComponent::NESTED)
        {
            let path = component.path();
            assert!(path.is_absolute());
            assert!(path.starts_with(ReleaseSignedComponent::Application.path()));
            assert!(
                !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            );
        }
    }

    #[test]
    fn release_security_propagates_timeout_and_output_bounds() {
        let timeout = finish_security_command(
            "Gatekeeper assessment",
            Err(BoundedCommandError::TimedOut {
                program: SPCTL.into(),
                timeout: COMMAND_TIMEOUT,
                cleanup: "terminated and reaped".into(),
            }),
        )
        .expect_err("timeout");
        assert!(timeout.to_string().contains("exceeded its 15000ms timeout"));

        let oversized = finish_security_command(
            "code signature identity inspection",
            Err(BoundedCommandError::OutputExceeded {
                program: CODESIGN.into(),
                stream: "stderr",
                limit: MAX_STDERR_BYTES,
            }),
        )
        .expect_err("oversized output");
        assert!(oversized.to_string().contains("1048576-byte safety bound"));
    }
}
