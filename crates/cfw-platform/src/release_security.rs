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
    NativeUi,
    GlobalAuthority,
    ProxyAgent,
    PacketTunnel,
    LegacyHelperTombstone,
}

impl ReleaseSignedComponent {
    pub const NESTED: [Self; 7] = [
        Self::MainExecutable,
        Self::NativeBridge,
        Self::NativeUi,
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
            Self::NativeUi => {
                "/Applications/Clash for Mac.app/Contents/Frameworks/libCFMNativeDashboard.dylib"
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
            Self::NativeUi => "Contents/Frameworks/libCFMNativeDashboard.dylib",
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
    verify_signature_at(fixed_path(component))
}

pub fn inspect_release_signature(
    component: ReleaseSignedComponent,
) -> Result<ReleaseSecurityCommandOutput> {
    inspect_signature_at(fixed_path(component))
}

pub fn observe_gatekeeper_status() -> Result<ReleaseSecurityCommandOutput> {
    run_security_command("Gatekeeper status", SPCTL, &["--status"])
}

pub fn assess_release_application() -> Result<ReleaseSecurityCommandOutput> {
    assess_application_at(fixed_path(ReleaseSignedComponent::Application))
}

fn fixed_path(component: ReleaseSignedComponent) -> &'static str {
    component.path().to_str().expect("fixed path is UTF-8")
}

fn verify_signature_at(path: &str) -> Result<ReleaseSecurityCommandOutput> {
    run_security_command(
        "code signature verification",
        CODESIGN,
        &["--verify", "--strict", "--verbose=4", path],
    )
}

fn inspect_signature_at(path: &str) -> Result<ReleaseSecurityCommandOutput> {
    run_security_command(
        "code signature identity inspection",
        CODESIGN,
        &["--display", "--verbose=4", path],
    )
}

fn assess_application_at(path: &str) -> Result<ReleaseSecurityCommandOutput> {
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
mod tests;
