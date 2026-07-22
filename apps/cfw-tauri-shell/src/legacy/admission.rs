use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

const CANONICAL_BUNDLE: &str = "/Applications/Clash for Mac.app";
const CANONICAL_EXECUTABLE: &str = "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";
const RELEASE_VERSION: &str = "0.4.0";
const RELEASE_TEAM_ID: &str = "YKUPL7Z869";
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 4096;

const SIGNED_COMPONENTS: &[&str] = &[
    "Contents/MacOS/clash-for-mac",
    "Contents/Frameworks/CFWNativeBridge.framework",
    "Contents/Library/LoginItems/CFWProxyAgent.app",
    "Contents/Library/SystemExtensions/CFWPacketTunnel.systemextension",
    "Contents/Library/HelperTools/cfw-helper-tombstone",
];

/// Release identity boundary for every operation that can freeze the old GUI
/// or retire any part of the old network. This intentionally fails for local,
/// unsigned, ad-hoc, relocated, writable, or partially installed builds.
pub(crate) fn require_canonical_handoff_candidate() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the running executable: {error}"))?;
    if executable != Path::new(CANONICAL_EXECUTABLE) {
        return Err(format!(
            "migration handoff requires the installed {RELEASE_VERSION} executable at {CANONICAL_EXECUTABLE}"
        ));
    }
    require_secure_regular(&executable, "running executable")?;
    for directory in [
        Path::new(CANONICAL_BUNDLE),
        Path::new("/Applications/Clash for Mac.app/Contents"),
        Path::new("/Applications/Clash for Mac.app/Contents/MacOS"),
    ] {
        require_secure_directory(directory)?;
    }

    let info_path = Path::new(CANONICAL_BUNDLE).join("Contents/Info.plist");
    require_secure_regular(&info_path, "installed Info.plist")?;
    let info = plist::Value::from_file(&info_path)
        .map_err(|error| format!("installed Info.plist is invalid: {error}"))?;
    let dictionary = info
        .as_dictionary()
        .ok_or_else(|| "installed Info.plist is not a dictionary".to_owned())?;
    if dictionary
        .get("CFBundleShortVersionString")
        .and_then(plist::Value::as_string)
        != Some(RELEASE_VERSION)
        || dictionary
            .get("CFBundleIdentifier")
            .and_then(plist::Value::as_string)
            != Some("com.bill.clashformac")
        || !dictionary
            .get("CFBundleVersion")
            .and_then(plist::Value::as_string)
            .is_some_and(positive_build_number)
    {
        return Err("installed bundle version, identifier, or build number is not the 0.4.0 release contract".into());
    }

    reject_retired_bundle_payloads(Path::new(CANONICAL_BUNDLE))?;
    for relative in SIGNED_COMPONENTS {
        let path = Path::new(CANONICAL_BUNDLE).join(relative);
        require_secure_regular_or_bundle(&path, relative)?;
        verify_developer_id_signature(&path)?;
    }
    verify_developer_id_signature(Path::new(CANONICAL_BUNDLE))?;
    run_checked(
        "/usr/sbin/spctl",
        &[
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            CANONICAL_BUNDLE,
        ],
        "Gatekeeper assessment",
    )?;
    Ok(())
}

fn positive_build_number(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|number| number > 0)
}

fn require_secure_regular(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || !trusted_install_owner(metadata.uid(), uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "{label} has unsafe type, ownership, links, or mode"
        ));
    }
    Ok(())
}

fn require_secure_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect installed directory: {error}"))?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || !trusted_install_owner(metadata.uid(), uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "installed directory {} is symlinked, untrusted, or writable by group/others",
            path.display()
        ));
    }
    Ok(())
}

fn trusted_install_owner(owner: u32, effective_uid: u32) -> bool {
    owner == 0 || owner == effective_uid
}

fn require_secure_regular_or_bundle(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("required signed component {label} is missing: {error}"))?;
    if metadata.file_type().is_dir() {
        require_secure_directory(path)
    } else {
        require_secure_regular(path, label)
    }
}

fn verify_developer_id_signature(path: &Path) -> Result<(), String> {
    let rendered = path
        .to_str()
        .ok_or_else(|| "signed component path is not UTF-8".to_owned())?;
    run_checked(
        "/usr/bin/codesign",
        &["--verify", "--strict", "--verbose=4", rendered],
        "code signature verification",
    )?;
    let details = run_checked(
        "/usr/bin/codesign",
        &["--display", "--verbose=4", rendered],
        "code signature identity inspection",
    )?;
    if !signature_details_are_release(&details) {
        return Err(format!(
            "signed component {} is not timestamped Developer ID Team {RELEASE_TEAM_ID}",
            path.display()
        ));
    }
    Ok(())
}

fn signature_details_are_release(details: &str) -> bool {
    details
        .lines()
        .any(|line| line == "TeamIdentifier=YKUPL7Z869")
        && details.lines().any(|line| {
            line.starts_with("Authority=Developer ID Application:")
                && line.ends_with("(YKUPL7Z869)")
        })
        && details.lines().any(|line| line.starts_with("Timestamp="))
        && !details.lines().any(|line| line == "Timestamp=none")
        && !details.lines().any(|line| line == "Signature=adhoc")
}

fn run_checked(program: &str, args: &[&str], label: &str) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {label}: {error}"))?;
    if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
        return Err(format!("{label} output exceeded its bound"));
    }
    let mut combined =
        String::from_utf8(output.stdout).map_err(|_| format!("{label} stdout is not UTF-8"))?;
    combined.push_str(
        &String::from_utf8(output.stderr).map_err(|_| format!("{label} stderr is not UTF-8"))?,
    );
    if !output.status.success() {
        return Err(format!("{label} failed: {}", combined.trim()));
    }
    Ok(combined)
}

fn reject_retired_bundle_payloads(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("failed to inspect installed bundle: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("failed to inspect bundle entry: {error}"))?;
            visited = visited
                .checked_add(1)
                .ok_or_else(|| "installed bundle entry counter overflowed".to_owned())?;
            if visited > MAX_BUNDLE_ENTRIES {
                return Err("installed bundle exceeds the 4096-entry admission bound".into());
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| "installed bundle contains a non-UTF-8 entry".to_owned())?;
            if matches!(
                name,
                "mihomo" | "clash-rs" | "clash-darwin" | "cfw-helper" | "cores"
            ) {
                return Err(format!(
                    "installed 0.4.0 bundle contains retired payload {name}"
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("failed to inspect bundle metadata: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("installed bundle contains a symlink".into());
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_identity_requires_team_authority_and_timestamp() {
        let valid = "Authority=Developer ID Application: Example (YKUPL7Z869)\nTeamIdentifier=YKUPL7Z869\nTimestamp=Jul 22, 2026";
        assert!(signature_details_are_release(valid));
        assert!(!signature_details_are_release(
            &valid.replace("YKUPL7Z869", "ATTACKER00")
        ));
        assert!(!signature_details_are_release(
            "Authority=Developer ID Application: Example (YKUPL7Z869)\nTeamIdentifier=YKUPL7Z869\nTimestamp=none"
        ));
        assert!(!signature_details_are_release(
            "TeamIdentifier=YKUPL7Z869\nTimestamp=Jul 22, 2026\nSignature=adhoc"
        ));
    }

    #[test]
    fn build_number_is_canonical_positive_decimal() {
        assert!(positive_build_number("2026072201"));
        for invalid in ["", "0", "-1", "+1", "1.0", " 1"] {
            assert!(!positive_build_number(invalid), "{invalid:?}");
        }
    }
}
