use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use cfw_platform::{
    ReleaseSignedComponent, assess_release_application, inspect_release_signature,
    observe_gatekeeper_status, verify_release_signature,
};

const RELEASE_VERSION: &str = "0.4.0";
const RELEASE_TEAM_ID: &str = "YKUPL7Z869";
const MAX_BUNDLE_ENTRIES: usize = 4096;
const GLOBAL_AUTHORITY_IDENTIFIER: &str = "com.bill.clashformac.global-authority";

const FRAMEWORK_ROOT: &str = "Contents/Frameworks/CFWNativeBridge.framework";
const FRAMEWORK_SYMLINKS: &[(&str, &str, SymlinkTargetKind)] = &[
    (
        "Contents/Frameworks/CFWNativeBridge.framework/CFWNativeBridge",
        "Versions/Current/CFWNativeBridge",
        SymlinkTargetKind::File,
    ),
    (
        "Contents/Frameworks/CFWNativeBridge.framework/Headers",
        "Versions/Current/Headers",
        SymlinkTargetKind::Directory,
    ),
    (
        "Contents/Frameworks/CFWNativeBridge.framework/Modules",
        "Versions/Current/Modules",
        SymlinkTargetKind::Directory,
    ),
    (
        "Contents/Frameworks/CFWNativeBridge.framework/Resources",
        "Versions/Current/Resources",
        SymlinkTargetKind::Directory,
    ),
    (
        "Contents/Frameworks/CFWNativeBridge.framework/Versions/Current",
        "A",
        SymlinkTargetKind::Directory,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymlinkTargetKind {
    File,
    Directory,
}

/// Release identity boundary for every operation that can exit the old GUI
/// or retire any part of the old network. This intentionally fails for local,
/// unsigned, ad-hoc, relocated, writable, or partially installed builds.
pub(crate) fn require_canonical_handoff_candidate() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the running executable: {error}"))?;
    let canonical_executable = ReleaseSignedComponent::MainExecutable.path();
    let canonical_bundle = ReleaseSignedComponent::Application.path();
    if executable != canonical_executable {
        return Err(format!(
            "migration handoff requires the installed {RELEASE_VERSION} executable at {}",
            canonical_executable.display()
        ));
    }
    require_secure_regular(&executable, "running executable")?;
    for directory in [
        canonical_bundle,
        Path::new("/Applications/Clash for Mac.app/Contents"),
        Path::new("/Applications/Clash for Mac.app/Contents/MacOS"),
    ] {
        require_secure_directory(directory)?;
    }

    let info_path = canonical_bundle.join("Contents/Info.plist");
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

    validate_installed_bundle_tree(canonical_bundle)?;
    for component in ReleaseSignedComponent::NESTED {
        require_secure_regular_or_bundle(component.path(), component.label())?;
        let details = verify_developer_id_signature(component)?;
        if component == ReleaseSignedComponent::GlobalAuthority
            && !global_authority_details_are_release(&details)
        {
            return Err("CFWGlobalAuthority does not have its exact release identifier".into());
        }
    }
    let application_signature = verify_developer_id_signature(ReleaseSignedComponent::Application)?;
    verify_gatekeeper_assessment(&application_signature)?;
    Ok(())
}

fn positive_build_number(value: &str) -> bool {
    matches!(value.as_bytes(), [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit))
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

fn verify_developer_id_signature(component: ReleaseSignedComponent) -> Result<String, String> {
    let verification = verify_release_signature(component)
        .map_err(|error| format!("failed to run code signature verification: {error}"))?;
    if !verification.success() {
        return Err(format!(
            "code signature verification failed: {}",
            verification.combined().trim()
        ));
    }
    let inspection = inspect_release_signature(component)
        .map_err(|error| format!("failed to run code signature identity inspection: {error}"))?;
    if !inspection.success() {
        return Err(format!(
            "code signature identity inspection failed: {}",
            inspection.combined().trim()
        ));
    }
    let details = inspection.combined().to_owned();
    if !signature_details_are_release(&details) {
        return Err(format!(
            "signed component {} is not timestamped Developer ID Team {RELEASE_TEAM_ID}",
            component.path().display()
        ));
    }
    Ok(details)
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

fn global_authority_details_are_release(details: &str) -> bool {
    details
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Identifier="))
        .eq([GLOBAL_AUTHORITY_IDENTIFIER])
}

fn verify_gatekeeper_assessment(codesign_details: &str) -> Result<(), String> {
    let authority = release_leaf_authority(codesign_details)?;
    let before = observe_gatekeeper_status()
        .map_err(|error| format!("failed to observe Gatekeeper before assessment: {error}"))?;
    validate_gatekeeper_status(before.success(), before.combined(), "before assessment")?;
    let rendered = ReleaseSignedComponent::Application
        .path()
        .to_str()
        .ok_or_else(|| "Gatekeeper target path is not UTF-8".to_owned())?;
    let assessment = assess_release_application()
        .map_err(|error| format!("failed to run Gatekeeper assessment: {error}"))?;
    validate_gatekeeper_assessment_output(
        assessment.success(),
        assessment.combined(),
        rendered,
        &authority,
    )?;
    let after = observe_gatekeeper_status()
        .map_err(|error| format!("failed to observe Gatekeeper after assessment: {error}"))?;
    validate_gatekeeper_status(after.success(), after.combined(), "after assessment")
}

fn validate_gatekeeper_status(success: bool, combined: &str, phase: &str) -> Result<(), String> {
    let lines = nonempty_trimmed_lines(combined);
    if !success || lines.as_slice() != ["assessments enabled"] {
        return Err(format!(
            "Gatekeeper is not provably enabled {phase}: {lines:?}"
        ));
    }
    Ok(())
}

fn validate_gatekeeper_assessment_output(
    success: bool,
    combined: &str,
    target: &str,
    authority: &str,
) -> Result<(), String> {
    let lines = nonempty_trimmed_lines(combined);
    if !success {
        return Err(format!("Gatekeeper assessment failed: {lines:?}"));
    }
    if lines.iter().any(|line| {
        let folded = line.to_ascii_lowercase();
        folded.starts_with("warning:")
            || folded.starts_with("error:")
            || folded.starts_with("override=")
    }) {
        return Err("Gatekeeper assessment contains a diagnostic or security override".into());
    }
    let accepted = format!("{target}: accepted");
    if lines.iter().filter(|line| **line == accepted).count() != 1 {
        return Err("Gatekeeper assessment does not contain the exact accepted target".into());
    }
    let sources = lines
        .iter()
        .filter_map(|line| line.strip_prefix("source="))
        .collect::<Vec<_>>();
    if sources.as_slice() != ["Notarized Developer ID"] {
        return Err("Gatekeeper source is not exactly Notarized Developer ID".into());
    }
    let origins = lines
        .iter()
        .filter_map(|line| line.strip_prefix("origin="))
        .collect::<Vec<_>>();
    if origins.len() > 1 || origins.first().is_some_and(|origin| *origin != authority) {
        return Err("Gatekeeper origin does not match the leaf Developer ID authority".into());
    }
    if lines.iter().any(|line| {
        line.as_str() != accepted
            && line.as_str() != "source=Notarized Developer ID"
            && !line.starts_with("origin=")
    }) {
        return Err("Gatekeeper assessment contains an unexpected or noncanonical field".into());
    }
    Ok(())
}

fn nonempty_trimmed_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn release_leaf_authority(details: &str) -> Result<String, String> {
    let authorities = details
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Authority="))
        .collect::<Vec<_>>();
    let Some(authority) = authorities.first() else {
        return Err("code signature has no leaf authority".into());
    };
    if !authority.starts_with("Developer ID Application:")
        || !authority.ends_with(&format!("({RELEASE_TEAM_ID})"))
    {
        return Err(
            "code signature leaf authority is not the release Developer ID identity".into(),
        );
    }
    Ok((*authority).to_owned())
}

fn validate_installed_bundle_tree(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    let mut observed_symlinks = BTreeSet::new();
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
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect bundle metadata: {error}"))?;
            let uid = unsafe { libc::geteuid() };
            if !trusted_install_owner(metadata.uid(), uid) {
                return Err(format!(
                    "installed bundle entry has an untrusted owner: {}",
                    path.display()
                ));
            }
            if metadata.file_type().is_symlink() {
                validate_framework_symlink(root, &path, &mut observed_symlinks)?;
                continue;
            }
            if metadata.mode() & 0o022 != 0 {
                return Err(format!(
                    "installed bundle entry is writable by group or others: {}",
                    path.display()
                ));
            }
            if metadata.file_type().is_file() && metadata.nlink() != 1 {
                return Err(format!(
                    "installed bundle file has multiple hard links: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.file_type().is_file() {
                return Err(format!(
                    "installed bundle contains an unsupported entry type: {}",
                    path.display()
                ));
            }
        }
    }
    let expected = FRAMEWORK_SYMLINKS
        .iter()
        .map(|(relative, _, _)| (*relative).to_owned())
        .collect::<BTreeSet<_>>();
    if observed_symlinks != expected {
        return Err("installed Native Bridge framework does not contain exactly its five canonical symlinks".into());
    }
    Ok(())
}

fn validate_framework_symlink(
    root: &Path,
    path: &Path,
    observed: &mut BTreeSet<String>,
) -> Result<(), String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "installed bundle symlink is outside the bundle root".to_owned())?;
    let relative = relative
        .to_str()
        .ok_or_else(|| "installed bundle symlink path is not UTF-8".to_owned())?;
    let Some((_, expected_target, target_kind)) = FRAMEWORK_SYMLINKS
        .iter()
        .find(|(allowed, _, _)| *allowed == relative)
    else {
        return Err(format!(
            "installed bundle contains noncanonical symlink {relative}"
        ));
    };
    if !relative.starts_with(&format!("{FRAMEWORK_ROOT}/")) {
        return Err("allowed framework symlink escaped its framework root".into());
    }
    let target = fs::read_link(path)
        .map_err(|error| format!("failed to read framework symlink {relative}: {error}"))?;
    if target != Path::new(expected_target) || target.is_absolute() {
        return Err(format!(
            "framework symlink {relative} has a noncanonical target"
        ));
    }
    let resolved = path
        .parent()
        .ok_or_else(|| "framework symlink has no parent".to_owned())?
        .join(&target);
    let metadata = fs::metadata(&resolved)
        .map_err(|error| format!("framework symlink {relative} is dangling: {error}"))?;
    let correct_type = match target_kind {
        SymlinkTargetKind::File => metadata.is_file(),
        SymlinkTargetKind::Directory => metadata.is_dir(),
    };
    if !correct_type {
        return Err(format!(
            "framework symlink {relative} resolves to the wrong type"
        ));
    }
    if !observed.insert(relative.to_owned()) {
        return Err(format!("framework symlink {relative} was observed twice"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    fn global_authority_requires_its_exact_release_identifier() {
        assert!(global_authority_details_are_release(
            "Identifier=com.bill.clashformac.global-authority\n"
        ));
        assert!(!global_authority_details_are_release(
            "Identifier=com.bill.clashformac.proxy-agent\n"
        ));
        assert!(!global_authority_details_are_release(
            "Identifier=com.bill.clashformac.global-authority\nIdentifier=com.bill.clashformac.global-authority\n"
        ));
    }

    #[test]
    fn gatekeeper_policy_requires_enabled_notarized_output_and_matching_origin() {
        let authority = "Developer ID Application: Example (YKUPL7Z869)";
        assert!(validate_gatekeeper_status(true, "assessments enabled\n", "test").is_ok());
        assert!(
            validate_gatekeeper_assessment_output(
                true,
                "/Applications/Clash for Mac.app: accepted\nsource=Notarized Developer ID\n",
                "/Applications/Clash for Mac.app",
                authority,
            )
            .is_ok()
        );
        let with_origin = format!(
            "/Applications/Clash for Mac.app: accepted\nsource=Notarized Developer ID\norigin={authority}\n"
        );
        assert!(
            validate_gatekeeper_assessment_output(
                true,
                &with_origin,
                "/Applications/Clash for Mac.app",
                authority,
            )
            .is_ok()
        );
        for invalid in [
            "assessments disabled\n",
            "assessments enabled\nwarning: bypassed\n",
        ] {
            assert!(validate_gatekeeper_status(true, invalid, "test").is_err());
        }
        for invalid in [
            "/Applications/Clash for Mac.app: accepted\nsource=Developer ID\n",
            "/Applications/Clash for Mac.app: accepted\nSource=Notarized Developer ID\n",
            "/Applications/Clash for Mac.app: accepted\nsource=Notarized Developer ID\noverride=security disabled\n",
            "/Applications/Clash for Mac.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Attacker (ATTACKER00)\n",
        ] {
            assert!(
                validate_gatekeeper_assessment_output(
                    true,
                    invalid,
                    "/Applications/Clash for Mac.app",
                    authority,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn release_security_accepts_only_the_closed_component_enum() {
        assert_eq!(ReleaseSignedComponent::NESTED.len(), 6);
        assert_eq!(
            ReleaseSignedComponent::Application.path(),
            Path::new("/Applications/Clash for Mac.app")
        );
        assert!(ReleaseSignedComponent::NESTED.iter().all(|component| {
            component
                .path()
                .starts_with(ReleaseSignedComponent::Application.path())
        }));
    }

    fn create_framework_fixture(root: &Path) -> PathBuf {
        let framework = root.join(FRAMEWORK_ROOT);
        for directory in [
            "Versions/A/Headers",
            "Versions/A/Modules",
            "Versions/A/Resources",
        ] {
            fs::create_dir_all(framework.join(directory)).expect("create framework directory");
        }
        fs::write(framework.join("Versions/A/CFWNativeBridge"), b"binary")
            .expect("write framework binary");
        for (relative, target, _) in FRAMEWORK_SYMLINKS {
            let path = root.join(relative);
            std::os::unix::fs::symlink(target, path).expect("create canonical symlink");
        }
        framework
    }

    #[test]
    fn installed_tree_accepts_only_the_five_real_framework_symlinks() {
        let fixture = tempfile::tempdir().expect("fixture");
        create_framework_fixture(fixture.path());
        assert!(validate_installed_bundle_tree(fixture.path()).is_ok());

        let extra = fixture.path().join("Contents/extra-link");
        std::os::unix::fs::symlink("MacOS", &extra).expect("extra link");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());
        fs::remove_file(extra).expect("remove extra");

        let binary_link = fixture.path().join(FRAMEWORK_SYMLINKS[0].0);
        fs::remove_file(&binary_link).expect("remove binary link");
        std::os::unix::fs::symlink("../../../../outside", &binary_link).expect("escaping link");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());
    }

    #[test]
    fn framework_symlink_rejects_dangling_and_wrong_target_types() {
        let fixture = tempfile::tempdir().expect("fixture");
        let framework = create_framework_fixture(fixture.path());
        fs::remove_file(framework.join("Versions/A/CFWNativeBridge")).expect("remove binary");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());

        fs::create_dir(framework.join("Versions/A/CFWNativeBridge")).expect("wrong type");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());
    }

    #[test]
    fn installed_tree_rejects_writable_and_hardlinked_regular_entries() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().expect("fixture");
        let framework = create_framework_fixture(fixture.path());
        let resource = framework.join("Versions/A/Resources/fixture.txt");
        fs::write(&resource, b"resource").expect("write resource");
        fs::set_permissions(&resource, fs::Permissions::from_mode(0o664)).expect("make writable");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());

        fs::set_permissions(&resource, fs::Permissions::from_mode(0o644))
            .expect("protect resource");
        fs::hard_link(&resource, framework.join("Versions/A/Resources/second.txt"))
            .expect("hard link");
        assert!(validate_installed_bundle_tree(fixture.path()).is_err());
    }

    #[test]
    fn build_number_is_canonical_positive_decimal() {
        assert!(positive_build_number("2026072201"));
        for invalid in ["", "0", "00", "01", "0001", "-1", "+1", "1.0", " 1"] {
            assert!(!positive_build_number(invalid), "{invalid:?}");
        }
    }
}
