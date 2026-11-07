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
    assert_eq!(ReleaseSignedComponent::NESTED.len(), 7);
    assert!(ReleaseSignedComponent::NESTED.contains(&ReleaseSignedComponent::NativeUi));
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

    fs::set_permissions(&resource, fs::Permissions::from_mode(0o644)).expect("protect resource");
    fs::hard_link(&resource, framework.join("Versions/A/Resources/second.txt")).expect("hard link");
    assert!(validate_installed_bundle_tree(fixture.path()).is_err());
}

#[test]
fn handoff_identity_requires_the_exact_compiled_release_build() {
    const COMPILED: &str = "70001";
    assert!(installed_product_identity_is_current(
        COMPILED,
        Some(RELEASE_VERSION),
        Some(COMPILED)
    ));
    for (version, build) in [
        (Some(RELEASE_VERSION), Some("70000")),
        (Some(RELEASE_VERSION), Some("70002")),
        (Some(RELEASE_VERSION), Some("070001")),
        (Some(RELEASE_VERSION), Some("70001 ")),
        (Some(RELEASE_VERSION), Some("0")),
        (Some(RELEASE_VERSION), None),
        (Some("0.4.0"), Some(COMPILED)),
        (Some("0.5.0-preview"), Some(COMPILED)),
        (None, Some(COMPILED)),
    ] {
        assert!(
            !installed_product_identity_is_current(COMPILED, version, build),
            "{version:?}/{build:?}"
        );
    }
}
