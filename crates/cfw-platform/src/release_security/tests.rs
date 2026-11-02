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

/// A system application: validly signed by Apple, and never this product.
const SYSTEM_APPLICATION: &str = "/System/Applications/Calculator.app";

#[test]
fn each_nested_label_is_its_path_inside_the_application() {
    assert_eq!(
        ReleaseSignedComponent::Application.label(),
        "application bundle"
    );
    for component in ReleaseSignedComponent::NESTED {
        assert_eq!(
            ReleaseSignedComponent::Application
                .path()
                .join(component.label()),
            component.path(),
            "{component:?}"
        );
    }
}

#[test]
fn a_command_outcome_keeps_its_verdict_and_both_streams() {
    use crate::test_support::exited;

    let output = finish_security_command("Gatekeeper status", Ok(exited(0, b"out\n", b"err\n")))
        .expect("outcome");
    assert!(output.success());
    assert_eq!(output.combined(), "out\nerr\n");
    let output = finish_security_command("Gatekeeper status", Ok(exited(3, b"", b"rejected\n")))
        .expect("outcome");
    assert!(!output.success());
    assert_eq!(output.combined(), "rejected\n");

    for (stdout, stderr, message) in [
        (
            &b"\xff"[..],
            &b""[..],
            "Gatekeeper status stdout is not UTF-8",
        ),
        (
            &b""[..],
            &b"\xff"[..],
            "Gatekeeper status stderr is not UTF-8",
        ),
    ] {
        let error = finish_security_command("Gatekeeper status", Ok(exited(0, stdout, stderr)))
            .expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn a_validly_signed_application_verifies_and_shows_its_identity() {
    let verified = verify_signature_at(SYSTEM_APPLICATION).expect("verification ran");
    assert!(verified.success(), "{}", verified.combined());
    assert!(
        verified.combined().contains("valid on disk"),
        "{}",
        verified.combined()
    );

    let inspected = inspect_signature_at(SYSTEM_APPLICATION).expect("inspection ran");
    assert!(inspected.success(), "{}", inspected.combined());
    assert!(
        inspected
            .combined()
            .contains("Identifier=com.apple.calculator"),
        "{}",
        inspected.combined()
    );

    let assessed = assess_application_at(SYSTEM_APPLICATION).expect("assessment ran");
    assert!(assessed.success(), "{}", assessed.combined());
    assert!(
        assessed.combined().contains("accepted"),
        "{}",
        assessed.combined()
    );
}

#[test]
fn an_unsigned_bundle_fails_verification_with_the_tool_diagnostics() {
    let root = std::env::temp_dir().join(format!(
        "cfw-release-security-unsigned-{}",
        std::process::id()
    ));
    let executable = root.join("Unsigned.app/Contents/MacOS");
    std::fs::create_dir_all(&executable).expect("bundle layout");
    std::fs::write(executable.join("Unsigned"), b"not code").expect("payload");
    let bundle = root.join("Unsigned.app");

    let verified = verify_signature_at(bundle.to_str().expect("UTF-8 path"));
    std::fs::remove_dir_all(&root).expect("remove the bundle");
    let verified = verified.expect("verification ran");
    assert!(!verified.success());
    assert!(
        verified.combined().contains("not signed at all"),
        "{}",
        verified.combined()
    );
}

#[test]
fn gatekeeper_status_reports_whether_assessments_run() {
    let status = observe_gatekeeper_status().expect("status ran");
    assert!(
        status.combined().contains("assessments"),
        "{}",
        status.combined()
    );
}
