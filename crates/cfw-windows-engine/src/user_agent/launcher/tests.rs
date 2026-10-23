use super::*;
use cfw_singbox_config::ProjectionMode;
use sha2::{Digest, Sha256};

fn executable() -> VerifiedExecutable {
    let path = std::env::current_exe().unwrap();
    let hash = Sha256::digest(std::fs::read(&path).unwrap()).into();
    VerifiedExecutable::open(&path, hash, "0.5.0").unwrap()
}

#[test]
fn cancelled_launch_keeps_cleanup_context_without_creating_a_child() {
    let launch = crate::user_agent::tests::launch(ProjectionMode::LocalProxy);
    let context = launch.context().clone();
    let outcome = UserAgentChild::launch(
        executable(),
        UserAgentInvocation::installed("CFW-test").unwrap(),
        launch,
        &tempfile::tempfile().unwrap(),
        Instant::now() + Duration::from_secs(5),
        Arc::new(AtomicBool::new(true)),
    );
    let Err(failure) = outcome else {
        panic!("cancelled launcher created an agent");
    };
    assert!(matches!(failure.error, LaunchError::Cancelled));
    assert!(failure.owner.is_none());
    assert!(failure.context.as_ref() == &context);
}

#[test]
fn launch_never_creates_a_child_for_a_nonmedium_or_foreign_recorded_owner() {
    // The shared input's SID/logon/session is synthetic. Regardless of whether
    // this test runner is elevated, it cannot become that native lease owner.
    let launch = crate::user_agent::tests::launch(ProjectionMode::LocalProxy);
    let context = launch.context().clone();
    let outcome = UserAgentChild::launch(
        executable(),
        UserAgentInvocation::installed("CFW-test").unwrap(),
        launch,
        &tempfile::tempfile().unwrap(),
        Instant::now() + Duration::from_secs(5),
        Arc::new(AtomicBool::new(false)),
    );
    let Err(failure) = outcome else {
        panic!("launcher accepted the wrong native identity");
    };
    assert!(matches!(failure.error, LaunchError::Identity));
    assert!(failure.owner.is_none());
    assert!(failure.context.as_ref() == &context);
}

#[test]
fn installed_invocation_cannot_inject_extra_command_line_fields() {
    for name in [
        "",
        "CFW other",
        "CFW\"other",
        "CFW\nother",
        "CFW/other",
        "CFW\0other",
        "--other",
    ] {
        assert!(matches!(
            UserAgentInvocation::installed(name),
            Err(LaunchError::Invocation)
        ));
    }
    assert!(matches!(
        UserAgentInvocation::installed(&"a".repeat(201)),
        Err(LaunchError::Invocation)
    ));
    assert!(UserAgentInvocation::installed("CFW-Authority_050").is_ok());
}
