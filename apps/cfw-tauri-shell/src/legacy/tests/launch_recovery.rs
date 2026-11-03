//! The read-only launch preflight, and how a launch recovery classifies its
//! failures without exposing their causes.

use super::*;

#[test]
fn launch_preflight_is_read_only_and_distinguishes_network_from_data_cleanup() {
    let mut network_called = false;
    let mut data_called = false;
    let status = launch_preflight_with(
        || Ok(false),
        || {
            network_called = true;
            Ok(())
        },
        || {
            data_called = true;
            Ok(())
        },
    );
    assert_eq!(status, LegacyRetirementStatus::AwaitingConfirmation);
    assert!(!network_called && !data_called);

    assert!(matches!(
        launch_preflight_with(
            || Ok(true),
            || Err("helper remains".into()),
            || Ok(())
        ),
        LegacyRetirementStatus::ManualCleanupRequired { message, .. }
            if message.contains("helper remains")
    ));
    assert!(matches!(
        launch_preflight_with(
            || Ok(true),
            || Ok(()),
            || Err("old YAML remains".into())
        ),
        LegacyRetirementStatus::PostCutoverCleanupRequired { message }
            if message.contains("old YAML remains")
    ));
    assert_eq!(
        launch_preflight_with(|| Ok(true), || Ok(()), || Ok(())),
        LegacyRetirementStatus::Cleared
    );
}

#[test]
fn launch_recovery_classifies_a_non_handoff_process_before_other_checks() {
    let failure = require_explicit_pre_network_recovery(
        false,
        || panic!("role rejection must precede admission"),
        || panic!("role rejection must precede recovery"),
    )
    .expect_err("dashboard process must fail closed");

    assert_eq!(failure.category(), LaunchRecoveryFailureCategory::Role);
    assert!(failure.user_message().contains("Open Recovery"));
    assert!(failure.user_message().len() <= 512);
}

#[test]
fn launch_recovery_classifies_canonical_admission_without_exposing_its_cause() {
    let failure = require_explicit_pre_network_recovery(
        true,
        || Err("private admission detail: /Users/alice/secret".into()),
        || panic!("recovery must not run after failed admission"),
    )
    .expect_err("untrusted install must fail closed");

    assert_eq!(failure.category(), LaunchRecoveryFailureCategory::Admission);
    assert!(failure.user_message().contains("/Applications"));
    assert!(!failure.user_message().contains("alice"));
    assert!(failure.user_message().len() <= 512);
}

#[test]
fn launch_recovery_classifies_pre_network_recovery_without_exposing_its_cause() {
    let failure = require_explicit_pre_network_recovery(
        true,
        || Ok(()),
        || Err("private recovery detail: token=secret".into()),
    )
    .expect_err("unproven legacy identity must fail closed");

    assert_eq!(failure.category(), LaunchRecoveryFailureCategory::Recovery);
    assert!(
        failure
            .user_message()
            .contains("durably seal NetworkRetiring")
    );
    assert!(!failure.user_message().contains("secret"));
    assert!(failure.user_message().len() <= 512);
}

#[test]
fn launch_recovery_classifies_replacement_active_proof_without_exposing_its_cause() {
    let failure =
        classify_replacement_active_proof(Err("private runtime detail: digest=secret".into()))
            .expect_err("unproven ReplacementActive must fail closed");

    assert_eq!(
        failure.category(),
        LaunchRecoveryFailureCategory::ActiveProof
    );
    assert!(failure.user_message().contains("owner, context, digest"));
    assert!(!failure.user_message().contains("secret"));
    assert!(failure.user_message().len() <= 512);
}

#[test]
fn launch_recovery_cause_is_redacted_by_debug_and_bounded_at_the_diagnostic_boundary() {
    let failure = classify_replacement_active_proof(Err("token=private\nline two".into()))
        .expect_err("injected proof failure");
    let debug = format!("{failure:?}");
    assert!(!debug.contains("private"));

    let diagnostic = bounded_diagnostic_cause(&format!("first line\n{}", "x".repeat(4096)));
    assert!(!diagnostic.contains('\n'));
    assert!(diagnostic.len() <= 2 * 1024);
    assert!(diagnostic.ends_with(" [truncated]"));
}
