//! The legacy retirement gate's attempts and their outcomes, and the legacy
//! data cleanup that follows an Active replacement.

use super::*;

#[test]
fn later_legacy_cleanup_preserves_modern_preferences() {
    use cfw_core::{AppearanceTheme, UiPreferences};
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    let legacy = UiPreferences {
        theme: AppearanceTheme::Light,
        launch_at_login: true,
        ..UiPreferences::default()
    };
    assert_eq!(
        crate::legacy::migration::preferences_for_legacy_cleanup(&store, &legacy)
            .expect("unwritten modern preferences"),
        legacy
    );
    let modern = UiPreferences {
        theme: AppearanceTheme::Dark,
        launch_at_login: false,
        ..UiPreferences::default()
    };
    store
        .write(&modern)
        .expect("user writes modern preferences");
    assert_eq!(
        crate::legacy::migration::preferences_for_legacy_cleanup(&store, &legacy)
            .expect("existing modern preferences win"),
        modern
    );
}

#[test]
fn legacy_retirement_gate_serializes_attempts_and_preserves_post_cutover_access() {
    let gate = LegacyRetirementGate::default();
    let mut attempt = gate
        .begin_attempt()
        .expect("begin retirement")
        .expect("pending gate starts an attempt");
    assert_eq!(
        gate.status().expect("status"),
        LegacyRetirementStatus::Cleaning
    );
    assert!(gate.begin_attempt().is_err());

    attempt
        .mark_post_cutover_cleanup_required("old YAML remains")
        .expect("record post cleanup");
    assert!(
        gate.require_start_allowed().is_ok(),
        "new engine remains usable"
    );
    let mut cleanup_retry = gate
        .begin_attempt()
        .expect("query state")
        .expect("post-cutover cleanup remains retryable");
    cleanup_retry.mark_cleared().expect("finish retry");
}

#[test]
fn failed_and_interrupted_retirement_are_explicitly_retryable() {
    let gate = LegacyRetirementGate::default();
    let mut attempt = gate.begin_attempt().expect("begin").expect("attempt");
    attempt
        .mark_failed(LegacyCleanupAction::Retry, "network residue")
        .expect("mark failure");
    assert!(matches!(
        gate.status().expect("status"),
        LegacyRetirementStatus::ManualCleanupRequired { message, .. }
            if message == "network residue"
    ));
    drop(gate.begin_attempt().expect("retry").expect("attempt"));
    assert!(matches!(
        gate.status().expect("status"),
        LegacyRetirementStatus::ManualCleanupRequired { message, .. }
            if message.contains("interrupted")
    ));
}

#[test]
fn pending_login_item_approval_is_post_active_cleanup_not_false_success() {
    let error = require_enabled_login_item(ServiceModeStatus::RequiresApproval)
        .expect_err("approval must remain explicit");
    assert!(error.contains("replacement networking remains active"));
    assert!(require_enabled_login_item(ServiceModeStatus::Enabled).is_ok());
}

#[test]
fn legacy_dns_requires_an_explicit_non_mutating_review() {
    let network = LegacyNetworkState {
        restore_dns_servers: Some(vec!["1.1.1.1".into()]),
        ..LegacyNetworkState::default()
    };
    let error = restore_legacy_dns(&network, false).expect_err("manual review required");
    assert_eq!(error.action(), LegacyCleanupAction::ReviewDns);
    assert!(error.to_string().contains("no DNS setting is changed"));
    assert!(restore_legacy_dns(&network, true).is_ok());
}
