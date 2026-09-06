use std::fs;
use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cfw_core::{LegacyNetworkState, MacOsAppPaths};
use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineSnapshot, EngineState, RuntimeIdentity,
};
use cfw_platform::ServiceModeStatus;
use cfw_profiles::ProfileRepository;

use super::migration::{
    LaunchRecoveryFailureCategory, bounded_diagnostic_cause, classify_replacement_active_proof,
    launch_preflight_with, remove_managed_path, require_enabled_login_item,
    require_pre_network_launch_recovery, restore_legacy_dns,
};
use super::process_cleanup::{
    ProcessRecord, parse_loopback_listener_owners, parse_managed_process, require_path_absent,
    validate_unique_root_managed_process,
};
use super::state_gate::{LegacyCleanupAction, LegacyRetirementGate, LegacyRetirementStatus};
use super::{
    require_explicit_cutover_confirmation, require_replacement_active, spawn_supervised_app_result,
};

#[tokio::test]
async fn renderer_response_cancellation_cannot_cancel_the_app_owned_task() {
    let (release, released) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let after_response = Arc::new(AtomicBool::new(false));
    let operation_completed = completed.clone();
    let response_completed = after_response.clone();
    let receiver = spawn_supervised_app_result(
        async move {
            released.await.expect("release app task");
            operation_completed.store(true, Ordering::Release);
        },
        |operation| operation,
        move || response_completed.store(true, Ordering::Release),
    );
    drop(receiver);
    release.send(()).expect("release sender");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !completed.load(Ordering::Acquire) || !after_response.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached task must reach terminal side effects");
}

#[tokio::test]
async fn supervised_app_task_turns_worker_panic_into_a_terminal_error() {
    let receiver = spawn_supervised_app_result(
        async move {
            panic!("injected migration worker panic");
        },
        |operation| operation,
        || {},
    );
    let error = receiver
        .await
        .expect("supervisor response")
        .expect_err("worker panic must fail");
    assert_eq!(error, "migration handoff application task panicked");
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
    assert!(gate.require_cleared().is_ok(), "new engine remains usable");
    let mut cleanup_retry = gate
        .begin_attempt()
        .expect("query state")
        .expect("post-cutover cleanup remains retryable");
    cleanup_retry.mark_cleared().expect("finish retry");
}

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
    let failure = require_pre_network_launch_recovery(
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
    let failure = require_pre_network_launch_recovery(
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
    let failure = require_pre_network_launch_recovery(
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

#[test]
fn destructive_cutover_requires_an_explicit_positive_confirmation() {
    assert!(require_explicit_cutover_confirmation(true).is_ok());
    assert!(
        require_explicit_cutover_confirmation(false)
            .expect_err("missing confirmation")
            .contains("left unchanged")
    );
}

#[test]
fn start_handoff_requires_exact_active_target_and_digest() {
    let digest = "01".repeat(32);
    let runtime = RuntimeIdentity {
        owner: EngineOwner::ProxyAgent,
        context: EngineCommandContext {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
            generation: 7,
        },
        config_digest: digest.clone(),
        ready: true,
    };
    let context = runtime.context.clone();
    let active = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive { runtime },
        generation: 7,
        config_digest: Some(digest.clone()),
    };
    require_replacement_active(active.clone(), EngineMode::SystemProxy, &digest, &context)
        .expect("exact Active proof");
    assert!(require_replacement_active(active, EngineMode::Tunnel, &digest, &context).is_err());
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

#[test]
fn process_parser_only_accepts_fixed_managed_core_paths() {
    let cores_dir =
        std::path::Path::new("/Users/test/Library/Application Support/Clash for Mac/cores");
    assert_eq!(
        parse_managed_process(
            "0 42 Tue Jul 22 10:11:12 2026 /Users/test/Library/Application Support/Clash for Mac/cores/mihomo -d x",
            cores_dir
        )
        .expect("parse fixed identity"),
        Some(ProcessRecord {
            uid: 0,
            pid: 42,
            start_identity: "Tue Jul 22 10:11:12 2026".into(),
            executable: cores_dir.join("mihomo"),
            command: "/Users/test/Library/Application Support/Clash for Mac/cores/mihomo -d x"
                .into(),
        })
    );
    assert_eq!(
        parse_managed_process(
            "0 42 Tue Jul 22 10:11:12 2026 /tmp/mihomo --config /Users/test/Library/Application Support/Clash for Mac/cores/config.yaml",
            cores_dir
        )
        .expect("unrelated process"),
        None
    );
    assert!(parse_managed_process("root 42 malformed", cores_dir).is_err());
}

#[test]
fn core_ownership_requires_one_root_identity_with_exact_arguments() {
    let app_home = std::path::Path::new("/Users/test/Library/Application Support/Clash for Mac");
    let config = app_home.join("config.yaml");
    let executable = app_home.join("cores/clash-darwin");
    let root = ProcessRecord {
        uid: 0,
        pid: 42,
        start_identity: "Tue Jul 22 10:11:12 2026".into(),
        command: format!(
            "{} -d {} -f {}",
            executable.display(),
            app_home.display(),
            config.display()
        ),
        executable,
    };
    assert_eq!(
        validate_unique_root_managed_process(std::slice::from_ref(&root), app_home, &config)
            .expect("unique root"),
        root
    );

    let mut non_root = root.clone();
    non_root.uid = 501;
    assert!(validate_unique_root_managed_process(&[non_root], app_home, &config).is_err());
    assert!(
        validate_unique_root_managed_process(&[root.clone(), root.clone()], app_home, &config)
            .is_err()
    );
    let mut reused = root;
    reused.command.push_str(" --unexpected");
    assert!(validate_unique_root_managed_process(&[reused], app_home, &config).is_err());
}

#[test]
fn netstat_listener_parser_requires_exact_loopback_rows() {
    let fixture = r#"tcp4 0 0 127.0.0.1.7900 *.* LISTEN 0 0 131072 131072 clash-darwin:67262 00180
tcp4 0 0 *.7900 *.* LISTEN 0 0 131072 131072 attacker:9 00180
tcp4 0 0 127.0.0.1.7901 *.* LISTEN 0 0 131072 131072 other:8 00180
tcp4 0 0 127.0.0.1.7900 127.0.0.1.50000 ESTABLISHED 0 0 1 1 clash-darwin:67262 00180"#;
    assert_eq!(
        parse_loopback_listener_owners(fixture, 7900).expect("owners"),
        ["clash-darwin:67262"]
    );
    let duplicate =
        format!("{fixture}\ntcp4 0 0 127.0.0.1.7900 *.* LISTEN 0 0 131072 131072 attacker:9 00180");
    assert_eq!(
        parse_loopback_listener_owners(&duplicate, 7900).expect("duplicates"),
        ["clash-darwin:67262", "attacker:9"]
    );
}

#[test]
fn managed_cleanup_unlinks_a_symlink_without_touching_target() {
    let root = std::env::temp_dir().join(format!(
        "cfw-managed-cleanup-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let target = root.join("target");
    let link = root.join("managed-link");
    fs::create_dir_all(&target).expect("create target");
    fs::write(target.join("sentinel"), b"keep").expect("write sentinel");
    symlink(&target, &link).expect("create symlink");
    remove_managed_path(&link).expect("unlink managed symlink");
    assert_eq!(fs::read(target.join("sentinel")).expect("read"), b"keep");
    fs::remove_dir_all(root).expect("remove root");
}

#[test]
fn legacy_profile_cleanup_cannot_delete_staged_native_profiles() {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-cutover-isolation-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let paths = MacOsAppPaths::from_app_home(root.join("app"));
    fs::create_dir_all(&paths.legacy_profiles_dir).expect("create legacy profiles");
    fs::create_dir_all(&paths.profiles_dir).expect("create staged profiles");
    fs::write(paths.legacy_profiles_dir.join("legacy.yaml"), b"legacy").expect("legacy");
    let staged = paths.profiles_dir.join("staged-sentinel");
    fs::write(&staged, b"keep staged replacement").expect("staged");
    ProfileRepository::new(paths.legacy_profiles_dir.clone())
        .clear_managed_profiles()
        .expect("clear legacy only");
    remove_managed_path(&paths.legacy_profiles_dir).expect("remove legacy dir");
    assert_eq!(
        fs::read(&staged).expect("read staged"),
        b"keep staged replacement"
    );
    fs::remove_dir_all(root).expect("remove root");
}

#[test]
fn broken_symlink_is_not_treated_as_an_absent_privileged_artifact() {
    let root = std::env::temp_dir().join(format!(
        "cfw-privileged-absence-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::create_dir_all(&root).expect("root");
    let link = root.join("retired-helper");
    symlink(root.join("missing-target"), &link).expect("link");
    assert!(
        require_path_absent(&link, "legacy privileged helper")
            .expect_err("broken link remains")
            .contains("remains")
    );
    fs::remove_file(link).expect("remove link");
    fs::remove_dir(root).expect("remove root");
}
