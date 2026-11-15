//! A profile transaction by hand: a new mode intent whose activating
//! candidate passes the start admission of a running mode and the system's
//! authorization, and then replaces what the engine runs. A transaction that
//! leaves the engine as it is succeeds whatever state the engine is in.

use std::sync::atomic::AtomicBool;

use super::kept_engine::{PROFILE, newer_document, running_system_proxy};
use super::restoration::{RestorationRightsBridge, engine_with_rights_bridge};
use super::*;
use crate::engine::{
    ManagedEngine, apply_profile_change_admitted_by, apply_profile_change_keeping_engine,
};
use cfw_application::ProfileChange;

const OTHER_PROFILE: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// A candidate for `profile_id` whose commit sets `committed`.
fn candidate(profile_id: &str, activate: bool, committed: &Arc<AtomicBool>) -> ProfileChange<()> {
    let committed = committed.clone();
    ProfileChange {
        profile_id: profile_id.into(),
        profile: newer_document(),
        activate,
        previous_profile: None,
        commit: Box::new(move || {
            committed.store(true, Ordering::Release);
            Ok(())
        }),
    }
}

#[tokio::test]
async fn a_change_by_hand_restarts_the_running_engine_after_admission_and_authorization() {
    let (engine, bridge, before) = running_system_proxy().await;
    let revision = engine.mode_intent_revision().expect("revision");
    let admissions = Arc::new(Mutex::new(Vec::new()));
    let asked = admissions.clone();
    let committed = Arc::new(AtomicBool::new(false));
    let change = candidate(PROFILE, true, &committed);

    let result = apply_profile_change_admitted_by(
        &engine,
        move |mode| {
            asked.lock().expect("admissions").push(mode);
            Ok(())
        },
        move |_settings| async move { Ok(change) },
    )
    .await;

    assert_eq!(result, Ok(()));
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(
        *admissions.lock().expect("admissions"),
        [EngineMode::SystemProxy]
    );
    assert_eq!(
        bridge.requests(),
        [false],
        "macOS authorizes the System Proxy change once, with full rights"
    );
    let after = engine.coordinator.snapshot();
    assert_eq!(after.desired_mode, EngineMode::SystemProxy);
    assert!(
        after.generation > before.generation,
        "the engine was restarted"
    );
    assert_ne!(after.config_digest, before.config_digest);
    assert_eq!(
        engine.mode_intent_revision(),
        Ok(revision + 1),
        "a change by hand is a new mode intent"
    );
    // The controller is the new runtime's.
    let digest = |snapshot: &EngineSnapshot| snapshot.config_digest.clone().expect("digest");
    assert!(
        engine
            .active_controller_access(after.generation, &digest(&after))
            .is_ok()
    );
    assert!(
        engine
            .active_controller_access(before.generation, &digest(&before))
            .is_err()
    );
    assert!(
        engine.reserve_maintenance().is_ok(),
        "the turn was returned"
    );
}

#[tokio::test]
async fn a_refused_start_admission_ends_an_activating_change_before_authorization() {
    let (engine, bridge, before) = running_system_proxy().await;
    let refuse = |_mode: EngineMode| Err("a legacy client is still running".to_owned());
    let committed = Arc::new(AtomicBool::new(false));
    let change = candidate(PROFILE, true, &committed);
    let result =
        apply_profile_change_admitted_by(
            &engine,
            refuse,
            move |_settings| async move { Ok(change) },
        )
        .await;
    assert_eq!(
        result,
        Err("profile preparation failed: a legacy client is still running".to_owned())
    );
    assert!(!committed.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot(), before);
    assert!(bridge.requests().is_empty());

    // A change that activates nothing starts nothing: the refusal does not
    // concern it, and neither does macOS.
    let change = candidate(OTHER_PROFILE, false, &committed);
    let result =
        apply_profile_change_admitted_by(
            &engine,
            refuse,
            move |_settings| async move { Ok(change) },
        )
        .await;
    assert_eq!(result, Ok(()));
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot(), before);
    assert!(bridge.requests().is_empty());
}

#[tokio::test]
async fn an_engine_that_is_off_is_asked_for_no_start_admission_and_no_authorization() {
    let bridge = Arc::new(RestorationRightsBridge::default());
    let engine = engine_with_rights_bridge(bridge.clone());
    let committed = Arc::new(AtomicBool::new(false));
    let change = candidate(PROFILE, true, &committed);
    let result = apply_profile_change_admitted_by(
        &engine,
        |mode| -> Result<(), String> { panic!("an engine that is off starts no {mode:?}") },
        move |_settings| async move { Ok(change) },
    )
    .await;
    assert_eq!(result, Ok(()));
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot().state, EngineState::Off);
    assert!(bridge.requests().is_empty());
}

/// An engine whose start failed: nothing runs, and its state names no runtime
/// a controller could be bound to.
async fn failed_engine() -> ManagedEngine {
    let mut backend = EndpointRetryBackend::new(0);
    backend.rule_set_start_failure = Some(BackendErrorKind::SystemProxyRuntimeFailed);
    let engine = ManagedEngine {
        coordinator: endpoint_retry_coordinator(Arc::new(backend)),
        ..engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()))
    };
    let two_remote_nodes = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080}]}"#,
    )
    .expect("two remote nodes");
    let settings = EngineSettings {
        mainland_china_direct: true,
        ..EngineSettings::default()
    };
    engine
        .coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            two_remote_nodes,
            settings,
        )
        .await
        .expect_err("the rule sets cannot be downloaded");
    engine
}

#[tokio::test]
async fn a_change_that_starts_nothing_is_committed_beside_an_engine_that_failed() {
    let engine = failed_engine().await;
    let before = engine.coordinator.snapshot();
    assert!(
        matches!(before.state, EngineState::Failed { .. }),
        "{:?}",
        before.state
    );
    assert!(
        record_endpoint_runtime(
            &engine.endpoints,
            engine.coordinator.runtime_platform(),
            &before
        )
        .is_err(),
        "this state binds no controller"
    );

    let by_hand = Arc::new(AtomicBool::new(false));
    let change = candidate(OTHER_PROFILE, false, &by_hand);
    let result = apply_profile_change_admitted_by(
        &engine,
        |_mode| Ok(()),
        move |_settings| async move { Ok(change) },
    )
    .await;
    assert_eq!(result, Ok(()), "by hand");
    assert!(by_hand.load(Ordering::Acquire));

    let in_the_background = Arc::new(AtomicBool::new(false));
    let change = candidate(OTHER_PROFILE, false, &in_the_background);
    let result =
        apply_profile_change_keeping_engine(
            &engine,
            move |_settings, _mode| async move { Ok(change) },
        )
        .await;
    assert_eq!(result, Ok(()), "in the background");
    assert!(in_the_background.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot(), before);
}
