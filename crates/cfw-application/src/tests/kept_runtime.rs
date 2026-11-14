//! A profile change that keeps the running engine: what needs no replacement
//! is committed, and what would replace the runtime is declined before
//! anything is checked, stopped or committed.

use super::support::{FakeBackend, coordinator};
use crate::{EngineCoordinatorError, EngineModeCoordinator, ProfileChange, RunningEngine};
use cfw_engine_api::{EngineMode, EngineSnapshot, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const RUNNING: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn newer_document() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"direct","tag":"DIRECT"},{"type":"block","tag":"REJECT"},{"type":"selector","tag":"PROXY","outbounds":["DIRECT","REJECT"]}],"route":{"final":"PROXY"}}"#,
    )
    .expect("newer document")
}

fn change(
    profile_id: &str,
    profile: ValidatedSingBoxProfile,
    activate: bool,
    committed: &Arc<AtomicBool>,
) -> ProfileChange<&'static str> {
    let committed = committed.clone();
    ProfileChange {
        profile_id: profile_id.into(),
        profile,
        activate,
        previous_profile: Some((RUNNING.into(), ValidatedSingBoxProfile::direct())),
        commit: Box::new(move || {
            committed.store(true, Ordering::Release);
            Ok("committed")
        }),
    }
}

async fn running_local_proxy() -> (Arc<FakeBackend>, EngineModeCoordinator, EngineSnapshot) {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            RUNNING.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("running engine");
    (backend, coordinator, snapshot)
}

#[tokio::test]
async fn a_newer_document_of_the_running_profile_is_declined_untouched() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(RUNNING, newer_document(), true, &committed);
    let error = coordinator
        .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
            Ok(candidate)
        })
        .await
        .expect_err("the running engine is kept");
    assert_eq!(error, EngineCoordinatorError::RunningEngineKept);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(
        backend.operations(),
        ["start_proxy"],
        "a declined candidate is not even checked"
    );
    assert!(!committed.load(Ordering::Acquire));
    let spec = coordinator.restart_spec().await.unwrap().unwrap();
    assert_eq!(
        spec.profile().digest(),
        ValidatedSingBoxProfile::direct().digest()
    );
    assert!(spec.matches_ready_snapshot(&coordinator.snapshot()));

    // The same candidate is a valid replacement when the caller allows one.
    let candidate = change(RUNNING, newer_document(), true, &committed);
    assert_eq!(
        coordinator
            .change_profile_with(EngineSettings::default(), RunningEngine::Replace, async {
                Ok(candidate)
            })
            .await,
        Ok("committed")
    );
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(
        backend.operations(),
        [
            "start_proxy",
            "check_configuration",
            "stop_proxy",
            "start_proxy"
        ]
    );
}

#[tokio::test]
async fn another_profile_taking_over_the_running_engine_is_declined() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(OTHER, ValidatedSingBoxProfile::direct(), true, &committed);
    let error = coordinator
        .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
            Ok(candidate)
        })
        .await
        .expect_err("the running engine is kept");
    assert_eq!(error, EngineCoordinatorError::RunningEngineKept);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
    assert!(!committed.load(Ordering::Acquire));
}

#[tokio::test]
async fn different_settings_alone_would_restart_the_engine_and_are_declined() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(RUNNING, ValidatedSingBoxProfile::direct(), true, &committed);
    let settings = EngineSettings {
        mixed_port: EngineSettings::default().mixed_port + 1,
        ..EngineSettings::default()
    };
    let error = coordinator
        .change_profile_with(settings, RunningEngine::Keep, async { Ok(candidate) })
        .await
        .expect_err("the running engine is kept");
    assert_eq!(error, EngineCoordinatorError::RunningEngineKept);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
    assert!(!committed.load(Ordering::Acquire));
}

#[tokio::test]
async fn what_the_engine_already_runs_is_committed_without_touching_it() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(RUNNING, ValidatedSingBoxProfile::direct(), true, &committed);
    assert_eq!(
        coordinator
            .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
                Ok(candidate)
            })
            .await,
        Ok("committed")
    );
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
}

#[tokio::test]
async fn a_profile_the_engine_does_not_run_is_committed_while_it_runs() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(OTHER, newer_document(), false, &committed);
    assert_eq!(
        coordinator
            .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
                Ok(candidate)
            })
            .await,
        Ok("committed")
    );
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
}

#[tokio::test]
async fn the_selected_profile_is_committed_while_the_engine_is_off() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let committed = Arc::new(AtomicBool::new(false));
    let candidate = change(RUNNING, newer_document(), true, &committed);
    assert_eq!(
        coordinator
            .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
                Ok(candidate)
            })
            .await,
        Ok("committed")
    );
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert!(backend.operations().is_empty());
}

#[tokio::test]
async fn a_preparation_may_itself_report_that_it_kept_the_engine() {
    let (backend, coordinator, before) = running_local_proxy().await;
    let error = coordinator
        .change_profile_with(EngineSettings::default(), RunningEngine::Keep, async {
            Err::<ProfileChange<()>, _>(EngineCoordinatorError::RunningEngineKept)
        })
        .await
        .expect_err("the preparation declined");
    assert_eq!(error, EngineCoordinatorError::RunningEngineKept);
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
}
