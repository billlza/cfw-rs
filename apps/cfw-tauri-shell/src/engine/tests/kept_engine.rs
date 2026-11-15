//! Background profile transactions: a turn in the queue that is no new mode
//! intent, and a change that never replaces what the engine runs and never
//! asks the system for authorization.

use std::sync::atomic::AtomicBool;

use super::restoration::{RestorationRightsBridge, engine_with_rights_bridge};
use super::*;
use crate::engine::{KeptEngineChangeError, ManagedEngine, apply_profile_change_keeping_engine};
use cfw_application::{EngineCoordinatorError, ProfileChange};

pub(super) const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

pub(super) fn newer_document() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"direct","tag":"DIRECT"},{"type":"block","tag":"REJECT"},{"type":"selector","tag":"PROXY","outbounds":["DIRECT","REJECT"]}],"route":{"final":"PROXY"}}"#,
    )
    .expect("newer document")
}

/// An engine in System Proxy mode, the mode whose changes macOS authorizes.
pub(super) async fn running_system_proxy()
-> (ManagedEngine, Arc<RestorationRightsBridge>, EngineSnapshot) {
    let bridge = Arc::new(RestorationRightsBridge::default());
    let engine = engine_with_rights_bridge(bridge.clone());
    let snapshot = engine
        .coordinator
        .set_mode(
            EngineMode::SystemProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            engine.engine_settings().expect("engine settings"),
        )
        .await
        .expect("running engine");
    record_endpoint_runtime(
        &engine.endpoints,
        engine.coordinator.runtime_platform(),
        &snapshot,
    )
    .expect("controller binding");
    (engine, bridge, snapshot)
}

#[tokio::test]
async fn storage_work_that_keeps_the_runtime_is_no_new_mode_intent() {
    let gate = EngineMaintenanceGate::default();
    let observed = gate.intent_revision().expect("revision");
    let storage_work = gate
        .begin_mode_change(EngineModeChangeIntent::KeepRuntime)
        .await
        .expect("admission");
    assert_eq!(gate.intent_revision(), Ok(observed));
    drop(storage_work);
    // An automatic request that observed the intent before the storage work
    // is still current ...
    let automatic = gate
        .begin_mode_change_if_current(
            EngineModeChangeIntent::Set(EngineMode::SystemProxy),
            Some(observed),
        )
        .await
        .expect("the automatic request was not superseded");
    drop(automatic);
    // ... while a mode change by the user supersedes one.
    let observed = gate.intent_revision().expect("revision");
    drop(
        gate.begin_mode_change(EngineModeChangeIntent::ReapplyCurrent)
            .await
            .expect("user change"),
    );
    assert!(matches!(
        gate.begin_mode_change_if_current(
            EngineModeChangeIntent::Set(EngineMode::SystemProxy),
            Some(observed),
        )
        .await,
        Err(EngineMaintenanceError::StaleIntent)
    ));
}

#[tokio::test]
async fn storage_work_takes_its_turn_and_is_visible_to_maintenance() {
    let gate = EngineMaintenanceGate::default();
    let mode_change = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("mode change admission");
    let storage_work = gate.begin_mode_change(EngineModeChangeIntent::KeepRuntime);
    tokio::pin!(storage_work);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut storage_work)
            .await
            .is_err(),
        "storage work waits for the mode change before it"
    );
    drop(mode_change);
    let storage_work = tokio::time::timeout(Duration::from_secs(1), &mut storage_work)
        .await
        .expect("storage work resumes")
        .expect("storage work admission");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    let next = gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off));
    tokio::pin!(next);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut next)
            .await
            .is_err(),
        "a mode change waits for the storage work before it"
    );
    drop(storage_work);
    drop(
        tokio::time::timeout(Duration::from_secs(1), &mut next)
            .await
            .expect("the mode change resumes")
            .expect("mode change admission"),
    );
    let maintenance = gate.reserve_if_idle().expect("idle admission");
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::KeepRuntime)
            .await,
        Err(EngineMaintenanceError::AlreadyActive)
    ));
    drop(maintenance);
}

#[tokio::test]
async fn saving_what_the_engine_runs_asks_for_nothing_and_is_no_new_intent() {
    let (engine, bridge, before) = running_system_proxy().await;
    let revision = engine.mode_intent_revision().expect("revision");
    let committed = Arc::new(AtomicBool::new(false));
    let commit = committed.clone();
    let seen = apply_profile_change_keeping_engine(&engine, move |settings, mode| async move {
        Ok(ProfileChange {
            profile_id: PROFILE.into(),
            profile: ValidatedSingBoxProfile::direct(),
            activate: true,
            previous_profile: None,
            commit: Box::new(move || {
                commit.store(true, Ordering::Release);
                Ok((settings, mode))
            }),
        })
    })
    .await
    .expect("committed");
    assert_eq!(
        seen,
        (
            engine.engine_settings().expect("engine settings"),
            EngineMode::SystemProxy
        ),
        "the preparation learns the settings and the mode of its turn"
    );
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot(), before);
    assert!(
        bridge.requests().is_empty(),
        "background work never asks macOS for authorization"
    );
    assert_eq!(engine.mode_intent_revision(), Ok(revision));
    assert!(
        engine.reserve_maintenance().is_ok(),
        "the turn was returned"
    );
}

#[tokio::test]
async fn a_change_that_needs_a_restart_is_declined_without_asking_for_authorization() {
    let (engine, bridge, before) = running_system_proxy().await;
    let committed = Arc::new(AtomicBool::new(false));
    let commit = committed.clone();
    let result = apply_profile_change_keeping_engine(&engine, move |_settings, _mode| async move {
        Ok(ProfileChange {
            profile_id: PROFILE.into(),
            profile: newer_document(),
            activate: true,
            previous_profile: None,
            commit: Box::new(move || {
                commit.store(true, Ordering::Release);
                Ok(())
            }),
        })
    })
    .await;
    assert_eq!(result, Err(KeptEngineChangeError::RunningEngineKept));
    assert!(!committed.load(Ordering::Acquire));
    assert_eq!(engine.coordinator.snapshot(), before);
    assert!(bridge.requests().is_empty());
    assert!(
        engine.reserve_maintenance().is_ok(),
        "the turn was returned"
    );
}

#[tokio::test]
async fn a_preparation_that_declines_is_told_apart_from_one_that_fails() {
    let (engine, _bridge, before) = running_system_proxy().await;
    let declined = apply_profile_change_keeping_engine(&engine, |_settings, _mode| async {
        Err::<ProfileChange<()>, _>(EngineCoordinatorError::RunningEngineKept)
    })
    .await;
    assert_eq!(declined, Err(KeptEngineChangeError::RunningEngineKept));
    let failed = apply_profile_change_keeping_engine(&engine, |_settings, _mode| async {
        Err::<ProfileChange<()>, _>(EngineCoordinatorError::ProfilePreparation(
            "the download is not a profile".into(),
        ))
    })
    .await;
    assert_eq!(
        failed,
        Err(KeptEngineChangeError::Failed(
            "profile preparation failed: the download is not a profile".into()
        ))
    );
    assert_eq!(engine.coordinator.snapshot(), before);
}

#[tokio::test]
async fn background_work_is_not_admitted_under_maintenance_and_prepares_nothing() {
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let maintenance = engine.reserve_maintenance().expect("maintenance");
    let prepared = Arc::new(AtomicBool::new(false));
    let flag = prepared.clone();
    let result = apply_profile_change_keeping_engine(&engine, move |_settings, _mode| {
        flag.store(true, Ordering::Release);
        async { Err::<ProfileChange<()>, _>(EngineCoordinatorError::RunningEngineKept) }
    })
    .await;
    assert_eq!(
        result,
        Err(KeptEngineChangeError::NotAdmitted(
            EngineMaintenanceError::AlreadyActive
        ))
    );
    assert!(!prepared.load(Ordering::Acquire));
    drop(maintenance);
}

#[tokio::test]
async fn an_engine_that_is_off_saves_the_selected_profile_and_stays_off() {
    let bridge = Arc::new(RestorationRightsBridge::default());
    let engine = engine_with_rights_bridge(bridge.clone());
    let mode = apply_profile_change_keeping_engine(&engine, |_settings, mode| async move {
        Ok(ProfileChange {
            profile_id: PROFILE.into(),
            profile: newer_document(),
            activate: true,
            previous_profile: None,
            commit: Box::new(move || Ok(mode)),
        })
    })
    .await;
    assert_eq!(mode, Ok(EngineMode::Off));
    assert_eq!(engine.coordinator.snapshot().state, EngineState::Off);
    assert!(bridge.requests().is_empty());
}
