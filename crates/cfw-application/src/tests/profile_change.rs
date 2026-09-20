use super::support::{FakeBackend, coordinator};
use crate::{EngineCoordinatorError, ProfileChange};
use cfw_engine_api::{BackendErrorKind, EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const OLD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NEW: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn candidate(committed: Arc<AtomicBool>, fail_commit: bool) -> ProfileChange<String> {
    ProfileChange {
        profile_id: NEW.into(),
        profile: ValidatedSingBoxProfile::direct(),
        activate: true,
        previous_profile: Some((OLD.into(), ValidatedSingBoxProfile::direct())),
        commit: Box::new(move || {
            if fail_commit {
                return Err("injected catalog failure before commit".into());
            }
            committed.store(true, Ordering::Release);
            Ok(NEW.into())
        }),
    }
}

#[tokio::test]
async fn an_identical_download_commits_without_interrupting_the_working_runtime() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let before = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let committed = Arc::new(AtomicBool::new(false));
    let mut change = candidate(committed.clone(), false);
    change.profile_id = OLD.into();
    coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap();
    assert!(committed.load(Ordering::Acquire));
    assert_eq!(coordinator.snapshot(), before);
    assert_eq!(backend.operations(), ["start_proxy"]);
}

#[tokio::test]
async fn invalid_candidate_leaves_working_runtime_and_catalog_untouched() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let before = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    *backend.configuration_check_error.lock().unwrap() =
        Some(BackendErrorKind::ConfigurationRejected);
    let committed = Arc::new(AtomicBool::new(false));
    let change = candidate(committed.clone(), false);
    let error = coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        EngineCoordinatorError::Backend {
            operation: crate::EngineOperation::CheckConfiguration,
            ..
        }
    ));
    assert_eq!(before, coordinator.snapshot());
    assert!(!committed.load(Ordering::Acquire));
    assert_eq!(backend.operations(), ["start_proxy", "check_configuration"]);
}

#[tokio::test]
async fn online_change_validates_before_stop_and_commits_after_ready() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let committed = Arc::new(AtomicBool::new(false));
    let mut change = candidate(committed.clone(), false);
    let prior_commit = change.commit;
    let observer = coordinator.clone();
    change.commit = Box::new(move || {
        assert!(matches!(
            observer.snapshot().state,
            EngineState::LocalProxyActive { .. }
        ));
        prior_commit()
    });
    assert_eq!(
        coordinator
            .change_profile(EngineSettings::default(), async { Ok(change) })
            .await
            .unwrap(),
        NEW
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
    let spec = coordinator.restart_spec().await.unwrap().unwrap();
    assert_eq!(spec.profile_id(), NEW);
    assert!(spec.matches_ready_snapshot(&coordinator.snapshot()));
}

#[tokio::test]
async fn candidate_start_failure_restores_exact_prior_source_with_fresh_generation() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let old = coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    *backend.fail_proxy_start_once.lock().unwrap() = true;
    let committed = Arc::new(AtomicBool::new(false));
    let change = candidate(committed.clone(), false);
    let error = coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            EngineCoordinatorError::ProfileChangeRolledBack { .. }
        ),
        "{error}"
    );
    assert!(!committed.load(Ordering::Acquire));
    let spec = coordinator.restart_spec().await.unwrap().unwrap();
    assert_eq!(spec.profile_id(), OLD);
    assert!(spec.matches_ready_snapshot(&coordinator.snapshot()));
    assert!(coordinator.snapshot().generation > old.generation);
    let requests = backend.proxy_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].config_digest, requests[2].config_digest);
    assert_eq!(requests[0].mode, requests[2].mode);
}

#[tokio::test]
async fn catalog_failure_restores_prior_runtime_and_reports_failed_change() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let change = candidate(Arc::new(AtomicBool::new(false)), true);
    let error = coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            EngineCoordinatorError::ProfileChangeRolledBack { .. }
        ),
        "{error}"
    );
    assert_eq!(
        coordinator
            .restart_spec()
            .await
            .unwrap()
            .unwrap()
            .profile_id(),
        OLD
    );
    assert_eq!(backend.proxy_requests().len(), 3);
}

#[tokio::test]
async fn an_explicit_stop_before_admission_keeps_a_late_update_off() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    coordinator
        .set_mode(
            EngineMode::Off,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let change = candidate(Arc::new(AtomicBool::new(false)), false);
    coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap();
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
    assert_eq!(backend.operations(), ["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn unproven_candidate_cleanup_does_not_attempt_a_second_start() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    *backend.fail_proxy_start_once.lock().unwrap() = true;
    // A post-stop observation still reports an owner; no fresh runtime is safe.
    *backend.stop_leaves_owner_present.lock().unwrap() = true;
    let change = candidate(Arc::new(AtomicBool::new(false)), false);
    let error = coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            EngineCoordinatorError::ProfileChangeRecoveryRequired { .. }
        ),
        "{error}"
    );
    assert_eq!(backend.proxy_requests().len(), 1);
}

#[tokio::test]
async fn native_preparation_is_serialized_with_polling_and_survives_a_dropped_waiter() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            OLD.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .unwrap();
    let admitted = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let operation = tokio::spawn({
        let coordinator = coordinator.clone();
        let admitted = admitted.clone();
        let release = release.clone();
        async move {
            coordinator
                .change_profile(EngineSettings::default(), async move {
                    admitted.notify_one();
                    release.notified().await;
                    Ok(candidate(Arc::new(AtomicBool::new(false)), false))
                })
                .await
        }
    });
    admitted.notified().await;
    let before = backend.query_count();
    tokio::time::sleep(std::time::Duration::from_millis(65)).await;
    assert_eq!(
        backend.query_count(),
        before,
        "polling must not race native credential preparation"
    );
    operation.abort();
    release.notify_one();
    let spec = coordinator.restart_spec().await.unwrap().unwrap();
    assert_eq!(spec.profile_id(), NEW);
    assert!(spec.matches_ready_snapshot(&coordinator.snapshot()));
}
