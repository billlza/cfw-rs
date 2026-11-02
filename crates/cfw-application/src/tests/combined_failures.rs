//! A validation failure followed by a failed cleanup or Off proof reports
//! both causes, and a failed rollback reports the change and the rollback.

use std::{sync::Arc, time::Duration};

use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineState, NativeEngineStatus, RuntimeIdentity,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::support::{FakeBackend, MemoryGenerationStore, coordinator, test_session};
use crate::{EngineCoordinatorError, EngineModeCoordinator, EngineOperation, ProfileChange};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn foreign_runtime(owner: EngineOwner, generation: u64) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: EngineCommandContext {
            installation_id: "not-a-canonical-uuid".to_owned(),
            config_epoch: 4,
            generation,
        },
        config_digest: "a".repeat(64),
        ready: true,
    }
}

fn journal_unavailable(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_journal_unavailable_with(
        backend,
        "Data Protection Keychain is unavailable",
        Duration::from_millis(100),
        |task| {
            tokio::spawn(task);
        },
    )
}

fn set(flag: &std::sync::Mutex<bool>) {
    *flag.lock().expect("fake backend flag") = true;
}

#[tokio::test]
async fn an_invalid_recovered_runtime_whose_cleanup_fails_reports_both() {
    let backend = Arc::new(FakeBackend::default());
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: foreign_runtime(EngineOwner::ProxyAgent, 9),
    });
    set(&backend.fail_proxy_stop);
    let coordinator = journal_unavailable(backend.clone());

    let error = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("the cleanup failed");
    assert!(
        matches!(
            &error,
            EngineCoordinatorError::ValidationAndCleanupFailed {
                validation_error,
                cleanup_operation: EngineOperation::StopSystemProxy,
                ..
            } if matches!(
                **validation_error,
                EngineCoordinatorError::RecoveredRuntimeMismatch {
                    mismatch: crate::RecoveredRuntimeMismatch::InvalidInstallation,
                    ..
                }
            )
        ),
        "{error:?}"
    );
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn an_invalid_recovered_runtime_without_an_off_proof_reports_both() {
    let backend = Arc::new(FakeBackend::default());
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: foreign_runtime(EngineOwner::ProxyAgent, 9),
    });
    set(&backend.stop_leaves_owner_present);
    let coordinator = journal_unavailable(backend.clone());

    let error = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("the owner is still present after the stop");
    assert!(
        matches!(
            &error,
            EngineCoordinatorError::ValidationAndOffProofFailed { validation_error, .. }
                if matches!(
                    **validation_error,
                    EngineCoordinatorError::RecoveredRuntimeMismatch { .. }
                )
        ),
        "{error:?}"
    );
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn a_mismatched_recovered_owner_whose_cleanup_fails_reports_both() {
    let backend = Arc::new(FakeBackend::default());
    let session = test_session();
    backend.set_native_status(NativeEngineStatus::SystemProxy {
        runtime: RuntimeIdentity {
            owner: EngineOwner::PacketTunnelSystemExtension,
            context: EngineCommandContext::new(&session, 7),
            config_digest: "a".repeat(64),
            ready: true,
        },
    });
    set(&backend.fail_proxy_stop);
    let coordinator = EngineModeCoordinator::spawn_persisted(
        backend.clone(),
        Arc::new(MemoryGenerationStore::new(7)),
        Duration::from_millis(100),
    )
    .expect("persisted coordinator");

    let error = coordinator
        .wait_for_reconciliation()
        .await
        .expect_err("the cleanup failed");
    assert!(
        matches!(
            &error,
            EngineCoordinatorError::ValidationAndCleanupFailed { validation_error, .. }
                if matches!(
                    **validation_error,
                    EngineCoordinatorError::RecoveredRuntimeMismatch { .. }
                )
        ),
        "{error:?}"
    );
    assert_eq!(backend.operations(), vec!["stop_proxy"]);
}

#[tokio::test]
async fn a_started_runtime_with_the_wrong_identity_and_a_failed_stop_reports_both() {
    let backend = Arc::new(FakeBackend::default());
    set(&backend.wrong_proxy_digest);
    set(&backend.fail_proxy_stop);
    let coordinator = coordinator(backend.clone());

    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            PROFILE.to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("identity mismatch with a failed rollback");
    assert!(
        matches!(
            &error,
            EngineCoordinatorError::ValidationAndCleanupFailed {
                validation_error,
                cleanup_operation: EngineOperation::StopSystemProxy,
                ..
            } if matches!(
                **validation_error,
                EngineCoordinatorError::RuntimeIdentityMismatch { .. }
            )
        ),
        "{error:?}"
    );
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn a_profile_change_whose_rollback_also_fails_reports_both() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::LocalProxy,
            PROFILE.into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("working runtime");
    set(&backend.fail_proxy_start);
    let change = ProfileChange {
        profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
        profile: ValidatedSingBoxProfile::direct(),
        activate: true,
        previous_profile: Some((PROFILE.into(), ValidatedSingBoxProfile::direct())),
        commit: Box::new(|| Ok(String::from("committed"))),
    };

    let error = coordinator
        .change_profile(EngineSettings::default(), async { Ok(change) })
        .await
        .expect_err("both starts fail");
    assert!(
        matches!(
            error,
            EngineCoordinatorError::ProfileChangeRollbackFailed { .. }
        ),
        "{error:?}"
    );
    assert_eq!(backend.proxy_requests().len(), 3);
}

#[test]
fn every_engine_operation_has_a_stable_name() {
    for (operation, name) in [
        (EngineOperation::QueryStatus, "query_status"),
        (EngineOperation::CheckConfiguration, "check_configuration"),
        (EngineOperation::StartLocalProxy, "start_local_proxy"),
        (EngineOperation::StopLocalProxy, "stop_local_proxy"),
        (EngineOperation::StartSystemProxy, "start_system_proxy"),
        (EngineOperation::StopSystemProxy, "stop_system_proxy"),
        (EngineOperation::InstallTunnel, "install_tunnel"),
        (
            EngineOperation::CancelTunnelInstall,
            "cancel_tunnel_install",
        ),
        (
            EngineOperation::AuthorizeTunnelConfiguration,
            "authorize_tunnel_configuration",
        ),
        (EngineOperation::StartTunnel, "start_tunnel"),
        (EngineOperation::StopTunnel, "stop_tunnel"),
    ] {
        assert_eq!(operation.to_string(), name);
    }
}
