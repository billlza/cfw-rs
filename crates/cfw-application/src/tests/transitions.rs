use std::{sync::Arc, time::Duration};

use cfw_engine_api::{
    BackendError, BackendErrorKind, EngineMode, EngineOwner, EngineSnapshot, EngineState,
    NativeEngineStatus,
};
use cfw_singbox_config::{
    EngineSettings, RELEASE_PACKET_TRANSPORT_IPV4, ReleasePacketEvidenceCase,
    ValidatedSingBoxProfile,
};

use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator, EngineOperation};

use super::support::{FakeBackend, coordinator, test_session};

async fn wait_for_failed(coordinator: &EngineModeCoordinator) -> EngineSnapshot {
    let mut snapshots = coordinator.subscribe();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = snapshots.borrow().clone();
            if matches!(snapshot.state, EngineState::Failed { .. }) {
                return snapshot;
            }
            snapshots
                .changed()
                .await
                .expect("coordinator remains available while awaiting failure");
        }
    })
    .await
    .expect("active runtime reconciliation publishes failure before the deadline")
}

#[tokio::test]
async fn starts_proxy_only_after_publishing_starting_state() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");

    assert!(matches!(snapshot.state, EngineState::ProxyActive { .. }));
    assert_eq!(backend.operations(), vec!["start_proxy"]);
}

#[tokio::test]
async fn periodic_reconciliation_detects_proxy_crash_and_retains_exact_stop_ownership() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    let expected_context = match active.state {
        EngineState::ProxyActive { runtime } => runtime.context,
        state => panic!("expected active proxy, received {state:?}"),
    };

    backend.set_native_status(NativeEngineStatus::Off);
    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(
        failed.state,
        EngineState::Failed {
            target: EngineMode::SystemProxy,
            ..
        }
    ));

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("exact proxy ownership is stopped after the failed observation");
    assert_eq!(backend.proxy_stop_contexts(), vec![expected_context]);
}

#[tokio::test]
async fn periodic_reconciliation_detects_tunnel_crash_and_retains_exact_stop_ownership() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start tunnel");
    let expected_context = match active.state {
        EngineState::TunnelActive { runtime } => runtime.context,
        state => panic!("expected active tunnel, received {state:?}"),
    };

    backend.set_native_status(NativeEngineStatus::Off);
    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(
        failed.state,
        EngineState::Failed {
            target: EngineMode::Tunnel,
            ..
        }
    ));

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("exact tunnel ownership is stopped after the failed observation");
    assert_eq!(backend.tunnel_stop_contexts(), vec![expected_context]);
}

#[tokio::test]
async fn periodic_query_failure_invalidates_active_snapshot_without_releasing_ownership() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    let expected_context = match active.state {
        EngineState::ProxyActive { runtime } => runtime.context,
        state => panic!("expected active proxy, received {state:?}"),
    };
    *backend.fail_query.lock().expect("query failure lock") = true;

    let failed = wait_for_failed(&coordinator).await;
    let error = match failed.state {
        EngineState::Failed { error, .. } => error,
        state => panic!("expected failed state, received {state:?}"),
    };
    assert!(error.contains("query_status"));

    *backend.fail_query.lock().expect("query failure lock") = false;
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("query failure retains the exact stop lease");
    assert_eq!(backend.proxy_stop_contexts(), vec![expected_context]);
}

#[tokio::test]
async fn same_digest_request_reconciles_immediately_before_idempotent_success() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(30),
            initial_generation: 0,
        },
    );
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    assert_eq!(backend.query_count(), 1, "startup query only");
    backend.set_native_status(NativeEngineStatus::Off);

    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("stale same-digest snapshot must not return success");
    assert!(matches!(
        error,
        EngineCoordinatorError::ActiveRuntimeStatusMismatch {
            expected_mode: EngineMode::SystemProxy,
            ..
        }
    ));
    assert_eq!(
        backend.query_count(),
        2,
        "same-digest request queried native state"
    );
    assert_eq!(backend.operations(), vec!["start_proxy"]);

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("cleanup retained ownership");
}

#[tokio::test]
async fn late_tunnel_identity_drift_fails_and_stops_the_original_context() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start tunnel");
    let expected_runtime = match active.state {
        EngineState::TunnelActive { runtime } => runtime,
        state => panic!("expected active tunnel, received {state:?}"),
    };
    let mut late_runtime = expected_runtime.clone();
    late_runtime.owner = EngineOwner::ProxyAgent;
    backend.set_native_status(NativeEngineStatus::Tunnel {
        runtime: late_runtime,
    });

    let failed = wait_for_failed(&coordinator).await;
    assert!(matches!(failed.state, EngineState::Failed { .. }));
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("late drift retains original stop ownership");
    assert_eq!(
        backend.tunnel_stop_contexts(),
        vec![expected_runtime.context]
    );
}

#[tokio::test]
async fn approval_wait_is_not_misclassified_as_an_active_runtime_crash() {
    let backend = Arc::new(FakeBackend::default());
    *backend.awaiting_approval.lock().expect("approval lock") = true;
    let coordinator = coordinator(backend.clone());
    let awaiting = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("await approval");
    tokio::time::sleep(Duration::from_millis(70)).await;

    assert_eq!(coordinator.snapshot(), awaiting);
    assert_eq!(
        backend.query_count(),
        1,
        "periodic active-runtime reconciliation must skip approval waits"
    );
    coordinator.shutdown().await.expect("cancel approval wait");
}

#[tokio::test(start_paused = true)]
async fn reconciliation_skips_missed_ticks_and_resumes_after_suspension() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(2),
            initial_generation: 0,
        },
    );
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    assert_eq!(backend.query_count(), 1);

    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        backend.query_count(),
        2,
        "a suspended actor performs one skipped-tick reconciliation, not a burst"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(backend.query_count(), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.query_count(), 3, "the regular cadence resumes");

    coordinator.shutdown().await.expect("stop proxy");
}

#[tokio::test]
async fn proxy_to_tunnel_always_stops_before_installing() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy");
    let snapshot = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start tunnel");

    assert!(matches!(snapshot.state, EngineState::TunnelActive { .. }));
    assert_eq!(
        backend.operations(),
        vec![
            "start_proxy",
            "stop_proxy",
            "install_tunnel",
            "start_tunnel"
        ]
    );
}

#[tokio::test]
async fn runtime_identity_mismatch_fails_closed_and_stops_proxy() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .wrong_proxy_digest
        .lock()
        .expect("wrong digest lock") = true;
    let coordinator = coordinator(backend.clone());
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("identity mismatch must fail");

    assert!(matches!(
        error,
        EngineCoordinatorError::RuntimeIdentityMismatch { .. }
    ));
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn wrong_owner_is_cleaned_up_using_the_attempted_proxy_mode() {
    let backend = Arc::new(FakeBackend::default());
    *backend.wrong_proxy_owner.lock().expect("wrong owner lock") = true;
    let coordinator = coordinator(backend.clone());
    coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("wrong owner must fail");

    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn failed_cleanup_blocks_all_subsequent_starts() {
    let backend = Arc::new(FakeBackend::default());
    *backend.fail_proxy_start.lock().expect("fail start lock") = true;
    *backend.fail_proxy_stop.lock().expect("fail stop lock") = true;
    let coordinator = coordinator(backend.clone());
    let first_error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("start and cleanup must fail");
    assert!(matches!(
        first_error,
        EngineCoordinatorError::StartAndCleanupFailed { .. }
    ));

    *backend.fail_proxy_start.lock().expect("fail start lock") = false;
    let second_error = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("uncertain proxy ownership must block tunnel");
    assert!(matches!(
        second_error,
        EngineCoordinatorError::Backend {
            operation: EngineOperation::StopSystemProxy,
            ..
        }
    ));
    assert_eq!(
        backend.operations(),
        vec!["start_proxy", "stop_proxy", "stop_proxy"]
    );
}

#[tokio::test]
async fn backend_timeout_is_explicit_and_cleanup_is_attempted() {
    let backend = Arc::new(FakeBackend::default());
    *backend.hang_proxy_start.lock().expect("hang start lock") = true;
    let coordinator = EngineModeCoordinator::spawn_with_options(
        backend.clone(),
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(10),
            status_query_timeout: Duration::from_millis(10),
            status_reconciliation_interval: Duration::from_millis(20),
            initial_generation: 0,
        },
    );
    let error = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("hung start must time out");

    assert!(matches!(
        error,
        EngineCoordinatorError::Backend {
            source: BackendError {
                kind: BackendErrorKind::Timeout,
                ..
            },
            ..
        }
    ));
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
}

#[tokio::test]
async fn approved_system_extension_retry_cancels_old_wait_before_starting_new_generation() {
    let backend = Arc::new(FakeBackend::default());
    *backend.awaiting_approval.lock().expect("approval lock") = true;
    let coordinator = coordinator(backend.clone());
    let snapshot = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("approval is a stable pending state");

    assert!(matches!(
        snapshot.state,
        EngineState::AwaitingApproval { .. }
    ));
    assert_eq!(backend.operations(), vec!["install_tunnel"]);

    *backend.awaiting_approval.lock().expect("approval lock") = false;
    let activated = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("approved system extension starts on explicit retry");

    assert!(matches!(activated.state, EngineState::TunnelActive { .. }));
    assert_eq!(activated.generation, snapshot.generation + 1);
    assert_eq!(
        backend.operations(),
        vec![
            "install_tunnel",
            "cancel_tunnel_install",
            "install_tunnel",
            "start_tunnel"
        ]
    );

    let install_contexts = backend.tunnel_install_contexts();
    let cancel_contexts = backend.tunnel_cancel_contexts();
    assert_eq!(install_contexts.len(), 2);
    assert_eq!(cancel_contexts, vec![install_contexts[0].clone()]);
    assert_eq!(install_contexts[0].generation, snapshot.generation);
    assert_eq!(install_contexts[1].generation, activated.generation);
    assert_ne!(install_contexts[0], install_contexts[1]);
    assert_eq!(
        backend.tunnel_requests()[0].context,
        install_contexts[1],
        "a late completion carrying the cancelled context cannot identify the new runtime"
    );

    coordinator.shutdown().await.expect("stop active tunnel");
    assert_eq!(
        backend.operations(),
        vec![
            "install_tunnel",
            "cancel_tunnel_install",
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel"
        ]
    );
}

#[tokio::test]
async fn tunnel_mtu_and_private_bypass_changes_restart_with_new_identity() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let initial = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("initial tunnel");

    let mtu_changed = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings {
                tunnel_mtu: 1_400,
                ..EngineSettings::default()
            },
        )
        .await
        .expect("MTU restart");
    let bypass_changed = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings {
                tunnel_mtu: 1_400,
                bypass_private_networks: false,
                ..EngineSettings::default()
            },
        )
        .await
        .expect("private-network capture restart");

    assert_eq!(mtu_changed.generation, initial.generation + 1);
    assert_eq!(bypass_changed.generation, mtu_changed.generation + 1);
    let requests = backend.tunnel_requests();
    assert_eq!(requests.len(), 3);
    assert_ne!(requests[0].config_json, requests[1].config_json);
    assert_eq!(requests[1].config_json, requests[2].config_json);
    assert_ne!(
        requests[0].config_content_digest,
        requests[1].config_content_digest
    );
    assert_eq!(
        requests[1].config_content_digest,
        requests[2].config_content_digest
    );
    assert_ne!(requests[0].config_digest, requests[1].config_digest);
    assert_ne!(requests[1].config_digest, requests[2].config_digest);
    assert_eq!(requests[1].tunnel_options.expect("MTU options").mtu, 1_400);
    assert!(
        !requests[2]
            .tunnel_options
            .expect("bypass options")
            .bypass_private_networks
    );
    assert_eq!(
        backend.operations(),
        vec![
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel",
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel",
            "install_tunnel",
            "start_tunnel",
        ]
    );
}

#[tokio::test]
async fn release_excluded_route_restarts_with_the_exact_identity_bound_native_option() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let ordinary = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("ordinary tunnel");
    let excluded = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::release_packet_evidence(
                ReleasePacketEvidenceCase::ExcludedRoutes,
            ),
            EngineSettings::default(),
        )
        .await
        .expect("excluded-route tunnel");

    assert_eq!(excluded.generation, ordinary.generation + 1);
    let requests = backend.tunnel_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].config_json, requests[1].config_json);
    assert_eq!(
        requests[0].config_content_digest,
        requests[1].config_content_digest
    );
    assert_ne!(requests[0].config_digest, requests[1].config_digest);
    assert!(
        requests[0]
            .tunnel_options
            .expect("ordinary options")
            .direct_ipv4_hosts
            .is_empty()
    );
    assert_eq!(
        requests[1]
            .tunnel_options
            .expect("release options")
            .direct_ipv4_hosts
            .as_slice(),
        &[RELEASE_PACKET_TRANSPORT_IPV4]
    );
}
