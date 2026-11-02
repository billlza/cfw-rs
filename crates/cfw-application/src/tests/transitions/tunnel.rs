//! Tunnel transitions: stopping the proxy first, extension and VPN approvals,
//! and restarts when tunnel options change.

use super::*;

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
async fn only_an_awaited_extension_approval_names_its_pending_installation() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let start = || {
        coordinator.set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
    };
    let off = coordinator.snapshot();
    assert_eq!(
        coordinator.pending_tunnel_approval(off.clone()).await,
        Ok(None)
    );

    *backend.awaiting_approval.lock().expect("approval lock") = true;
    let awaiting = start().await.expect("approval is a stable pending state");
    let context = coordinator
        .pending_tunnel_approval(awaiting.clone())
        .await
        .expect("query")
        .expect("the installation awaits approval");
    assert_eq!(backend.tunnel_install_contexts(), [context]);
    assert_eq!(
        coordinator.pending_tunnel_approval(off).await,
        Ok(None),
        "a stale observation names nothing"
    );

    *backend.awaiting_approval.lock().expect("approval lock") = false;
    let active = start().await.expect("the approved retry starts");
    assert!(matches!(active.state, EngineState::TunnelActive { .. }));
    assert_eq!(
        coordinator.pending_tunnel_approval(awaiting).await,
        Ok(None)
    );
    assert_eq!(coordinator.pending_tunnel_approval(active).await, Ok(None));
}

#[test]
fn a_start_waiting_for_the_vpn_consent_names_no_pending_installation() {
    use crate::runtime::{CoordinatorState, NativeLease, NativeLeaseKind, pending_tunnel_approval};
    let snapshot = EngineSnapshot {
        desired_mode: EngineMode::Tunnel,
        state: EngineState::AwaitingApproval { generation: 5 },
        generation: 5,
        config_digest: Some("ab".repeat(32)),
    };
    let context = cfw_engine_api::EngineCommandContext::new(&test_session(), 5);
    let state = |kind, generation| CoordinatorState {
        runtime_platform: cfw_engine_api::EngineRuntimePlatform::MacOs,
        snapshot: snapshot.clone(),
        native_lease: Some(NativeLease {
            kind,
            context: cfw_engine_api::EngineCommandContext::new(&test_session(), generation),
        }),
        quarantine: None,
        restart_spec: None,
        status_recheck: None,
        missed_observations: 0,
    };
    assert_eq!(
        pending_tunnel_approval(&state(NativeLeaseKind::TunnelInstallation, 5), &snapshot),
        Some(context)
    );
    assert_eq!(
        pending_tunnel_approval(&state(NativeLeaseKind::TunnelRuntime, 5), &snapshot),
        None
    );
    assert_eq!(
        pending_tunnel_approval(&state(NativeLeaseKind::TunnelInstallation, 4), &snapshot),
        None
    );
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
