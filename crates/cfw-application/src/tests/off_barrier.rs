//! Global Off barrier enforcement for stop and cross-mode switching in the
//! serialized coordinator (Requirements 2.4, 2.5, 3.2, 3.3, 7.3).
//!
//! These tests prove that:
//! - a Proxy<->Tunnel switch stops the current owner, performs an independent
//!   OS-state Off observation between the two owners, and allocates a fresh
//!   generation only after Off is proven;
//! - a switch whose stop attests the owner stopped but cannot prove the global
//!   Off barrier (a lingering owner is still observed) does not start the other
//!   mode, never restarts the previous mode, and stays fail-closed;
//! - an unavailable OS-state observation (connection loss) alone is never Off;
//! - the stop path also refuses to declare Off from an ambiguous observation.

use std::{sync::Arc, time::Duration};

use cfw_engine_api::{EngineMode, EngineState, NativeEngineStatus};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator, EngineOperation};

use super::support::{FakeBackend, test_session};

fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

/// Coordinator with a long periodic reconciliation interval so that the only
/// native queries observed are the startup reconciliation and the deterministic
/// Off-barrier proofs performed during a stop or switch.
fn quiet_coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(30),
            initial_generation: 0,
        },
    )
}

fn generation_of(state: &EngineState) -> u64 {
    match state {
        EngineState::ProxyActive { runtime } | EngineState::TunnelActive { runtime } => {
            runtime.context.generation
        }
        other => panic!("expected an active runtime, received {other:?}"),
    }
}

#[tokio::test]
async fn cross_mode_switch_proves_off_between_owners_then_allocates_fresh_generation() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    let proxy = coordinator
        .set_mode(EngineMode::SystemProxy, direct(), EngineSettings::default())
        .await
        .expect("start proxy");
    let proxy_generation = generation_of(&proxy.state);
    // Startup reconciliation only; a start from Off needs no Off proof.
    assert_eq!(backend.query_count(), 1);

    let tunnel = coordinator
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
        .await
        .expect("switch to tunnel");
    let tunnel_generation = generation_of(&tunnel.state);

    // The current owner is stopped before the target owner is prepared/started.
    assert_eq!(
        backend.operations(),
        vec![
            "start_proxy",
            "stop_proxy",
            "install_tunnel",
            "start_tunnel"
        ]
    );
    // Exactly one independent OS-state Off observation ran between the owners
    // (startup query + one Off proof during the switch).
    assert_eq!(
        backend.query_count(),
        2,
        "the switch proves global Off with an independent observation between owners"
    );
    // The fresh generation is allocated only after Off is proven.
    assert_eq!(tunnel_generation, proxy_generation + 1);
    assert_eq!(tunnel.generation, tunnel_generation);
}

#[tokio::test]
async fn switch_whose_stop_cannot_prove_off_does_not_start_other_mode() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    coordinator
        .set_mode(EngineMode::SystemProxy, direct(), EngineSettings::default())
        .await
        .expect("start proxy");

    // The stop attests the owner stopped, but the independent OS-state
    // observation still reports the proxy owner: the Off barrier is unproven.
    *backend
        .stop_leaves_owner_present
        .lock()
        .expect("stop leaves owner lock") = true;

    let error = coordinator
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
        .await
        .expect_err("an unproven Off barrier must block the target mode");
    assert!(
        matches!(error, EngineCoordinatorError::GlobalOffUnproven { .. }),
        "unexpected error: {error:?}"
    );

    // The other mode is never prepared/started and the previous mode is never
    // restarted on failure.
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));

    // The coordinator stays fail-closed: a newer operation is blocked by the
    // sticky quarantine and touches the backend for no new start.
    let blocked = coordinator
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
        .await
        .expect_err("quarantine blocks a newer operation");
    assert_eq!(blocked, error, "quarantine returns the exact typed error");
    assert_eq!(
        backend.operations(),
        vec!["start_proxy", "stop_proxy"],
        "no newer operation mutates the native backend while Off is unproven"
    );
}

#[tokio::test]
async fn connection_loss_during_off_proof_alone_is_not_off() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    coordinator
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
        .await
        .expect("start tunnel");

    // The owner attests stopped, but the independent OS-state observation is
    // unavailable (connection loss). An unavailable observation is not Off.
    *backend.fail_query.lock().expect("query failure lock") = true;

    let error = coordinator
        .set_mode(EngineMode::SystemProxy, direct(), EngineSettings::default())
        .await
        .expect_err("connection loss alone must not prove Off");
    assert!(
        matches!(
            error,
            EngineCoordinatorError::Backend {
                operation: EngineOperation::QueryStatus,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );

    // The other mode is never started and the previous mode is never restarted.
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "start_tunnel", "stop_tunnel"]
    );
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn lingering_owner_status_alone_is_never_off() {
    // A native observation that still reports an owner (e.g. because the
    // effective SystemConfiguration / NEVPNStatus predicates are not all met)
    // is never treated as Off during a switch.
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    coordinator
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
        .await
        .expect("start tunnel");
    *backend
        .stop_leaves_owner_present
        .lock()
        .expect("stop leaves owner lock") = true;

    let error = coordinator
        .set_mode(EngineMode::SystemProxy, direct(), EngineSettings::default())
        .await
        .expect_err("a lingering owner observation is not Off");
    let observed = match &error {
        EngineCoordinatorError::GlobalOffUnproven { observed } => observed.as_ref().clone(),
        other => panic!("expected GlobalOffUnproven, received {other:?}"),
    };
    assert!(matches!(observed, NativeEngineStatus::Tunnel { .. }));
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "start_tunnel", "stop_tunnel"]
    );
}

#[tokio::test]
async fn stop_to_off_refuses_to_declare_off_from_an_ambiguous_observation() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    coordinator
        .set_mode(EngineMode::SystemProxy, direct(), EngineSettings::default())
        .await
        .expect("start proxy");
    *backend
        .stop_leaves_owner_present
        .lock()
        .expect("stop leaves owner lock") = true;

    let error = coordinator
        .set_mode(EngineMode::Off, direct(), EngineSettings::default())
        .await
        .expect_err("stop must not declare Off while an owner is still observed");
    assert!(
        matches!(error, EngineCoordinatorError::GlobalOffUnproven { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}
