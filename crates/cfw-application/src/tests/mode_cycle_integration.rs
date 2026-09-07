//! End-to-end mode-cycle integration for the serialized coordinator
//! (Requirements 1.1, 1.2, 3.1, 3.2, 3.3, 7.1).
//!
//! These tests exercise the public command boundary across a full multi-hop mode
//! cycle rather than a single transition:
//! - every Proxy<->Tunnel switch is Off-mediated (the current owner is stopped
//!   before the target owner is prepared/started) and allocates a strictly newer
//!   generation, so the replay high-water mark never regresses across the cycle;
//! - a registration-denied Authority error on the Tunnel install path surfaces as
//!   a stable typed `Backend` error with no fallback to another mode and no
//!   start_tunnel side effect;
//! - the public `RuntimeIdentity`/snapshot command contract is unchanged.

use std::{sync::Arc, time::Duration};

use cfw_engine_api::{BackendErrorKind, EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator};

use super::support::{FakeBackend, test_session};

fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

/// Coordinator with a long periodic reconciliation interval so the operation
/// sequence observed is exactly the awaited transitions, with no interleaved
/// periodic reconciliation queries.
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

fn active_generation(state: &EngineState) -> u64 {
    match state {
        EngineState::ProxyActive { runtime } | EngineState::TunnelActive { runtime } => {
            runtime.context.generation
        }
        other => panic!("expected an active runtime, received {other:?}"),
    }
}

#[tokio::test]
async fn full_mode_cycle_is_off_mediated_with_strictly_increasing_generations() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = quiet_coordinator(backend.clone());

    // Off -> Proxy
    let proxy = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("start proxy from Off");
    let proxy_generation = active_generation(&proxy.state);

    // Proxy -> Tunnel (stops proxy, proves Off, then installs/starts tunnel)
    let tunnel = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("switch proxy -> tunnel");
    let tunnel_generation = active_generation(&tunnel.state);

    // Tunnel -> Proxy (stops tunnel, proves Off, then starts proxy)
    let proxy_again = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("switch tunnel -> proxy");
    let proxy_again_generation = active_generation(&proxy_again.state);

    // Proxy -> Off
    let off = coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("stop to Off");
    assert_eq!(off.state, EngineState::Off);

    // Every switch stopped the current owner before starting the next: the Off
    // barrier sits between each pair of owners.
    assert_eq!(
        backend.operations(),
        vec![
            "start_proxy",
            "stop_proxy",
            "install_tunnel",
            "start_tunnel",
            "stop_tunnel",
            "start_proxy",
            "stop_proxy",
        ]
    );

    // Generations advance strictly across the whole cycle: no consumed generation
    // is ever reused and the high-water mark never regresses.
    assert!(proxy_generation < tunnel_generation);
    assert!(tunnel_generation < proxy_again_generation);
    assert!(off.generation >= proxy_again_generation);
}

#[tokio::test]
async fn registration_denied_on_install_surfaces_typed_error_without_fallback() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_install_error
        .lock()
        .expect("tunnel install error lock") =
        Some(BackendErrorKind::GlobalAuthorityRegistrationRequired);
    let coordinator = quiet_coordinator(backend.clone());

    let error = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("registration-denied install must fail closed");
    match &error {
        EngineCoordinatorError::Backend { source, .. } => {
            assert_eq!(
                source.kind,
                BackendErrorKind::GlobalAuthorityRegistrationRequired,
                "the stable typed registration-required error is preserved"
            );
        }
        other => panic!("expected a typed Backend error, received {other:?}"),
    }

    // The install-stage denial cancels the pending installation as cleanup; the
    // tunnel never started and no other mode was attempted as a fallback.
    let operations = backend.operations();
    assert_eq!(operations, vec!["install_tunnel", "cancel_tunnel_install"]);
    assert!(!operations.contains(&"start_tunnel"));
    assert!(!operations.contains(&"start_proxy"));
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}
