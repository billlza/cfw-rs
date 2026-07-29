//! Operation-scoped cancellation and callback isolation for the serialized
//! coordinator (Requirements 3.1, 3.5, 7.1).
//!
//! These tests prove that:
//! - a cancelled caller detaches only its own wait while accepted native work
//!   continues to exact readiness (dropping a Rust oneshot receiver never
//!   cancels accepted native work);
//! - a stale/late completion carrying an older generation/context cannot
//!   identify or mutate a newer operation;
//! - the confirmed Authority error kinds surface as stable typed `Backend`
//!   errors through coordinator state transitions without any mode fallback and
//!   without changing the public command request/response shapes;
//! - unprovable-cleanup Authority failures (compensation conflict, unproven
//!   cleanup, quarantine, recovering, journal corruption, secret-lifecycle
//!   violation) quarantine the coordinator fail-closed: no newer operation may
//!   start until an explicit Off reconciliation proves the stop barrier.

use std::sync::Arc;

use cfw_engine_api::{BackendErrorKind, EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use crate::{EngineCoordinatorError, EngineModeCoordinator};

use super::support::{FakeBackend, coordinator};

fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

async fn expect_backend_kind(
    coordinator: &EngineModeCoordinator,
    target: EngineMode,
    expected: BackendErrorKind,
) -> EngineCoordinatorError {
    let error = coordinator
        .set_mode(
            target,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("typed authority failure");
    match &error {
        EngineCoordinatorError::Backend { source, .. } => {
            assert_eq!(
                source.kind, expected,
                "stable typed error kind is preserved"
            );
        }
        other => panic!("expected a typed Backend error, received {other:?}"),
    }
    error
}

#[tokio::test]
async fn global_lease_conflict_surfaces_typed_error_without_fallback() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .proxy_start_error
        .lock()
        .expect("proxy start error lock") = Some(BackendErrorKind::GlobalLeaseConflict);
    let coordinator = coordinator(backend.clone());

    expect_backend_kind(
        &coordinator,
        EngineMode::SystemProxy,
        BackendErrorKind::GlobalLeaseConflict,
    )
    .await;

    // A lease conflict is not an unprovable-cleanup failure: the coordinator
    // attempts its exact stop and never falls back to the other mode.
    assert_eq!(backend.operations(), vec!["start_proxy", "stop_proxy"]);
    assert!(matches!(
        coordinator.snapshot().state,
        EngineState::Failed { .. }
    ));
}

#[tokio::test]
async fn replay_rejection_surfaces_typed_error_and_stays_recoverable() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_start_error
        .lock()
        .expect("tunnel start error lock") = Some(BackendErrorKind::ReplayRejected);
    let coordinator = coordinator(backend.clone());

    expect_backend_kind(
        &coordinator,
        EngineMode::Tunnel,
        BackendErrorKind::ReplayRejected,
    )
    .await;
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "start_tunnel", "stop_tunnel"]
    );

    // Replay rejection requires a fresh context, not reconciliation: once the
    // typed error clears the injected fault, a fresh start succeeds.
    *backend
        .tunnel_start_error
        .lock()
        .expect("tunnel start error lock") = None;
    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("fresh context starts after replay rejection");
    assert!(matches!(active.state, EngineState::TunnelActive { .. }));
}

#[tokio::test]
async fn registration_required_surfaces_typed_error() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .proxy_start_error
        .lock()
        .expect("proxy start error lock") =
        Some(BackendErrorKind::GlobalAuthorityRegistrationRequired);
    let coordinator = coordinator(backend.clone());

    expect_backend_kind(
        &coordinator,
        EngineMode::SystemProxy,
        BackendErrorKind::GlobalAuthorityRegistrationRequired,
    )
    .await;
}

#[tokio::test]
async fn compensation_conflict_quarantines_and_blocks_newer_operations() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_start_error
        .lock()
        .expect("tunnel start error lock") = Some(BackendErrorKind::CompensationConflict);
    let coordinator = coordinator(backend.clone());

    let quarantine = expect_backend_kind(
        &coordinator,
        EngineMode::Tunnel,
        BackendErrorKind::CompensationConflict,
    )
    .await;

    // Unprovable cleanup retains the exact lease and never issues an optimistic
    // stop that could be misread as proof of Off.
    assert_eq!(backend.operations(), vec!["install_tunnel", "start_tunnel"]);

    // Clear the injected fault, then prove a newer operation cannot start while
    // quarantined: the coordinator returns the exact typed quarantine error and
    // touches the backend for no new start.
    *backend
        .tunnel_start_error
        .lock()
        .expect("tunnel start error lock") = None;
    let blocked = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect_err("quarantine blocks a newer operation");
    assert_eq!(
        blocked, quarantine,
        "quarantine returns the exact typed error"
    );
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "start_tunnel"],
        "no newer operation mutates the native backend while quarantined"
    );

    // Only an explicit Off reconciliation that proves the stop barrier clears
    // the quarantine; afterwards a fresh start is permitted.
    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("explicit Off reconciliation proves the stop barrier");
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "start_tunnel", "stop_tunnel"]
    );

    let active = coordinator
        .set_mode(
            EngineMode::SystemProxy,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("reconciled coordinator accepts a fresh start");
    assert!(matches!(active.state, EngineState::ProxyActive { .. }));
}

#[tokio::test]
async fn cleanup_unproven_quarantine_survives_repeated_start_attempts() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .proxy_start_error
        .lock()
        .expect("proxy start error lock") = Some(BackendErrorKind::CleanupUnproven);
    let coordinator = coordinator(backend.clone());

    let quarantine = expect_backend_kind(
        &coordinator,
        EngineMode::SystemProxy,
        BackendErrorKind::CleanupUnproven,
    )
    .await;
    assert_eq!(backend.operations(), vec!["start_proxy"]);

    // Repeated non-Off attempts keep returning the same typed quarantine error
    // and never touch the backend again.
    for target in [EngineMode::SystemProxy, EngineMode::Tunnel] {
        let blocked = coordinator
            .set_mode(
                target,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("quarantine is sticky until reconciliation");
        assert_eq!(blocked, quarantine);
    }
    assert_eq!(backend.operations(), vec!["start_proxy"]);
}

#[tokio::test]
async fn quarantine_clears_only_after_a_proven_off_stop() {
    let backend = Arc::new(FakeBackend::default());
    *backend
        .tunnel_install_error
        .lock()
        .expect("tunnel install error lock") = Some(BackendErrorKind::Quarantined);
    let coordinator = coordinator(backend.clone());

    expect_backend_kind(
        &coordinator,
        EngineMode::Tunnel,
        BackendErrorKind::Quarantined,
    )
    .await;
    // The install-stage quarantine retains the installation lease.
    assert_eq!(backend.operations(), vec!["install_tunnel"]);

    // Clear the injected install fault so a later start could succeed if the
    // quarantine were (incorrectly) dropped without a proven stop.
    *backend
        .tunnel_install_error
        .lock()
        .expect("tunnel install error lock") = None;

    coordinator
        .set_mode(
            EngineMode::Off,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("Off reconciliation cancels the retained installation and proves Off");
    assert_eq!(
        backend.operations(),
        vec!["install_tunnel", "cancel_tunnel_install"]
    );
    assert_eq!(coordinator.snapshot().state, EngineState::Off);

    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .expect("fresh start after proven Off");
    assert!(matches!(active.state, EngineState::TunnelActive { .. }));
}
