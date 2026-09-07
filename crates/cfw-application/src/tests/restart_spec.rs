use std::sync::Arc;

use cfw_engine_api::{BackendErrorKind, EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ReleaseDnsEvidenceCase, ValidatedSingBoxProfile};

use crate::{EngineCoordinatorError, EngineModeCoordinator};

use super::support::{FakeBackend, coordinator};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

async fn start_baseline(
    coordinator: &EngineModeCoordinator,
) -> (cfw_engine_api::EngineSnapshot, ValidatedSingBoxProfile) {
    let profile = ValidatedSingBoxProfile::direct();
    let snapshot = coordinator
        .set_mode(
            EngineMode::Tunnel,
            PROFILE_ID.to_owned(),
            profile.clone(),
            EngineSettings::default(),
        )
        .await
        .expect("active baseline");
    (snapshot, profile)
}

#[tokio::test]
async fn actor_retains_the_exact_last_accepted_restart_spec_in_memory() {
    let coordinator = coordinator(Arc::new(FakeBackend::default()));
    assert!(
        coordinator
            .restart_spec()
            .await
            .expect("actor response")
            .is_none()
    );

    let (snapshot, profile) = start_baseline(&coordinator).await;
    let spec = coordinator
        .restart_spec()
        .await
        .expect("actor response")
        .expect("accepted restart spec");
    assert_eq!(spec.mode(), EngineMode::Tunnel);
    assert_eq!(spec.profile_id(), PROFILE_ID);
    assert_eq!(spec.profile(), &profile);
    assert_eq!(spec.settings(), &EngineSettings::default());
    assert_eq!(spec.generation(), snapshot.generation);
    assert_eq!(spec.config_digest(), snapshot.config_digest.as_deref());
    assert!(spec.matches_ready_snapshot(&snapshot));
    let debug = format!("{spec:?}");
    assert!(debug.contains(profile.digest()));
    assert!(!debug.contains("authenticated_dns_servers"));
}

#[tokio::test]
async fn a_failed_replacement_does_not_overwrite_the_last_accepted_baseline() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let (baseline, _) = start_baseline(&coordinator).await;
    *backend
        .tunnel_start_error
        .lock()
        .expect("tunnel error lock") = Some(BackendErrorKind::Unavailable);

    coordinator
        .set_mode(
            EngineMode::Tunnel,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ValidatedSingBoxProfile::release_dns_evidence(ReleaseDnsEvidenceCase::PrimaryIpv4),
            EngineSettings::default(),
        )
        .await
        .expect_err("replacement start fails");
    let retained = coordinator
        .restart_spec()
        .await
        .expect("actor response")
        .expect("prior accepted spec remains");
    assert_eq!(retained.profile_id(), PROFILE_ID);
    assert_eq!(retained.generation(), baseline.generation);
    assert_eq!(retained.config_digest(), baseline.config_digest.as_deref());
}

#[tokio::test]
async fn conditional_transition_rejects_a_stale_snapshot_without_native_io() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let (stale_baseline, _) = start_baseline(&coordinator).await;
    coordinator
        .set_mode(
            EngineMode::Off,
            PROFILE_ID.to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("concurrent state change");
    let current = coordinator.snapshot();
    let operations_before = backend.operations();

    assert_eq!(
        coordinator
            .set_mode_if_snapshot(
                stale_baseline,
                EngineMode::Tunnel,
                PROFILE_ID.to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("stale compare-and-set must fail"),
        EngineCoordinatorError::SnapshotPreconditionChanged
    );
    assert_eq!(coordinator.snapshot(), current);
    assert_eq!(backend.operations(), operations_before);
}

#[tokio::test]
async fn release_restore_quarantine_blocks_non_off_until_explicit_off_proof() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let (_baseline, _) = start_baseline(&coordinator).await;
    let quarantined = coordinator
        .quarantine_release_evidence_restore()
        .await
        .expect("quarantine command");
    assert!(matches!(
        quarantined.state,
        EngineState::Failed {
            target: EngineMode::Tunnel,
            ..
        }
    ));

    let before = backend.operations();
    assert_eq!(
        coordinator
            .set_mode(
                EngineMode::Tunnel,
                PROFILE_ID.to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("quarantine rejects non-Off"),
        EngineCoordinatorError::ReleaseEvidenceRestoreUnproven
    );
    assert_eq!(backend.operations(), before);

    let off = coordinator
        .set_mode(
            EngineMode::Off,
            PROFILE_ID.to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("explicit Off proves cleanup");
    assert_eq!(off.state, EngineState::Off);
    coordinator
        .set_mode(
            EngineMode::Tunnel,
            PROFILE_ID.to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("non-Off is admitted after explicit Off");
}

#[tokio::test]
async fn awaiting_approval_is_retained_but_not_a_ready_transaction_baseline() {
    let backend = Arc::new(FakeBackend::default());
    *backend.awaiting_approval.lock().expect("approval lock") = true;
    let coordinator = coordinator(backend);
    let snapshot = coordinator
        .set_mode(
            EngineMode::Tunnel,
            PROFILE_ID.to_owned(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("accepted approval wait");
    assert!(matches!(
        snapshot.state,
        EngineState::AwaitingApproval { .. }
    ));
    let spec = coordinator
        .restart_spec()
        .await
        .expect("actor response")
        .expect("accepted spec");
    assert!(!spec.matches_ready_snapshot(&snapshot));
}
