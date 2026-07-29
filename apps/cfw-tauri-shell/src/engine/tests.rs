use std::fs;
use std::future::Future as _;
use std::task::{Context, Poll, Waker};

use cfw_engine_api::EngineMode;
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::ValidatedSingBoxProfile;

use super::maintenance::{EngineMaintenanceError, EngineMaintenanceGate};
use super::selected_profile_for_mode;

#[tokio::test]
async fn maintenance_waits_for_prior_change_and_blocks_every_renderer_mode() {
    let gate = EngineMaintenanceGate::default();
    let prior_change = gate
        .begin_mode_change(EngineMode::SystemProxy)
        .expect("initial admission")
        .expect("non-Off changes are tracked");
    let maintenance = gate.reserve().expect("maintenance reservation");

    for mode in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert!(matches!(
            gate.begin_mode_change(mode),
            Err(EngineMaintenanceError::AlreadyActive)
        ));
    }
    let mut waiting = Box::pin(maintenance.wait_for_idle());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
    drop(waiting);

    drop(prior_change);
    maintenance.wait_for_idle().await.expect("prior released");
    drop(maintenance);
    assert!(
        gate.begin_mode_change(EngineMode::Tunnel)
            .expect("released")
            .is_some()
    );
}

#[test]
fn profile_mutation_reservation_rejects_concurrent_mode_changes_without_waiting() {
    let gate = EngineMaintenanceGate::default();
    let mode_change = gate
        .begin_mode_change(EngineMode::Tunnel)
        .expect("mode change admission")
        .expect("non-Off mode lease");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(mode_change);
    let mutation = gate.reserve_if_idle().expect("idle admission");
    assert!(matches!(
        gate.begin_mode_change(EngineMode::SystemProxy),
        Err(EngineMaintenanceError::AlreadyActive)
    ));
    drop(mutation);
}

#[test]
fn non_off_mode_uses_the_digest_bound_selected_profile() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    let expected = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"shadowsocks","tag":"selected","server":"proxy.example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","credential_ref":{"id":"34db18b6-9903-4e9f-8854-15648e19e4f3","kind":"shadowsocks_password"}}],"route":{"final":"selected"}}"#,
    )
    .expect("typed profile");
    let imported = repository
        .import(Some("Selected"), &expected)
        .expect("import");
    repository.select(&imported.id).expect("select");
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy).expect("selected"),
        (imported.id.clone(), expected)
    );
}

#[test]
fn non_off_mode_rejects_absent_or_stale_selection_but_off_remains_available() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::Tunnel),
        Err(ProfileError::NoSelectedProfile)
    ));
    let imported = repository
        .import(Some("Selected"), &ValidatedSingBoxProfile::direct())
        .expect("import");
    repository.select(&imported.id).expect("select");
    fs::remove_file(
        root.path()
            .join("profiles")
            .join(format!("{}.profile.json", imported.id)),
    )
    .expect("remove selected profile");
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::Off).expect("Off profile"),
        (
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
        )
    );
}
