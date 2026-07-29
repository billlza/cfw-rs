use std::fs;
use std::sync::Arc;
use std::time::Duration;

use cfw_engine_api::EngineMode;
use cfw_profiles::{ProfileError, ProfileRepository};
use cfw_singbox_config::ValidatedSingBoxProfile;

use super::maintenance::{
    EngineMaintenanceError, EngineMaintenanceGate, EngineModeChangeIntent, MAX_PENDING_MODE_CHANGES,
};
use super::selected_profile_for_mode;

#[tokio::test]
async fn maintenance_rejects_queued_off_change_and_blocks_every_renderer_mode() {
    let gate = EngineMaintenanceGate::default();
    let prior_change = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
        .await
        .expect("initial admission");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(prior_change);
    let maintenance = gate
        .reserve_if_idle()
        .expect("idle maintenance reservation");

    for mode in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert!(matches!(
            gate.begin_mode_change(EngineModeChangeIntent::Set(mode))
                .await,
            Err(EngineMaintenanceError::AlreadyActive)
        ));
    }
    drop(maintenance);
    gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("released");
}

#[tokio::test]
async fn queued_mode_changes_are_serial_and_visible_to_maintenance() {
    let gate = EngineMaintenanceGate::default();
    let first_change = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("mode change admission");
    let second_change = gate.begin_mode_change(EngineModeChangeIntent::ReapplyCurrent);
    tokio::pin!(second_change);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut second_change)
            .await
            .is_err(),
        "a second mutation must wait for the first response"
    );
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(first_change);
    let second_change = tokio::time::timeout(Duration::from_secs(1), &mut second_change)
        .await
        .expect("queued mutation must resume")
        .expect("queued mutation admission");
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    drop(second_change);
    let maintenance = gate.reserve_if_idle().expect("idle admission");
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::SystemProxy))
            .await,
        Err(EngineMaintenanceError::AlreadyActive)
    ));
    drop(maintenance);
}

#[tokio::test]
async fn queued_current_reapply_reads_off_only_after_prior_off_releases() {
    let gate = EngineMaintenanceGate::default();
    let desired_mode = Arc::new(std::sync::Mutex::new(EngineMode::Tunnel));
    let off = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
        .await
        .expect("Off admission");
    let current_mode = desired_mode.clone();
    let queued_reapply = async {
        let lease = gate
            .begin_mode_change(EngineModeChangeIntent::ReapplyCurrent)
            .await
            .expect("current-mode admission");
        let observed = *current_mode.lock().expect("desired mode lock");
        (observed, lease)
    };
    tokio::pin!(queued_reapply);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut queued_reapply)
            .await
            .is_err(),
        "reapply must wait behind the prior Off intent"
    );

    *desired_mode.lock().expect("desired mode lock") = EngineMode::Off;
    drop(off);
    let (observed, reapply) = tokio::time::timeout(Duration::from_secs(1), &mut queued_reapply)
        .await
        .expect("queued reapply resumes");
    assert_eq!(observed, EngineMode::Off);
    drop(reapply);
}

#[tokio::test]
async fn mode_change_queue_is_bounded_and_cancelled_waiters_release_capacity() {
    let gate = EngineMaintenanceGate::default();
    let first = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("first mode mutation");
    let mut queued = Vec::new();
    for _ in 1..MAX_PENDING_MODE_CHANGES {
        let mut pending =
            Box::pin(gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel)));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), pending.as_mut())
                .await
                .is_err(),
            "a queued mutation cannot bypass the held serial permit"
        );
        queued.push(pending);
    }
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
            .await,
        Err(EngineMaintenanceError::QueueFull)
    ));

    drop(queued);
    drop(first);
    let maintenance = gate
        .reserve_if_idle()
        .expect("cancelled waiters release their registrations");
    drop(maintenance);
}

#[tokio::test]
async fn caller_cancellation_cannot_release_an_accepted_mode_operation() {
    let gate = EngineMaintenanceGate::default();
    let lease = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel))
        .await
        .expect("mode mutation");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let operation_started = started.clone();
    let operation_release = release.clone();
    let response = lease.run_to_completion(async move {
        operation_started.notify_one();
        operation_release.notified().await;
    });
    started.notified().await;
    drop(response);

    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::ModeChangeActive)
    ));
    release.notify_one();
    let maintenance = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match gate.reserve_if_idle() {
                Ok(lease) => break lease,
                Err(EngineMaintenanceError::ModeChangeActive) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected maintenance error: {error}"),
            }
        }
    })
    .await
    .expect("accepted operation must eventually release its lease");
    drop(maintenance);
}

#[tokio::test]
async fn shutdown_maintenance_survives_caller_cancellation_and_blocks_all_modes() {
    let gate = EngineMaintenanceGate::default();
    let shutdown = gate
        .reserve_if_idle()
        .expect("exclusive shutdown admission");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let operation_started = started.clone();
    let operation_release = release.clone();
    let response = shutdown.run_to_completion(async move {
        operation_started.notify_one();
        operation_release.notified().await;
    });
    started.notified().await;
    drop(response);

    for mode in [EngineMode::Off, EngineMode::SystemProxy, EngineMode::Tunnel] {
        assert!(matches!(
            gate.begin_mode_change(EngineModeChangeIntent::Set(mode))
                .await,
            Err(EngineMaintenanceError::AlreadyActive)
        ));
    }
    assert!(matches!(
        gate.reserve_if_idle(),
        Err(EngineMaintenanceError::AlreadyActive)
    ));

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match gate
                .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
                .await
            {
                Ok(lease) => break lease,
                Err(EngineMaintenanceError::AlreadyActive) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected mode admission error: {error}"),
            }
        }
    })
    .await
    .expect("completed shutdown task releases its dropped response guard");
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
