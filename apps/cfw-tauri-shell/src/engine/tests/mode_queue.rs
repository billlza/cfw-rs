//! The mode-change queue and the maintenance gate: serial changes, the bound
//! on waiting changes, cancellation, and automatic starts that an explicit Off
//! supersedes.

use super::*;

#[test]
fn a_delayed_integration_disable_cannot_restart_a_core_the_user_stopped() {
    let observed = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        ..EngineSnapshot::default()
    };
    let stopped = EngineSnapshot {
        generation: 8,
        ..EngineSnapshot::default()
    };
    assert_eq!(
        crate::engine::serialized_switch_transition(
            &observed,
            &stopped,
            EngineMode::SystemProxy,
            false
        ),
        Ok(None)
    );
    assert_eq!(
        crate::engine::switch_transition(&stopped, EngineMode::SystemProxy, false),
        None
    );
    assert_eq!(
        crate::engine::switch_transition(&stopped, EngineMode::Tunnel, false),
        None
    );
}

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
async fn an_explicit_off_supersedes_a_debounced_automatic_start_even_when_already_off() {
    let gate = EngineMaintenanceGate::default();
    let observed = gate.intent_revision().unwrap();
    let stop = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
        .await
        .unwrap();
    drop(stop);
    let result = gate
        .begin_mode_change_if_current(
            EngineModeChangeIntent::Set(EngineMode::Tunnel),
            Some(observed),
        )
        .await;
    assert!(matches!(result, Err(EngineMaintenanceError::StaleIntent)));
}

#[tokio::test]
async fn an_off_queued_after_an_automatic_start_cancels_the_older_automatic_intent() {
    let gate = EngineMaintenanceGate::default();
    let first = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::LocalProxy))
        .await
        .unwrap();
    let automatic = gate.begin_mode_change_if_current(
        EngineModeChangeIntent::Set(EngineMode::Tunnel),
        Some(gate.intent_revision().unwrap()),
    );
    tokio::pin!(automatic);
    assert!(
        tokio::time::timeout(Duration::from_millis(15), &mut automatic)
            .await
            .is_err()
    );
    let stop = gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off));
    tokio::pin!(stop);
    assert!(
        tokio::time::timeout(Duration::from_millis(15), &mut stop)
            .await
            .is_err()
    );
    drop(first);
    assert!(matches!(
        automatic.await,
        Err(EngineMaintenanceError::StaleIntent)
    ));
    drop(stop.await.unwrap());
    assert!(gate.reserve_if_idle().is_ok());
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
