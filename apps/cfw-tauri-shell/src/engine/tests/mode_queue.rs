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
    // An admitted change would wait for the held serial permit, so the refusal
    // is bounded: a queue that admits one change too many fails here at once.
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off)),
        )
        .await
        .expect("a full queue refuses without waiting for the serial permit"),
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

/// A change of the runtime preferences is counted among the mode changes from
/// its press, before what it asks is read: maintenance waits for it, the bound
/// of the queue refuses it, and its press moves the revision on, so what is
/// observed after it is later. Given up before its turn it was no intent: it
/// supersedes no retry and no expectation.
#[tokio::test]
async fn a_reapplication_is_counted_from_its_press_and_is_no_intent_before_its_turn() {
    let gate = EngineMaintenanceGate::default();
    let observed = gate.intent_revision().expect("the revision");
    let pressed = gate.register_reapply().expect("the press");
    assert!(
        gate.intent_revision()
            .expect("the revision after the press")
            > observed,
        "the press moves the revision on"
    );
    let maintenance = gate.reserve_if_idle().err();
    drop(pressed);
    assert_eq!(maintenance, Some(EngineMaintenanceError::ModeChangeActive));
    let start = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::SystemProxy))
        .await
        .expect("a start");
    let retry = start.retry_guard();
    let observed = gate.intent_revision().expect("the revision the start gave");
    drop(gate.register_reapply().expect("a press given up"));
    assert_eq!(
        retry(),
        Ok(()),
        "a change given up before its turn supersedes no retry"
    );
    drop(start);
    assert_eq!(
        gate.begin_mode_change_if_current(
            EngineModeChangeIntent::Set(EngineMode::Tunnel),
            Some(observed)
        )
        .await
        .map(drop),
        Ok(()),
        "and no expectation"
    );
    let maintenance = gate.reserve_if_idle().expect("the press gave up its place");
    assert!(matches!(
        gate.register_reapply(),
        Err(EngineMaintenanceError::AlreadyActive)
    ));
    drop(maintenance);
    let presses = (0..MAX_PENDING_MODE_CHANGES)
        .map(|_| gate.register_reapply().expect("a press"))
        .collect::<Vec<_>>();
    assert!(matches!(
        gate.register_reapply(),
        Err(EngineMaintenanceError::QueueFull)
    ));
    assert!(matches!(
        gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Off))
            .await,
        Err(EngineMaintenanceError::QueueFull)
    ));
    drop(presses);
    let maintenance = gate
        .reserve_if_idle()
        .expect("the presses gave up their places");
    drop(maintenance);
}

/// The turn of a change of the runtime preferences is a new intent asked for
/// at its press. One pressed before a start leaves the start its retry, as the
/// start was asked for later; one pressed after the start supersedes it, as
/// any later operation does. An automatic request observed before either is
/// stale.
#[tokio::test]
async fn a_reapplication_supersedes_only_what_was_registered_before_its_press() {
    let gate = EngineMaintenanceGate::default();
    let earlier = gate.register_reapply().expect("the earlier press");
    let start = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::SystemProxy))
        .await
        .expect("the start");
    let retry = start.retry_guard();
    let observed = gate.intent_revision().expect("the revision");
    let later = gate.register_reapply().expect("the later press");
    let earlier_turn = earlier.begin();
    tokio::pin!(earlier_turn);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut earlier_turn)
            .await
            .is_err(),
        "the earlier change waits for the start"
    );
    assert_eq!(
        retry(),
        Ok(()),
        "a change pressed before the start leaves it its retry"
    );
    let later_turn = later.begin();
    tokio::pin!(later_turn);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut later_turn)
            .await
            .is_err(),
        "the later change waits for the earlier one"
    );
    assert_eq!(
        retry(),
        Err(EngineMaintenanceError::StaleIntent),
        "one pressed after the start supersedes it"
    );
    drop(start);
    let earlier_lease = tokio::time::timeout(Duration::from_secs(1), &mut earlier_turn)
        .await
        .expect("the earlier turn")
        .expect("the earlier change");
    drop(earlier_lease);
    let later_lease = tokio::time::timeout(Duration::from_secs(1), &mut later_turn)
        .await
        .expect("the later turn")
        .expect("the later change");
    drop(later_lease);
    assert!(
        matches!(
            gate.begin_mode_change_if_current(
                EngineModeChangeIntent::Set(EngineMode::Tunnel),
                Some(observed)
            )
            .await,
            Err(EngineMaintenanceError::StaleIntent)
        ),
        "an automatic request observed before them is stale"
    );
}

/// An automatic request that waits for its turn is stale once an intent asked
/// for after it has been registered: a change of the runtime preferences
/// pressed after it supersedes it, and one pressed before it does not, as it
/// would not end its retries.
#[tokio::test]
async fn an_automatic_request_is_superseded_only_by_a_change_pressed_after_it() {
    let gate = EngineMaintenanceGate::default();
    for pressed_after in [false, true] {
        let holder = gate
            .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::LocalProxy))
            .await
            .expect("the holder");
        let before = (!pressed_after).then(|| gate.register_reapply().expect("the press"));
        let automatic = gate.begin_mode_change_if_current(
            EngineModeChangeIntent::Set(EngineMode::Tunnel),
            Some(gate.intent_revision().expect("the revision")),
        );
        tokio::pin!(automatic);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut automatic)
                .await
                .is_err(),
            "the automatic request waits for the holder"
        );
        let pressed = before.unwrap_or_else(|| gate.register_reapply().expect("the press"));
        let turn = pressed.begin();
        tokio::pin!(turn);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut turn)
                .await
                .is_err(),
            "the change waits for the automatic request"
        );
        drop(holder);
        let outcome = tokio::time::timeout(Duration::from_secs(1), &mut automatic)
            .await
            .expect("the automatic request's turn")
            .map(drop);
        let expected = if pressed_after {
            Err(EngineMaintenanceError::StaleIntent)
        } else {
            Ok(())
        };
        assert_eq!(
            outcome, expected,
            "pressed after the request: {pressed_after}"
        );
        drop(
            tokio::time::timeout(Duration::from_secs(1), &mut turn)
                .await
                .expect("the change's turn")
                .expect("the change"),
        );
    }
}

/// An automatic request that expects a revision is stale once an intent asked
/// for at that revision or after has been registered: a change of the runtime
/// preferences pressed before the revision was given leaves the expectation
/// current, and one pressed at it does not.
#[tokio::test]
async fn an_expectation_is_superseded_only_by_a_change_pressed_at_it_or_after() {
    for pressed_at_it in [false, true] {
        let gate = EngineMaintenanceGate::default();
        let before = (!pressed_at_it).then(|| gate.register_reapply().expect("the press"));
        drop(
            gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::LocalProxy))
                .await
                .expect("the start"),
        );
        let observed = gate.intent_revision().expect("the revision the start gave");
        let pressed = before.unwrap_or_else(|| gate.register_reapply().expect("the press"));
        drop(pressed.begin().await.expect("the change"));
        let outcome = gate
            .begin_mode_change_if_current(
                EngineModeChangeIntent::Set(EngineMode::Tunnel),
                Some(observed),
            )
            .await
            .map(drop);
        let expected = if pressed_at_it {
            Err(EngineMaintenanceError::StaleIntent)
        } else {
            Ok(())
        };
        assert_eq!(
            outcome, expected,
            "pressed at the revision: {pressed_at_it}"
        );
    }
}

/// A change of the runtime preferences pressed before two starts leaves the
/// later its retry, and does not give the earlier, which the later superseded,
/// its retry back.
#[tokio::test]
async fn a_change_pressed_before_two_starts_gives_no_superseded_retry_back() {
    let gate = EngineMaintenanceGate::default();
    let pressed = gate.register_reapply().expect("the press");
    let first = gate
        .begin_mode_change(EngineModeChangeIntent::Set(EngineMode::SystemProxy))
        .await
        .expect("the first start");
    let first_retry = first.retry_guard();
    let second_start = gate.begin_mode_change(EngineModeChangeIntent::Set(EngineMode::Tunnel));
    tokio::pin!(second_start);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut second_start)
            .await
            .is_err(),
        "the second start waits for the first"
    );
    assert_eq!(
        first_retry(),
        Err(EngineMaintenanceError::StaleIntent),
        "the second start supersedes the first"
    );
    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(1), &mut second_start)
        .await
        .expect("the second start's turn")
        .expect("the second start");
    let second_retry = second.retry_guard();
    let turn = pressed.begin();
    tokio::pin!(turn);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut turn)
            .await
            .is_err(),
        "the change waits for the second start"
    );
    assert_eq!(
        second_retry(),
        Ok(()),
        "the change pressed before the second start leaves it its retry"
    );
    assert_eq!(
        first_retry(),
        Err(EngineMaintenanceError::StaleIntent),
        "and gives the first no retry back"
    );
    drop(second);
    drop(
        tokio::time::timeout(Duration::from_secs(1), &mut turn)
            .await
            .expect("the change's turn")
            .expect("the change"),
    );
}
