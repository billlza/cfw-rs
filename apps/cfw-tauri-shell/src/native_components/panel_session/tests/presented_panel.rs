//! A presented panel's updates, dismissals, reloads and closes, including
//! closes that name another session.

use super::*;

#[test]
fn update_maps_each_native_status_and_keeps_stale_frames_from_the_panel() {
    let state = installed();
    let (outcome, events, _alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    let other = ProbeRequest {
        request_id: "another-request",
        ..frame_of(2, 0)
    };
    assert_eq!(state.update_on_main(&other), Ok(false));
    assert_eq!(
        state.update_on_main(&frame_of(1, 0)),
        Ok(false),
        "the presented sequence is not newer"
    );
    assert_eq!(
        state.update_on_main(&frame_of(2, 1)),
        Err("native probe acknowledged an unknown submission".into())
    );
    assert_eq!(calls(), ["present"]);

    assert_eq!(state.update_on_main(&frame_of(2, 0)), Ok(true));
    assert_eq!(
        state.update_on_main(&frame_of(2, 0)),
        Ok(false),
        "an accepted sequence is not sent twice"
    );
    script(|panel| panel.update = 2);
    assert_eq!(state.update_on_main(&frame_of(3, 0)), Ok(false));
    for status in [0, 3] {
        script(|panel| panel.update = status);
        assert_eq!(
            state.update_on_main(&frame_of(3, 0)),
            Err(format!("native probe update rejected (status {status})"))
        );
    }
    script(|panel| panel.update = 1);
    assert_eq!(
        state.update_on_main(&frame_of(3, 0)),
        Ok(true),
        "a frame the panel did not take leaves its sequence free"
    );
    let panel = retained();
    // SAFETY: the panel holds this context until the dismissal below.
    assert_eq!(
        unsafe { (panel.event)(panel.context, panel.session, [1_u8].as_ptr(), 1) },
        1
    );
    assert_eq!(state.update_on_main(&frame_of(4, 1)), Ok(true));
    assert_eq!(PANEL.with_borrow(|panel| panel.accepted.clone()), [2, 3, 4]);
    assert_eq!(
        *events.lock().unwrap(),
        [serde_json::json!({"intent": 1, "requestId": REQUEST_ID})]
    );
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(true));
    assert_eq!(
        calls(),
        [
            "present", "update", "update", "update", "update", "update", "update", "dismiss"
        ]
    );
}

#[test]
fn dismiss_maps_each_native_status_and_closes_through_the_callback() {
    let state = installed();
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    assert_eq!(state.dismiss_on_main("another-request"), Ok(false));
    assert_eq!(calls(), ["present"]);
    for status in [0, 3] {
        script(|panel| panel.dismiss = status);
        assert_eq!(
            state.dismiss_on_main(REQUEST_ID),
            Err(format!("native probe dismissal rejected (status {status})"))
        );
    }
    script(|panel| panel.dismiss = 2);
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(false));
    assert!(state.current().unwrap().is_some());
    assert!(events.lock().unwrap().is_empty());
    script(|panel| panel.dismiss = 1);
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(true));
    assert!(
        state.current().unwrap().is_none(),
        "the closed callback released the session"
    );
    assert_eq!(*events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&alive), 1);
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(false));
    assert_eq!(
        calls(),
        ["present", "dismiss", "dismiss", "dismiss", "dismiss"]
    );
}

#[test]
fn a_reload_releases_the_presented_panel_and_reports_a_refusal() {
    let state = installed();
    assert_eq!(state.cancel_on_main(), Ok(()));
    assert!(
        calls().is_empty(),
        "nothing is presented, nothing is called"
    );
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    let epoch = state.epoch.load(Ordering::Acquire);
    for status in [0, 3] {
        script(|panel| panel.dismiss = status);
        assert_eq!(
            state.cancel_on_main(),
            Err(format!("native probe dismissal rejected: {status}"))
        );
    }
    script(|panel| panel.dismiss = 2);
    assert_eq!(state.cancel_on_main(), Ok(()));
    assert!(events.lock().unwrap().is_empty());
    script(|panel| panel.dismiss = 1);
    assert_eq!(state.cancel_on_main(), Ok(()));
    assert_eq!(
        state.epoch.load(Ordering::Acquire),
        epoch + 4,
        "every reload ends the epoch, whatever the panel answered"
    );
    assert!(state.current().unwrap().is_none());
    assert_eq!(*events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&alive), 1);
    assert_eq!(
        calls(),
        ["present", "dismiss", "dismiss", "dismiss", "dismiss"]
    );
}

#[test]
fn a_close_with_a_differing_session_still_releases_and_is_reported() {
    let state = installed();
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    let panel = retained();
    // SAFETY: the one close of the context the panel holds.
    unsafe { (panel.closed)(panel.context, panel.session + 1) };
    assert!(state.current().unwrap().is_none());
    assert_eq!(
        *events.lock().unwrap(),
        [closed_event()],
        "the renderer is not left waiting for a panel that is gone"
    );
    assert_eq!(Arc::strong_count(&alive), 1);
    assert_eq!(calls(), ["present"]);
}

#[test]
fn a_late_close_of_a_replaced_session_leaves_its_successor_registered() {
    let state = installed();
    let (outcome, replaced_events, replaced_alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    let replaced = retained();
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    let successor = retained();
    assert_ne!(replaced.session, successor.session);
    // SAFETY: the one close of the first context.
    unsafe { (replaced.closed)(replaced.context, replaced.session) };
    assert_eq!(*replaced_events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&replaced_alive), 1);
    assert_eq!(
        state.current().unwrap().map(|pending| pending.session),
        Some(successor.session)
    );
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(true));
    assert_eq!(*events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&alive), 1);
    assert_eq!(calls(), ["present", "present", "dismiss"]);
}
