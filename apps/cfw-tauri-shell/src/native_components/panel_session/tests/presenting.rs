//! Presenting a panel: a refused present, a panel that closes while it is
//! presented, a present begun before a reload, and a state that cannot
//! register its session.

use super::*;

#[test]
fn a_rejected_present_releases_its_context_and_registers_nothing() {
    let state = installed();
    for status in [0, 2, 3] {
        script(|panel| panel.present = status);
        let (outcome, events, alive) = present(&state);
        assert_eq!(
            outcome,
            Err(format!(
                "native probe presentation rejected (status {status})"
            ))
        );
        assert_eq!(
            Arc::strong_count(&alive),
            1,
            "status {status} left its context alive"
        );
        assert!(state.current().unwrap().is_none());
        assert!(events.lock().unwrap().is_empty());
    }
    assert_eq!(calls(), ["present", "present", "present"]);
}

#[test]
fn a_panel_that_closes_inside_present_leaves_nothing_registered() {
    let state = installed();
    script(|panel| panel.closes_inside_present = true);
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Ok(()));
    assert!(
        state.current().unwrap().is_none(),
        "a session that already closed is never registered"
    );
    assert_eq!(*events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&alive), 1);
    assert_eq!(state.update_on_main(&frame_of(2, 0)), Ok(false));
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(false));
    assert_eq!(calls(), ["present"]);
    assert_eq!(PANEL.with_borrow(|panel| panel.windows.clone()), [7]);
}

#[test]
fn a_present_begun_before_a_reload_is_refused_at_its_epoch() {
    let state = installed();
    let stale = state.epoch.load(Ordering::Acquire);
    assert_eq!(state.cancel_on_main(), Ok(()));
    let (channel, events, alive) = recording_channel();
    let resolved = std::cell::Cell::new(false);
    let outcome = state.present_on_main(stale, &frame_of(1, 0), channel, || {
        resolved.set(true);
        Ok(7)
    });
    assert_eq!(outcome, Err("native probe renderer reloaded".into()));
    assert!(
        !resolved.get(),
        "no window is resolved for a page that is gone"
    );
    assert!(calls().is_empty());
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(Arc::strong_count(&alive), 1);

    let (channel, _events, alive) = recording_channel();
    let current = state.epoch.load(Ordering::Acquire);
    let unavailable = || Err("native probe parent is unavailable (status 2)".to_owned());
    assert_eq!(
        state.present_on_main(current, &frame_of(1, 0), channel, unavailable),
        Err("native probe parent is unavailable (status 2)".into())
    );
    assert!(calls().is_empty());
    assert_eq!(Arc::strong_count(&alive), 1);

    let (outcome, _events, _alive) = present(&state);
    assert_eq!(outcome, Ok(()), "the page loaded by the reload presents");
    assert_eq!(state.dismiss_on_main(REQUEST_ID), Ok(true));
    assert_eq!(calls(), ["present", "dismiss"]);
}

#[test]
fn a_state_that_cannot_register_dismisses_its_panel_outside_the_lock() {
    let state = installed();
    let active = state.active.clone();
    let poisoning = std::thread::spawn(move || {
        let _guard = active.lock().unwrap();
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(poisoning.join().is_err());
    assert!(state.active.is_poisoned());
    let (outcome, events, alive) = present(&state);
    assert_eq!(outcome, Err("native probe state lock failed".into()));
    assert_eq!(calls(), ["present", "dismiss"]);
    assert_eq!(*events.lock().unwrap(), [closed_event()]);
    assert_eq!(Arc::strong_count(&alive), 1);
}
