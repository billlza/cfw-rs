use super::*;
use std::cell::RefCell;

type Events = Arc<Mutex<Vec<serde_json::Value>>>;

/// A renderer channel that records its events. The second value is held
/// by the channel alone, so its count tells whether the channel, and with
/// it the session that owns it, is still alive.
fn recording_channel<T>() -> (tauri::ipc::Channel<T>, Events, Arc<()>) {
    let events = Events::default();
    let alive = Arc::new(());
    let (sent, held) = (events.clone(), alive.clone());
    let channel = tauri::ipc::Channel::new(move |message| {
        let _held = &held;
        match message {
            tauri::ipc::InvokeResponseBody::Json(text) => sent
                .lock()
                .unwrap()
                .push(serde_json::from_str(&text).unwrap()),
            _ => panic!("dialog events must be JSON"),
        }
        Ok(())
    });
    (channel, events, alive)
}

/// Drives the native callbacks of one session the way the panel does and
/// returns the events its renderer channel received. Every family shares
/// the ownership rules asserted here; a family asserts its own events.
pub(crate) fn callback_ownership<F: Family>(
    request: &F::Request,
    valid: &[u8],
) -> Vec<serde_json::Value> {
    let owner = Arc::new(Mutex::new(None));
    let (channel, events, _alive) = recording_channel();
    let pending = Session::<F>::begin(&owner, request, 3, 7, channel);
    let weak = Arc::downgrade(&pending);
    *owner.lock().unwrap() = Some(pending.clone());
    let pointer = Arc::into_raw(pending) as usize;
    // SAFETY: `pointer` is the count a present would hand to the panel; it
    // is borrowed by each event and returned by the one close below.
    let deliver =
        |session, bytes: *const u8, count| unsafe { event::<F>(pointer, session, bytes, count) };
    assert_eq!(deliver(2, valid.as_ptr(), valid.len()), 0);
    assert_eq!(deliver(3, b"{}".as_ptr(), 2), 0);
    assert_eq!(deliver(3, std::ptr::null(), valid.len()), 0);
    // The same intent, padded with insignificant whitespace past the limit.
    let mut oversized = valid.to_vec();
    oversized.resize(MAXIMUM_BYTES + 1, b' ');
    assert_eq!(deliver(3, oversized.as_ptr(), oversized.len()), 0);
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(deliver(3, valid.as_ptr(), valid.len()), 1);
    assert_eq!(
        deliver(3, valid.as_ptr(), valid.len()),
        0,
        "replayed intents are rejected"
    );
    assert!(
        weak.upgrade().is_some(),
        "an intent borrows the existing observer"
    );
    // SAFETY: as above; this is the one close.
    unsafe { closed::<F>(pointer, 3) };
    assert!(owner.lock().unwrap().is_none());
    assert!(
        weak.upgrade().is_none(),
        "the close callback releases the observer"
    );
    events.lock().unwrap().clone()
}

/// A family that admits no intent: every delivery is refused, nothing
/// reaches the renderer but the close, and the close releases the context.
pub(crate) fn eventless_ownership<F: Family>(request: &F::Request) -> Vec<serde_json::Value> {
    let owner = Arc::new(Mutex::new(None));
    let (channel, events, _alive) = recording_channel();
    let pending = Session::<F>::begin(&owner, request, 3, 7, channel);
    let weak = Arc::downgrade(&pending);
    *owner.lock().unwrap() = Some(pending.clone());
    let pointer = Arc::into_raw(pending) as usize;
    let intent = br#"{"action":"activate","submissionId":1}"#;
    // SAFETY: `pointer` is the count a present would hand to the panel; it
    // is borrowed by each event and returned by the one close below.
    assert_eq!(
        unsafe { event::<F>(pointer, 3, intent.as_ptr(), intent.len()) },
        0
    );
    assert_eq!(unsafe { event::<F>(pointer, 3, b"{}".as_ptr(), 2) }, 0);
    assert!(events.lock().unwrap().is_empty());
    assert!(weak.upgrade().is_some());
    // SAFETY: as above; this is the one close.
    unsafe { closed::<F>(pointer, 3) };
    assert!(owner.lock().unwrap().is_none());
    assert!(
        weak.upgrade().is_none(),
        "the close callback releases the observer"
    );
    events.lock().unwrap().clone()
}

/// The frame a family sends for `request` in session 3 of window 7.
pub(crate) fn native_frame<F: Family>(request: &F::Request) -> serde_json::Value {
    serde_json::from_slice(&frame::<F>(request, 3, 7).unwrap()).unwrap()
}

/// One native intent delivered to a session that presented `request` and
/// then accepted each of `updates`. Returns the callback's verdict.
pub(crate) fn intent_after<F: Family>(
    request: &F::Request,
    updates: &[&F::Request],
    intent: &[u8],
) -> i32 {
    let owner = Arc::new(Mutex::new(None));
    let pending = Session::<F>::begin(&owner, request, 3, 7, tauri::ipc::Channel::new(|_| Ok(())));
    for update in updates {
        pending.family.accepted(update).unwrap();
    }
    let pointer = Arc::into_raw(pending) as usize;
    // SAFETY: `pointer` is borrowed by the event and returned by the close.
    unsafe {
        let verdict = event::<F>(pointer, 3, intent.as_ptr(), intent.len());
        closed::<F>(pointer, 3);
        verdict
    }
}

const REQUEST_ID: &str = "probe-request";

/// A family whose panel is the three functions below, scripted and
/// observed through `PANEL` by the test thread that drives them.
struct Probe;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeRequest {
    request_id: &'static str,
    sequence: u64,
    acknowledged_submission: u64,
}
impl Request for ProbeRequest {
    fn request_id(&self) -> &str {
        self.request_id
    }
    fn sequence(&self) -> u64 {
        self.sequence
    }
    fn acknowledged_submission(&self) -> u64 {
        self.acknowledged_submission
    }
}

fn frame_of(sequence: u64, acknowledged_submission: u64) -> ProbeRequest {
    ProbeRequest {
        request_id: REQUEST_ID,
        sequence,
        acknowledged_submission,
    }
}

impl Family for Probe {
    type Request = ProbeRequest;
    type Event = serde_json::Value;
    const LABEL: &'static str = "native probe";
    const PRESENT_ACKNOWLEDGEMENT_REFUSED: &'static str = "a new probe acknowledges nothing";
    const CANCEL_FAILURE: &'static str = "native_probe_cancel_failed";
    const ABI: Abi = Abi {
        present: panel_present,
        update: panel_update,
        dismiss: panel_dismiss,
    };

    fn begin(_request: &ProbeRequest) -> Self {
        Self
    }
    fn accepted(&self, request: &ProbeRequest) -> Result<(), String> {
        PANEL.with_borrow_mut(|panel| panel.accepted.push(request.sequence));
        Ok(())
    }
    /// An intent is one byte: its submission.
    fn admit(&self, request_id: &str, data: &[u8]) -> Option<(u64, serde_json::Value)> {
        let submission = u64::from(*data.first()?);
        Some((
            submission,
            serde_json::json!({"intent": submission, "requestId": request_id}),
        ))
    }
    fn closed(request_id: String) -> serde_json::Value {
        serde_json::json!({"closed": request_id})
    }
}

/// What an accepted present handed to the panel.
#[derive(Clone, Copy)]
struct Retained {
    event: EventCallback,
    closed: ClosedCallback,
    context: usize,
    session: u64,
}

#[derive(Default)]
struct Panel {
    /// The lock no call into the panel may run under.
    state: Option<Arc<Active<Probe>>>,
    present: i32,
    update: i32,
    dismiss: i32,
    /// Close before an accepted present returns, as a panel that could not
    /// be shown does.
    closes_inside_present: bool,
    retained: Option<Retained>,
    calls: Vec<&'static str>,
    entered_under_lock: bool,
    windows: Vec<i64>,
    accepted: Vec<u64>,
}

thread_local! {
    static PANEL: RefCell<Panel> = RefCell::default();
}

/// Records one call into the panel. A panel entered under the state lock
/// reports it and does nothing, because its closed callback would wait for
/// that lock forever.
fn enter(call: &'static str) -> bool {
    PANEL.with_borrow_mut(|panel| {
        panel.calls.push(call);
        let held = panel.state.as_ref().is_some_and(|state| {
            matches!(state.try_lock(), Err(std::sync::TryLockError::WouldBlock))
        });
        panel.entered_under_lock |= held;
        !held
    })
}

fn frame_number(bytes: *const u8, count: usize, key: &str) -> Option<i64> {
    // SAFETY: the caller lends `count` readable bytes for this call.
    let data = unsafe { std::slice::from_raw_parts(bytes, count) };
    serde_json::from_slice::<serde_json::Value>(data).ok()?[key].as_i64()
}

unsafe extern "C" fn panel_present(
    bytes: *const u8,
    count: usize,
    event: EventCallback,
    closed: ClosedCallback,
    context: usize,
) -> i32 {
    if !enter("present") {
        return 0;
    }
    let Some(session) = frame_number(bytes, count, "session").and_then(|n| n.try_into().ok())
    else {
        return 0;
    };
    let (status, closes) = PANEL.with_borrow_mut(|panel| {
        panel
            .windows
            .extend(frame_number(bytes, count, "windowNumber"));
        (panel.present, panel.closes_inside_present)
    });
    if status != 1 {
        return status;
    }
    if closes {
        // SAFETY: an accepted present owns the context until this one close.
        unsafe { closed(context, session) };
    } else {
        let retained = Retained {
            event,
            closed,
            context,
            session,
        };
        PANEL.with_borrow_mut(|panel| panel.retained = Some(retained));
    }
    1
}

unsafe extern "C" fn panel_update(_bytes: *const u8, _count: usize) -> i32 {
    if !enter("update") {
        return 0;
    }
    PANEL.with_borrow(|panel| panel.update)
}

unsafe extern "C" fn panel_dismiss(session: u64) -> i32 {
    if !enter("dismiss") {
        return 0;
    }
    // Only an accepted dismissal closes the panel.
    let (status, retained) = PANEL.with_borrow_mut(|panel| {
        let closing = if panel.dismiss == 1 {
            panel.retained.take()
        } else {
            None
        };
        (panel.dismiss, closing)
    });
    if let Some(retained) = retained {
        // SAFETY: the retained context is returned exactly once, here.
        unsafe { (retained.closed)(retained.context, session) };
    }
    status
}

/// A fresh family state whose panel accepts every call.
fn installed() -> State<Probe> {
    let state = State::<Probe>::default();
    PANEL.set(Panel {
        state: Some(state.active.clone()),
        present: 1,
        update: 1,
        dismiss: 1,
        ..Panel::default()
    });
    state
}

fn script(change: impl FnOnce(&mut Panel)) {
    PANEL.with_borrow_mut(change);
}

/// The calls the panel received. No test accepts one made under the lock.
fn calls() -> Vec<&'static str> {
    PANEL.with_borrow(|panel| {
        assert!(
            !panel.entered_under_lock,
            "the panel was entered under the state lock"
        );
        panel.calls.clone()
    })
}

fn retained() -> Retained {
    PANEL
        .with_borrow(|panel| panel.retained)
        .expect("the panel holds an accepted present")
}

fn present(state: &State<Probe>) -> (Result<(), String>, Events, Arc<()>) {
    let (channel, events, alive) = recording_channel();
    let epoch = state.epoch.load(Ordering::Acquire);
    let outcome = state.present_on_main(epoch, &frame_of(1, 0), channel, || Ok(7));
    (outcome, events, alive)
}

fn closed_event() -> serde_json::Value {
    serde_json::json!({"closed": REQUEST_ID})
}

mod presented_panel;
mod presenting;
