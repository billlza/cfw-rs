//! Ownership of the one native dialog panel a component family may present.
//! A family supplies its wire types and C entry points. Session identity, the
//! reload epoch and the context returned by the closed callback live here once.
//!
//! The state lock is never held across a call into the panel: the panel may run
//! the closed callback before that call returns, and the callback takes the lock.
//!
//! A reload advances the epoch and dismisses the presented panel. A present
//! whose command began before the reload and reaches the UI thread after it is
//! refused. A command of the previous page that only begins after the reload
//! reads the new epoch, so nothing here tells it from a command of the new page.
use super::require_window;
use serde::Serialize;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tauri::{AppHandle, Manager, WebviewWindow};

/// Every frame and native event is bounded by the same wire limit.
const MAXIMUM_BYTES: usize = 16_384;
/// Submissions stay exactly representable in the renderer.
const MAXIMUM_COUNTER: u64 = 9_007_199_254_740_991;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub(crate) type EventCallback = unsafe extern "C" fn(usize, u64, *const u8, usize) -> i32;
pub(crate) type ClosedCallback = unsafe extern "C" fn(usize, u64);

/// The three C entry points of one dialog family.
pub(crate) struct Abi {
    pub present:
        unsafe extern "C" fn(*const u8, usize, EventCallback, ClosedCallback, usize) -> i32,
    pub update: unsafe extern "C" fn(*const u8, usize) -> i32,
    pub dismiss: unsafe extern "C" fn(u64) -> i32,
}

/// The envelope every dialog request carries around its family's frame.
pub(crate) trait Request: Serialize + Send + 'static {
    fn request_id(&self) -> &str;
    fn sequence(&self) -> u64;
    fn acknowledged_submission(&self) -> u64;
}

/// One dialog family. A value of the family is the state it keeps for a
/// presented session beside the shared identity.
pub(crate) trait Family: Send + Sync + Sized + 'static {
    type Request: Request;
    type Event: Serialize + Send + Sync + 'static;
    /// Subject of this family's error messages, for example "native settings".
    const LABEL: &'static str;
    /// Refusal of a first frame that claims to acknowledge a submission.
    const PRESENT_ACKNOWLEDGEMENT_REFUSED: &'static str;
    /// Diagnostic kind recorded when a reload cannot release the panel.
    const CANCEL_FAILURE: &'static str;
    const ABI: Abi;

    /// Family state for the frame a new session presents.
    fn begin(request: &Self::Request) -> Self;
    /// Family state after the native panel accepted an updated frame.
    fn accepted(&self, _request: &Self::Request) -> Result<(), String> {
        Ok(())
    }
    /// Decodes one native intent and admits it against the current frame.
    /// Returns its submission and the typed event for the renderer.
    fn admit(&self, request_id: &str, data: &[u8]) -> Option<(u64, Self::Event)>;
    fn closed(request_id: String) -> Self::Event;
}

type Active<F> = Mutex<Option<Arc<Session<F>>>>;

/// The family's presented session and the epoch of the renderer that owns it.
pub(crate) struct State<F: Family> {
    active: Arc<Active<F>>,
    epoch: AtomicU64,
}
impl<F: Family> Default for State<F> {
    fn default() -> Self {
        Self {
            active: Arc::new(Mutex::new(None)),
            epoch: AtomicU64::new(0),
        }
    }
}

/// The context a successful present hands to the native panel. Event callbacks
/// borrow it; the closed callback returns it exactly once.
pub(crate) struct Session<F: Family> {
    owner: Weak<Active<F>>,
    request_id: String,
    session: u64,
    window_number: i64,
    sequence: AtomicU64,
    submission: AtomicU64,
    finished: AtomicBool,
    channel: tauri::ipc::Channel<F::Event>,
    family: F,
}
impl<F: Family> Session<F> {
    fn begin(
        owner: &Arc<Active<F>>,
        request: &F::Request,
        session: u64,
        window_number: i64,
        channel: tauri::ipc::Channel<F::Event>,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner: Arc::downgrade(owner),
            request_id: request.request_id().to_owned(),
            session,
            window_number,
            sequence: AtomicU64::new(request.sequence()),
            submission: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            channel,
            family: F::begin(request),
        })
    }
}

unsafe extern "C" {
    fn cfm_webview_window_number_v1(view: *mut std::ffi::c_void, window: *mut i64) -> i32;
}

/// Resolve the decorated host from the borrowed WKWebView of the request.
/// Window lookup retains neither the view nor its parent and needs no DOM geometry.
fn parent_of_webview<F: Family>(view: *mut std::ffi::c_void) -> Result<i64, String> {
    let mut number = 0_i64;
    // SAFETY: caller is within Tauri's main-thread with_webview closure.
    let status = unsafe { cfm_webview_window_number_v1(view, &mut number) };
    if status == 1 {
        Ok(number)
    } else {
        Err(format!(
            "{} parent is unavailable (status {status})",
            F::LABEL
        ))
    }
}

/// The panel's report of one user intent.
///
/// # Safety
/// `context` is the pointer an accepted present handed to the panel, the
/// closed callback for it has not run, and `bytes` is null or readable for
/// `count` bytes until this call returns.
unsafe extern "C" fn event<F: Family>(
    context: usize,
    session: u64,
    bytes: *const u8,
    count: usize,
) -> i32 {
    if bytes.is_null() || count == 0 || count > MAXIMUM_BYTES {
        return 0;
    }
    // SAFETY: the panel keeps its count of the session until the closed callback.
    let pending = unsafe { &*(context as *const Session<F>) };
    if pending.session != session || pending.finished.load(Ordering::Acquire) {
        return 0;
    }
    // SAFETY: the buffer is borrowed for this call and was checked above.
    let data = unsafe { std::slice::from_raw_parts(bytes, count) };
    let Some((submission_id, intent)) = pending.family.admit(&pending.request_id, data) else {
        return 0;
    };
    if submission_id == 0
        || submission_id > MAXIMUM_COUNTER
        || submission_id <= pending.submission.load(Ordering::Acquire)
    {
        return 0;
    }
    pending.submission.store(submission_id, Ordering::Release);
    match pending.channel.send(intent) {
        Ok(()) => 1,
        Err(error) => {
            eprintln!("{} action could not be delivered: {error}", F::LABEL);
            0
        }
    }
}

/// The panel's once-only report that it has left the screen.
///
/// # Safety
/// `context` is the pointer an accepted present handed to the panel, and this
/// is the only closed callback for it: the call takes that count back.
unsafe extern "C" fn closed<F: Family>(context: usize, session: u64) {
    // SAFETY: this callback consumes the one Arc retained by a successful present.
    let pending = unsafe { Arc::<Session<F>>::from_raw(context as *const Session<F>) };
    pending.finished.store(true, Ordering::Release);
    if pending.session != session {
        // The context is what identifies the panel, and that panel is gone
        // whatever number came with it. The renderer is still told.
        eprintln!("{} close identity differs", F::LABEL);
    }
    if let Some(owner) = pending.owner.upgrade() {
        match owner.lock() {
            Ok(mut current) => {
                if current
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &pending))
                {
                    *current = None;
                }
            }
            Err(_) => eprintln!("{} state could not release its window", F::LABEL),
        }
    }
    if let Err(error) = pending.channel.send(F::closed(pending.request_id.clone())) {
        eprintln!("{} close could not be delivered: {error}", F::LABEL);
    }
}

fn frame<F: Family>(request: &F::Request, session: u64, window: i64) -> Result<Vec<u8>, String> {
    let serde_json::Value::Object(mut object) =
        serde_json::to_value(request).map_err(|e| e.to_string())?
    else {
        return Err(format!("invalid {} frame", F::LABEL));
    };
    object.remove("requestId");
    object.insert("version".into(), 1.into());
    object.insert("session".into(), session.into());
    object.insert("windowNumber".into(), window.into());
    let bytes = serde_json::to_vec(&object).map_err(|e| e.to_string())?;
    if bytes.len() > MAXIMUM_BYTES {
        return Err(format!("{} frame exceeds its size bound", F::LABEL));
    }
    Ok(bytes)
}

/// The UI-thread halves of the commands. Each enters the panel with no state
/// lock held.
impl<F: Family> State<F> {
    /// The presented session. The guard ends with this call.
    fn current(&self) -> Result<Option<Arc<Session<F>>>, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| format!("{} state lock failed", F::LABEL))?;
        Ok(active.clone())
    }

    /// `epoch` is the one the command read when it began. `parent` resolves
    /// the host window, and only for a renderer that is still the current one.
    fn present_on_main(
        &self,
        epoch: u64,
        request: &F::Request,
        channel: tauri::ipc::Channel<F::Event>,
        parent: impl FnOnce() -> Result<i64, String>,
    ) -> Result<(), String> {
        if self.epoch.load(Ordering::Acquire) != epoch {
            return Err(format!("{} renderer reloaded", F::LABEL));
        }
        let number = parent()?;
        let session = NEXT_SESSION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| format!("{} session exhausted", F::LABEL))?;
        let bytes = frame::<F>(request, session, number)?;
        let pending = Session::begin(&self.active, request, session, number, channel);
        let pointer = Arc::into_raw(pending.clone()) as usize;
        // SAFETY: UI-thread call with synchronously borrowed JSON. An accepted
        // present keeps `pointer` until its closed callback; event callbacks
        // only borrow it.
        let status = unsafe {
            (F::ABI.present)(
                bytes.as_ptr(),
                bytes.len(),
                event::<F>,
                closed::<F>,
                pointer,
            )
        };
        if status != 1 {
            // SAFETY: a rejected present retained nothing, so the count handed
            // out above is still this function's to release.
            unsafe { drop(Arc::<Session<F>>::from_raw(pointer as *const Session<F>)) };
            return Err(format!(
                "{} presentation rejected (status {status})",
                F::LABEL
            ));
        }
        // The panel may have closed, through its callback, before present returned.
        if pending.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        let registered = match self.active.lock() {
            Ok(mut active) => {
                *active = Some(pending);
                true
            }
            Err(_) => false,
        };
        if registered {
            return Ok(());
        }
        // SAFETY: UI-thread call; the guard of the failed lock ended with the
        // statement above.
        let status = unsafe { (F::ABI.dismiss)(session) };
        if status != 1 {
            eprintln!("{} dismissal rejected (status {status})", F::LABEL);
        }
        Err(format!("{} state lock failed", F::LABEL))
    }

    fn update_on_main(&self, request: &F::Request) -> Result<bool, String> {
        let Some(pending) = self
            .current()?
            .filter(|pending| pending.request_id == request.request_id())
        else {
            return Ok(false);
        };
        if request.sequence() <= pending.sequence.load(Ordering::Acquire) {
            return Ok(false);
        }
        if request.acknowledged_submission() > pending.submission.load(Ordering::Acquire) {
            return Err(format!("{} acknowledged an unknown submission", F::LABEL));
        }
        let bytes = frame::<F>(request, pending.session, pending.window_number)?;
        // SAFETY: UI-thread call with a synchronously borrowed buffer.
        match unsafe { (F::ABI.update)(bytes.as_ptr(), bytes.len()) } {
            1 => {
                pending
                    .sequence
                    .store(request.sequence(), Ordering::Release);
                pending.family.accepted(request)?;
                Ok(true)
            }
            2 => Ok(false),
            status => Err(format!("{} update rejected (status {status})", F::LABEL)),
        }
    }

    fn dismiss_on_main(&self, request_id: &str) -> Result<bool, String> {
        let Some(pending) = self
            .current()?
            .filter(|pending| pending.request_id == request_id)
        else {
            return Ok(false);
        };
        // SAFETY: UI-thread call. The panel runs the closed callback before it returns.
        match unsafe { (F::ABI.dismiss)(pending.session) } {
            1 => Ok(true),
            2 => Ok(false),
            status => Err(format!("{} dismissal rejected (status {status})", F::LABEL)),
        }
    }

    /// Before the renderer reloads: a present the previous page already began
    /// is refused from here on, and a presented panel is released.
    fn cancel_on_main(&self) -> Result<(), String> {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let Some(pending) = self.current()? else {
            return Ok(());
        };
        // SAFETY: the host page-load callback runs on the UI thread.
        match unsafe { (F::ABI.dismiss)(pending.session) } {
            1 | 2 => Ok(()),
            status => Err(format!("{} dismissal rejected: {status}", F::LABEL)),
        }
    }
}

pub(crate) async fn present<F: Family>(
    app: AppHandle,
    window: WebviewWindow,
    request: F::Request,
    channel: tauri::ipc::Channel<F::Event>,
) -> Result<(), String> {
    require_window(&app, &window)?;
    if request.acknowledged_submission() != 0 {
        return Err(F::PRESENT_ACKNOWLEDGEMENT_REFUSED.into());
    }
    let epoch = app.state::<State<F>>().epoch.load(Ordering::Acquire);
    let observed_window = window.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .with_webview(move |webview| {
            let outcome = require_window(&app, &observed_window).and_then(|()| {
                app.state::<State<F>>()
                    .present_on_main(epoch, &request, channel, || {
                        parent_of_webview::<F>(webview.inner())
                    })
            });
            if sender.send(outcome).is_err() {
                eprintln!("native UI completion receiver closed");
            }
        })
        .map_err(|e| e.to_string())?;
    receiver
        .await
        .map_err(|_| format!("{} presentation ended without a result", F::LABEL))?
}

pub(crate) async fn update<F: Family>(
    app: AppHandle,
    window: WebviewWindow,
    request: F::Request,
) -> Result<bool, String> {
    require_window(&app, &window)?;
    crate::startup::on_main(&app, move |app| {
        require_window(&app, &window)?;
        app.state::<State<F>>().update_on_main(&request)
    })
    .await
}

pub(crate) async fn dismiss<F: Family>(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    if window.label() != "main" {
        return Err(format!("{} dismissal requires main window", F::LABEL));
    }
    crate::startup::on_main(&app, move |app| {
        app.state::<State<F>>().dismiss_on_main(&request_id)
    })
    .await
}

/// Called on the host UI thread before the renderer reloads.
pub(crate) fn cancel_for_reload<F: Family>(app: &AppHandle, label: &str) {
    if label != "main" {
        return;
    }
    if let Err(message) = app.state::<State<F>>().cancel_on_main() {
        crate::emit_startup_error(app, F::CANCEL_FAILURE, message);
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        let deliver = |session, bytes: *const u8, count| unsafe {
            event::<F>(pointer, session, bytes, count)
        };
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
        let pending =
            Session::<F>::begin(&owner, request, 3, 7, tauri::ipc::Channel::new(|_| Ok(())));
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
}
