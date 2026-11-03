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
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
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
pub(crate) mod tests;
