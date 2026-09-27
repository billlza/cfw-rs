//! In-place General switch presentation. The renderer's existing handlers own all effects.
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Viewport {
    width: f64,
    height: f64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}
impl Rect {
    fn valid(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite() && v.abs() <= 100_000.0)
            && self.width >= 0.0
            && self.height >= 0.0
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Item {
    key: u32,
    label: String,
    help: String,
    enabled: bool,
    checked: bool,
    rect: Rect,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    #[serde(skip_serializing)]
    request_id: String,
    sequence: u64,
    acknowledged_submission: u64,
    locale: String,
    appearance: String,
    viewport: Viewport,
    clip: Rect,
    items: Vec<Item>,
}
impl Request {
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| "invalid native switches request ID")?;
        let finite_viewport = [self.viewport.width, self.viewport.height]
            .iter()
            .all(|v| v.is_finite() && *v > 0.0 && *v <= 100_000.0);
        let mut keys = std::collections::BTreeSet::new();
        if self.sequence == 0
            || self.sequence > 9_007_199_254_740_991
            || self.acknowledged_submission > 9_007_199_254_740_991
            || !["en", "zh-Hans", "zh-Hant", "ja"].contains(&self.locale.as_str())
            || !["light", "dark"].contains(&self.appearance.as_str())
            || !finite_viewport
            || !self.clip.valid()
            || self.clip.x < 0.0
            || self.clip.y < 0.0
            || self.clip.x + self.clip.width > self.viewport.width
            || self.clip.y + self.clip.height > self.viewport.height
            || self.items.len() > 6
            || self.items.iter().any(|item| {
                !(1..=6).contains(&item.key)
                    || !keys.insert(item.key)
                    || item.label.trim().is_empty()
                    || item.label.chars().count() > 160
                    || item.help.chars().count() > 1024
                    || !item.rect.valid()
                    || item.rect.width <= 0.0
                    || item.rect.height <= 0.0
            })
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 15_500
        {
            return Err("invalid native General switches frame".into());
        }
        Ok(())
    }
}

#[cfg(feature = "native-ui")]
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Event {
    #[cfg(feature = "native-ui")]
    Input {
        #[serde(rename = "requestId")]
        request_id: String,
        sequence: u64,
        submission: u64,
        key: u32,
        action: u32,
        value: bool,
    },
    #[cfg(feature = "native-ui")]
    Closed {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

#[tauri::command]
pub(crate) async fn sync_native_general_switches(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
    completion: Option<tauri::ipc::JavaScriptChannelId>,
) -> Result<bool, String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        platform::sync(app, window, request, completion).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, completion);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn focus_native_general_switch(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
    sequence: u64,
    key: u32,
) -> Result<bool, String> {
    #[cfg(feature = "native-ui")]
    {
        platform::focus(app, window, request_id, sequence, key).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, request_id, sequence, key);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn dismiss_native_general_switches(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    #[cfg(feature = "native-ui")]
    {
        platform::dismiss(app, window, request_id).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, request_id);
        Err("native UI is not built into this host".into())
    }
}

#[cfg(feature = "native-ui")]
pub(crate) use platform::{GeneralSwitchesState, cancel_for_reload};

#[cfg(feature = "native-ui")]
mod platform {
    use super::*;
    use crate::native_components::profile_menu::require_window;
    use std::sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    };
    use tauri::Manager;

    static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
    type Active = Mutex<Option<Arc<Pending>>>;
    #[derive(Default)]
    pub(crate) struct GeneralSwitchesState(Arc<Active>, AtomicU64);
    struct Pending {
        owner: Weak<Active>,
        session: u64,
        request_id: String,
        epoch: u64,
        frame: Mutex<Request>,
        submission: AtomicU64,
        channel: tauri::ipc::Channel<Event>,
    }
    #[derive(Serialize)]
    struct Frame<'a> {
        version: u32,
        session: u64,
        #[serde(flatten)]
        request: &'a Request,
    }
    type Input = extern "C" fn(usize, u64, u64, u64, u32, u32, u8) -> i32;
    unsafe extern "C" {
        fn cfm_general_switches_sync_v1(
            view: *mut std::ffi::c_void,
            bytes: *const u8,
            count: usize,
            input: Option<Input>,
            closed: Option<extern "C" fn(usize)>,
            context: usize,
        ) -> i32;
        fn cfm_general_switches_focus_v1(session: u64, sequence: u64, key: u32) -> i32;
        fn cfm_general_switches_dismiss_v1(session: u64) -> i32;
    }
    extern "C" fn input(
        context: usize,
        session: u64,
        sequence: u64,
        submission: u64,
        key: u32,
        action: u32,
        value: u8,
    ) -> i32 {
        // SAFETY: Swift retains this context until its single closed callback,
        // and invokes input synchronously on the main thread before releasing it.
        let pending = unsafe { &*(context as *const Pending) };
        let valid = (|| {
            let frame = pending
                .frame
                .lock()
                .map_err(|_| "native switches frame lock failed")?;
            if session != pending.session
                || sequence != frame.sequence
                || value > 1
                || !(1..=5).contains(&action)
                || (action == 5 && key != 0)
                || (action != 5 && !frame.items.iter().any(|i| i.key == key && i.enabled))
                || (action != 1 && (submission != 0 || value != 0))
            {
                return Err("obsolete or invalid native switches event");
            }
            if action == 1 {
                let previous = pending.submission.load(Ordering::Acquire);
                if submission != previous + 1
                    || frame.acknowledged_submission != previous
                    || !frame
                        .items
                        .iter()
                        .any(|i| i.key == key && i.checked != (value == 1))
                {
                    return Err("unacknowledged or duplicate native switch intent");
                }
                pending.submission.store(submission, Ordering::Release);
            }
            Ok(())
        })();
        if let Err(error) = valid {
            eprintln!("{error}");
            return 0;
        }
        match pending.channel.send(Event::Input {
            request_id: pending.request_id.clone(),
            sequence,
            submission,
            key,
            action,
            value: value == 1,
        }) {
            Ok(()) => 1,
            Err(error) => {
                eprintln!("native switch event could not be delivered: {error}");
                0
            }
        }
    }
    extern "C" fn closed(context: usize) {
        // SAFETY: exactly one Arc was transferred on successful first sync;
        // Swift removes all event sources before calling this exactly once.
        let pending = unsafe { Arc::<Pending>::from_raw(context as *const Pending) };
        if let Some(owner) = pending.owner.upgrade() {
            match owner.lock() {
                Ok(mut active)
                    if active
                        .as_ref()
                        .is_some_and(|p| p.session == pending.session) =>
                {
                    *active = None
                }
                Ok(_) => {}
                Err(_) => eprintln!("native switches ownership lock failed during close"),
            }
        }
        if let Err(error) = pending.channel.send(Event::Closed {
            request_id: pending.request_id.clone(),
        }) {
            eprintln!("native switches close could not be delivered: {error}");
        }
    }
    pub(super) async fn sync(
        app: AppHandle,
        window: WebviewWindow,
        request: Request,
        channel: Option<tauri::ipc::JavaScriptChannelId>,
    ) -> Result<bool, String> {
        require_window(&app, &window)?;
        let epoch = app
            .state::<GeneralSwitchesState>()
            .1
            .load(Ordering::Acquire);
        let window_state = window.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        window
            .with_webview(move |view| {
                let result = (|| {
                    require_window(&app, &window_state)?;
                    let state = app.state::<GeneralSwitchesState>();
                    if state.1.load(Ordering::Acquire) != epoch {
                        return Err("native switches renderer was closed or reloaded".into());
                    }
                    let previous = state
                        .0
                        .lock()
                        .map_err(|_| "native switches state lock failed")?
                        .clone();
                    let existing = previous
                        .as_ref()
                        .filter(|p| p.request_id == request.request_id);
                    if let Some(pending) = existing {
                        if channel.is_some() {
                            return Err(
                                "native switches updates must retain their original channel".into(),
                            );
                        }
                        let prior = pending
                            .frame
                            .lock()
                            .map_err(|_| "native switches frame lock failed")?
                            .clone();
                        if request.sequence <= prior.sequence
                            || request.acknowledged_submission < prior.acknowledged_submission
                            || request.acknowledged_submission
                                > pending.submission.load(Ordering::Acquire)
                        {
                            return Err("obsolete native switches update".into());
                        }
                        let bytes = serde_json::to_vec(&Frame {
                            version: 1,
                            session: pending.session,
                            request: &request,
                        })
                        .map_err(|e| e.to_string())?;
                        // Callbacks may run synchronously during focus/layout. Publish
                        // the proposed frame before the call, with no lock held.
                        *pending
                            .frame
                            .lock()
                            .map_err(|_| "native switches frame lock failed")? = request;
                        // SAFETY: borrowed WKWebView and JSON on the main thread; update owns no new context.
                        let status = unsafe {
                            cfm_general_switches_sync_v1(
                                view.inner(),
                                bytes.as_ptr(),
                                bytes.len(),
                                None,
                                None,
                                0,
                            )
                        };
                        if status != 1 {
                            *pending
                                .frame
                                .lock()
                                .map_err(|_| "native switches frame lock failed")? = prior;
                            if status == 2 {
                                return Ok(false);
                            }
                            return Err(format!(
                                "native switches update rejected (status {status})"
                            ));
                        }
                        return Ok(true);
                    }
                    if request.acknowledged_submission != 0 {
                        return Err("new native switches session has prior submission".into());
                    }
                    let channel =
                        channel.ok_or("new native switches session needs a completion channel")?;
                    let session = NEXT_SESSION
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                        .map_err(|_| "native switches session exhausted")?;
                    let bytes = serde_json::to_vec(&Frame {
                        version: 1,
                        session,
                        request: &request,
                    })
                    .map_err(|e| e.to_string())?;
                    let pending = Arc::new(Pending {
                        owner: Arc::downgrade(&state.0),
                        session,
                        request_id: request.request_id.clone(),
                        epoch,
                        frame: Mutex::new(request),
                        submission: AtomicU64::new(0),
                        // Optional command inputs use Tauri's deserializable ID;
                        // construct its owner only for this new native session.
                        channel: channel.channel_on(window_state.as_ref().clone()),
                    });
                    let context = Arc::into_raw(pending.clone()) as usize;
                    // SAFETY: main-thread borrowed inputs. Only successful initial sync
                    // retains context; closed consumes that Arc once.
                    let status = unsafe {
                        cfm_general_switches_sync_v1(
                            view.inner(),
                            bytes.as_ptr(),
                            bytes.len(),
                            Some(input),
                            Some(closed),
                            context,
                        )
                    };
                    if status != 1 {
                        unsafe {
                            drop(Arc::<Pending>::from_raw(context as *const Pending));
                        }
                        if status == 2 {
                            return Ok(false);
                        }
                        return Err(format!(
                            "native switches presentation rejected (status {status})"
                        ));
                    }
                    match state.0.lock() {
                        Ok(mut active) => *active = Some(pending),
                        Err(_) => {
                            unsafe {
                                cfm_general_switches_dismiss_v1(session);
                            }
                            return Err("native switches ownership lock failed".into());
                        }
                    }
                    Ok(true)
                })();
                let _receiver_closed = tx.send(result);
            })
            .map_err(|e| e.to_string())?;
        rx.await
            .map_err(|_| "native switches sync ended without a result".to_owned())?
    }
    pub(super) async fn focus(
        app: AppHandle,
        window: WebviewWindow,
        request_id: String,
        sequence: u64,
        key: u32,
    ) -> Result<bool, String> {
        require_window(&app, &window)?;
        crate::startup::on_main(&app, move |app| {
            require_window(&app, &window)?;
            let pending = app
                .state::<GeneralSwitchesState>()
                .0
                .lock()
                .map_err(|_| "native switches ownership lock failed")?
                .clone();
            let Some(p) = pending.filter(|p| p.request_id == request_id) else {
                return Ok(false);
            };
            // SAFETY: main-thread call addresses only this accepted session.
            Ok(unsafe { cfm_general_switches_focus_v1(p.session, sequence, key) } == 1)
        })
        .await
    }
    pub(super) async fn dismiss(
        app: AppHandle,
        window: WebviewWindow,
        request_id: String,
    ) -> Result<bool, String> {
        if window.label() != "main" {
            return Err("invalid native switches window".into());
        }
        crate::startup::on_main(&app, move |app| {
            let pending = app
                .state::<GeneralSwitchesState>()
                .0
                .lock()
                .map_err(|_| "native switches ownership lock failed")?
                .clone();
            let Some(p) = pending.filter(|p| p.request_id == request_id) else {
                return Ok(false);
            };
            // SAFETY: closing remains available during shutdown, and the context
            // is consumed exclusively by the synchronous closed callback.
            Ok(unsafe { cfm_general_switches_dismiss_v1(p.session) } == 1)
        })
        .await
    }
    pub(crate) fn cancel_for_reload(app: &AppHandle, label: &str) {
        if label != "main" {
            return;
        }
        let epoch = app
            .state::<GeneralSwitchesState>()
            .1
            .fetch_add(1, Ordering::AcqRel);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let result = crate::startup::on_main(&app, move |app| {
                let pending = app
                    .state::<GeneralSwitchesState>()
                    .0
                    .lock()
                    .map_err(|_| "native switches ownership lock failed")?
                    .clone();
                if let Some(p) = pending.filter(|p| p.epoch <= epoch) {
                    unsafe {
                        cfm_general_switches_dismiss_v1(p.session);
                    }
                }
                Ok::<_, String>(())
            })
            .await;
            if let Err(error) = result {
                eprintln!("native switches reload cleanup failed: {error}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        serde_json::from_value(
            serde_json::json!({"requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "sequence":1,"acknowledgedSubmission":0,"locale":"en","appearance":"light",
            "viewport":{"width":850,"height":572},"clip":{"x":170,"y":0,"width":680,"height":572},
            "items":[{"key":3,"label":"TUN Mode","help":"","checked":true,"enabled":true,
                "rect":{"x":790,"y":330,"width":34,"height":20}}]}),
        )
        .unwrap()
    }
    #[test]
    fn boundary_preserves_disable_intent_and_rejects_duplicate_or_invalid_geometry() {
        let mut r = request();
        assert!(r.validate().is_ok());
        r.items[0].help = "Current request can still be cancelled".into();
        assert!(r.validate().is_ok());
        r.items.push(r.items[0].clone());
        assert!(r.validate().is_err());
        let mut r = request();
        r.clip.width = 1000.0;
        assert!(r.validate().is_err());
        let mut r = request();
        r.items[0].rect.x = f64::NAN;
        assert!(r.validate().is_err());
        let mut r = request();
        r.items[0].key = 7;
        assert!(r.validate().is_err());
        let mut r = request();
        r.items.clear();
        assert!(r.validate().is_ok());
    }
}
