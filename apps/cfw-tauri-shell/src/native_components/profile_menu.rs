use super::{MenuItem, PROFILE_ACTIONS, ProfileMenuRequest, ProfileMenuResult};
use serde::Serialize;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};
use tauri::{AppHandle, Manager, WebviewWindow};
use tokio::sync::oneshot;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
type ActiveMenu = Mutex<Option<Arc<Pending>>>;
#[derive(Default)]
pub(crate) struct NativeProfileMenuState(Arc<ActiveMenu>, AtomicU64);
struct Pending {
    owner: Weak<ActiveMenu>,
    request_id: String,
    session: u64,
    frame: Mutex<Frame>,
    completed: Mutex<bool>,
    channel: tauri::ipc::Channel<ProfileMenuResult>,
}
#[derive(Clone, Serialize)]
struct Anchor {
    x: f64,
    y: f64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Frame {
    version: u32,
    session: u64,
    revision: u64,
    window_number: i64,
    anchor: Anchor,
    locale: String,
    appearance: String,
    more_label: String,
    items: Vec<MenuItem>,
}
unsafe extern "C" {
    fn cfm_webview_window_number_v1(view: *mut std::ffi::c_void, window: *mut i64) -> i32;
    fn cfm_profile_menu_anchor_v1(
        view: *mut std::ffi::c_void,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
        window: *mut i64,
        screen_x: *mut f64,
        screen_y: *mut f64,
    ) -> i32;
    fn cfm_profile_menu_present_v1(
        bytes: *const u8,
        count: usize,
        callback: extern "C" fn(usize, u64, u32),
        context: usize,
    ) -> i32;
    fn cfm_profile_menu_update_v1(bytes: *const u8, count: usize) -> i32;
    fn cfm_profile_menu_dismiss_v1(session: u64) -> i32;
}
pub(super) fn require_window(app: &AppHandle, window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main"
        || app.state::<crate::LaunchContext>().is_migration_handoff()
        || !app
            .state::<crate::lifecycle::AppLifecycle>()
            .startup_work_allowed()
    {
        return Err("native profile menus are unavailable for this window or lifecycle".into());
    }
    app.state::<crate::startup_state::NativeStartup>()
        .require_ready()
}

/// Resolve the decorated host from the same borrowed WKWebView used for menus.
/// Window lookup retains neither the view nor its parent and needs no DOM geometry.
pub(super) fn parent_of_webview(view: *mut std::ffi::c_void) -> Result<i64, String> {
    let mut number = 0_i64;
    // SAFETY: caller is within Tauri's main-thread with_webview closure.
    let status = unsafe { cfm_webview_window_number_v1(view, &mut number) };
    if status == 1 {
        Ok(number)
    } else {
        Err(format!(
            "native settings parent is unavailable (status {status})"
        ))
    }
}
extern "C" fn completed(context: usize, session: u64, action: u32) {
    // SAFETY: exactly one retained Arc is transferred by a successful present.
    // Swift clears its callback before invoking it once on selection/dismissal.
    let pending = unsafe { Arc::<Pending>::from_raw(context as *const Pending) };
    let result = (|| {
        let mut closed = pending
            .completed
            .lock()
            .map_err(|_| "native menu completion lock failed")?;
        if *closed || session != pending.session {
            return Err("native menu completion identity differs");
        }
        *closed = true;
        let frame = pending
            .frame
            .lock()
            .map_err(|_| "native menu frame lock failed")?;
        if action == 0 {
            return Ok(None);
        }
        let id = PROFILE_ACTIONS
            .get(action as usize - 1)
            .ok_or("native menu selected an unknown action")?;
        if !frame
            .items
            .iter()
            .any(|item| item.id == *id && item.enabled)
        {
            return Err("native menu selected an unavailable action");
        }
        Ok(Some((*id).to_owned()))
    })();
    if let Some(owner) = pending.owner.upgrade() {
        match owner.lock() {
            Ok(mut current)
                if current
                    .as_ref()
                    .is_some_and(|value| value.session == pending.session) =>
            {
                *current = None;
            }
            Ok(_) => {}
            Err(_) => eprintln!("native menu state could not release its completion"),
        }
    }
    let (action, error) = match result {
        Ok(action) => (action, None),
        Err(error) => (None, Some(error.to_owned())),
    };
    if let Err(error) = pending.channel.send(ProfileMenuResult {
        request_id: pending.request_id.clone(),
        action,
        error,
    }) {
        // A renderer may have closed/reloaded; no business command was executed.
        eprintln!("native profile menu result could not be delivered: {error}");
    }
}

pub(super) async fn present(
    app: AppHandle,
    window: WebviewWindow,
    request: ProfileMenuRequest,
    channel: tauri::ipc::Channel<ProfileMenuResult>,
) -> Result<(), String> {
    require_window(&app, &window)?;
    let epoch = app
        .state::<NativeProfileMenuState>()
        .1
        .load(Ordering::Acquire);
    let (sender, receiver) = oneshot::channel();
    let window_state = window.clone();
    window
        .with_webview(move |webview| {
            let outcome = (|| {
                require_window(&app, &window_state)?;
                if app
                    .state::<NativeProfileMenuState>()
                    .1
                    .load(Ordering::Acquire)
                    != epoch
                {
                    return Err("native menu renderer was closed or reloaded".into());
                }
                let session = NEXT_SESSION
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                    .map_err(|_| "native menu session exhausted")?;
                let (mut number, mut x, mut y) = (0_i64, 0.0, 0.0);
                let point = &request.point;
                // SAFETY: Tauri calls this closure on the UI thread and lends the real
                // WKWebView NSView pointer for its duration. The helper retains nothing.
                let placement = unsafe {
                    cfm_profile_menu_anchor_v1(
                        webview.inner(),
                        point.x,
                        point.y,
                        point.viewport_width,
                        point.viewport_height,
                        &mut number,
                        &mut x,
                        &mut y,
                    )
                };
                if placement != 1 {
                    return Err(format!("native menu placement failed (status {placement})"));
                }
                let frame = Frame {
                    version: 1,
                    session,
                    revision: request.revision,
                    window_number: number,
                    anchor: Anchor { x, y },
                    locale: request.locale,
                    appearance: request.appearance,
                    more_label: request.more_label,
                    items: request.items,
                };
                let bytes = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
                if bytes.len() > 16_384 {
                    return Err("native menu frame exceeds size limit".into());
                }
                let owner = app.state::<NativeProfileMenuState>().0.clone();
                let pending = Arc::new(Pending {
                    owner: Arc::downgrade(&owner),
                    request_id: request.request_id,
                    session,
                    frame: Mutex::new(frame),
                    completed: Mutex::new(false),
                    channel,
                });
                let pointer = Arc::into_raw(pending.clone()) as usize;
                // SAFETY: synchronous borrowed JSON on the main thread. A successful
                // present consumes the Arc through the one-shot completion callback.
                let status = unsafe {
                    cfm_profile_menu_present_v1(bytes.as_ptr(), bytes.len(), completed, pointer)
                };
                if status != 1 {
                    // Rejected presents retain neither the callback nor its context.
                    unsafe {
                        drop(Arc::<Pending>::from_raw(pointer as *const Pending));
                    }
                    return Err(format!(
                        "native menu presentation rejected (status {status})"
                    ));
                }
                if !*pending
                    .completed
                    .lock()
                    .map_err(|_| "native menu completion lock failed")?
                {
                    match owner.lock() {
                        Ok(mut active) => *active = Some(pending.clone()),
                        Err(_) => {
                            // SAFETY: accepted presentation is still owned by this main-thread session.
                            unsafe {
                                cfm_profile_menu_dismiss_v1(session);
                            }
                            return Err("native menu state lock failed".into());
                        }
                    }
                }
                Ok(())
            })();
            let _receiver_closed = sender.send(outcome);
        })
        .map_err(|e| e.to_string())?;
    receiver
        .await
        .map_err(|_| "native menu presentation ended without a result".to_owned())?
}

pub(super) async fn update(
    app: AppHandle,
    window: WebviewWindow,
    request: ProfileMenuRequest,
) -> Result<bool, String> {
    require_window(&app, &window)?;
    crate::startup::on_main(&app, move |app| {
        require_window(&app, &window)?;
        let state = app.state::<NativeProfileMenuState>();
        let pending = state
            .0
            .lock()
            .map_err(|_| "native menu state lock failed")?
            .clone();
        let Some(pending) = pending.filter(|value| value.request_id == request.request_id) else {
            return Ok(false);
        };
        if *pending
            .completed
            .lock()
            .map_err(|_| "native menu completion lock failed")?
        {
            return Ok(false);
        }
        let prior = pending
            .frame
            .lock()
            .map_err(|_| "native menu frame lock failed")?
            .clone();
        if request.revision <= prior.revision {
            return Ok(false);
        }
        let next = Frame {
            revision: request.revision,
            locale: request.locale,
            appearance: request.appearance,
            more_label: request.more_label,
            items: request.items,
            ..prior.clone()
        };
        let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
        if bytes.len() > 16_384 {
            return Err("native menu frame exceeds size limit".into());
        }
        // SAFETY: main-thread synchronous borrowed JSON, scoped to the current session.
        let status = unsafe { cfm_profile_menu_update_v1(bytes.as_ptr(), bytes.len()) };
        match status {
            1 => {
                *pending
                    .frame
                    .lock()
                    .map_err(|_| "native menu frame lock failed")? = next;
                Ok(true)
            }
            2 => Ok(false),
            other => Err(format!("native menu update rejected (status {other})")),
        }
    })
    .await
}

pub(super) async fn dismiss(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    if window.label() != "main" {
        return Err("native menu dismissal requires the main window".into());
    }
    crate::startup::on_main(&app, move |app| {
        let state = app.state::<NativeProfileMenuState>();
        let pending = state
            .0
            .lock()
            .map_err(|_| "native menu state lock failed")?
            .clone();
        let Some(pending) = pending.filter(|value| value.request_id == request_id) else {
            return Ok(false);
        };
        // SAFETY: main-thread session-scoped cancellation. Completion owns the context.
        match unsafe { cfm_profile_menu_dismiss_v1(pending.session) } {
            1 => Ok(true),
            2 => Ok(false),
            status => Err(format!("native menu dismissal rejected (status {status})")),
        }
    })
    .await
}

/// Called on the existing host UI thread before renderer reload or window hide.
/// No selection can survive a detached renderer and later run in a fresh page.
pub(crate) fn cancel_for_window(app: &AppHandle, label: &str) {
    if label != "main" {
        return;
    }
    let state = app.state::<NativeProfileMenuState>();
    state.1.fetch_add(1, Ordering::AcqRel);
    let pending = match state.0.lock() {
        Ok(current) => current.clone(),
        Err(_) => {
            crate::emit_startup_error(
                app,
                "native_menu_cancel_failed",
                "native menu state lock failed".into(),
            );
            return;
        }
    };
    if let Some(pending) = pending {
        // SAFETY: host page/window callbacks run on its UI thread; no lock crosses the callback.
        let status = unsafe { cfm_profile_menu_dismiss_v1(pending.session) };
        if status != 1 && status != 2 {
            crate::emit_startup_error(
                app,
                "native_menu_cancel_failed",
                format!("native menu dismissal failed: {status}"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::ipc::{Channel, InvokeResponseBody};

    fn completion(action: u32, enabled: bool) -> serde_json::Value {
        let owner = Arc::new(Mutex::new(None));
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sent = messages.clone();
        let pending = Arc::new(Pending {
            owner: Arc::downgrade(&owner),
            request_id: "request".into(),
            session: 1,
            frame: Mutex::new(Frame {
                version: 1,
                session: 1,
                revision: 2,
                window_number: 1,
                anchor: Anchor { x: 0.0, y: 0.0 },
                locale: "en".into(),
                appearance: "light".into(),
                more_label: "more".into(),
                items: vec![MenuItem {
                    id: "edit".into(),
                    title: "Edit".into(),
                    icon: "edit".into(),
                    enabled,
                    reason: (!enabled).then(|| "disabled now".into()),
                    danger: false,
                }],
            }),
            completed: Mutex::new(false),
            channel: Channel::new(move |message| {
                sent.lock().unwrap().push(message);
                Ok(())
            }),
        });
        let weak = Arc::downgrade(&pending);
        *owner.lock().unwrap() = Some(pending.clone());
        completed(Arc::into_raw(pending) as usize, 1, action);
        assert!(
            owner.lock().unwrap().is_none(),
            "completed menus release the channel owner"
        );
        assert!(
            weak.upgrade().is_none(),
            "no callback context remains after release"
        );
        let mut messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        match messages.remove(0) {
            InvokeResponseBody::Json(json) => serde_json::from_str(&json).unwrap(),
            InvokeResponseBody::Raw(_) => panic!("menu result must be typed JSON"),
        }
    }

    #[test]
    fn native_result_is_bound_to_current_enabled_action_and_releases_context() {
        let selected = completion(2, true);
        assert_eq!(selected["action"], "edit");
        assert!(selected["error"].is_null());
        let disabled = completion(2, false);
        assert!(disabled["action"].is_null());
        assert!(disabled["error"].as_str().unwrap().contains("unavailable"));
        let invalid = completion(13, true);
        assert!(invalid["action"].is_null());
        assert!(invalid["error"].as_str().unwrap().contains("unknown"));
        let cancelled = completion(0, true);
        assert!(cancelled["action"].is_null() && cancelled["error"].is_null());
    }
}
