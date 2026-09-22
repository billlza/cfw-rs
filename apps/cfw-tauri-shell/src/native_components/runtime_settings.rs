//! Presentation of the existing network settings form; no network mutation lives here.
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Draft {
    port: String,
    level: String,
    mtu: String,
    #[serde(rename = "ipv6DNS")]
    ipv6_dns: bool,
    allow: bool,
    lan_address: String,
    lan_port: String,
    lan_sources: String,
    #[serde(rename = "ipv6DNSEdited")]
    ipv6_dns_edited: bool,
}
impl Draft {
    fn validate(&self) -> Result<(), String> {
        if !["trace", "debug", "info", "warn", "error", "fatal", "silent"]
            .contains(&self.level.as_str())
            || [
                (&self.port, 32),
                (&self.mtu, 32),
                (&self.lan_port, 32),
                (&self.lan_address, 255),
                (&self.lan_sources, 8192),
            ]
            .into_iter()
            .any(|(value, limit)| value.chars().count() > limit)
        {
            return Err("invalid native network settings draft".into());
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Labels {
    title: String,
    description: String,
    port: String,
    automatic: String,
    level: String,
    mtu: String,
    #[serde(rename = "ipv6DNS")]
    ipv6_dns: String,
    ipv6_note: String,
    allow: String,
    lan_note: String,
    lan_address: String,
    lan_port: String,
    lan_sources: String,
    cancel: String,
    apply: String,
    applying: String,
    transport_failure: String,
    input_too_long: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    request_id: String,
    sequence: u64,
    acknowledged_submission: u64,
    locale: String,
    appearance: String,
    labels: Labels,
    draft: Draft,
    saving: bool,
    error: Option<String>,
}
impl Request {
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| "invalid native settings request ID")?;
        self.draft.validate()?;
        let serde_json::Value::Object(labels) =
            serde_json::to_value(&self.labels).map_err(|e| e.to_string())?
        else {
            return Err("invalid native settings labels".into());
        };
        if self.sequence == 0
            || self.sequence > 9_007_199_254_740_991
            || self.acknowledged_submission > 9_007_199_254_740_991
            || !["en", "zh-Hans", "zh-Hant", "ja"].contains(&self.locale.as_str())
            || !["light", "dark"].contains(&self.appearance.as_str())
            || labels.iter().any(|(key, v)| {
                let limit = if [
                    "description",
                    "ipv6Note",
                    "lanNote",
                    "transportFailure",
                    "inputTooLong",
                ]
                .contains(&key.as_str())
                {
                    1024
                } else {
                    160
                };
                v.as_str()
                    .is_none_or(|s| s.trim().is_empty() || s.chars().count() > limit)
            })
            || !self.labels.input_too_long.contains("{label}")
            || !self.labels.input_too_long.contains("{maximum}")
            || self
                .error
                .as_ref()
                .is_some_and(|s| s.trim().is_empty() || s.chars().count() > 4096)
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 16_384
        {
            return Err("invalid native settings envelope".into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ResultEvent {
    #[cfg(feature = "native-ui")]
    Submit {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "submissionId")]
        submission_id: u64,
        draft: Draft,
    },
    #[cfg(feature = "native-ui")]
    Closed {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

#[tauri::command]
pub(crate) async fn present_native_runtime_settings(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
    completion: tauri::ipc::Channel<ResultEvent>,
) -> Result<(), String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        platform::present(app, window, request, completion).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, completion);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn update_native_runtime_settings(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
) -> Result<bool, String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        platform::update(app, window, request).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn dismiss_native_runtime_settings(
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
pub(crate) use platform::{RuntimeSettingsState, cancel_for_reload};

#[cfg(feature = "native-ui")]
mod platform {
    use super::*;
    use crate::native_components::profile_menu::{parent_of_webview, require_window};
    use std::sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use tauri::Manager;

    static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
    type Active = Mutex<Option<Arc<Pending>>>;
    #[derive(Default)]
    pub(crate) struct RuntimeSettingsState(Arc<Active>, AtomicU64);
    struct Pending {
        owner: Weak<Active>,
        request_id: String,
        session: u64,
        window_number: i64,
        sequence: AtomicU64,
        submission: AtomicU64,
        finished: AtomicBool,
        channel: tauri::ipc::Channel<ResultEvent>,
    }
    unsafe extern "C" {
        fn cfm_runtime_settings_present_v1(
            bytes: *const u8,
            count: usize,
            event: extern "C" fn(usize, u64, *const u8, usize) -> i32,
            closed: extern "C" fn(usize, u64),
            context: usize,
        ) -> i32;
        fn cfm_runtime_settings_update_v1(bytes: *const u8, count: usize) -> i32;
        fn cfm_runtime_settings_dismiss_v1(session: u64) -> i32;
    }
    #[derive(Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
    enum Intent {
        Submit {
            #[serde(rename = "submissionId")]
            submission_id: u64,
            draft: Draft,
        },
    }

    extern "C" fn event(context: usize, session: u64, bytes: *const u8, count: usize) -> i32 {
        if bytes.is_null() || count == 0 || count > 16_384 {
            return 0;
        }
        // SAFETY: an accepted panel retains one Arc until its once-only closed
        // callback, and borrows the event buffer synchronously on the UI thread.
        let pending = unsafe { &*(context as *const Pending) };
        if pending.session != session || pending.finished.load(Ordering::Acquire) {
            return 0;
        }
        let data = unsafe { std::slice::from_raw_parts(bytes, count) };
        let Ok(Intent::Submit {
            submission_id,
            draft,
        }) = serde_json::from_slice::<Intent>(data)
        else {
            return 0;
        };
        if draft.validate().is_err()
            || submission_id == 0
            || submission_id > 9_007_199_254_740_991
            || submission_id <= pending.submission.load(Ordering::Acquire)
        {
            return 0;
        }
        pending.submission.store(submission_id, Ordering::Release);
        match pending.channel.send(ResultEvent::Submit {
            request_id: pending.request_id.clone(),
            submission_id,
            draft,
        }) {
            Ok(()) => 1,
            Err(error) => {
                eprintln!("native settings action could not be delivered: {error}");
                0
            }
        }
    }
    extern "C" fn closed(context: usize, session: u64) {
        // SAFETY: this callback consumes the one Arc retained by a successful present.
        let pending = unsafe { Arc::<Pending>::from_raw(context as *const Pending) };
        pending.finished.store(true, Ordering::Release);
        if pending.session != session {
            eprintln!("native settings close identity differs");
            return;
        }
        if let Some(owner) = pending.owner.upgrade() {
            match owner.lock() {
                Ok(mut current) if current.as_ref().is_some_and(|v| v.session == session) => {
                    *current = None
                }
                Ok(_) => {}
                Err(_) => eprintln!("native settings state could not release its window"),
            }
        }
        if let Err(error) = pending.channel.send(ResultEvent::Closed {
            request_id: pending.request_id.clone(),
        }) {
            eprintln!("native settings close could not be delivered: {error}");
        }
    }
    fn frame(request: &Request, session: u64, window: i64) -> Result<Vec<u8>, String> {
        let serde_json::Value::Object(mut object) =
            serde_json::to_value(request).map_err(|e| e.to_string())?
        else {
            return Err("invalid native settings frame".into());
        };
        object.remove("requestId");
        object.insert("version".into(), 1.into());
        object.insert("session".into(), session.into());
        object.insert("windowNumber".into(), window.into());
        let bytes = serde_json::to_vec(&object).map_err(|e| e.to_string())?;
        if bytes.len() > 16_384 {
            return Err("native settings frame exceeds its size bound".into());
        }
        Ok(bytes)
    }
    pub(super) async fn present(
        app: AppHandle,
        window: WebviewWindow,
        request: Request,
        channel: tauri::ipc::Channel<ResultEvent>,
    ) -> Result<(), String> {
        require_window(&app, &window)?;
        if request.acknowledged_submission != 0 {
            return Err("a new settings window cannot acknowledge a previous submission".into());
        }
        let epoch = app
            .state::<RuntimeSettingsState>()
            .1
            .load(Ordering::Acquire);
        let observed_window = window.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        window
            .with_webview(move |webview| {
                let outcome = (|| {
                    require_window(&app, &observed_window)?;
                    let state = app.state::<RuntimeSettingsState>();
                    if state.1.load(Ordering::Acquire) != epoch {
                        return Err("native settings renderer reloaded".into());
                    }
                    let number = parent_of_webview(webview.inner())?;
                    let session = NEXT_SESSION
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                        .map_err(|_| "native settings session exhausted")?;
                    let bytes = frame(&request, session, number)?;
                    let pending = Arc::new(Pending {
                        owner: Arc::downgrade(&state.0),
                        request_id: request.request_id,
                        session,
                        window_number: number,
                        sequence: AtomicU64::new(request.sequence),
                        submission: AtomicU64::new(0),
                        finished: AtomicBool::new(false),
                        channel,
                    });
                    let pointer = Arc::into_raw(pending.clone()) as usize;
                    // SAFETY: main-thread synchronous borrowed JSON; success transfers
                    // the Arc to closed, while event callbacks borrow it only.
                    let status = unsafe {
                        cfm_runtime_settings_present_v1(
                            bytes.as_ptr(),
                            bytes.len(),
                            event,
                            closed,
                            pointer,
                        )
                    };
                    if status != 1 {
                        unsafe {
                            drop(Arc::<Pending>::from_raw(pointer as *const Pending));
                        }
                        return Err(format!(
                            "native settings presentation rejected (status {status})"
                        ));
                    }
                    if pending.finished.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    match state.0.lock() {
                        Ok(mut active) => *active = Some(pending),
                        Err(_) => {
                            unsafe {
                                cfm_runtime_settings_dismiss_v1(session);
                            }
                            return Err("native settings state lock failed".into());
                        }
                    }
                    Ok(())
                })();
                let _receiver_closed = sender.send(outcome);
            })
            .map_err(|e| e.to_string())?;
        receiver
            .await
            .map_err(|_| "native settings presentation ended without a result".to_owned())?
    }
    pub(super) async fn update(
        app: AppHandle,
        window: WebviewWindow,
        request: Request,
    ) -> Result<bool, String> {
        require_window(&app, &window)?;
        crate::startup::on_main(&app, move |app| {
            require_window(&app, &window)?;
            let current = app
                .state::<RuntimeSettingsState>()
                .0
                .lock()
                .map_err(|_| "native settings state lock failed")?
                .clone();
            let Some(pending) = current.filter(|p| p.request_id == request.request_id) else {
                return Ok(false);
            };
            if request.sequence <= pending.sequence.load(Ordering::Acquire) {
                return Ok(false);
            }
            if request.acknowledged_submission > pending.submission.load(Ordering::Acquire) {
                return Err("native settings acknowledged an unknown submission".into());
            }
            let bytes = frame(&request, pending.session, pending.window_number)?;
            // SAFETY: main-thread borrowed buffer; the session remains owned during this call.
            match unsafe { cfm_runtime_settings_update_v1(bytes.as_ptr(), bytes.len()) } {
                1 => {
                    pending.sequence.store(request.sequence, Ordering::Release);
                    Ok(true)
                }
                2 => Ok(false),
                status => Err(format!("native settings update rejected (status {status})")),
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
            return Err("native settings dismissal requires main window".into());
        }
        crate::startup::on_main(&app, move |app| {
            let current = app
                .state::<RuntimeSettingsState>()
                .0
                .lock()
                .map_err(|_| "native settings state lock failed")?
                .clone();
            let Some(pending) = current.filter(|p| p.request_id == request_id) else {
                return Ok(false);
            };
            // SAFETY: on the UI thread with no lock held across the close callback.
            match unsafe { cfm_runtime_settings_dismiss_v1(pending.session) } {
                1 => Ok(true),
                2 => Ok(false),
                status => Err(format!(
                    "native settings dismissal rejected (status {status})"
                )),
            }
        })
        .await
    }
    pub(crate) fn cancel_for_reload(app: &AppHandle, label: &str) {
        if label != "main" {
            return;
        }
        let state = app.state::<RuntimeSettingsState>();
        state.1.fetch_add(1, Ordering::AcqRel);
        let current = match state.0.lock() {
            Ok(current) => current.clone(),
            Err(_) => {
                crate::emit_startup_error(
                    app,
                    "native_settings_cancel_failed",
                    "native settings state lock failed".into(),
                );
                return;
            }
        };
        if let Some(pending) = current {
            // SAFETY: the host page-load callback runs on the UI thread.
            let status = unsafe { cfm_runtime_settings_dismiss_v1(pending.session) };
            if !matches!(status, 1 | 2) {
                crate::emit_startup_error(
                    app,
                    "native_settings_cancel_failed",
                    format!("native settings dismissal rejected: {status}"),
                );
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn settings_events_borrow_context_and_close_releases_it_once() {
            let request = super::super::tests::request();
            let owner = Arc::new(Mutex::new(None));
            let messages = Arc::new(Mutex::new(Vec::new()));
            let sent = messages.clone();
            let pending = Arc::new(Pending {
                owner: Arc::downgrade(&owner),
                request_id: request.request_id.clone(),
                session: 3,
                window_number: 7,
                sequence: AtomicU64::new(1),
                submission: AtomicU64::new(0),
                finished: AtomicBool::new(false),
                channel: tauri::ipc::Channel::new(move |message| {
                    sent.lock().unwrap().push(message);
                    Ok(())
                }),
            });
            let weak = Arc::downgrade(&pending);
            *owner.lock().unwrap() = Some(pending.clone());
            let pointer = Arc::into_raw(pending) as usize;
            let valid = serde_json::to_vec(
                &serde_json::json!({"action":"submit", "submissionId":1, "draft":request.draft}),
            )
            .unwrap();
            assert_eq!(event(pointer, 2, valid.as_ptr(), valid.len()), 0);
            assert_eq!(event(pointer, 3, b"{}".as_ptr(), 2), 0);
            assert!(messages.lock().unwrap().is_empty());
            assert_eq!(event(pointer, 3, valid.as_ptr(), valid.len()), 1);
            assert_eq!(
                event(pointer, 3, valid.as_ptr(), valid.len()),
                0,
                "replayed submits are rejected"
            );
            assert!(
                weak.upgrade().is_some(),
                "submitting a form borrows the existing observer"
            );
            closed(pointer, 3);
            assert!(owner.lock().unwrap().is_none());
            assert!(
                weak.upgrade().is_none(),
                "the close callback releases the observer"
            );
            let messages = messages.lock().unwrap();
            assert_eq!(messages.len(), 2);
            let json: Vec<serde_json::Value> = messages
                .iter()
                .map(|message| match message {
                    tauri::ipc::InvokeResponseBody::Json(text) => {
                        serde_json::from_str(text).unwrap()
                    }
                    _ => panic!("settings events must be JSON"),
                })
                .collect();
            assert_eq!(json[0]["kind"], "submit");
            assert_eq!(json[0]["draft"]["ipv6DNS"], true);
            assert_eq!(json[1]["kind"], "closed");
            assert_eq!(json[1]["requestId"], request.request_id);
        }

        #[test]
        fn native_frame_uses_the_exact_settings_contract_without_host_request_id() {
            let bytes = frame(&super::super::tests::request(), 3, 7).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(value.get("requestId").is_none());
            assert_eq!(value["version"], 1);
            assert_eq!(value["session"], 3);
            assert_eq!(value["windowNumber"], 7);
            assert_eq!(value["draft"]["ipv6DNSEdited"], false);
            assert!(value["labels"]["ipv6DNS"].is_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn request() -> Request {
        let mut labels = serde_json::Map::new();
        for name in [
            "title",
            "description",
            "port",
            "automatic",
            "level",
            "mtu",
            "ipv6DNS",
            "ipv6Note",
            "allow",
            "lanNote",
            "lanAddress",
            "lanPort",
            "lanSources",
            "cancel",
            "apply",
            "applying",
            "transportFailure",
        ] {
            labels.insert(name.into(), name.into());
        }
        labels.insert(
            "inputTooLong".into(),
            "{label} must contain at most {maximum} characters".into(),
        );
        serde_json::from_value(serde_json::json!({
            "requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sequence":1, "acknowledgedSubmission":0, "locale":"en", "appearance":"dark",
            "labels":labels, "draft":{"port":"", "level":"info", "mtu":"1500", "ipv6DNS":true, "allow":false,
            "lanAddress":"0.0.0.0", "lanPort":"7898", "lanSources":"", "ipv6DNSEdited":false}, "saving":false, "error":null,
        })).unwrap()
    }
    #[test]
    fn settings_presentation_accepts_unsaved_values_but_never_expands_the_wire_contract() {
        let mut request = request();
        assert!(request.validate().is_ok());
        request.draft.port = "not a port".into();
        assert!(
            request.validate().is_ok(),
            "the existing application validator owns business validation"
        );
        request.draft.port = "x".repeat(33);
        assert!(request.validate().is_err());
        request.draft.port.clear();
        request.appearance = "system".into();
        assert!(request.validate().is_err());
        request.appearance = "dark".into();
        request.labels.title = "x".repeat(161);
        assert!(request.validate().is_err());
        let mut value = serde_json::to_value(request).unwrap();
        value["draft"]["revision"] = "forged".into();
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
}
