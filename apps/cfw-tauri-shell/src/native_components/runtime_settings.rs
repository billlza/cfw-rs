//! Presentation of the existing network settings form; no network mutation lives here.
#[cfg(feature = "native-ui")]
use super::panel_session;
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
        panel_session::present::<platform::Settings>(app, window, request, completion).await
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
        panel_session::update::<platform::Settings>(app, window, request).await
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
        panel_session::dismiss::<platform::Settings>(app, window, request_id).await
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
    use panel_session::{Abi, Family};

    unsafe extern "C" {
        fn cfm_runtime_settings_present_v1(
            bytes: *const u8,
            count: usize,
            event: panel_session::EventCallback,
            closed: panel_session::ClosedCallback,
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

    /// The form's draft stays in the native panel and the renderer; a session
    /// keeps nothing beside its shared identity.
    pub(crate) struct Settings;
    pub(crate) type RuntimeSettingsState = panel_session::State<Settings>;

    impl panel_session::Request for Request {
        fn request_id(&self) -> &str {
            &self.request_id
        }
        fn sequence(&self) -> u64 {
            self.sequence
        }
        fn acknowledged_submission(&self) -> u64 {
            self.acknowledged_submission
        }
    }
    impl Family for Settings {
        type Request = Request;
        type Event = ResultEvent;
        const LABEL: &'static str = "native settings";
        const PRESENT_ACKNOWLEDGEMENT_REFUSED: &'static str =
            "a new settings window cannot acknowledge a previous submission";
        const CANCEL_FAILURE: &'static str = "native_settings_cancel_failed";
        const ABI: Abi = Abi {
            present: cfm_runtime_settings_present_v1,
            update: cfm_runtime_settings_update_v1,
            dismiss: cfm_runtime_settings_dismiss_v1,
        };

        fn begin(_request: &Request) -> Self {
            Self
        }
        fn admit(&self, request_id: &str, data: &[u8]) -> Option<(u64, ResultEvent)> {
            let Ok(Intent::Submit {
                submission_id,
                draft,
            }) = serde_json::from_slice::<Intent>(data)
            else {
                return None;
            };
            draft.validate().ok()?;
            Some((
                submission_id,
                ResultEvent::Submit {
                    request_id: request_id.to_owned(),
                    submission_id,
                    draft,
                },
            ))
        }
        fn closed(request_id: String) -> ResultEvent {
            ResultEvent::Closed { request_id }
        }
    }

    pub(crate) fn cancel_for_reload(app: &AppHandle, label: &str) {
        panel_session::cancel_for_reload::<Settings>(app, label);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::native_components::panel_session::tests::{callback_ownership, native_frame};

        #[test]
        fn settings_events_borrow_context_and_close_releases_it_once() {
            let request = super::super::tests::request();
            let valid = serde_json::to_vec(
                &serde_json::json!({"action":"submit", "submissionId":1, "draft":request.draft}),
            )
            .unwrap();
            let json = callback_ownership::<Settings>(&request, &valid);
            assert_eq!(json.len(), 2);
            assert_eq!(json[0]["kind"], "submit");
            assert_eq!(json[0]["draft"]["ipv6DNS"], true);
            assert_eq!(json[1]["kind"], "closed");
            assert_eq!(json[1]["requestId"], request.request_id);
        }

        #[test]
        fn native_frame_uses_the_exact_settings_contract_without_host_request_id() {
            let value = native_frame::<Settings>(&super::super::tests::request());
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
