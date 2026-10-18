//! Presentation of the existing confirmation and information dialogs. The
//! renderer decides what a button does; no profile or setting is touched here.
#[cfg(feature = "native-ui")]
use super::panel_session;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Cancel,
    Default,
    Destructive,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Button {
    id: String,
    title: String,
    role: Role,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    request_id: String,
    sequence: u64,
    acknowledged_submission: u64,
    locale: String,
    appearance: String,
    title: String,
    message: String,
    buttons: Vec<Button>,
    transport_failure: String,
}
impl Request {
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| "invalid native prompt dialog request ID")?;
        let bounded =
            |text: &str, limit: usize| !text.trim().is_empty() && text.chars().count() <= limit;
        let mut ids = std::collections::BTreeSet::new();
        // The button rule admits exactly one cancel button, and only in front.
        if self.sequence == 0
            || self.sequence > 9_007_199_254_740_991
            || self.acknowledged_submission > 9_007_199_254_740_991
            || !["en", "zh-Hans", "zh-Hant", "ja"].contains(&self.locale.as_str())
            || !["light", "dark"].contains(&self.appearance.as_str())
            || !bounded(&self.title, 160)
            || self.message.chars().count() > 4096
            || !bounded(&self.transport_failure, 1024)
            || !(1..=3).contains(&self.buttons.len())
            || self.buttons.iter().enumerate().any(|(index, button)| {
                (button.role == Role::Cancel) != (index == 0)
                    || !is_identifier(&button.id)
                    || !ids.insert(button.id.as_str())
                    || !bounded(&button.title, 160)
            })
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 16_384
        {
            return Err("invalid native prompt dialog envelope".into());
        }
        Ok(())
    }
}

/// `^[a-z][a-z0-9-]{0,31}$`
fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 32
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Event {
    #[cfg(feature = "native-ui")]
    Activate {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "submissionId")]
        submission_id: u64,
        #[serde(rename = "buttonId")]
        button_id: String,
    },
    #[cfg(feature = "native-ui")]
    Closed {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

#[tauri::command]
pub(crate) async fn present_native_prompt_dialog(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
    completion: tauri::ipc::Channel<Event>,
) -> Result<(), String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        panel_session::present::<platform::Prompt>(app, window, request, completion).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, completion);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn update_native_prompt_dialog(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
) -> Result<bool, String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        panel_session::update::<platform::Prompt>(app, window, request).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn dismiss_native_prompt_dialog(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    #[cfg(feature = "native-ui")]
    {
        panel_session::dismiss::<platform::Prompt>(app, window, request_id).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, request_id);
        Err("native UI is not built into this host".into())
    }
}

#[cfg(feature = "native-ui")]
pub(crate) use platform::{PromptDialogState, cancel_for_reload};

#[cfg(feature = "native-ui")]
mod platform {
    use super::*;
    use panel_session::{Abi, Family};
    use std::sync::Mutex;

    unsafe extern "C" {
        fn cfm_prompt_dialog_present_v1(
            bytes: *const u8,
            count: usize,
            event: panel_session::EventCallback,
            closed: panel_session::ClosedCallback,
            context: usize,
        ) -> i32;
        fn cfm_prompt_dialog_update_v1(bytes: *const u8, count: usize) -> i32;
        fn cfm_prompt_dialog_dismiss_v1(session: u64) -> i32;
    }
    #[derive(Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
    enum Intent {
        Activate {
            #[serde(rename = "submissionId")]
            submission_id: u64,
            #[serde(rename = "buttonId")]
            button_id: String,
        },
    }

    /// The buttons of the frame the panel shows that may report an activation.
    /// Cancel only closes the panel, so it is never one of them.
    pub(crate) struct Prompt {
        activatable: Mutex<Vec<String>>,
    }
    pub(crate) type PromptDialogState = panel_session::State<Prompt>;

    fn activatable(request: &Request) -> Vec<String> {
        request
            .buttons
            .iter()
            .filter(|button| button.role != Role::Cancel)
            .map(|button| button.id.clone())
            .collect()
    }

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
    impl Family for Prompt {
        type Request = Request;
        type Event = Event;
        const LABEL: &'static str = "native prompt dialog";
        const PRESENT_ACKNOWLEDGEMENT_REFUSED: &'static str =
            "a new prompt dialog cannot acknowledge a previous submission";
        const CANCEL_FAILURE: &'static str = "native_prompt_dialog_cancel_failed";
        const ABI: Abi = Abi {
            present: cfm_prompt_dialog_present_v1,
            update: cfm_prompt_dialog_update_v1,
            dismiss: cfm_prompt_dialog_dismiss_v1,
        };

        fn begin(request: &Request) -> Self {
            Self {
                activatable: Mutex::new(activatable(request)),
            }
        }
        fn accepted(&self, request: &Request) -> Result<(), String> {
            *self
                .activatable
                .lock()
                .map_err(|_| "native prompt dialog button lock failed")? = activatable(request);
            Ok(())
        }
        fn admit(&self, request_id: &str, data: &[u8]) -> Option<(u64, Event)> {
            let Ok(Intent::Activate {
                submission_id,
                button_id,
            }) = serde_json::from_slice::<Intent>(data)
            else {
                return None;
            };
            // A poisoned lock cannot vouch for the button, so the intent is refused.
            if !self.activatable.lock().ok()?.contains(&button_id) {
                return None;
            }
            Some((
                submission_id,
                Event::Activate {
                    request_id: request_id.to_owned(),
                    submission_id,
                    button_id,
                },
            ))
        }
        fn closed(request_id: String) -> Event {
            Event::Closed { request_id }
        }
    }

    pub(crate) fn cancel_for_reload(app: &AppHandle, label: &str) {
        panel_session::cancel_for_reload::<Prompt>(app, label);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::native_components::panel_session::tests::{
            callback_ownership, intent_after, native_frame,
        };

        fn activation(submission: u64, button: &str) -> Vec<u8> {
            serde_json::to_vec(
                &serde_json::json!({"action":"activate", "submissionId":submission, "buttonId":button}),
            )
            .unwrap()
        }

        #[test]
        fn prompt_events_borrow_context_and_close_releases_it_once() {
            let request = super::super::tests::request();
            let json = callback_ownership::<Prompt>(&request, &activation(1, "confirm"));
            assert_eq!(json.len(), 2);
            assert_eq!(
                json[0],
                serde_json::json!({"kind":"activate", "requestId":request.request_id,
                    "submissionId":1, "buttonId":"confirm"})
            );
            assert_eq!(
                json[1],
                serde_json::json!({"kind":"closed", "requestId":request.request_id})
            );
        }

        #[test]
        fn only_a_current_non_cancel_button_can_be_activated() {
            let request = super::super::tests::request();
            let verdict = |intent: &[u8]| intent_after::<Prompt>(&request, &[], intent);
            assert_eq!(verdict(&activation(1, "confirm")), 1);
            assert_eq!(verdict(&activation(1, "cancel")), 0, "cancel only closes");
            assert_eq!(verdict(&activation(1, "delete")), 0, "unknown button");
            assert_eq!(verdict(&activation(0, "confirm")), 0);
            assert_eq!(verdict(&activation(9_007_199_254_740_992, "confirm")), 0);
            assert_eq!(
                verdict(
                    br#"{"action":"activate","submissionId":1,"buttonId":"confirm","command":"x"}"#
                ),
                0
            );
            assert_eq!(
                verdict(br#"{"action":"submit","submissionId":1,"buttonId":"confirm"}"#),
                0
            );

            let mut replaced = request.clone();
            replaced.sequence = 2;
            replaced.buttons[1].id = "discard".into();
            let verdict = |intent: &[u8]| intent_after::<Prompt>(&request, &[&replaced], intent);
            assert_eq!(
                verdict(&activation(1, "confirm")),
                0,
                "a button of a replaced frame is no longer current"
            );
            assert_eq!(verdict(&activation(1, "discard")), 1);
        }

        #[test]
        fn native_frame_uses_the_exact_prompt_contract_without_host_request_id() {
            let value = native_frame::<Prompt>(&super::super::tests::request());
            let mut keys: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "acknowledgedSubmission",
                    "appearance",
                    "buttons",
                    "locale",
                    "message",
                    "sequence",
                    "session",
                    "title",
                    "transportFailure",
                    "version",
                    "windowNumber",
                ]
            );
            assert_eq!(value["version"], 1);
            assert_eq!(value["session"], 3);
            assert_eq!(value["windowNumber"], 7);
            assert_eq!(
                value["buttons"],
                serde_json::json!([
                    {"id":"cancel", "title":"No", "role":"cancel"},
                    {"id":"confirm", "title":"Yes", "role":"destructive"},
                ])
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn request() -> Request {
        serde_json::from_value(serde_json::json!({
            "requestId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sequence":1,
            "acknowledgedSubmission":0, "locale":"en", "appearance":"dark",
            "title":"Delete profile", "message":"Delete “Work”?",
            "buttons":[{"id":"cancel", "title":"No", "role":"cancel"},
                {"id":"confirm", "title":"Yes", "role":"destructive"}],
            "transportFailure":"Could not deliver this action.",
        }))
        .unwrap()
    }
    fn button(id: &str, role: Role) -> Button {
        Button {
            id: id.into(),
            title: id.into(),
            role,
        }
    }

    #[test]
    fn prompt_presentation_admits_bounded_text_and_never_expands_the_wire_contract() {
        let mut value = request();
        assert!(value.validate().is_ok());
        value.message.clear();
        assert!(value.validate().is_ok(), "a notice may carry a title only");
        value.message = "字".repeat(4096);
        assert!(value.validate().is_ok());
        value.message.push('字');
        assert!(value.validate().is_err());
        type Change = fn(&mut Request);
        let invalid: [(&str, Change); 10] = [
            ("request ID", |r| r.request_id = "not-a-uuid".into()),
            ("sequence zero", |r| r.sequence = 0),
            ("sequence above the counter bound", |r| {
                r.sequence = 9_007_199_254_740_992
            }),
            ("acknowledgement above the counter bound", |r| {
                r.acknowledged_submission = 9_007_199_254_740_992
            }),
            ("locale", |r| r.locale = "fr".into()),
            ("appearance", |r| r.appearance = "system".into()),
            ("blank title", |r| r.title = " ".into()),
            ("title of 161 scalars", |r| r.title = "x".repeat(161)),
            ("empty transport failure", |r| r.transport_failure.clear()),
            ("transport failure of 1025 scalars", |r| {
                r.transport_failure = "x".repeat(1025)
            }),
        ];
        for (case, change) in invalid {
            let mut value = request();
            change(&mut value);
            assert!(value.validate().is_err(), "{case}");
        }
        let mut value = request();
        value.message = "\u{1F512}".repeat(4096);
        assert!(
            value.validate().is_err(),
            "four-byte scalars within every text bound still exceed the frame"
        );
        // The renderer decides nothing through the frame and states no result in it.
        for (field, forged) in [
            ("command", serde_json::json!("delete_profile")),
            ("busy", serde_json::json!(false)),
            ("error", serde_json::Value::Null),
            ("error", serde_json::json!("Refused")),
            ("message", serde_json::Value::Null),
        ] {
            let mut json = serde_json::to_value(request()).unwrap();
            json[field] = forged;
            assert!(serde_json::from_value::<Request>(json).is_err(), "{field}");
        }
        let mut json = serde_json::to_value(request()).unwrap();
        json["buttons"][1]["command"] = "delete_profile".into();
        assert!(serde_json::from_value::<Request>(json).is_err());
        let mut json = serde_json::to_value(request()).unwrap();
        json["buttons"][1]["role"] = "primary".into();
        assert!(serde_json::from_value::<Request>(json).is_err());
    }

    #[test]
    fn prompt_buttons_are_one_leading_cancel_and_unique_bounded_identifiers() {
        let admitted = |buttons: Vec<Button>| {
            let mut value = request();
            value.buttons = buttons;
            value.validate().is_ok()
        };
        assert!(admitted(vec![button("cancel", Role::Cancel)]));
        assert!(admitted(vec![
            button("cancel", Role::Cancel),
            button("keep", Role::Default),
            button(&format!("a{}", "0".repeat(31)), Role::Destructive),
        ]));
        assert!(!admitted(vec![]));
        assert!(!admitted(vec![
            button("cancel", Role::Cancel),
            button("one", Role::Default),
            button("two", Role::Default),
            button("three", Role::Default),
        ]));
        assert!(!admitted(vec![button("confirm", Role::Destructive)]));
        assert!(!admitted(vec![
            button("confirm", Role::Destructive),
            button("cancel", Role::Cancel),
        ]));
        assert!(!admitted(vec![
            button("cancel", Role::Cancel),
            button("close", Role::Cancel),
        ]));
        assert!(!admitted(vec![
            button("cancel", Role::Cancel),
            button("cancel", Role::Destructive),
        ]));
        let overlong = format!("a{}", "0".repeat(32));
        for id in [
            "",
            "Confirm",
            "1st",
            "a_b",
            "confirm ",
            "é",
            overlong.as_str(),
        ] {
            assert!(
                !admitted(vec![
                    button("cancel", Role::Cancel),
                    Button {
                        id: id.into(),
                        title: "Yes".into(),
                        role: Role::Destructive,
                    },
                ]),
                "{id:?}"
            );
        }
        let mut value = request();
        value.buttons[1].title = " ".into();
        assert!(value.validate().is_err());
        value.buttons[1].title = "x".repeat(161);
        assert!(value.validate().is_err());
    }
}
