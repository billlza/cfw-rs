//! The glass behind the page: the window's slab and the panels, cards and
//! navigation pill the page lays out, drawn natively under the WKWebView. The
//! renderer measures and names them; nothing here reads or changes state.
#[cfg(feature = "native-ui")]
use super::panel_session;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

const MAXIMUM_PANELS: usize = 32;
const MAXIMUM_RADIUS: f64 = 64.0;

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Panel,
    Card,
    Pill,
    Strip,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Panel {
    id: String,
    kind: Kind,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    radius: f64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Viewport {
    width: f64,
    height: f64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    request_id: String,
    sequence: u64,
    acknowledged_submission: u64,
    appearance: String,
    viewport: Viewport,
    panels: Vec<Panel>,
}
impl Request {
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.request_id)
            .map_err(|_| "invalid native window glass request ID")?;
        let mut ids = std::collections::BTreeSet::new();
        let finite = self
            .panels
            .iter()
            .flat_map(|panel| [panel.x, panel.y, panel.width, panel.height, panel.radius])
            .chain([self.viewport.width, self.viewport.height])
            .all(f64::is_finite);
        // The backdrop emits no submission, so there is never one to acknowledge.
        if self.sequence == 0
            || self.sequence > 9_007_199_254_740_991
            || self.acknowledged_submission != 0
            || !["light", "dark"].contains(&self.appearance.as_str())
            || !finite
            || self.viewport.width <= 0.0
            || self.viewport.height <= 0.0
            || self.panels.len() > MAXIMUM_PANELS
            || self.panels.iter().any(|panel| {
                !is_identifier(&panel.id)
                    || !ids.insert(panel.id.as_str())
                    || panel.width < 0.0
                    || panel.height < 0.0
                    || !(0.0..=MAXIMUM_RADIUS).contains(&panel.radius)
            })
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 16_384
        {
            return Err("invalid native window glass envelope".into());
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
    Closed {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

#[tauri::command]
pub(crate) async fn present_native_window_glass(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
    completion: tauri::ipc::Channel<Event>,
) -> Result<(), String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        panel_session::present::<platform::Glass>(app, window, request, completion).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, completion);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn update_native_window_glass(
    app: AppHandle,
    window: WebviewWindow,
    request: Request,
) -> Result<bool, String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        panel_session::update::<platform::Glass>(app, window, request).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window);
        Err("native UI is not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn dismiss_native_window_glass(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    #[cfg(feature = "native-ui")]
    {
        panel_session::dismiss::<platform::Glass>(app, window, request_id).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, request_id);
        Err("native UI is not built into this host".into())
    }
}

#[cfg(feature = "native-ui")]
pub(crate) use platform::{WindowGlassState, cancel_for_reload};

#[cfg(feature = "native-ui")]
mod platform {
    use super::*;
    use panel_session::{Abi, Family};

    unsafe extern "C" {
        fn cfm_window_glass_present_v1(
            bytes: *const u8,
            count: usize,
            event: panel_session::EventCallback,
            closed: panel_session::ClosedCallback,
            context: usize,
        ) -> i32;
        fn cfm_window_glass_update_v1(bytes: *const u8, count: usize) -> i32;
        fn cfm_window_glass_dismiss_v1(session: u64) -> i32;
    }

    /// The backdrop keeps no state beside the session: it never reports an
    /// intent, so there is nothing to admit.
    pub(crate) struct Glass;
    pub(crate) type WindowGlassState = panel_session::State<Glass>;

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
    impl Family for Glass {
        type Request = Request;
        type Event = Event;
        const LABEL: &'static str = "native window glass";
        const PRESENT_ACKNOWLEDGEMENT_REFUSED: &'static str =
            "the window glass acknowledges no submission";
        const CANCEL_FAILURE: &'static str = "native_window_glass_cancel_failed";
        const ABI: Abi = Abi {
            present: cfm_window_glass_present_v1,
            update: cfm_window_glass_update_v1,
            dismiss: cfm_window_glass_dismiss_v1,
        };

        fn begin(_request: &Request) -> Self {
            Self
        }
        fn admit(&self, _request_id: &str, _data: &[u8]) -> Option<(u64, Event)> {
            None
        }
        fn closed(request_id: String) -> Event {
            Event::Closed { request_id }
        }
    }

    pub(crate) fn cancel_for_reload(app: &AppHandle, label: &str) {
        panel_session::cancel_for_reload::<Glass>(app, label);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::native_components::panel_session::tests::{eventless_ownership, native_frame};

        #[test]
        fn the_backdrop_admits_no_intent_and_reports_only_its_closing() {
            let request = request(1, 0);
            let glass = Glass::begin(&request);
            assert!(
                glass
                    .admit("request", br#"{"action":"activate","submissionId":1}"#)
                    .is_none()
            );
            assert!(glass.admit("request", b"").is_none());
            let closed = serde_json::to_value(Glass::closed("request".into())).expect("event");
            assert_eq!(
                closed,
                serde_json::json!({ "kind": "closed", "requestId": "request" })
            );
            let frame = native_frame::<Glass>(&request);
            assert_eq!(frame["panels"][0]["kind"], "pill");
            assert_eq!(frame["acknowledgedSubmission"], 0);
        }

        #[test]
        fn present_owns_the_context_until_the_closed_callback_and_emits_only_that() {
            let request = request(1, 0);
            let events = eventless_ownership::<Glass>(&request);
            assert_eq!(
                events,
                vec![serde_json::json!({ "kind": "closed", "requestId": request.request_id })]
            );
        }
    }
}

#[cfg(test)]
fn request(sequence: u64, acknowledged_submission: u64) -> Request {
    Request {
        request_id: "7d3a9f0e-4b1c-4c1d-8e2f-0a1b2c3d4e5f".into(),
        sequence,
        acknowledged_submission,
        appearance: "light".into(),
        viewport: Viewport {
            width: 1120.0,
            height: 720.0,
        },
        panels: vec![Panel {
            id: "nav-active".into(),
            kind: Kind::Pill,
            x: 16.0,
            y: 120.0,
            width: 180.0,
            height: 44.0,
            radius: 0.0,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_is_bounded_and_names_its_panels_once() {
        request(1, 0).validate().expect("valid");
        let mut acknowledging = request(1, 1);
        assert!(acknowledging.validate().is_err());
        acknowledging.acknowledged_submission = 0;
        acknowledging.sequence = 0;
        assert!(acknowledging.validate().is_err());

        let mut duplicate = request(2, 0);
        duplicate.panels.push(duplicate.panels[0].clone());
        assert!(duplicate.validate().is_err());

        let mut named = request(2, 0);
        named.panels[0].id = "Nav".into();
        assert!(named.validate().is_err());

        let mut negative = request(2, 0);
        negative.panels[0].width = -1.0;
        assert!(negative.validate().is_err());

        let mut rounded = request(2, 0);
        rounded.panels[0].radius = MAXIMUM_RADIUS + 1.0;
        assert!(rounded.validate().is_err());

        let mut infinite = request(2, 0);
        infinite.panels[0].x = f64::INFINITY;
        assert!(infinite.validate().is_err());

        let mut flat = request(2, 0);
        flat.viewport.height = 0.0;
        assert!(flat.validate().is_err());

        let mut themed = request(2, 0);
        themed.appearance = "system".into();
        assert!(themed.validate().is_err());

        let mut many = request(2, 0);
        many.panels = (0..=MAXIMUM_PANELS)
            .map(|index| Panel {
                id: format!("panel-{index}"),
                ..many.panels[0].clone()
            })
            .collect();
        assert!(many.validate().is_err());
        many.panels.pop();
        many.validate().expect("the bound is inclusive");
    }

    #[test]
    fn the_request_rejects_unknown_fields_and_kinds() {
        let valid = serde_json::to_value(request(1, 0)).expect("value");
        serde_json::from_value::<Request>(valid.clone()).expect("round trip");
        let mut extra = valid.clone();
        extra["panels"][0]["tint"] = serde_json::json!("accent");
        assert!(serde_json::from_value::<Request>(extra).is_err());
        let mut kind = valid;
        kind["panels"][0]["kind"] = serde_json::json!("window");
        assert!(serde_json::from_value::<Request>(kind).is_err());
    }
}
