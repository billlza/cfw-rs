//! Native presentation components for the existing UI. No business/network command is owned here.
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

#[cfg(feature = "native-ui")]
mod profile_menu;
pub(crate) mod runtime_settings;

pub(crate) const PROFILE_ACTIONS: [&str; 12] = [
    "select",
    "edit",
    "edit-external",
    "update",
    "reveal",
    "outbounds",
    "route",
    "copy",
    "qrcode",
    "credentials",
    "settings",
    "delete",
];

#[derive(Clone, Copy, Serialize)]
pub(crate) struct NativeUiCapabilities {
    pub profile_menu: bool,
    pub runtime_settings: bool,
}
impl NativeUiCapabilities {
    pub fn current() -> Self {
        Self {
            profile_menu: cfg!(feature = "native-ui"),
            runtime_settings: cfg!(feature = "native-ui"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MenuItem {
    pub id: String,
    pub title: String,
    pub icon: String,
    pub enabled: bool,
    pub reason: Option<String>,
    pub danger: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MenuPoint {
    pub x: f64,
    pub y: f64,
    pub viewport_width: f64,
    pub viewport_height: f64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileMenuRequest {
    pub request_id: String,
    pub revision: u64,
    pub locale: String,
    pub appearance: String,
    pub more_label: String,
    pub point: MenuPoint,
    pub items: Vec<MenuItem>,
}
impl ProfileMenuRequest {
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.request_id).map_err(|_| "invalid profile menu request ID")?;
        if self.revision == 0
            || self.revision > 9_007_199_254_740_991
            || !["en", "zh-Hans", "zh-Hant", "ja"].contains(&self.locale.as_str())
            || !["light", "dark"].contains(&self.appearance.as_str())
            || self.more_label.trim().is_empty()
            || self.more_label.chars().count() > 160
            || self.items.is_empty()
            || self.items.len() > PROFILE_ACTIONS.len()
        {
            return Err("invalid profile menu envelope".into());
        }
        let p = &self.point;
        if ![p.x, p.y, p.viewport_width, p.viewport_height]
            .into_iter()
            .all(f64::is_finite)
            || p.viewport_width <= 0.0
            || p.viewport_height <= 0.0
            || p.x < 0.0
            || p.y < 0.0
            || p.x > p.viewport_width
            || p.y > p.viewport_height
        {
            return Err("invalid profile menu position".into());
        }
        let mut previous = None;
        for item in &self.items {
            let index = PROFILE_ACTIONS
                .iter()
                .position(|name| *name == item.id)
                .ok_or("unknown profile menu action")?;
            if previous.is_some_and(|value| index <= value) {
                return Err("profile menu order differs from the original action order".into());
            }
            previous = Some(index);
            if item.title.trim().is_empty()
                || item.title.chars().count() > 160
                || ![
                    "check", "edit", "refresh", "folder", "send", "rules", "copy", "qr", "gear",
                    "trash",
                ]
                .contains(&item.icon.as_str())
                || item.enabled != item.reason.is_none()
                || item
                    .reason
                    .as_ref()
                    .is_some_and(|s| s.trim().is_empty() || s.chars().count() > 1024)
                || item.danger != (item.id == "delete")
            {
                return Err("invalid profile menu item".into());
            }
        }
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 16_384 {
            return Err("profile menu request exceeds its size bound".into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileMenuResult {
    pub request_id: String,
    pub action: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub(crate) async fn present_native_profile_menu(
    app: AppHandle,
    window: WebviewWindow,
    request: ProfileMenuRequest,
    completion: tauri::ipc::Channel<ProfileMenuResult>,
) -> Result<(), String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        profile_menu::present(app, window, request, completion).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, completion);
        Err("native UI components are not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn update_native_profile_menu(
    app: AppHandle,
    window: WebviewWindow,
    request: ProfileMenuRequest,
) -> Result<bool, String> {
    request.validate()?;
    #[cfg(feature = "native-ui")]
    {
        profile_menu::update(app, window, request).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window);
        Err("native UI components are not built into this host".into())
    }
}

#[tauri::command]
pub(crate) async fn dismiss_native_profile_menu(
    app: AppHandle,
    window: WebviewWindow,
    request_id: String,
) -> Result<bool, String> {
    #[cfg(feature = "native-ui")]
    {
        profile_menu::dismiss(app, window, request_id).await
    }
    #[cfg(not(feature = "native-ui"))]
    {
        let _ = (app, window, request_id);
        Err("native UI components are not built into this host".into())
    }
}

#[cfg(feature = "native-ui")]
pub(crate) use profile_menu::{NativeProfileMenuState, cancel_for_window};

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ProfileMenuRequest {
        ProfileMenuRequest {
            request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            revision: 1,
            locale: "en".into(),
            appearance: "light".into(),
            more_label: "scroll to view more".into(),
            point: MenuPoint {
                x: 120.0,
                y: 90.0,
                viewport_width: 850.0,
                viewport_height: 572.0,
            },
            items: vec![
                MenuItem {
                    id: "edit".into(),
                    title: "Edit".into(),
                    icon: "edit".into(),
                    enabled: true,
                    reason: None,
                    danger: false,
                },
                MenuItem {
                    id: "delete".into(),
                    title: "Delete".into(),
                    icon: "trash".into(),
                    enabled: true,
                    reason: None,
                    danger: true,
                },
            ],
        }
    }
    #[test]
    fn profile_menu_admits_original_order_and_explicit_unavailable_reason() {
        let mut value = request();
        assert!(value.validate().is_ok());
        value.items[0].enabled = false;
        assert!(value.validate().is_err());
        value.items[0].reason = Some("unavailable".into());
        assert!(value.validate().is_ok());
        value.items.reverse();
        assert!(value.validate().is_err());
    }
    #[test]
    fn profile_menu_rejects_unknown_duplicate_oversized_or_outside_input() {
        let mut value = request();
        value.items[0].id = "start-tunnel".into();
        assert!(value.validate().is_err());
        let mut value = request();
        value.items.insert(1, value.items[0].clone());
        assert!(value.validate().is_err());
        let mut value = request();
        value.items[0].title = "x".repeat(161);
        assert!(value.validate().is_err());
        let mut value = request();
        value.point.x = f64::NAN;
        assert!(value.validate().is_err());
        let mut value = request();
        value.point.y = value.point.viewport_height + 1.0;
        assert!(value.validate().is_err());
        let mut value = request();
        value.revision = 0;
        assert!(value.validate().is_err());
        let mut value = request();
        value.appearance = "system".into();
        assert!(value.validate().is_err());
        let mut value = request();
        value.items[1].danger = false;
        assert!(value.validate().is_err());
        let mut json = serde_json::to_value(request()).unwrap();
        json["profileToken"] = "never accepted".into();
        assert!(serde_json::from_value::<ProfileMenuRequest>(json).is_err());
    }
}
