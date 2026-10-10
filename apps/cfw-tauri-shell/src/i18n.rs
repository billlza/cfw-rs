use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use cfw_core::UiLanguage;
use tauri::{AppHandle, Manager};

type Catalog = BTreeMap<String, String>;
static SIMPLIFIED: OnceLock<Result<Catalog, String>> = OnceLock::new();
static TRADITIONAL: OnceLock<Result<Catalog, String>> = OnceLock::new();
static JAPANESE: OnceLock<Result<Catalog, String>> = OnceLock::new();

#[derive(Default)]
pub(crate) struct NativeLanguage(AtomicU8);

impl NativeLanguage {
    fn load(&self) -> UiLanguage {
        match self.0.load(Ordering::Acquire) {
            1 => UiLanguage::SimplifiedChinese,
            2 => UiLanguage::TraditionalChinese,
            3 => UiLanguage::Japanese,
            _ => UiLanguage::English,
        }
    }

    fn store(&self, language: UiLanguage) {
        self.0.store(
            match language {
                UiLanguage::SimplifiedChinese => 1,
                UiLanguage::TraditionalChinese => 2,
                UiLanguage::Japanese => 3,
                UiLanguage::English | UiLanguage::System => 0,
            },
            Ordering::Release,
        );
    }
}

pub(crate) fn resolve(language: UiLanguage) -> UiLanguage {
    if language == UiLanguage::System {
        language.resolve(&cfw_platform::preferred_languages())
    } else {
        language
    }
}

fn catalog(language: UiLanguage) -> Result<Option<&'static Catalog>, String> {
    let (slot, source) = match language {
        UiLanguage::SimplifiedChinese => {
            (&SIMPLIFIED, include_str!("../ui/src/locales/zh-Hans.json"))
        }
        UiLanguage::TraditionalChinese => {
            (&TRADITIONAL, include_str!("../ui/src/locales/zh-Hant.json"))
        }
        UiLanguage::Japanese => (&JAPANESE, include_str!("../ui/src/locales/ja.json")),
        UiLanguage::English | UiLanguage::System => return Ok(None),
    };
    slot.get_or_init(|| {
        serde_json::from_str(source)
            .map_err(|error| format!("bundled language catalog is invalid: {error}"))
    })
    .as_ref()
    .map(Some)
    .map_err(Clone::clone)
}

/// Resolve OS preferences and parse bundled messages on the preparation worker.
pub(crate) fn prepare(language: UiLanguage) -> Result<UiLanguage, String> {
    let resolved = resolve(language);
    catalog(resolved)?;
    Ok(resolved)
}

pub(crate) fn text(app: &AppHandle, message: &str) -> String {
    let language = app.state::<NativeLanguage>().load();
    let slot = match language {
        UiLanguage::SimplifiedChinese => &SIMPLIFIED,
        UiLanguage::TraditionalChinese => &TRADITIONAL,
        UiLanguage::Japanese => &JAPANESE,
        UiLanguage::English | UiLanguage::System => return message.to_owned(),
    };
    // English is the defined fallback for a missing translation. Preparation
    // must have succeeded before the selected language can be installed.
    slot.get()
        .and_then(|value| value.as_ref().ok())
        .and_then(|messages| messages.get(message))
        .map_or_else(|| message.to_owned(), Clone::clone)
}

#[cfg(feature = "native-dashboard")]
pub(crate) fn locale_identifier(app: &AppHandle) -> &'static str {
    match app.state::<NativeLanguage>().load() {
        UiLanguage::SimplifiedChinese => "zh-Hans",
        UiLanguage::TraditionalChinese => "zh-Hant",
        UiLanguage::Japanese => "ja",
        UiLanguage::English | UiLanguage::System => "en",
    }
}

pub(crate) async fn apply(app: &AppHandle, language: UiLanguage) -> Result<(), String> {
    let resolved = crate::startup_state::prepare_off_main(move || prepare(language)).await?;
    if app.state::<NativeLanguage>().load() == resolved {
        return Ok(());
    }
    crate::startup::on_main(app, move |app| {
        app.state::<NativeLanguage>().store(resolved);
        app.set_menu(crate::shell::build_app_menu(&app).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        Ok(())
    })
    .await?;
    #[cfg(feature = "native-dashboard")]
    tauri::Emitter::emit(app, "cfm://native-overview-locale", ())
        .map_err(|error| format!("native overview language update failed: {error}"))?;
    if app.tray_by_id(crate::shell::TRAY_ID).is_some() {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = crate::shell::refresh_tray_from_controller(&app).await {
                crate::emit_startup_error(&app, "language_menu_refresh_failed", error);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_menus_share_the_complete_dashboard_catalogs() {
        for (language, dashboard, quit) in [
            (
                UiLanguage::SimplifiedChinese,
                "主界面",
                "退出 Clash for Mac",
            ),
            (
                UiLanguage::TraditionalChinese,
                "主介面",
                "結束 Clash for Mac",
            ),
            (
                UiLanguage::Japanese,
                "ダッシュボード",
                "Clash for Mac を終了",
            ),
        ] {
            assert_eq!(prepare(language).unwrap(), language);
            let messages = catalog(language).unwrap().unwrap();
            assert_eq!(messages.get("Dashboard").unwrap(), dashboard);
            assert_eq!(messages.get("Quit Clash for Mac").unwrap(), quit);
            for key in [
                "Edit",
                "Window",
                "Undo",
                "Redo",
                "Cut",
                "Copy",
                "Paste",
                "Select All",
                "Services",
                "Hide Clash for Mac",
                "Hide Others",
                "Minimize",
                "Zoom",
                "About",
                "About Clash for Mac",
                "Check for Update…",
                "Reload dashboard",
                "Open diagnostic logs…",
                "Start local core",
                "Stop core",
                "System Proxy",
                "TUN Mode",
                "Rule",
                "Global",
                "Direct",
                "Routing mode",
                "Quit",
            ] {
                assert!(
                    messages.get(key).is_some_and(|value| !value.is_empty()),
                    "{}: {key}",
                    language.code()
                );
            }
            let selection = NativeLanguage::default();
            selection.store(language);
            assert_eq!(selection.load(), language);
        }
    }
}
