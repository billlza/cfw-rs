//! Shell, window, and diagnostics helpers restored from 0.3.5.
//!
//! Nothing here touches the data plane. Opening the updater's internally
//! authorized release URL or revealing a directory goes through the operating
//! system's own `open` utility with a fixed absolute path and separate
//! arguments: no shell is involved, the URL scheme is restricted to
//! `http`/`https`, and every revealed path is one this application owns.
//! Diagnostics reads SystemConfiguration only, so the
//! historical `networksetup`, `scutil`, and `route` invocations are gone along
//! with the fields they produced.

use std::path::{Path, PathBuf};
use std::process::Command;

use cfw_platform::{MacOsPlatformService, NetworkServiceObservation};
use reqwest::Url;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::lifecycle::request_shutdown;
use crate::settings_store;

/// The operating system's own opener. It is referenced by absolute path and
/// never through a shell or a PATH lookup.
const OPEN_UTILITY: &str = "/usr/bin/open";
const MAX_EXTERNAL_URL_BYTES: usize = 2_048;
const MAX_PAGE_NAME_CHARS: usize = 64;
const MAX_DEEP_LINKS: usize = 32;
const MAX_DEEP_LINK_BYTES: usize = 4_096;

/// Fields the retired child-process tools used to supply. They are reported as
/// explicitly unavailable instead of being silently dropped or invented.
const UNAVAILABLE_DIAGNOSTICS: [&str; 4] = [
    "default_route_interface",
    "hardware_port",
    "bsd_device",
    "recommended_clash_proxy_services",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NetworkDiagnostics {
    default_route_interface: Option<String>,
    service_order: Vec<String>,
    services: Vec<NetworkServiceObservation>,
    recommended_clash_proxy_services: Vec<String>,
    proxied_services: Vec<String>,
    unavailable: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeepLinkAction {
    InstallConfig,
    InstallProfile,
    Quit,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeepLinkIntent {
    raw: String,
    action: DeepLinkAction,
    url: Option<String>,
    name: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeepLinkParseOutcome {
    raw: String,
    intent: Option<DeepLinkIntent>,
    error: Option<String>,
}

/// Opens a URL selected by a trusted Rust callsite. This is deliberately not a
/// Tauri command: renderer IPC must never bypass the updater's one-use metadata
/// authorization by supplying its own download destination.
pub(crate) fn open_trusted_external_url(url: &str) -> Result<(), String> {
    let target = validate_external_url(url)?;
    open_argument(&target)
}

#[tauri::command]
pub(crate) fn open_page(app: AppHandle, page: String) -> Result<(), String> {
    let page = validate_page_name(&page)?;
    app.emit("cfw://page", page)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn reveal_home_directory() -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    reveal_owned_directory(&store.paths().app_home)
}

#[tauri::command]
pub(crate) fn reveal_logs_directory() -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|error| error.to_string())?;
    reveal_owned_directory(&store.paths().logs_dir)
}

#[tauri::command]
pub(crate) fn open_login_items_settings() -> Result<(), String> {
    MacOsPlatformService.open_login_items_settings();
    Ok(())
}

#[tauri::command]
pub(crate) fn move_dashboard_to_nearest_monitor(app: AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is not available".to_string())?;
    window.show().map_err(|error| error.to_string())?;
    window.center().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn refresh_tray_menu(app: AppHandle) -> Result<(), String> {
    crate::shell::refresh_tray_from_controller(&app).await
}

#[tauri::command]
pub(crate) fn toggle_devtools(app: AppHandle) -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or_else(|| "main window is not available".to_string())?;
        if window.is_devtools_open() {
            window.close_devtools();
        } else {
            window.open_devtools();
        }
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = app;
        Err("DevTools are disabled in release builds to keep the ARM64 runtime lean".into())
    }
}

/// Quits with a failure exit code.
///
/// "Force" applies to the exit code, not to the data plane: the engine is still
/// stopped through the coordinator, because leaving an orphaned ProxyAgent or
/// Packet Tunnel behind is never an acceptable outcome of a user action.
#[tauri::command]
pub(crate) fn force_quit_app(app: AppHandle) -> Result<(), String> {
    request_shutdown(app, 1)
}

#[tauri::command]
pub(crate) fn parse_deep_links(urls: Vec<String>) -> Result<Vec<DeepLinkParseOutcome>, String> {
    if urls.len() > MAX_DEEP_LINKS {
        return Err(format!(
            "at most {MAX_DEEP_LINKS} deep links can be parsed at once"
        ));
    }
    Ok(urls.into_iter().map(parse_one_deep_link).collect())
}

#[tauri::command]
pub(crate) fn network_diagnostics() -> Result<NetworkDiagnostics, String> {
    let services = MacOsPlatformService
        .observe_network_services()
        .map_err(|error| error.to_string())?;
    Ok(NetworkDiagnostics {
        default_route_interface: None,
        service_order: services
            .iter()
            .map(|service| service.display_name.clone())
            .collect(),
        recommended_clash_proxy_services: Vec::new(),
        proxied_services: services
            .iter()
            .filter(|service| service.any_proxy_enabled())
            .map(|service| service.display_name.clone())
            .collect(),
        services,
        unavailable: UNAVAILABLE_DIAGNOSTICS.to_vec(),
    })
}

fn parse_one_deep_link(raw: String) -> DeepLinkParseOutcome {
    match parse_deep_link(&raw) {
        Ok(intent) => DeepLinkParseOutcome {
            raw,
            intent: Some(intent),
            error: None,
        },
        Err(error) => DeepLinkParseOutcome {
            raw,
            intent: None,
            error: Some(error),
        },
    }
}

fn parse_deep_link(raw: &str) -> Result<DeepLinkIntent, String> {
    if raw.len() > MAX_DEEP_LINK_BYTES {
        return Err("deep link is too long".into());
    }
    let parsed = Url::parse(raw).map_err(|error| format!("invalid clash:// URL: {error}"))?;
    if parsed.scheme() != "clash" {
        return Err(format!("unsupported URL scheme: {}", parsed.scheme()));
    }
    let action = match parsed.host_str().unwrap_or_default() {
        "install-config" => DeepLinkAction::InstallConfig,
        "install-profile" => DeepLinkAction::InstallProfile,
        "quit" => DeepLinkAction::Quit,
        _ => DeepLinkAction::Unknown,
    };
    let pairs = parsed.query_pairs().collect::<Vec<_>>();
    let value = |wanted: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| value.to_string())
    };
    Ok(DeepLinkIntent {
        raw: raw.to_owned(),
        action,
        url: value("url"),
        name: value("name"),
        source: value("source"),
    })
}

fn validate_external_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.len() > MAX_EXTERNAL_URL_BYTES {
        return Err("URL is too long to open".into());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "only absolute http(s) URLs can be opened")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("only http(s) URLs can be opened".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL must not carry embedded credentials".into());
    }
    // A URL that is not exactly what was requested, or that carries whitespace
    // or a leading dash, must never reach an argument vector.
    if parsed.host_str().is_none_or(str::is_empty)
        || parsed.as_str() != trimmed
        || trimmed.starts_with('-')
        || trimmed.chars().any(|character| {
            character.is_whitespace() || character.is_control() || character == '"'
        })
    {
        return Err("URL is not a plain absolute http(s) URL".into());
    }
    Ok(trimmed.to_owned())
}

fn validate_page_name(page: &str) -> Result<String, String> {
    let trimmed = page.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_PAGE_NAME_CHARS
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("unsupported page name: {page}"));
    }
    Ok(trimmed.to_owned())
}

/// Reveals a directory this application owns. The path is produced by the
/// settings store, never by the renderer.
fn reveal_owned_directory(path: &Path) -> Result<(), String> {
    if !path.is_dir() {
        return Err(format!("directory is unavailable: {}", path.display()));
    }
    open_path(path, false)
}

pub(super) fn open_path(path: &Path, reveal_in_finder: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("only an absolute application-owned path can be opened".into());
    }
    let mut command = Command::new(OPEN_UTILITY);
    if reveal_in_finder {
        command.arg("-R");
    }
    run_open(command.arg(path))
}

fn open_argument(url: &str) -> Result<(), String> {
    run_open(Command::new(OPEN_UTILITY).arg(url))
}

fn run_open(command: &mut Command) -> Result<(), String> {
    let status = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("could not start {OPEN_UTILITY}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{OPEN_UTILITY} failed with status {status}"))
    }
}

/// Absolute path of an application-owned profile envelope, used only to reveal
/// or open it.
pub(super) fn owned_profile_path(profiles_dir: &Path, file_name: &str) -> Result<PathBuf, String> {
    if file_name.contains('/') || file_name.contains("..") {
        return Err("profile file name is not a repository entry".into());
    }
    Ok(profiles_dir.join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_quit_propagates_lifecycle_rejection_to_ipc() {
        let source = include_str!("shell_ops.rs");
        let command = source
            .split("pub(crate) fn force_quit_app")
            .nth(1)
            .expect("force quit command")
            .split("#[tauri::command]")
            .next()
            .expect("force quit boundary");
        assert!(command.starts_with("(app: AppHandle) -> Result<(), String>"));
        assert!(command.contains("request_shutdown(app, 1)"));
        assert!(!command.contains("let _"));
    }

    #[test]
    fn only_plain_absolute_http_urls_can_be_opened() {
        assert_eq!(
            validate_external_url(" https://example.com/a?b=c ").expect("plain https URL"),
            "https://example.com/a?b=c"
        );
        for rejected in [
            "file:///etc/passwd",
            "clash://install-config?url=x",
            "javascript:alert(1)",
            "-R",
            "--args",
            "https://example.com/ evil",
            "https://example.com/\u{7}",
            "example.com",
            "https://",
            "https://user:pass@example.com/",
        ] {
            assert!(
                validate_external_url(rejected).is_err(),
                "accepted unsafe URL: {rejected}"
            );
        }
        assert!(
            validate_external_url(&format!("https://example.com/{}", "a".repeat(4096))).is_err()
        );
    }

    #[test]
    fn page_names_are_bounded_lowercase_tokens() {
        assert_eq!(validate_page_name(" general ").expect("page"), "general");
        assert_eq!(
            validate_page_name("proxy-groups").expect("page"),
            "proxy-groups"
        );
        for rejected in ["", "  ", "General", "page name", "page/../etc", "p\u{7}"] {
            assert!(
                validate_page_name(rejected).is_err(),
                "accepted unsafe page: {rejected}"
            );
        }
        assert!(validate_page_name(&"a".repeat(MAX_PAGE_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn deep_links_keep_the_0_3_5_intent_shape() {
        let outcomes = parse_deep_links(vec![
            "clash://install-config?url=https%3A%2F%2Fexample.com%2Fa.json&name=Work".to_owned(),
            "https://example.com".to_owned(),
        ])
        .expect("bounded deep links");
        assert_eq!(outcomes.len(), 2);
        let intent = outcomes[0].intent.as_ref().expect("parsed intent");
        assert_eq!(intent.action, DeepLinkAction::InstallConfig);
        assert_eq!(intent.url.as_deref(), Some("https://example.com/a.json"));
        assert_eq!(intent.name.as_deref(), Some("Work"));
        assert!(outcomes[0].error.is_none());
        assert!(outcomes[1].intent.is_none());
        assert!(
            outcomes[1]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("unsupported URL scheme"))
        );

        let payload = serde_json::to_value(&outcomes[0]).expect("serialize outcome");
        assert_eq!(payload["intent"]["action"], "install-config");
        assert!(parse_deep_links(vec!["clash://quit".to_owned(); MAX_DEEP_LINKS + 1]).is_err());
        assert!(
            parse_deep_link(&format!(
                "clash://quit?name={}",
                "a".repeat(MAX_DEEP_LINK_BYTES)
            ))
            .is_err()
        );
    }

    #[test]
    fn deep_link_actions_cover_the_0_3_5_verbs() {
        for (raw, expected) in [
            ("clash://install-config", DeepLinkAction::InstallConfig),
            ("clash://install-profile", DeepLinkAction::InstallProfile),
            ("clash://quit", DeepLinkAction::Quit),
            ("clash://something-else", DeepLinkAction::Unknown),
        ] {
            assert_eq!(parse_deep_link(raw).expect("intent").action, expected);
        }
    }

    #[test]
    fn only_repository_entry_names_resolve_to_a_profile_path() {
        let profiles = Path::new("/tmp/profiles");
        assert_eq!(
            owned_profile_path(profiles, "id.profile.json").expect("entry path"),
            profiles.join("id.profile.json")
        );
        for rejected in ["../escape.json", "nested/id.json", ".."] {
            assert!(
                owned_profile_path(profiles, rejected).is_err(),
                "accepted escaping entry: {rejected}"
            );
        }
    }

    #[test]
    fn relative_paths_are_never_opened() {
        assert!(open_path(Path::new("relative/path"), false).is_err());
    }

    #[test]
    fn diagnostics_declares_the_fields_the_retired_tools_used_to_supply() {
        let payload = serde_json::to_value(NetworkDiagnostics {
            default_route_interface: None,
            service_order: vec!["Wi-Fi".into()],
            services: Vec::new(),
            recommended_clash_proxy_services: Vec::new(),
            proxied_services: Vec::new(),
            unavailable: UNAVAILABLE_DIAGNOSTICS.to_vec(),
        })
        .expect("serialize diagnostics");
        assert!(payload["default_route_interface"].is_null());
        assert_eq!(
            payload["unavailable"],
            serde_json::json!([
                "default_route_interface",
                "hardware_port",
                "bsd_device",
                "recommended_clash_proxy_services",
            ])
        );
    }
}
