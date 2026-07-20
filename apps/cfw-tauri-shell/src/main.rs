use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cfw_controller::{
    ConfigPatch, ControllerClient, ControllerEndpoint, ControllerSnapshot, ProviderBatchResult,
    ProvidersSnapshot, ProxiesSnapshot, ProxyDelayResult, RulesSnapshot, StructuredLogEntry,
};
use cfw_core::{
    ControlSession, DeepLinkIntent, FeatureSet, PRODUCT_NAME, PersistedSettings, ProductBlueprint,
    QualityTargets, SettingsSkeleton, SettingsSnapshot, SettingsStore, UiPage, parse_deep_link,
};
use cfw_platform::{
    HelperInstallRequest, HelperService, LaunchAgentSpec, LaunchdDomain, LaunchdService,
    MacOsPlatformDesign, MacOsPlatformService, NetworkDiagnostics, PlatformTarget, ServiceModeService,
    ServiceModeStatus, SystemProxyMode, SystemProxyService, SystemProxyState, TunService,
};
use cfw_profiles::{
    ProfileApplyResult, ProfileImportRequest, ProfileImportResult, ProfileManager, ProfileRecord,
    ProfileSaveResult, ProfileText,
};
use cfw_runtime::{
    CoreInstallRequest, CoreInstallResult, CoreInstaller, CoreManager, CoreProcessSpec,
    CoreProcessState, CoreRuntimeError, CoreStatus, DEFAULT_CORE_BINARY_NAME, PINNED_MIHOMO_VERSION,
};
use futures_util::StreamExt;
use qrcode::QrCode;
use qrcode::render::svg;
use serde::{Deserialize, Serialize};
use tauri::Wry;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindowBuilder};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const TRAY_ID: &str = "cfw-tray";
const LAUNCH_AGENT_LABEL: &str = "com.bill.clashformac";
const HELPER_LABEL: &str = "com.bill.clashformac.helper";
const PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.bill.clashformac.helper";
const ACTION_TIMEOUT: Duration = Duration::from_secs(10);
const ACTION_OUTPUT_LIMIT: usize = 64 * 1024;
const BLOCKED_ACTION_EXECUTABLES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "osascript",
    "python",
    "python3",
    "ruby",
    "perl",
    "node",
];

#[derive(Default)]
struct ManagedCore {
    child: Mutex<Option<Child>>,
}

#[derive(Default)]
struct LiveStreams {
    connections_started: Mutex<bool>,
    logs_started: Mutex<bool>,
}

#[derive(Debug, Deserialize)]
struct LegacyProfileList {
    files: Vec<LegacyProfileEntry>,
    index: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct LegacyProfileEntry {
    time: Option<String>,
    name: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BootPayload {
    product: ProductBlueprint<PlatformTarget>,
    pages: Vec<UiPage>,
    settings: SettingsSkeleton,
    platform: MacOsPlatformDesign,
    quality: QualityTargets,
}

#[derive(Debug, Clone, Serialize)]
struct DeepLinkParseOutcome {
    raw: String,
    intent: Option<DeepLinkIntent>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StreamError {
    stream: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct LogLinePayload {
    time: String,
    level: String,
    source: String,
    message: String,
    fields: Vec<LogFieldPayload>,
}

#[derive(Debug, Clone, Serialize)]
struct LogFieldPayload {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Serialize)]
struct CoreProvisionResult {
    installed: bool,
    source_path: Option<PathBuf>,
    target_path: PathBuf,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct ActionRunResult {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct TrayProxyGroup {
    name: String,
    now: Option<String>,
    options: Vec<String>,
    selected_delay_ms: Option<u32>,
}

#[tauri::command]
fn boot_payload() -> BootPayload {
    BootPayload {
        product: ProductBlueprint::arm64_macos_only(
            FeatureSet::baseline_cfw_02039(),
            PlatformTarget::MacOsArm64,
        ),
        pages: UiPage::cfw_primary_nav(),
        settings: SettingsSkeleton::default(),
        platform: MacOsPlatformDesign::arm64_baseline(),
        quality: QualityTargets::macos_arm64_3x(),
    }
}

#[tauri::command]
fn open_page(app: AppHandle, page: String) -> Result<(), String> {
    app.emit("cfw://page", page).map_err(|err| err.to_string())
}

#[tauri::command]
fn quit_app(app: AppHandle, core: State<'_, ManagedCore>) {
    let _ = cleanup_runtime(&core);
    app.exit(0);
}

#[tauri::command]
fn force_quit_app(app: AppHandle, core: State<'_, ManagedCore>) {
    let _ = cleanup_runtime(&core);
    app.exit(1);
}

#[tauri::command]
fn current_platform_design() -> MacOsPlatformDesign {
    MacOsPlatformDesign::arm64_baseline()
}

#[tauri::command]
fn system_proxy_state() -> Result<SystemProxyState, String> {
    MacOsPlatformService
        .read_system_proxy_state()
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn network_diagnostics() -> Result<NetworkDiagnostics, String> {
    MacOsPlatformService
        .network_diagnostics()
        .map_err(|err| err.to_string())
}

fn settings_store() -> Result<SettingsStore, String> {
    SettingsStore::default_for_current_user().map_err(|err| err.to_string())
}

fn update_settings(
    mutate: impl FnOnce(&mut PersistedSettings) -> Result<(), String>,
) -> Result<SettingsSnapshot, String> {
    let store = settings_store()?;
    let mut settings = store.read_or_default().map_err(|err| err.to_string())?;
    mutate(&mut settings)?;
    store.write(&settings).map_err(|err| err.to_string())?;
    store.snapshot().map_err(|err| err.to_string())
}

fn core_manager_from_settings() -> Result<CoreManager, String> {
    let store = settings_store()?;
    let snapshot = store.snapshot().map_err(|err| err.to_string())?;
    Ok(CoreManager::new(CoreProcessSpec::from_settings(
        &snapshot.paths,
        &snapshot.settings,
    )))
}

fn provision_core_binary_from_resources(app: &AppHandle) -> Result<CoreProvisionResult, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let target_path = store.paths().cores_dir.join(DEFAULT_CORE_BINARY_NAME);
    if target_path.exists() {
        return Ok(CoreProvisionResult {
            installed: false,
            source_path: None,
            target_path,
            message: "Managed Clash core already exists".into(),
        });
    }

    let source_path = core_resource_candidates(app)
        .into_iter()
        .find(|path| path.exists() && path.is_file());
    let Some(source_path) = source_path else {
        return Ok(CoreProvisionResult {
            installed: false,
            source_path: None,
            target_path,
            message: format!(
                "No bundled ARM64 core found; place {DEFAULT_CORE_BINARY_NAME} in resources/cores before packaging"
            ),
        });
    };

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::copy(&source_path, &target_path).map_err(|err| err.to_string())?;
    let mut permissions = fs::metadata(&target_path)
        .map_err(|err| err.to_string())?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&target_path, permissions).map_err(|err| err.to_string())?;

    Ok(CoreProvisionResult {
        installed: true,
        source_path: Some(source_path),
        target_path,
        message: "Bundled Clash core installed into managed cores directory".into(),
    })
}

fn core_resource_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(resource_dir) = app.path().resource_dir() {
        // Tauri keeps the "resources/" prefix, so the bundled core lands here.
        candidates.push(
            resource_dir
                .join("resources")
                .join("cores")
                .join(DEFAULT_CORE_BINARY_NAME),
        );
        candidates.push(resource_dir.join("cores").join(DEFAULT_CORE_BINARY_NAME));
        candidates.push(resource_dir.join(DEFAULT_CORE_BINARY_NAME));
        candidates.push(
            resource_dir
                .join("cfw-0.20.39-arm64")
                .join(DEFAULT_CORE_BINARY_NAME),
        );
        collect_core_resource_candidates(&resource_dir, 0, &mut candidates);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidates.push(
        manifest_dir
            .join("resources")
            .join("cores")
            .join(DEFAULT_CORE_BINARY_NAME),
    );
    candidates.push(
        manifest_dir
            .join("../../reverse/cfw-0.20.39-arm64")
            .join(DEFAULT_CORE_BINARY_NAME),
    );
    candidates
}

fn collect_core_resource_candidates(
    root: &std::path::Path,
    depth: usize,
    candidates: &mut Vec<PathBuf>,
) {
    if depth > 5 {
        return;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .is_some_and(|name| name == DEFAULT_CORE_BINARY_NAME)
        {
            candidates.push(path);
        } else if path.is_dir() {
            collect_core_resource_candidates(&path, depth + 1, candidates);
        }
    }
}

#[tauri::command]
fn provision_core_binary(app: AppHandle) -> Result<CoreProvisionResult, String> {
    provision_core_binary_from_resources(&app)
}

#[tauri::command]
async fn install_core_from_url(
    url: String,
    sha256: Option<String>,
) -> Result<CoreInstallResult, String> {
    let sha256 = sha256
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "core install requires a pinned SHA-256 checksum".to_string())?;
    let store = settings_store()?;
    CoreInstaller::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .install_from_url(CoreInstallRequest {
            url,
            sha256: Some(sha256),
        })
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn install_latest_mihomo_core() -> Result<CoreInstallResult, String> {
    let store = settings_store()?;
    CoreInstaller::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .install_latest_mihomo_arm64()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn read_settings_snapshot() -> Result<SettingsSnapshot, String> {
    settings_store()?.snapshot().map_err(|err| err.to_string())
}

#[tauri::command]
fn write_settings_snapshot(settings: PersistedSettings) -> Result<SettingsSnapshot, String> {
    let store = settings_store()?;
    store.write(&settings).map_err(|err| err.to_string())?;
    store.snapshot().map_err(|err| err.to_string())
}

#[tauri::command]
fn reset_settings_snapshot() -> Result<SettingsSnapshot, String> {
    let store = settings_store()?;
    store
        .write(&PersistedSettings::default())
        .map_err(|err| err.to_string())?;
    store.snapshot().map_err(|err| err.to_string())
}

#[tauri::command]
fn set_system_proxy_enabled(enabled: bool) -> Result<SettingsSnapshot, String> {
    update_settings(|settings| {
        let mode = if enabled {
            SystemProxyMode::GlobalHttp
        } else {
            SystemProxyMode::Off
        };
        MacOsPlatformService
            .set_system_proxy_mode(mode, settings.mixed_port, &settings.proxy_bypass)
            .map_err(|err| err.to_string())?;
        settings.system_proxy = enabled;
        Ok(())
    })
}

fn render_runtime_config_from_settings() -> Result<PathBuf, String> {
    if let Some(result) = apply_active_profile_if_selected()? {
        Ok(result.config_path)
    } else {
        write_default_config_from_settings()
    }
}

#[tauri::command]
fn service_mode_status() -> ServiceModeStatus {
    MacOsPlatformService.service_mode_status()
}

#[tauri::command]
fn enable_service_mode() -> Result<ServiceModeStatus, String> {
    MacOsPlatformService
        .enable_service_mode()
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn disable_service_mode() -> Result<(), String> {
    MacOsPlatformService
        .disable_service_mode()
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn set_tun_enabled(
    app: AppHandle,
    core: State<'_, ManagedCore>,
    enabled: bool,
) -> Result<SettingsSnapshot, String> {
    if enabled {
        set_tun_on(&core).await
    } else {
        set_tun_off(&app, &core).await
    }
}

/// TUN ON: hand core ownership to the root daemon. Register/verify Service Mode,
/// render the tun-enabled config, stop the in-process core to free the ports,
/// then ask the daemon (via the control file) to run the core as root.
async fn set_tun_on(core: &ManagedCore) -> Result<SettingsSnapshot, String> {
    // SMAppService register + status check; bails with an actionable
    // "approve in System Settings" message if approval is still pending.
    MacOsPlatformService
        .install_tun_runtime()
        .map_err(|err| err.to_string())?;
    MacOsPlatformService
        .start_tun()
        .map_err(|err| err.to_string())?;

    let snapshot = update_settings(|settings| {
        settings.tun_mode = true;
        Ok(())
    })?;
    let _ = render_runtime_config_from_settings()?;

    // Free both ports for the root core: stop the unprivileged in-process core.
    stop_managed_core(core)?;
    wait_for_ports_free(&[
        snapshot.settings.mixed_port,
        snapshot.settings.external_controller_port,
    ])
    .await?;

    // Hand the core to the daemon and wait for its controller to come up.
    write_control_session(true)?;
    wait_for_controller_ready().await?;
    Ok(snapshot)
}

/// TUN OFF: take core ownership back. Tell the daemon to stop, remove the
/// control file (launchd then stops the daemon), then restart the in-process
/// unprivileged core with a tun-free config.
async fn set_tun_off(app: &AppHandle, core: &ManagedCore) -> Result<SettingsSnapshot, String> {
    let snapshot = update_settings(|settings| {
        settings.tun_mode = false;
        Ok(())
    })?;
    let _ = render_runtime_config_from_settings()?;

    let _ = write_control_session(false);
    ControlSession::remove().map_err(|err| err.to_string())?;
    MacOsPlatformService
        .stop_tun()
        .map_err(|err| err.to_string())?;

    // Let the root core release the controller port before respawning ours.
    let _ = wait_for_ports_free(&[snapshot.settings.external_controller_port]).await;
    start_managed_core(app, core).await?;
    Ok(snapshot)
}

/// True when the privileged root daemon (not the in-process child) owns the core.
fn service_mode_owns_core() -> Result<bool, String> {
    let settings = settings_store()?
        .read_or_default()
        .map_err(|err| err.to_string())?;
    Ok(settings.tun_mode && MacOsPlatformService.service_mode_status() == ServiceModeStatus::Enabled)
}

/// Write the app->daemon control file from current settings, bumping the
/// generation so the daemon's supervise loop reloads.
fn write_control_session(want_core: bool) -> Result<(), String> {
    let snapshot = settings_store()?.snapshot().map_err(|err| err.to_string())?;
    let generation = ControlSession::read()
        .ok()
        .flatten()
        .map(|session| session.generation + 1)
        .unwrap_or(1);
    ControlSession {
        app_home: snapshot.paths.app_home.clone(),
        config_file: snapshot.paths.config_file.clone(),
        mixed_port: snapshot.settings.mixed_port,
        controller_port: snapshot.settings.external_controller_port,
        secret: snapshot.settings.secret.clone(),
        want_core,
        generation,
        heartbeat_epoch_secs: now_epoch_secs(),
    }
    .write_atomic()
    .map_err(|err| err.to_string())
}

/// Poll the controller until it answers (no in-process Child handle — used when
/// the root daemon owns the core).
async fn wait_for_controller_ready() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match controller_client_from_settings()?.configs().await {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!(
                    "core controller not ready (see /Library/Logs/com.bill.clashformac.helper.log): {error}"
                ));
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until every listed loopback port can be bound (i.e. is free).
async fn wait_for_ports_free(ports: &[u16]) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if ports
            .iter()
            .all(|port| TcpListener::bind(("127.0.0.1", *port)).is_ok())
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("core ports are still in use after waiting".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tauri::command]
fn set_mixin_enabled(enabled: bool) -> Result<SettingsSnapshot, String> {
    update_settings(|settings| {
        settings.mixin = enabled;
        Ok(())
    })
}

#[tauri::command]
fn set_launch_at_login_enabled(enabled: bool) -> Result<SettingsSnapshot, String> {
    update_settings(|settings| {
        let platform = MacOsPlatformService;
        if enabled {
            let program = std::env::current_exe().map_err(|err| err.to_string())?;
            platform
                .install_launch_agent(&LaunchAgentSpec {
                    label: LAUNCH_AGENT_LABEL.into(),
                    program,
                    program_arguments: Vec::new(),
                    run_at_load: true,
                })
                .map_err(|err| err.to_string())?;
            platform
                .bootstrap(LAUNCH_AGENT_LABEL, LaunchdDomain::GuiAgent)
                .map_err(|err| err.to_string())?;
        } else {
            platform
                .bootout(LAUNCH_AGENT_LABEL, LaunchdDomain::GuiAgent)
                .map_err(|err| err.to_string())?;
            platform
                .uninstall_launch_agent(LAUNCH_AGENT_LABEL)
                .map_err(|err| err.to_string())?;
        }
        settings.launch_at_login = enabled;
        Ok(())
    })
}

#[tauri::command]
fn install_helper_service(app: AppHandle) -> Result<SettingsSnapshot, String> {
    let _ = app;
    let helper_path = PathBuf::from(PRIVILEGED_HELPER_PATH);
    MacOsPlatformService
        .install_helper(&HelperInstallRequest {
            label: HELPER_LABEL.into(),
            domain: LaunchdDomain::SystemDaemon,
            binary_relative_path: helper_path.to_string_lossy().to_string(),
        })
        .map_err(|err| err.to_string())?;
    update_settings(|settings| {
        settings.extra.insert(
            "service_mode".into(),
            serde_yaml::Value::String("installed".into()),
        );
        Ok(())
    })
}

#[tauri::command]
fn uninstall_helper_service() -> Result<SettingsSnapshot, String> {
    MacOsPlatformService
        .uninstall_helper(HELPER_LABEL)
        .map_err(|err| err.to_string())?;
    update_settings(|settings| {
        settings.extra.insert(
            "service_mode".into(),
            serde_yaml::Value::String("not-installed".into()),
        );
        Ok(())
    })
}

#[tauri::command]
fn run_tray_script() -> Result<ActionRunResult, String> {
    run_configured_action(&["tray_script", "trayScript"], "Tray Script")
}

#[tauri::command]
fn run_child_process() -> Result<ActionRunResult, String> {
    run_configured_action(
        &["child_process_command", "childProcessCommand"],
        "Child Process",
    )
}

#[tauri::command]
fn toggle_devtools(app: AppHandle) -> Result<(), String> {
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

#[tauri::command]
fn move_dashboard_to_nearest_monitor(app: AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is not available".to_string())?;
    window.show().map_err(|err| err.to_string())?;
    window.center().map_err(|err| err.to_string())?;
    window.set_focus().map_err(|err| err.to_string())
}

fn run_configured_action(setting_keys: &[&str], label: &str) -> Result<ActionRunResult, String> {
    let command_line = settings_store()
        .ok()
        .and_then(|store| store.read_or_default().ok())
        .and_then(|settings| setting_extra_string(&settings, setting_keys))
        .ok_or_else(|| format!("{label} command is empty"))?;
    let (program, arguments) = parse_action_command(&command_line)?;
    run_action_with_limits(&program, &arguments, label)
}

fn parse_action_command(command_line: &str) -> Result<(PathBuf, Vec<String>), String> {
    let parts = split_action_command(command_line)?;
    let program = PathBuf::from(
        parts
            .first()
            .ok_or_else(|| "action command is empty".to_string())?,
    );
    if !program.is_absolute() {
        return Err(format!(
            "action command must start with an absolute executable path: {}",
            program.display()
        ));
    }
    if !program.is_file() {
        return Err(format!(
            "action executable is missing: {}",
            program.display()
        ));
    }
    if is_blocked_action_executable(&program) {
        return Err(format!(
            "action executable is not allowed for safety: {}",
            program.display()
        ));
    }
    Ok((program, parts.into_iter().skip(1).collect()))
}

fn is_blocked_action_executable(program: &std::path::Path) -> bool {
    program
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| BLOCKED_ACTION_EXECUTABLES.contains(&name))
        .unwrap_or(false)
}

fn split_action_command(command_line: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in command_line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            value if value.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            value => current.push(value),
        }
    }

    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        return Err("unterminated quote in action command".into());
    }
    if !current.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}

fn run_action_with_limits(
    program: &std::path::Path,
    arguments: &[String],
    label: &str,
) -> Result<ActionRunResult, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let output_path =
        env::temp_dir().join(format!("cfm-action-{}-{stamp}.out", std::process::id()));
    let error_path = env::temp_dir().join(format!("cfm-action-{}-{stamp}.err", std::process::id()));
    let stdout = File::create(&output_path).map_err(|err| err.to_string())?;
    let stderr = File::create(&error_path).map_err(|err| err.to_string())?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|err| format!("{label} failed to spawn: {err}"))?;
    let deadline = Instant::now() + ACTION_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            break status.code();
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let stdout = read_limited_text(&output_path, ACTION_OUTPUT_LIMIT).unwrap_or_default();
    let mut stderr = read_limited_text(&error_path, ACTION_OUTPUT_LIMIT).unwrap_or_default();
    let _ = fs::remove_file(&output_path);
    let _ = fs::remove_file(&error_path);
    if timed_out {
        if !stderr.is_empty() {
            stderr.push('\n');
        }
        stderr.push_str(&format!(
            "{label} timed out after {} seconds",
            ACTION_TIMEOUT.as_secs()
        ));
    }

    Ok(ActionRunResult {
        status,
        stdout,
        stderr,
    })
}

fn read_limited_text(path: &std::path::Path, limit: usize) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_string())
}

fn setting_extra_string(settings: &PersistedSettings, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match settings.extra.get(*key) {
        Some(serde_yaml::Value::String(value)) if !value.trim().is_empty() => {
            Some(value.trim().to_string())
        }
        _ => None,
    })
}

fn controller_client_from_settings() -> Result<ControllerClient, String> {
    let settings = settings_store()?
        .read_or_default()
        .map_err(|err| err.to_string())?;
    let endpoint = ControllerEndpoint::new(
        settings.external_controller_host,
        settings.external_controller_port,
        settings.secret,
    );
    ControllerClient::new(endpoint).map_err(|err| err.to_string())
}

#[tauri::command]
async fn controller_snapshot() -> Result<ControllerSnapshot, String> {
    controller_client_from_settings()?
        .snapshot()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn providers_snapshot() -> Result<ProvidersSnapshot, String> {
    controller_client_from_settings()?
        .providers()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn rules_snapshot() -> Result<RulesSnapshot, String> {
    controller_client_from_settings()?
        .rules()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn update_proxy_provider(name: String) -> Result<(), String> {
    controller_client_from_settings()?
        .update_proxy_provider(&name)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn update_rule_provider(name: String) -> Result<(), String> {
    controller_client_from_settings()?
        .update_rule_provider(&name)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn health_check_proxy_provider(name: String) -> Result<(), String> {
    controller_client_from_settings()?
        .health_check_proxy_provider(&name)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn update_all_proxy_providers() -> Result<ProviderBatchResult, String> {
    controller_client_from_settings()?
        .update_all_proxy_providers()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn update_all_rule_providers() -> Result<ProviderBatchResult, String> {
    controller_client_from_settings()?
        .update_all_rule_providers()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn health_check_all_proxy_providers() -> Result<ProviderBatchResult, String> {
    controller_client_from_settings()?
        .health_check_all_proxy_providers()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn refresh_tray_menu(app: AppHandle) -> Result<(), String> {
    let client = controller_client_from_settings()?;
    let proxies = client.proxies().await.map_err(|err| err.to_string())?;
    update_tray_menu(&app, &tray_proxy_groups_from_snapshot(proxies)).map_err(|err| err.to_string())
}

#[tauri::command]
fn start_connections_stream(app: AppHandle, streams: State<'_, LiveStreams>) -> Result<(), String> {
    let mut started = streams
        .connections_started
        .lock()
        .map_err(|err| err.to_string())?;
    if *started {
        return Ok(());
    }

    *started = true;
    tauri::async_runtime::spawn(async move {
        let mut last_error: Option<String> = None;
        loop {
            match controller_client_from_settings() {
                Ok(client) => match run_connections_websocket(&app, &client).await {
                    Ok(()) => {
                        last_error = None;
                        emit_stream_error(&app, "connections", "connections stream closed".into());
                    }
                    Err(error) => {
                        emit_unique_stream_error(&app, "connections", &mut last_error, error);
                        emit_connections_poll_fallback(&app, &client).await;
                    }
                },
                Err(error) => {
                    emit_unique_stream_error(
                        &app,
                        "connections",
                        &mut last_error,
                        error.to_string(),
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(())
}

#[tauri::command]
fn start_log_stream(app: AppHandle, streams: State<'_, LiveStreams>) -> Result<(), String> {
    let mut started = streams.logs_started.lock().map_err(|err| err.to_string())?;
    if *started {
        return Ok(());
    }

    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let log_file = store.paths().logs_dir.join("clash-core.log");
    *started = true;

    let core_log_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut offset = initial_log_offset(&log_file);
        let mut skip_partial_line = offset > 0;
        let mut last_error: Option<String> = None;
        loop {
            match read_log_tail(&log_file, offset, skip_partial_line) {
                Ok((next_offset, lines)) => {
                    offset = next_offset;
                    skip_partial_line = false;
                    last_error = None;
                    if !lines.is_empty() {
                        let _ = core_log_app.emit("cfw://log-lines", lines);
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    if last_error.as_deref() != Some(message.as_str()) {
                        last_error = Some(message.clone());
                        emit_stream_error(&core_log_app, "core-logs", message);
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    });

    tauri::async_runtime::spawn(async move {
        let mut last_error: Option<String> = None;
        loop {
            match controller_client_from_settings() {
                Ok(client) => match run_log_websocket(&app, &client, &current_log_stream_level())
                    .await
                {
                    Ok(()) => {
                        last_error = None;
                        emit_stream_error(&app, "request-logs", "request log stream closed".into());
                    }
                    Err(error) => {
                        emit_unique_stream_error(&app, "request-logs", &mut last_error, error);
                    }
                },
                Err(error) => {
                    emit_unique_stream_error(
                        &app,
                        "request-logs",
                        &mut last_error,
                        error.to_string(),
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(())
}

async fn run_connections_websocket(
    app: &AppHandle,
    client: &ControllerClient,
) -> Result<(), String> {
    let url = client
        .connections_stream_url()
        .map_err(|err| err.to_string())?;
    let (socket, _response) = connect_async(url).await.map_err(|err| err.to_string())?;
    let (_write, mut read) = socket.split();
    while let Some(message) = read.next().await {
        let message = message.map_err(|err| err.to_string())?;
        if let Some(snapshot) = decode_connections_message(message)? {
            let _ = app.emit("cfw://connections-snapshot", snapshot);
        }
    }

    Ok(())
}

async fn emit_connections_poll_fallback(app: &AppHandle, client: &ControllerClient) {
    match client.connections().await {
        Ok(snapshot) => {
            let _ = app.emit("cfw://connections-snapshot", snapshot);
        }
        Err(error) => emit_stream_error(app, "connections-fallback", error.to_string()),
    }
}

fn decode_connections_message(
    message: Message,
) -> Result<Option<cfw_controller::ConnectionsSnapshot>, String> {
    if message.is_close() || message.is_ping() || message.is_pong() {
        return Ok(None);
    }

    let text = message.to_text().map_err(|err| err.to_string())?;
    ControllerClient::decode_connections_stream_message(text)
        .map(Some)
        .map_err(|err| err.to_string())
}

async fn run_log_websocket(
    app: &AppHandle,
    client: &ControllerClient,
    level: &str,
) -> Result<(), String> {
    let url = client
        .logs_stream_url(level)
        .map_err(|err| err.to_string())?;
    let (socket, _response) = connect_async(url).await.map_err(|err| err.to_string())?;
    let (_write, mut read) = socket.split();
    loop {
        if current_log_stream_level() != level {
            return Ok(());
        }

        let message = match tokio::time::timeout(Duration::from_secs(2), read.next()).await {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(()),
            Err(_) => continue,
        };
        let message = message.map_err(|err| err.to_string())?;
        if let Some(log) = decode_log_message(message)? {
            let _ = app.emit("cfw://log-lines", vec![log_line_from_structured(log)]);
        }
    }
}

fn current_log_stream_level() -> String {
    settings_store()
        .and_then(|store| store.read_or_default().map_err(|err| err.to_string()))
        .ok()
        .and_then(|settings| {
            settings
                .extra
                .get("logLevel")
                .or_else(|| settings.extra.get("log-level"))
                .and_then(serde_yaml::Value::as_str)
                .map(normalize_controller_log_level)
        })
        .unwrap_or_else(|| "info".into())
}

fn normalize_controller_log_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "trace" | "trc" | "debug" | "dbg" => "debug".into(),
        "warn" | "wrn" | "warning" => "warning".into(),
        "err" | "error" | "fatal" | "ftl" => "error".into(),
        "silent" => "silent".into(),
        _ => "info".into(),
    }
}

fn decode_log_message(message: Message) -> Result<Option<StructuredLogEntry>, String> {
    if message.is_close() || message.is_ping() || message.is_pong() {
        return Ok(None);
    }

    let text = message.to_text().map_err(|err| err.to_string())?;
    ControllerClient::decode_log_stream_message(text)
        .map(Some)
        .map_err(|err| err.to_string())
}

fn emit_unique_stream_error(
    app: &AppHandle,
    stream: &str,
    last_error: &mut Option<String>,
    message: String,
) {
    if last_error.as_deref() != Some(message.as_str()) {
        *last_error = Some(message.clone());
        emit_stream_error(app, stream, message);
    }
}

fn emit_stream_error(app: &AppHandle, stream: &str, message: String) {
    let _ = app.emit(
        "cfw://stream-error",
        StreamError {
            stream: stream.to_string(),
            message,
        },
    );
}

fn emit_shell_log(app: &AppHandle, level: &str, source: &str, message: impl Into<String>) {
    let _ = app.emit(
        "cfw://log-lines",
        vec![LogLinePayload {
            time: "live".into(),
            level: normalize_log_level(level),
            source: source.into(),
            message: message.into(),
            fields: Vec::new(),
        }],
    );
}

fn read_log_tail(
    log_file: &std::path::Path,
    offset: u64,
    skip_partial_line: bool,
) -> Result<(u64, Vec<LogLinePayload>), std::io::Error> {
    if !log_file.exists() {
        return Ok((0, Vec::new()));
    }

    let metadata = log_file.metadata()?;
    let start = offset.min(metadata.len());
    let mut file = File::open(log_file)?;
    file.seek(SeekFrom::Start(start))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let chunk = String::from_utf8_lossy(&bytes);
    let lines = chunk
        .lines()
        .skip(if skip_partial_line { 1 } else { 0 })
        .filter(|line| !line.trim().is_empty())
        .map(parse_log_line)
        .collect();

    Ok((metadata.len(), lines))
}

fn initial_log_offset(log_file: &std::path::Path) -> u64 {
    const PRELOAD_BYTES: u64 = 128 * 1024;
    log_file
        .metadata()
        .map(|metadata| metadata.len().saturating_sub(PRELOAD_BYTES))
        .unwrap_or(0)
}

fn parse_log_line(raw: &str) -> LogLinePayload {
    let level = extract_log_field(raw, "level")
        .or_else(|| infer_log_level(raw))
        .unwrap_or_else(|| "info".into());
    let time = extract_log_field(raw, "time")
        .map(|value| display_time(&value))
        .unwrap_or_else(|| "live".into());
    let message = extract_log_field(raw, "msg").unwrap_or_else(|| raw.trim().to_string());

    LogLinePayload {
        time,
        level: normalize_log_level(&level),
        source: "core".into(),
        message,
        fields: Vec::new(),
    }
}

fn log_line_from_structured(entry: StructuredLogEntry) -> LogLinePayload {
    LogLinePayload {
        time: entry
            .time
            .as_deref()
            .map(display_time)
            .unwrap_or_else(|| "live".into()),
        level: normalize_log_level(&entry.level),
        source: "request".into(),
        message: entry.message,
        fields: entry
            .fields
            .into_iter()
            .map(|field| LogFieldPayload {
                key: field.key,
                value: display_json_value(field.value),
            })
            .collect(),
    }
}

fn normalize_log_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "warn" | "wrn" | "warning" => "warning".into(),
        "err" | "error" | "fatal" | "ftl" => "error".into(),
        "dbg" | "debug" => "debug".into(),
        "trc" | "trace" => "debug".into(),
        _ => "info".into(),
    }
}

fn extract_log_field(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = raw.find(&needle)? + needle.len();
    let tail = raw[start..].trim_start();
    if let Some(stripped) = tail.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_string());
    }

    tail.split_whitespace()
        .next()
        .map(|value| value.trim_matches('"').to_string())
}

fn infer_log_level(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("error") {
        Some("error".into())
    } else if lower.contains("warn") {
        Some("warning".into())
    } else if lower.contains("debug") {
        Some("debug".into())
    } else {
        None
    }
}

fn display_time(value: &str) -> String {
    value
        .split('T')
        .nth(1)
        .and_then(|time| time.get(0..8))
        .unwrap_or(value)
        .to_string()
}

fn display_json_value(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[tauri::command]
fn parse_deep_links(urls: Vec<String>) -> Vec<DeepLinkParseOutcome> {
    urls.into_iter()
        .map(|url| match parse_deep_link(&url) {
            Ok(intent) => DeepLinkParseOutcome {
                raw: url,
                intent: Some(intent),
                error: None,
            },
            Err(error) => DeepLinkParseOutcome {
                raw: url,
                intent: None,
                error: Some(error.to_string()),
            },
        })
        .collect()
}

#[tauri::command]
async fn import_profile_url(
    url: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let store = settings_store()?;
    let paths = store.snapshot().map_err(|err| err.to_string())?.paths;
    ProfileManager::new(paths)
        .map_err(|err| err.to_string())?
        .import_remote(
            &store,
            ProfileImportRequest {
                url,
                name,
                activate,
            },
        )
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn import_profile_text(
    name: Option<String>,
    body: String,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .import_text(&store, name, body, activate)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn import_profile_file(
    path: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .import_file(&store, PathBuf::from(path), name, activate)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn migrate_legacy_cfw_profiles() -> Result<Vec<ProfileImportResult>, String> {
    let home = env::var_os("HOME").ok_or("HOME is not available")?;
    let legacy_profiles_dir = PathBuf::from(home).join(".config/clash/profiles");
    let list_path = legacy_profiles_dir.join("list.yml");
    if !list_path.exists() {
        return Err(format!(
            "legacy Clash for Windows profile list not found: {}",
            list_path.display()
        ));
    }

    let list_raw = fs::read_to_string(&list_path).map_err(|err| err.to_string())?;
    let list = serde_yaml::from_str::<LegacyProfileList>(&list_raw)
        .map_err(|err| format!("legacy profile list is invalid: {err}"))?;
    let active_index = list.index;
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let manager = ProfileManager::new(store.paths().clone()).map_err(|err| err.to_string())?;
    let mut imported = Vec::new();

    for (index, entry) in list.files.into_iter().enumerate() {
        let Some(file_name) = entry
            .time
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        if file_name.contains('/') || file_name.contains('\\') || file_name == "list.yml" {
            continue;
        }

        let profile_path = legacy_profiles_dir.join(file_name);
        if !profile_path.exists() {
            continue;
        }

        let body = fs::read_to_string(&profile_path).map_err(|err| err.to_string())?;
        let name = entry.name.or_else(|| {
            profile_path
                .file_stem()
                .map(|stem| stem.to_string_lossy().to_string())
        });
        let activate = active_index == Some(index);
        let result = manager
            .import_text_with_source_url(&store, name, body, entry.url, activate)
            .map_err(|err| err.to_string())?;
        imported.push(result);
    }

    if imported.is_empty() {
        Err(format!(
            "no importable legacy profiles found in {}",
            legacy_profiles_dir.display()
        ))
    } else {
        Ok(imported)
    }
}

/// How often the subscription auto-update scheduler scans for due profiles.
const PROFILE_UPDATE_TICK: Duration = Duration::from_secs(15 * 60);

/// Background task: periodically refresh remote subscriptions whose
/// `profile-update-interval` (hours) has elapsed since their last update, and
/// hot-reload the running core if the active profile changed.
async fn run_profile_update_scheduler(app: AppHandle) {
    loop {
        tokio::time::sleep(PROFILE_UPDATE_TICK).await;
        if let Err(error) = refresh_due_profiles(&app).await {
            emit_shell_log(
                &app,
                "warning",
                "profile",
                format!("subscription auto-update scan failed: {error}"),
            );
        }
    }
}

async fn refresh_due_profiles(app: &AppHandle) -> Result<(), String> {
    let store = settings_store()?;
    let manager = ProfileManager::new(store.paths().clone()).map_err(|err| err.to_string())?;
    let now = now_epoch_secs();
    for record in manager.list(&store).map_err(|err| err.to_string())? {
        if record.source_url.is_none() {
            continue;
        }
        let Some(hours) = record
            .update_interval
            .as_deref()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|hours| *hours > 0)
        else {
            continue;
        };
        let due = record
            .updated_epoch_secs
            .is_none_or(|updated| now.saturating_sub(updated) >= hours * 3600);
        if !due {
            continue;
        }
        match manager.update_remote(&store, &record.id).await {
            Ok(result) => {
                emit_shell_log(
                    app,
                    "info",
                    "profile",
                    format!("subscription auto-updated: {}", result.name),
                );
                if record.active
                    && let Err(error) = reapply_active_profile_to_running_core(app).await
                {
                    emit_shell_log(app, "warning", "profile", error);
                }
            }
            Err(error) => emit_shell_log(
                app,
                "warning",
                "profile",
                format!("auto-update of {} failed: {error}", record.id),
            ),
        }
    }
    Ok(())
}

async fn reapply_active_profile_to_running_core(app: &AppHandle) -> Result<(), String> {
    let config_path = render_runtime_config_from_settings()?;
    let core = app.state::<ManagedCore>();
    if managed_core_is_running(&core)? {
        controller_client_from_settings()?
            .reload_config(&config_path.to_string_lossy(), true)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// How often the app refreshes its heartbeat in the control file while the root
/// daemon owns the core. Must stay well under the daemon's stale threshold (60s)
/// so the daemon only tears down the root core when the app is genuinely gone.
const HELPER_HEARTBEAT_TICK: Duration = Duration::from_secs(20);

/// Background task: while Service Mode owns the core, bump the control file's
/// heartbeat so the root daemon knows the app is alive. Touches only the
/// heartbeat (not generation), so it never triggers a core respawn.
async fn run_helper_heartbeat() {
    loop {
        tokio::time::sleep(HELPER_HEARTBEAT_TICK).await;
        if !service_mode_owns_core().unwrap_or(false) {
            continue;
        }
        if let Ok(Some(mut session)) = ControlSession::read() {
            session.heartbeat_epoch_secs = now_epoch_secs();
            let _ = session.write_atomic();
        }
    }
}

#[tauri::command]
async fn update_profile(id: String) -> Result<ProfileImportResult, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .update_remote(&store, &id)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn profiles_snapshot() -> Result<Vec<ProfileRecord>, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .list(&store)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn delete_profile(id: String) -> Result<bool, String> {
    let store = settings_store()?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .delete(&store, &id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn reveal_profile(id: String) -> Result<(), String> {
    let store = settings_store()?;
    let path = ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .profile_path(&id)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("profile not found: {id}"))?;
    let status = Command::new("/usr/bin/open")
        .arg("-R")
        .arg(path)
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open -R failed with status {status}"))
    }
}

#[tauri::command]
fn read_profile_text(id: String) -> Result<ProfileText, String> {
    let store = settings_store()?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .read_text(&store, &id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn save_profile_text(id: String, body: String) -> Result<ProfileSaveResult, String> {
    let store = settings_store()?;
    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .save_text(&store, &id, body)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn profile_qrcode_svg(id: String) -> Result<String, String> {
    let store = settings_store()?;
    let profile = ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .read_text(&store, &id)
        .map_err(|err| err.to_string())?;
    let source_url = profile
        .source_url
        .ok_or_else(|| "local profiles do not have subscription URLs to encode".to_string())?;
    let code = QrCode::new(source_url.as_bytes()).map_err(|err| err.to_string())?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(190, 190)
        .dark_color(svg::Color("#2c3e50"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[tauri::command]
fn reveal_home_directory() -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let status = Command::new("/usr/bin/open")
        .arg(store.paths().app_home.clone())
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open failed with status {status}"))
    }
}

#[tauri::command]
fn reveal_logs_directory() -> Result<(), String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let status = Command::new("/usr/bin/open")
        .arg(store.paths().logs_dir.clone())
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open failed with status {status}"))
    }
}

fn apply_active_profile_if_selected() -> Result<Option<ProfileApplyResult>, String> {
    let store = settings_store()?;
    let settings = store.read_or_default().map_err(|err| err.to_string())?;
    if settings
        .active_profile
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(None);
    }

    ProfileManager::new(store.paths().clone())
        .map_err(|err| err.to_string())?
        .apply_active(&store)
        .map(Some)
        .map_err(|err| err.to_string())
}

fn ensure_default_config_for_empty_profile() -> Result<(), String> {
    let store = settings_store()?;
    let settings = store.read_or_default().map_err(|err| err.to_string())?;
    if settings
        .active_profile
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        let _ = ensure_default_config_if_missing()?;
    }
    Ok(())
}

fn ensure_default_config_if_missing() -> Result<Option<PathBuf>, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let paths = store.paths().clone();
    if paths.config_file.exists() {
        return Ok(None);
    }
    write_default_config_from_settings().map(Some)
}

fn write_default_config_from_settings() -> Result<PathBuf, String> {
    let store = settings_store()?;
    store.ensure_layout().map_err(|err| err.to_string())?;
    let settings = store.read_or_default().map_err(|err| err.to_string())?;
    // Shared with cfw-cli via cfw-runtime so the two never drift.
    cfw_runtime::write_default_config(store.paths(), &settings).map_err(|err| err.to_string())
}

fn managed_core_is_running(core: &State<'_, ManagedCore>) -> Result<bool, String> {
    let mut child = core.child.lock().map_err(|err| err.to_string())?;
    let Some(process) = child.as_mut() else {
        return Ok(false);
    };
    match process.try_wait().map_err(|err| err.to_string())? {
        Some(_status) => {
            *child = None;
            Ok(false)
        }
        None => Ok(true),
    }
}

#[tauri::command]
async fn apply_active_profile(core: State<'_, ManagedCore>) -> Result<ProfileApplyResult, String> {
    let result = apply_active_profile_if_selected()?
        .ok_or_else(|| "no active profile is selected".to_string())?;
    if managed_core_is_running(&core)? {
        controller_client_from_settings()?
            .reload_config(&result.config_path.to_string_lossy(), true)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(result)
}

#[tauri::command]
async fn set_proxy_mode(mode: String) -> Result<(), String> {
    controller_client_from_settings()?
        .patch_configs(ConfigPatch {
            mode: Some(mode),
            ..ConfigPatch::default()
        })
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn set_allow_lan(
    core: State<'_, ManagedCore>,
    enabled: bool,
) -> Result<SettingsSnapshot, String> {
    let snapshot = update_settings(|settings| {
        settings.allow_lan = enabled;
        Ok(())
    })?;
    let config_path = render_runtime_config_from_settings()?;
    if managed_core_is_running(&core)?
        && let Ok(client) = controller_client_from_settings()
    {
        let _ = client
            .reload_config(&config_path.to_string_lossy(), true)
            .await;
        let _ = client
            .patch_configs(ConfigPatch {
                allow_lan: Some(enabled),
                ..ConfigPatch::default()
            })
            .await;
    }
    Ok(snapshot)
}

#[tauri::command]
async fn set_ipv6(core: State<'_, ManagedCore>, enabled: bool) -> Result<SettingsSnapshot, String> {
    let snapshot = update_settings(|settings| {
        settings.enable_ipv6 = enabled;
        Ok(())
    })?;
    let config_path = render_runtime_config_from_settings()?;
    if managed_core_is_running(&core)?
        && let Ok(client) = controller_client_from_settings()
    {
        let _ = client
            .reload_config(&config_path.to_string_lossy(), true)
            .await;
        let _ = client
            .patch_configs(ConfigPatch {
                ipv6: Some(enabled),
                ..ConfigPatch::default()
            })
            .await;
    }
    Ok(snapshot)
}

#[tauri::command]
async fn set_log_level(level: String) -> Result<(), String> {
    let normalized = level.to_ascii_lowercase();
    if !matches!(
        normalized.as_str(),
        "trace" | "debug" | "info" | "warning" | "error" | "silent"
    ) {
        return Err(format!("unsupported Clash log level: {level}"));
    }

    controller_client_from_settings()?
        .patch_configs(ConfigPatch {
            log_level: Some(normalized),
            ..ConfigPatch::default()
        })
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn select_proxy(group: String, proxy: String) -> Result<(), String> {
    controller_client_from_settings()?
        .select_proxy(&group, &proxy)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn test_proxy_delays(
    proxies: Vec<String>,
    url: Option<String>,
    timeout_ms: Option<u16>,
) -> Result<Vec<ProxyDelayResult>, String> {
    let target_url = url.unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
    let timeout = timeout_ms.unwrap_or(5000);
    Ok(controller_client_from_settings()?
        .proxy_delays(proxies, target_url, timeout)
        .await)
}

#[tauri::command]
async fn close_all_connections() -> Result<(), String> {
    controller_client_from_settings()?
        .close_all_connections()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn close_connection(id: String) -> Result<(), String> {
    controller_client_from_settings()?
        .close_connection(&id)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn flush_fake_ip_cache() -> Result<(), String> {
    controller_client_from_settings()?
        .flush_fake_ip_cache()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn core_status(core: State<'_, ManagedCore>) -> Result<CoreStatus, String> {
    ensure_default_config_for_empty_profile()?;
    let manager = core_manager_from_settings()?;
    let mut child = core.child.lock().map_err(|err| err.to_string())?;
    let pid = match child.as_mut() {
        Some(process) => match process.try_wait().map_err(|err| err.to_string())? {
            Some(_status) => {
                *child = None;
                None
            }
            None => Some(process.id()),
        },
        None => None,
    };
    Ok(manager.status(pid))
}

#[tauri::command]
async fn start_core(app: AppHandle, core: State<'_, ManagedCore>) -> Result<CoreStatus, String> {
    start_managed_core(&app, &core).await
}

async fn start_managed_core(app: &AppHandle, core: &ManagedCore) -> Result<CoreStatus, String> {
    // Under Service Mode/TUN the root daemon owns the core. Never spawn an
    // in-process child (it would fight the root core for the ports); instead make
    // sure the daemon is asked to run the core and wait for its controller.
    if service_mode_owns_core()? {
        ensure_core_binary_available(app).await?;
        if apply_active_profile_if_selected()?.is_none() {
            let _ = write_default_config_from_settings()?;
        }
        write_control_session(true)?;
        wait_for_controller_ready().await?;
        let spec = core_manager_from_settings()?.spec().clone();
        return Ok(CoreStatus {
            state: CoreProcessState::Running,
            pid: None,
            spec,
            message: "Clash core running under Service Mode (root daemon)".into(),
        });
    }

    let initial_manager = core_manager_from_settings()?;
    {
        let mut child = core.child.lock().map_err(|err| err.to_string())?;
        if let Some(process) = child.as_mut() {
            if process.try_wait().map_err(|err| err.to_string())?.is_none() {
                return Ok(initial_manager.status(Some(process.id())));
            }
            *child = None;
        }
    }

    ensure_core_binary_available(app).await?;
    if apply_active_profile_if_selected()?.is_none() {
        let _ = write_default_config_from_settings()?;
    }
    let mut manager = core_manager_from_settings()?;
    let mut process = match manager.spawn() {
        Ok(process) => process,
        Err(CoreRuntimeError::PortInUse { purpose, .. }) if purpose == "mixed-port" => {
            let port = next_available_loopback_port(7900)
                .ok_or_else(|| "no available loopback mixed-port found".to_string())?;
            update_settings(|settings| {
                settings.mixed_port = port;
                Ok(())
            })?;
            if apply_active_profile_if_selected()?.is_none() {
                let _ = write_default_config_from_settings()?;
            }
            manager = core_manager_from_settings()?;
            manager.spawn().map_err(|err| err.to_string())?
        }
        Err(error) => return Err(error.to_string()),
    };
    let pid = process.id();
    if let Err(error) = wait_for_core_controller(&mut process).await {
        let _ = process.kill();
        let _ = process.wait();
        return Err(error);
    }
    let mut child = core.child.lock().map_err(|err| err.to_string())?;
    *child = Some(process);
    Ok(manager.status(Some(pid)))
}

async fn ensure_core_binary_available(app: &AppHandle) -> Result<(), String> {
    let provision = provision_core_binary_from_resources(app)?;
    if provision.target_path.exists() {
        if provision.installed {
            emit_shell_log(app, "info", "core", provision.message);
        }
        return Ok(());
    }

    // Download fallback: no core was bundled into this build, so fetch the
    // pinned, checksum-verified mihomo binary into the managed cores directory.
    emit_shell_log(
        app,
        "info",
        "core",
        format!(
            "{}; downloading pinned mihomo {PINNED_MIHOMO_VERSION}",
            provision.message
        ),
    );
    let store = settings_store()?;
    let installer = CoreInstaller::new(store.paths().clone()).map_err(|err| err.to_string())?;
    match installer.install_latest_mihomo_arm64().await {
        Ok(result) => {
            emit_shell_log(
                app,
                "info",
                "core",
                format!(
                    "Downloaded pinned mihomo core ({} bytes) into {}",
                    result.bytes,
                    result.target_path.display()
                ),
            );
            Ok(())
        }
        Err(error) => Err(format!(
            "no bundled core available and pinned core download failed: {error}"
        )),
    }
}

async fn wait_for_core_controller(process: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(8);

    loop {
        if let Some(status) = process.try_wait().map_err(|err| err.to_string())? {
            return Err(format!(
                "Clash core exited before controller became ready: {status}"
            ));
        }

        match controller_client_from_settings()?.configs().await {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("Clash core controller readiness failed: {error}"));
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn next_available_loopback_port(start: u16) -> Option<u16> {
    (start..=u16::MAX).find(|port| TcpListener::bind(("127.0.0.1", *port)).is_ok())
}

#[tauri::command]
fn stop_core(core: State<'_, ManagedCore>) -> Result<CoreStatus, String> {
    let manager = core_manager_from_settings()?;
    stop_managed_core(&core)?;
    Ok(manager.status(None))
}

fn stop_managed_core(core: &ManagedCore) -> Result<(), String> {
    let mut child = core.child.lock().map_err(|err| err.to_string())?;
    if let Some(mut process) = child.take() {
        process.kill().map_err(|err| err.to_string())?;
        process.wait().map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn cleanup_runtime(core: &ManagedCore) -> Vec<String> {
    let mut errors = Vec::new();
    // If the root daemon owns the core, tell it to stop and remove the control
    // file (launchd PathState then stops the daemon) so no orphaned root core
    // keeps holding utun + routes. Keep Service Mode registered for next launch.
    match service_mode_owns_core() {
        Ok(true) => {
            if let Err(error) = write_control_session(false) {
                errors.push(error);
            }
            if let Err(error) = ControlSession::remove() {
                errors.push(error.to_string());
            }
        }
        Ok(false) => {
            if let Err(error) = stop_managed_core(core) {
                errors.push(error);
            }
        }
        Err(error) => {
            errors.push(error);
            if let Err(error) = stop_managed_core(core) {
                errors.push(error);
            }
        }
    }

    let should_restore_proxy = settings_store()
        .and_then(|store| store.read_or_default().map_err(|err| err.to_string()))
        .map(|settings| settings.system_proxy)
        .unwrap_or(false);
    if should_restore_proxy
        && let Err(error) = MacOsPlatformService.restore_original_system_proxy_state()
    {
        errors.push(error.to_string());
    }

    errors
}

fn emit_page(app: &AppHandle, page: &str) {
    let _ = app.emit("cfw://page", page.to_string());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn emit_deep_links(app: &AppHandle, urls: Vec<String>) {
    let _ = app.emit("cfw://deep-link", urls);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn emit_tray_action(app: &AppHandle, action: &str) {
    let _ = app.emit("cfw://tray-action", action.to_string());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn current_settings_for_tray() -> PersistedSettings {
    settings_store()
        .and_then(|store| store.read_or_default().map_err(|err| err.to_string()))
        .unwrap_or_default()
}

fn fallback_tray_proxy_groups() -> Vec<TrayProxyGroup> {
    Vec::new()
}

fn tray_proxy_groups_from_snapshot(snapshot: ProxiesSnapshot) -> Vec<TrayProxyGroup> {
    let global_order = snapshot
        .groups
        .iter()
        .find(|group| group.name == "GLOBAL")
        .map(|group| group.options.clone())
        .unwrap_or_default();

    let delay_by_name = snapshot
        .proxies
        .iter()
        .filter_map(|proxy| {
            proxy
                .history
                .last()
                .map(|entry| (proxy.name.clone(), entry.delay))
        })
        .collect::<std::collections::HashMap<_, _>>();

    let mut groups = snapshot
        .groups
        .into_iter()
        .filter(|group| !group.options.is_empty())
        .map(|group| {
            let selected_delay_ms = group
                .now
                .as_ref()
                .and_then(|name| delay_by_name.get(name).copied())
                .or_else(|| group.history.last().map(|entry| entry.delay));
            TrayProxyGroup {
                name: group.name,
                now: group.now,
                options: group.options,
                selected_delay_ms,
            }
        })
        .collect::<Vec<_>>();

    groups.sort_by(|left, right| {
        let left_order = global_order
            .iter()
            .position(|name| name == &left.name)
            .unwrap_or(usize::MAX);
        let right_order = global_order
            .iter()
            .position(|name| name == &right.name)
            .unwrap_or(usize::MAX);
        left_order
            .cmp(&right_order)
            .then_with(|| left.name.cmp(&right.name))
    });
    groups
}

fn build_proxy_group_menu(app: &AppHandle, group: &TrayProxyGroup) -> tauri::Result<Submenu<Wry>> {
    let mut node_items = Vec::new();
    for option in &group.options {
        let id = format!(
            "proxy-select:{}:{}",
            urlencoding::encode(&group.name),
            urlencoding::encode(option)
        );
        node_items.push(CheckMenuItem::with_id(
            app,
            id,
            option,
            true,
            group.now.as_deref() == Some(option.as_str()),
            None::<&str>,
        )?);
    }

    let node_refs = node_items
        .iter()
        .map(|item| item as &dyn IsMenuItem<Wry>)
        .collect::<Vec<_>>();

    Submenu::with_id_and_items(
        app,
        format!("proxy-group:{}", urlencoding::encode(&group.name)),
        &group.name,
        true,
        &node_refs,
    )
}

fn build_tray_menu(app: &AppHandle, proxy_groups: &[TrayProxyGroup]) -> tauri::Result<Menu<Wry>> {
    let settings = current_settings_for_tray();
    let dashboard = MenuItem::with_id(app, "dashboard", "Dashboard", true, None::<&str>)?;
    let run_tray_script = MenuItem::with_id(
        app,
        "run-tray-script",
        "Run Tray Script",
        true,
        None::<&str>,
    )?;
    let system_proxy = CheckMenuItem::with_id(
        app,
        "system-proxy",
        "System Proxy",
        true,
        settings.system_proxy,
        None::<&str>,
    )?;
    let tun_mode = CheckMenuItem::with_id(
        app,
        "tun-mode",
        "TUN Mode",
        true,
        settings.tun_mode,
        None::<&str>,
    )?;
    let mixin = CheckMenuItem::with_id(app, "mixin", "Mixin", true, settings.mixin, None::<&str>)?;
    let mode_global = CheckMenuItem::with_id(
        app,
        "mode-global",
        "Global",
        true,
        settings.runtime_mode == cfw_core::RuntimeMode::Global,
        None::<&str>,
    )?;
    let mode_rule = CheckMenuItem::with_id(
        app,
        "mode-rule",
        "Rule",
        true,
        settings.runtime_mode == cfw_core::RuntimeMode::Rule,
        None::<&str>,
    )?;
    let mode_direct = CheckMenuItem::with_id(
        app,
        "mode-direct",
        "Direct",
        true,
        settings.runtime_mode == cfw_core::RuntimeMode::Direct,
        None::<&str>,
    )?;
    let mode_script = CheckMenuItem::with_id(
        app,
        "mode-script",
        "Script",
        true,
        settings.runtime_mode == cfw_core::RuntimeMode::Script,
        None::<&str>,
    )?;
    let open_connections =
        MenuItem::with_id(app, "connections", "Connections", true, None::<&str>)?;
    let close_all = MenuItem::with_id(app, "close-all", "Close All", true, None::<&str>)?;
    let toggle_devtools = MenuItem::with_id(
        app,
        "toggle-devtools",
        "Toggle DevTools",
        true,
        None::<&str>,
    )?;
    let move_dashboard = MenuItem::with_id(
        app,
        "move-dashboard",
        "Move Dashboard To Nearest Monitor",
        true,
        None::<&str>,
    )?;
    let restart = MenuItem::with_id(app, "restart", "Restart", true, None::<&str>)?;
    let force_quit = MenuItem::with_id(app, "force-quit", "Force Quit", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator_a = PredefinedMenuItem::separator(app)?;
    let separator_b = PredefinedMenuItem::separator(app)?;
    let separator_c = PredefinedMenuItem::separator(app)?;
    let unavailable_proxy_groups = MenuItem::with_id(
        app,
        "proxy-groups-unavailable",
        "Controller unavailable",
        false,
        None::<&str>,
    )?;

    let proxy_group_menus = proxy_groups
        .iter()
        .map(|group| build_proxy_group_menu(app, group))
        .collect::<tauri::Result<Vec<_>>>()?;
    let proxy_group_refs = if proxy_group_menus.is_empty() {
        vec![&unavailable_proxy_groups as &dyn IsMenuItem<Wry>]
    } else {
        proxy_group_menus
            .iter()
            .map(|item| item as &dyn IsMenuItem<Wry>)
            .collect::<Vec<_>>()
    };
    let proxy_mode_menu = Submenu::with_id_and_items(
        app,
        "proxy-mode",
        "Proxy Mode",
        true,
        &[&mode_global, &mode_rule, &mode_direct, &mode_script],
    )?;
    let proxy_groups_menu =
        Submenu::with_id_and_items(app, "proxy-groups", "Proxy Groups", true, &proxy_group_refs)?;
    let connections_menu = Submenu::with_id_and_items(
        app,
        "connections-menu",
        "Connections",
        true,
        &[&open_connections, &close_all],
    )?;
    let more_menu = Submenu::with_id_and_items(
        app,
        "more",
        "More",
        true,
        &[&toggle_devtools, &move_dashboard, &restart, &force_quit],
    )?;

    Menu::with_items(
        app,
        &[
            &dashboard,
            &run_tray_script,
            &separator_a,
            &system_proxy,
            &tun_mode,
            &mixin,
            &separator_b,
            &proxy_mode_menu,
            &proxy_groups_menu,
            &connections_menu,
            &more_menu,
            &separator_c,
            &quit,
        ],
    )
}

fn update_tray_menu(app: &AppHandle, proxy_groups: &[TrayProxyGroup]) -> tauri::Result<()> {
    let menu = build_tray_menu(app, proxy_groups)?;
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        tray.set_menu(Some(menu))?;
        let settings = current_settings_for_tray();
        let tooltip = if settings.show_tray_proxy_delay_indicator {
            let delays = proxy_groups
                .iter()
                .filter_map(|group| {
                    group
                        .selected_delay_ms
                        .map(|delay| format!("{} {}ms", group.name, delay))
                })
                .take(3)
                .collect::<Vec<_>>();
            if delays.is_empty() {
                PRODUCT_NAME.to_string()
            } else {
                format!("{} · {}", PRODUCT_NAME, delays.join(" · "))
            }
        } else {
            PRODUCT_NAME.to_string()
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }
    Ok(())
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let proxy_groups = fallback_tray_proxy_groups();
    let menu = build_tray_menu(app, &proxy_groups)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip(PRODUCT_NAME)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "dashboard" => emit_page(app, "general"),
            "run-tray-script" => emit_tray_action(app, "run-tray-script"),
            "system-proxy" => emit_tray_action(app, "toggle-system-proxy"),
            "tun-mode" => emit_tray_action(app, "toggle-tun-mode"),
            "mixin" => emit_tray_action(app, "toggle-mixin"),
            "mode-global" => emit_tray_action(app, "mode:Global"),
            "mode-rule" => emit_tray_action(app, "mode:Rule"),
            "mode-direct" => emit_tray_action(app, "mode:Direct"),
            "mode-script" => emit_tray_action(app, "mode:Script"),
            id if id.starts_with("proxy-select:") => emit_tray_action(app, id),
            "connections" => emit_page(app, "connections"),
            "close-all" => emit_tray_action(app, "close-all"),
            "toggle-devtools" => emit_tray_action(app, "toggle-devtools"),
            "move-dashboard" => emit_tray_action(app, "move-dashboard"),
            "restart" => emit_tray_action(app, "restart-core"),
            "force-quit" => {
                let core = app.state::<ManagedCore>();
                let _ = cleanup_runtime(&core);
                app.exit(1);
            }
            "quit" => {
                let core = app.state::<ManagedCore>();
                let _ = cleanup_runtime(&core);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                emit_page(tray.app_handle(), "general");
            }
        })
        .build(app)?;

    Ok(())
}

fn ensure_main_window(app: &AppHandle) -> tauri::Result<()> {
    if app.get_webview_window("main").is_none() {
        WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
            .title("")
            .inner_size(850.0, 603.0)
            .min_inner_size(850.0, 603.0)
            .decorations(true)
            .center()
            .build()?;
    }

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(ManagedCore::default())
        .manage(LiveStreams::default())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let urls = argv
                .into_iter()
                .filter(|arg| arg.starts_with("clash://"))
                .collect::<Vec<_>>();
            emit_deep_links(app, urls);
        }))
        .invoke_handler(tauri::generate_handler![
            boot_payload,
            open_page,
            quit_app,
            force_quit_app,
            current_platform_design,
            provision_core_binary,
            install_core_from_url,
            install_latest_mihomo_core,
            system_proxy_state,
            network_diagnostics,
            read_settings_snapshot,
            write_settings_snapshot,
            reset_settings_snapshot,
            set_system_proxy_enabled,
            set_tun_enabled,
            service_mode_status,
            enable_service_mode,
            disable_service_mode,
            set_mixin_enabled,
            set_launch_at_login_enabled,
            install_helper_service,
            uninstall_helper_service,
            run_tray_script,
            run_child_process,
            toggle_devtools,
            move_dashboard_to_nearest_monitor,
            controller_snapshot,
            providers_snapshot,
            rules_snapshot,
            update_proxy_provider,
            update_rule_provider,
            health_check_proxy_provider,
            update_all_proxy_providers,
            update_all_rule_providers,
            health_check_all_proxy_providers,
            refresh_tray_menu,
            start_connections_stream,
            start_log_stream,
            parse_deep_links,
            import_profile_url,
            import_profile_text,
            import_profile_file,
            migrate_legacy_cfw_profiles,
            update_profile,
            profiles_snapshot,
            delete_profile,
            reveal_profile,
            read_profile_text,
            save_profile_text,
            profile_qrcode_svg,
            reveal_home_directory,
            reveal_logs_directory,
            apply_active_profile,
            set_proxy_mode,
            set_allow_lan,
            set_ipv6,
            set_log_level,
            select_proxy,
            test_proxy_delays,
            close_connection,
            close_all_connections,
            flush_fake_ip_cache,
            core_status,
            start_core,
            stop_core
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let core = app_handle.state::<ManagedCore>();
                match start_managed_core(&app_handle, &core).await {
                    Ok(status) => {
                        let _ = app_handle.emit("cfw://core-status", status);
                    }
                    Err(error) => emit_stream_error(&app_handle, "core", error),
                }
            });
            let scheduler_handle = app.handle().clone();
            tauri::async_runtime::spawn(run_profile_update_scheduler(scheduler_handle));
            tauri::async_runtime::spawn(run_helper_heartbeat());
            ensure_main_window(app.handle())?;
            build_tray(app.handle())?;
            emit_deep_links(app.handle(), Vec::new());
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                let core = window.app_handle().state::<ManagedCore>();
                let _ = cleanup_runtime(&core);
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run Clash for Mac tauri shell");
}
