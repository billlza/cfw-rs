//! `cfw-cli` — headless command-line control for Clash for Mac (cfw-rs).
//!
//! Exists so an AI tool (or any script) can drive the essentials — start/stop
//! the core, toggle the system proxy, import/switch profiles, inspect and switch
//! proxies, read connections/logs — without the GUI, e.g. when computer-use is
//! unavailable. It reuses the same library crates as the desktop shell so
//! behavior never diverges. Every command supports `--json` for machine parsing.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;

use cfw_core::{MacOsAppPaths, PersistedSettings, SettingsStore};
use cfw_controller::{ControllerClient, ControllerEndpoint};
use cfw_platform::{MacOsPlatformService, SystemProxyMode, SystemProxyService};
use cfw_profiles::{ProfileImportRequest, ProfileManager};
use cfw_runtime::{CoreInstaller, CoreManager, CoreProcessSpec, DEFAULT_CORE_BINARY_NAME};

const PID_FILE: &str = "cfw-cli-core.pid";
const DELAY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Parser)]
#[command(
    name = "cfw-cli",
    version,
    about = "Headless control for Clash for Mac (cfw-rs)"
)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Overall status: core, system proxy, active profile.
    Status,
    /// Manage the Clash core process.
    Core {
        #[command(subcommand)]
        action: CoreAction,
    },
    /// Manage the macOS system proxy.
    Sysproxy {
        #[command(subcommand)]
        action: SysproxyAction,
    },
    /// Manage profiles / subscriptions.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Inspect or switch proxies via the controller.
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Print the live connections snapshot.
    Connections,
    /// Print the tail of the core log.
    Logs {
        /// Number of trailing lines to show.
        #[arg(long, default_value_t = 80)]
        lines: usize,
    },
    /// Show or regenerate the core config.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum CoreAction {
    /// Start the core detached (provisioning/downloading it if needed).
    Start,
    /// Stop the CLI-managed core (via its pid file).
    Stop,
    /// Report core process state.
    Status,
    /// Download and install the pinned mihomo core.
    Install,
}

#[derive(Subcommand)]
enum SysproxyAction {
    /// Point the system proxy at the local mixed port.
    On {
        /// Override the port (defaults to the configured mixed-port).
        #[arg(long)]
        port: Option<u16>,
    },
    /// Restore the system proxy to its pre-Clash snapshot.
    Off,
    /// Report the current system proxy state.
    Status,
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List managed profiles.
    List,
    /// Import a remote subscription URL.
    Import {
        url: String,
        #[arg(long)]
        name: Option<String>,
        /// Do not activate the imported profile.
        #[arg(long)]
        no_activate: bool,
    },
    /// Import a local profile file.
    ImportFile {
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        no_activate: bool,
    },
    /// Make a profile active and re-render the config.
    Use { id: String },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// List proxy groups and their current selection.
    List,
    /// Select a node within a selector group.
    Select { group: String, node: String },
    /// Delay-test a single proxy.
    Delay {
        proxy: String,
        #[arg(long, default_value = DELAY_TEST_URL)]
        url: String,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u16,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the current core config file.
    Show,
    /// Regenerate the core config from the active profile or settings.
    Regen,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Status => status(cli).await,
        Commands::Core { action } => core(cli, action).await,
        Commands::Sysproxy { action } => sysproxy(cli, action),
        Commands::Profile { action } => profile(cli, action).await,
        Commands::Proxy { action } => proxy(cli, action).await,
        Commands::Connections => connections(cli).await,
        Commands::Logs { lines } => logs(cli, *lines),
        Commands::Config { action } => config(cli, action),
    }
}

// --- shared context ------------------------------------------------------

fn store() -> Result<SettingsStore> {
    let store = SettingsStore::default_for_current_user()
        .context("failed to resolve the Clash for Mac settings store")?;
    store.ensure_layout().context("failed to prepare app layout")?;
    Ok(store)
}

fn controller(settings: &PersistedSettings) -> Result<ControllerClient> {
    let endpoint = ControllerEndpoint::new(
        settings.external_controller_host.clone(),
        settings.external_controller_port,
        settings.secret.clone(),
    );
    ControllerClient::new(endpoint).context("failed to build controller client")
}

fn pid_file(paths: &MacOsAppPaths) -> PathBuf {
    paths.app_home.join(PID_FILE)
}

fn read_pid(paths: &MacOsAppPaths) -> Option<u32> {
    fs::read_to_string(pid_file(paths))
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
}

fn emit<T: Serialize>(json: bool, value: &T, human: impl FnOnce()) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        human();
    }
    Ok(())
}

// --- status --------------------------------------------------------------

async fn status(cli: &Cli) -> Result<()> {
    let store = store()?;
    let settings = store.read_or_default()?;
    let controller_up = controller(&settings)?.configs().await.is_ok();
    let proxy_state = MacOsPlatformService
        .read_system_proxy_state()
        .map(|state| format!("{state:?}"))
        .unwrap_or_else(|err| format!("unknown ({err})"));
    let report = serde_json::json!({
        "core_running": controller_up,
        "controller": format!("{}:{}", settings.external_controller_host, settings.external_controller_port),
        "mixed_port": settings.mixed_port,
        "system_proxy": proxy_state,
        "tun_mode": settings.tun_mode,
        "active_profile": settings.active_profile,
        "managed_pid": read_pid(store.paths()),
    });
    emit(cli.json, &report, || {
        println!(
            "core:          {}",
            if controller_up { "running" } else { "stopped" }
        );
        println!("system proxy:  {proxy_state}");
        println!("mixed-port:    {}", settings.mixed_port);
        println!("tun mode:      {}", settings.tun_mode);
        println!(
            "active profile:{}",
            settings
                .active_profile
                .as_deref()
                .map(|p| format!(" {p}"))
                .unwrap_or_else(|| " (none)".into())
        );
    })
}

// --- core ----------------------------------------------------------------

async fn core(cli: &Cli, action: &CoreAction) -> Result<()> {
    let store = store()?;
    match action {
        CoreAction::Install => {
            let result = CoreInstaller::new(store.paths().clone())?
                .install_latest_mihomo_arm64()
                .await
                .context("pinned mihomo core download failed")?;
            emit(cli.json, &result, || {
                println!(
                    "installed core: {} ({} bytes)",
                    result.target_path.display(),
                    result.bytes
                );
            })
        }
        CoreAction::Status => {
            let settings = store.read_or_default()?;
            let spec = CoreProcessSpec::from_settings(store.paths(), &settings);
            let manager = CoreManager::new(spec);
            let status = manager.status(read_pid(store.paths()));
            emit(cli.json, &status, || println!("{}", status.message))
        }
        CoreAction::Stop => {
            let Some(pid) = read_pid(store.paths()) else {
                bail!("no CLI-managed core pid file found");
            };
            let killed = Command::new("/bin/kill")
                .arg(pid.to_string())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            let _ = fs::remove_file(pid_file(store.paths()));
            emit(cli.json, &serde_json::json!({ "stopped": killed, "pid": pid }), || {
                println!("core pid {pid}: {}", if killed { "stopped" } else { "not running" });
            })
        }
        CoreAction::Start => start_core(cli, &store).await,
    }
}

async fn start_core(cli: &Cli, store: &SettingsStore) -> Result<()> {
    let settings = store.read_or_default()?;
    // Provision the core binary: rely on the GUI-managed copy, else download the
    // pinned build (the same fallback the shell uses).
    let binary = store.paths().cores_dir.join(DEFAULT_CORE_BINARY_NAME);
    if !binary.exists() {
        CoreInstaller::new(store.paths().clone())?
            .install_latest_mihomo_arm64()
            .await
            .context("no managed core present and the pinned download failed")?;
    }
    let config_path = ensure_config(store, &settings)?;
    let spec = CoreProcessSpec::from_settings(store.paths(), &settings);
    let manager = CoreManager::new(spec);
    let child = manager.spawn().context("failed to spawn the core")?;
    let pid = child.id();
    fs::write(pid_file(store.paths()), pid.to_string())?;
    // Dropping `child` does not kill the process on Unix; the core keeps running
    // detached after the CLI exits.
    drop(child);

    let client = controller(&settings)?;
    let mut ready = false;
    for _ in 0..40 {
        if client.configs().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let report = serde_json::json!({
        "pid": pid,
        "controller_ready": ready,
        "config": config_path,
    });
    emit(cli.json, &report, || {
        println!(
            "core started (pid {pid}); controller {}",
            if ready { "ready" } else { "not ready within 4s" }
        );
    })
}

fn ensure_config(store: &SettingsStore, settings: &PersistedSettings) -> Result<PathBuf> {
    if settings
        .active_profile
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        let manager = ProfileManager::new(store.paths().clone())?;
        Ok(manager.apply_active(store)?.config_path)
    } else {
        cfw_runtime::write_default_config(store.paths(), settings)
            .map_err(|err| anyhow!("default config generation failed: {err}"))
    }
}

// --- sysproxy ------------------------------------------------------------

fn sysproxy(cli: &Cli, action: &SysproxyAction) -> Result<()> {
    let store = store()?;
    match action {
        SysproxyAction::On { port } => {
            let mut settings = store.read_or_default()?;
            let port = port.unwrap_or(settings.mixed_port);
            MacOsPlatformService
                .set_system_proxy_mode(SystemProxyMode::GlobalHttp, port, &[], None)
                .map_err(|err| anyhow!("failed to enable system proxy: {err}"))?;
            settings.system_proxy = true;
            store.write(&settings)?;
            emit(cli.json, &serde_json::json!({ "system_proxy": true, "port": port }), || {
                println!("system proxy enabled -> 127.0.0.1:{port}");
            })
        }
        SysproxyAction::Off => {
            let mut settings = store.read_or_default()?;
            MacOsPlatformService
                .restore_original_system_proxy_state()
                .map_err(|err| anyhow!("failed to restore system proxy: {err}"))?;
            settings.system_proxy = false;
            store.write(&settings)?;
            emit(cli.json, &serde_json::json!({ "system_proxy": false }), || {
                println!("system proxy restored");
            })
        }
        SysproxyAction::Status => {
            let state = MacOsPlatformService
                .read_system_proxy_state()
                .map_err(|err| anyhow!("failed to read system proxy state: {err}"))?;
            emit(cli.json, &serde_json::json!({ "system_proxy": format!("{state:?}") }), || {
                println!("system proxy: {state:?}");
            })
        }
    }
}

// --- profile -------------------------------------------------------------

async fn profile(cli: &Cli, action: &ProfileAction) -> Result<()> {
    let store = store()?;
    let manager = ProfileManager::new(store.paths().clone())?;
    match action {
        ProfileAction::List => {
            let profiles = manager.list(&store)?;
            emit(cli.json, &profiles, || {
                if profiles.is_empty() {
                    println!("(no profiles)");
                }
                for record in &profiles {
                    println!(
                        "{} {}  {}  {} rules",
                        if record.active { "*" } else { " " },
                        record.id,
                        record.name,
                        record.rule_count
                    );
                }
            })
        }
        ProfileAction::Import {
            url,
            name,
            no_activate,
        } => {
            let result = manager
                .import_remote(
                    &store,
                    ProfileImportRequest {
                        url: url.clone(),
                        name: name.clone(),
                        activate: !no_activate,
                    },
                )
                .await?;
            emit(cli.json, &result, || {
                println!("imported {} ({} bytes)", result.name, result.bytes);
            })
        }
        ProfileAction::ImportFile {
            path,
            name,
            no_activate,
        } => {
            let result = manager.import_file(&store, path.clone(), name.clone(), !no_activate)?;
            emit(cli.json, &result, || {
                println!("imported {} ({} bytes)", result.name, result.bytes);
            })
        }
        ProfileAction::Use { id } => {
            let mut settings = store.read_or_default()?;
            settings.active_profile = Some(id.clone());
            store.write(&settings)?;
            let applied = manager.apply_active(&store)?;
            emit(cli.json, &applied, || {
                println!("active profile -> {id}");
            })
        }
    }
}

// --- proxy ---------------------------------------------------------------

async fn proxy(cli: &Cli, action: &ProxyAction) -> Result<()> {
    let store = store()?;
    let settings = store.read_or_default()?;
    let client = controller(&settings)?;
    match action {
        ProxyAction::List => {
            let snapshot = client.proxies().await?;
            emit(cli.json, &snapshot, || {
                for group in &snapshot.groups {
                    println!(
                        "[{}] {} -> {}",
                        group.kind,
                        group.name,
                        group.now.as_deref().unwrap_or("-")
                    );
                }
            })
        }
        ProxyAction::Select { group, node } => {
            client.select_proxy(group, node).await?;
            emit(cli.json, &serde_json::json!({ "group": group, "now": node }), || {
                println!("{group} -> {node}");
            })
        }
        ProxyAction::Delay {
            proxy,
            url,
            timeout_ms,
        } => {
            let delay = client.proxy_delay(proxy, url, *timeout_ms).await?;
            emit(cli.json, &serde_json::json!({ "proxy": proxy, "delay_ms": delay }), || {
                println!("{proxy}: {delay} ms");
            })
        }
    }
}

// --- connections / logs / config ----------------------------------------

async fn connections(cli: &Cli) -> Result<()> {
    let store = store()?;
    let settings = store.read_or_default()?;
    let snapshot = controller(&settings)?.connections().await?;
    emit(cli.json, &snapshot, || {
        println!("{} active connections", snapshot.connections.len());
    })
}

fn logs(cli: &Cli, lines: usize) -> Result<()> {
    let store = store()?;
    let log_path = store
        .paths()
        .logs_dir
        .join(cfw_runtime::CORE_LOG_FILE_NAME);
    let body = fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path.display()))?;
    let tail: Vec<&str> = body.lines().rev().take(lines).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    emit(cli.json, &serde_json::json!({ "lines": tail }), || {
        println!("{}", tail.join("\n"));
    })
}

fn config(cli: &Cli, action: &ConfigAction) -> Result<()> {
    let store = store()?;
    match action {
        ConfigAction::Show => {
            let path = &store.paths().config_file;
            let body = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            emit(cli.json, &serde_json::json!({ "path": path, "config": body }), || {
                println!("{body}");
            })
        }
        ConfigAction::Regen => {
            let settings = store.read_or_default()?;
            let path = ensure_config(&store, &settings)?;
            emit(cli.json, &serde_json::json!({ "config": path }), || {
                println!("config regenerated -> {}", path.display());
            })
        }
    }
}
