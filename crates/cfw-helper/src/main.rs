//! Privileged helper for Clash for Mac (cfw-rs).
//!
//! Installed as a root launchd daemon via SMAppService. Its `serve` command is
//! the long-running supervisor launchd starts (KeepAlive=PathState on the
//! control file): it reads the app-written [`ControlSession`], validates it for
//! root use, and spawns/supervises the mihomo core as root so the core can open
//! a utun device for TUN mode. The other subcommands (status/run-core/stop-core)
//! remain for diagnostics and accept an explicit `--app-home`.

use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use cfw_core::{ControlSession, CoreKind, MacOsAppPaths, PersistedSettings, SettingsStore};
use cfw_runtime::{
    CORE_LOG_FILE_NAME, CoreManager, CoreProcessSpec, MIHOMO_CORE_BINARY_NAME, core_binary_name,
    resolve_core_kind,
};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;

/// Fallback wake interval when FSEvents miss an event (also used for heartbeat).
const SUPERVISE_FALLBACK: Duration = Duration::from_secs(5);
/// Tear the root core down if the app's heartbeat is older than this (app died).
const HEARTBEAT_STALE_SECS: u64 = 60;

#[derive(Debug, Serialize)]
struct HelperOutcome<T> {
    ok: bool,
    command: String,
    payload: T,
}

#[derive(Debug, Serialize)]
struct PidPayload {
    pid: u32,
}

#[derive(Debug, Serialize)]
struct StopPayload {
    stopped: bool,
}

fn main() {
    if let Err(error) = run() {
        let payload = serde_json::json!({
            "ok": false,
            "error": error.to_string(),
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let (command, options) = HelperOptions::parse(std::env::args().skip(1))?;
    match command.as_str() {
        "status" => print_outcome("status", manager(&options)?.status(None)),
        "run-core" => {
            let child = manager(&options)?
                .spawn()
                .context("failed to spawn Clash core")?;
            let pid = child.id();
            // Detach unless launched as the long-running supervisor.
            drop(child);
            print_outcome("run-core", PidPayload { pid })
        }
        // The launchd daemon entrypoint: supervise the root core off the control
        // file. Always returns Ok so launchd (KeepAlive) never crash-loops.
        "serve" => supervise(),
        "stop-core" => {
            let stopped = stop_core(&options)?;
            print_outcome("stop-core", StopPayload { stopped })
        }
        other => bail!("unsupported helper command: {other}"),
    }
}

/// Long-running root supervisor. Never exits non-zero while it might be wanted —
/// it exits 0 (clean) only when the app no longer wants the core, so launchd's
/// PathState/KeepAlive does not thrash it.
fn supervise() -> Result<()> {
    let mut child: Option<Child> = None;
    let mut running_generation: Option<u64> = None;

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<notify::Event>| {
            let _ = tx.send(result);
        },
        notify::Config::default(),
    )
    .context("failed to create control-session watcher")?;

    let dir = ControlSession::dir();
    let _ = std::fs::create_dir_all(&dir);
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch {}", dir.display()))?;

    loop {
        // Block until FSEvents/kqueue reports a change, or fall back for heartbeat.
        let _ = rx.recv_timeout(SUPERVISE_FALLBACK);
        while rx.try_recv().is_ok() {}

        let session = match ControlSession::read() {
            Ok(Some(session)) => session,
            // File gone -> the app wants Service Mode off; launchd is stopping us.
            Ok(None) => {
                stop_child(&mut child);
                return Ok(());
            }
            Err(error) => {
                eprintln!("control session unreadable, tearing down: {error}");
                stop_child(&mut child);
                return Ok(());
            }
        };

        // The app bumps heartbeat on a timer; a stale heartbeat means it died
        // without cleaning up. Remove the file (we are root) so PathState stops
        // us, and tear the orphaned core + routes down.
        if now_epoch_secs().saturating_sub(session.heartbeat_epoch_secs) > HEARTBEAT_STALE_SECS {
            eprintln!("control session heartbeat is stale; tearing down orphaned core");
            stop_child(&mut child);
            let _ = ControlSession::remove();
            return Ok(());
        }

        if !session.want_core {
            // Transient state before the app removes the file; idle, don't exit
            // (exiting with the file still present would relaunch in a loop).
            stop_child(&mut child);
            running_generation = None;
            continue;
        }

        // want_core = true: only ever act on a session that is safe for root.
        if let Err(error) = session.validate_for_root() {
            eprintln!("refusing unsafe control session: {error}");
            stop_child(&mut child);
            running_generation = None;
            continue;
        }

        let core_dead = child
            .as_mut()
            .map(|process| matches!(process.try_wait(), Ok(Some(_)) | Err(_)))
            .unwrap_or(true);
        let generation_changed = running_generation != Some(session.generation);
        if core_dead || generation_changed {
            stop_child(&mut child);
            match spawn_core_for_session(&session) {
                Ok(process) => {
                    child = Some(process);
                    running_generation = Some(session.generation);
                }
                Err(error) => {
                    // Log and keep supervising; never exit non-zero under KeepAlive.
                    eprintln!("core spawn failed: {error:#}");
                    running_generation = None;
                }
            }
        }
    }
}

/// Build a core spec straight from the validated control session (NOT from
/// `$HOME`, which is `/var/root` under launchd) and spawn the core as root.
fn spawn_core_for_session(session: &ControlSession) -> Result<Child> {
    let paths = MacOsAppPaths::from_app_home(&session.app_home);
    let settings = SettingsStore::new(paths.clone())
        .read_or_default()
        .unwrap_or_else(|_| PersistedSettings::default());
    let mut kind = resolve_core_kind(&settings);
    let mut binary_path = paths.cores_dir.join(core_binary_name(kind));
    if kind == CoreKind::ClashRs && !binary_path.exists() {
        // Service Mode must stay up; fall back to mihomo without claiming cutover.
        eprintln!("clash-rs binary missing under Service Mode; falling back to mihomo");
        kind = CoreKind::Mihomo;
        binary_path = paths.cores_dir.join(MIHOMO_CORE_BINARY_NAME);
    }
    let spec = CoreProcessSpec {
        binary_path,
        config_path: session.config_file.clone(),
        home_dir: paths.app_home.clone(),
        log_file: paths.logs_dir.join(CORE_LOG_FILE_NAME),
        controller_host: "127.0.0.1".into(),
        controller_port: session.controller_port,
        mixed_port: session.mixed_port,
        core_kind: kind,
    };
    CoreManager::new(spec)
        .spawn()
        .context("failed to spawn Clash core as root")
}

fn stop_child(child: &mut Option<Child>) {
    if let Some(mut process) = child.take() {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
struct HelperOptions {
    app_home: Option<std::path::PathBuf>,
}

impl HelperOptions {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<(String, Self)> {
        let mut command = None;
        let mut options = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--app-home" => {
                    let value = args
                        .next()
                        .context("--app-home requires an absolute path argument")?;
                    let path = std::path::PathBuf::from(value);
                    if !path.is_absolute() {
                        bail!("--app-home must be absolute: {}", path.display());
                    }
                    options.app_home = Some(path);
                }
                value if value.starts_with("--") => bail!("unsupported option: {value}"),
                value if command.is_none() => command = Some(value.to_string()),
                value => bail!("unexpected extra argument: {value}"),
            }
        }
        Ok((command.unwrap_or_else(|| "status".into()), options))
    }
}

fn manager(options: &HelperOptions) -> Result<CoreManager> {
    let store = if let Some(app_home) = options.app_home.clone() {
        SettingsStore::new(MacOsAppPaths::from_app_home(app_home))
    } else {
        SettingsStore::default_for_current_user()?
    };
    let settings = store.read_or_default()?;
    Ok(CoreManager::new(CoreProcessSpec::from_settings(
        store.paths(),
        &settings,
    )))
}

fn stop_core(options: &HelperOptions) -> Result<bool> {
    let spec = manager(options)?.spec().clone();
    let pattern = spec.binary_path.display().to_string();
    let status = Command::new("/usr/bin/pkill")
        .arg("-f")
        .arg(&pattern)
        .status()
        .with_context(|| format!("failed to run pkill for {pattern}"))?;
    Ok(status.success())
}

fn print_outcome<T: Serialize>(command: &str, payload: T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&HelperOutcome {
            ok: true,
            command: command.into(),
            payload,
        })?
    );
    Ok(())
}
