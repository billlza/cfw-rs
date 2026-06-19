use std::process::Command;

use anyhow::{Context, Result, bail};
use cfw_core::{MacOsAppPaths, SettingsStore};
use cfw_runtime::{CoreManager, CoreProcessSpec};
use serde::Serialize;

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
            // Detach unless launched as the long-running daemon command.
            drop(child);
            print_outcome("run-core", PidPayload { pid })
        }
        "serve" => {
            let mut child = manager(&options)?
                .spawn()
                .context("failed to spawn Clash core")?;
            let pid = child.id();
            print_outcome("serve", PidPayload { pid })?;
            let status = child
                .wait()
                .context("failed while waiting for Clash core")?;
            if status.success() {
                Ok(())
            } else {
                bail!("Clash core exited with status {status}")
            }
        }
        "stop-core" => {
            let stopped = stop_core(&options)?;
            print_outcome("stop-core", StopPayload { stopped })
        }
        other => bail!("unsupported helper command: {other}"),
    }
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
