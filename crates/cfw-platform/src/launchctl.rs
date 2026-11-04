use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::bounded_command::{BoundedCommandError, BoundedCommandOutput, run_bounded_command};

const ID: &str = "/usr/bin/id";
const LAUNCHCTL: &str = "/bin/launchctl";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STDOUT_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;

pub(crate) fn current_uid() -> Result<String> {
    parse_uid(run_bounded_command(
        ID,
        &["-u"],
        COMMAND_TIMEOUT,
        MAX_STDOUT_BYTES,
        MAX_STDERR_BYTES,
    ))
}

fn parse_uid(result: Result<BoundedCommandOutput, BoundedCommandError>) -> Result<String> {
    let output = result.with_context(|| format!("failed to run {ID} -u"))?;
    if !output.status.success() {
        bail!(
            "{ID} -u failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{ID} -u returned an invalid uid: {uid:?}");
    }
    Ok(uid)
}

#[derive(Debug)]
struct LaunchctlFailure {
    operation: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl LaunchctlFailure {
    fn is_missing_bootout_target(&self, target: &str) -> bool {
        self.operation == format!("bootout {target}")
            && self.exit_code == Some(3)
            && self.stdout.is_empty()
            && self.stderr == "Boot-out failed: 3: No such process"
    }

    fn is_missing_print_target(&self, target: &str) -> bool {
        let Some(expected) = expected_missing_print_error(target) else {
            return false;
        };
        self.operation == format!("print {target}")
            && self.exit_code == Some(113)
            && self.stdout.is_empty()
            && self.stderr == expected
    }
}

impl fmt::Display for LaunchctlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{LAUNCHCTL} {} failed ", self.operation)?;
        // No exit code: a signal ended launchctl, or it never ran to completion.
        match self.exit_code {
            Some(code) => write!(formatter, "with status {code}")?,
            None => formatter.write_str("without an exit status")?,
        }
        if !self.stderr.is_empty() {
            write!(formatter, ": {}", self.stderr)?;
        }
        if !self.stdout.is_empty() {
            write!(formatter, "; standard output: {}", self.stdout)?;
        }
        Ok(())
    }
}

impl std::error::Error for LaunchctlFailure {}

fn run(args: &[&str]) -> Result<String, LaunchctlFailure> {
    finish(
        args.join(" "),
        run_bounded_command(
            LAUNCHCTL,
            args,
            COMMAND_TIMEOUT,
            MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
        ),
    )
}

/// The standard output of a successful run; any other outcome, including a
/// success that wrote to standard error, as a failure of `operation`.
fn finish(
    operation: String,
    result: Result<BoundedCommandOutput, BoundedCommandError>,
) -> Result<String, LaunchctlFailure> {
    let output = result.map_err(|error| LaunchctlFailure {
        operation: operation.clone(),
        exit_code: None,
        stdout: String::new(),
        stderr: error.to_string(),
    })?;
    let exit_code = output.status.code();
    let stdout = String::from_utf8(output.stdout).map_err(|_| LaunchctlFailure {
        operation: operation.clone(),
        exit_code,
        stdout: String::new(),
        stderr: "launchctl stdout was not valid UTF-8".into(),
    })?;
    let stderr = String::from_utf8(output.stderr).map_err(|_| LaunchctlFailure {
        operation: operation.clone(),
        exit_code,
        stdout: stdout.trim().to_owned(),
        stderr: "launchctl stderr was not valid UTF-8".into(),
    })?;
    if !output.status.success() {
        return Err(LaunchctlFailure {
            operation,
            exit_code,
            stdout: stdout.trim().to_owned(),
            stderr: stderr.trim().to_owned(),
        });
    }
    if !stderr.trim().is_empty() {
        return Err(LaunchctlFailure {
            operation,
            exit_code,
            stdout: stdout.trim().to_owned(),
            stderr: format!(
                "launchctl succeeded with unexpected stderr: {}",
                stderr.trim()
            ),
        });
    }
    Ok(stdout)
}

fn expected_missing_print_error(target: &str) -> Option<String> {
    if let Some(label) = target.strip_prefix("system/")
        && !label.is_empty()
        && !label.contains('/')
    {
        return Some(format!(
            "Bad request.\nCould not find service \"{label}\" in domain for system"
        ));
    }
    let remainder = target.strip_prefix("gui/")?;
    let (uid, label) = remainder.split_once('/')?;
    if uid.is_empty()
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || label.is_empty()
        || label.contains('/')
    {
        return None;
    }
    Some(format!(
        "Bad request.\nCould not find service \"{label}\" in domain for user gui: {uid}"
    ))
}

pub(crate) fn run_allow_absent(args: &[&str]) -> Result<()> {
    allow_absent(args, run(args))
}

/// Success, or the structured result of booting out a job that is not loaded.
fn allow_absent(args: &[&str], result: Result<String, LaunchctlFailure>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(error)
            if args.len() == 2
                && args[0] == "bootout"
                && error.is_missing_bootout_target(args[1]) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn ensure_unloaded(service_target: &str) -> Result<()> {
    if print_target(service_target)?.is_some() {
        bail!("legacy launchd service remains loaded: {service_target}")
    }
    Ok(())
}

pub(crate) fn print_target(service_target: &str) -> Result<Option<String>> {
    match run(&["print", service_target]) {
        Ok(output) => Ok(Some(output)),
        Err(error) if error.is_missing_print_target(service_target) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
