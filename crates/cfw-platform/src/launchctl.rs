use std::fmt;
use std::process::Command;

use anyhow::{Context, Result, bail};

const ID: &str = "/usr/bin/id";
const LAUNCHCTL: &str = "/bin/launchctl";

pub(crate) fn current_uid() -> Result<String> {
    let output = Command::new(ID)
        .arg("-u")
        .output()
        .with_context(|| format!("failed to run {ID} -u"))?;
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
    fn is_missing_bootout_target(&self) -> bool {
        self.operation.starts_with("bootout ")
            && self.exit_code == Some(3)
            && self.stdout.is_empty()
            && self.stderr == "Boot-out failed: 3: No such process"
    }

    fn is_missing_print_target(&self) -> bool {
        self.operation.starts_with("print ")
            && self.exit_code == Some(113)
            && self.stdout.is_empty()
            && self
                .stderr
                .starts_with("Bad request.\nCould not find service \"")
            && self.stderr.contains("\" in domain for ")
    }
}

impl fmt::Display for LaunchctlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{LAUNCHCTL} {} failed with status {}: {}{}",
            self.operation,
            self.exit_code.map_or_else(
                || "terminated by signal".to_string(),
                |code| code.to_string()
            ),
            self.stderr,
            self.stdout
        )
    }
}

impl std::error::Error for LaunchctlFailure {}

fn run(args: &[&str]) -> Result<String, LaunchctlFailure> {
    let operation = args.join(" ");
    let output = Command::new(LAUNCHCTL)
        .args(args)
        .output()
        .map_err(|error| LaunchctlFailure {
            operation: operation.clone(),
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to execute: {error}"),
        })?;
    if !output.status.success() {
        return Err(LaunchctlFailure {
            operation,
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(crate) fn run_allow_absent(args: &[&str]) -> Result<()> {
    match run(args) {
        Ok(_) => Ok(()),
        Err(error) if error.is_missing_bootout_target() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn ensure_unloaded(service_target: &str) -> Result<()> {
    match run(&["print", service_target]) {
        Ok(_) => bail!("legacy launchd service remains loaded: {service_target}"),
        Err(error) if error.is_missing_print_target() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(operation: &str, exit_code: i32, stderr: &str) -> LaunchctlFailure {
        LaunchctlFailure {
            operation: operation.into(),
            exit_code: Some(exit_code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn bootout_accepts_only_the_structured_missing_result() {
        assert!(
            failure(
                "bootout system/com.example.missing",
                3,
                "Boot-out failed: 3: No such process"
            )
            .is_missing_bootout_target()
        );
        assert!(!failure("bootout system/x", 5, "Boot-out failed: 5").is_missing_bootout_target());
        assert!(
            !failure("disable system/x", 3, "Boot-out failed: 3: No such process")
                .is_missing_bootout_target()
        );
    }

    #[test]
    fn print_accepts_only_launchctl_missing_service_output() {
        assert!(
            failure(
                "print gui/501/com.example.missing",
                113,
                "Bad request.\nCould not find service \"com.example.missing\" in domain for user gui: 501"
            )
            .is_missing_print_target()
        );
        assert!(!failure("print gui/501/x", 5, "Load failed: 5").is_missing_print_target());
        assert!(!failure("print gui/501/x", 113, "Bad request.").is_missing_print_target());
    }
}
