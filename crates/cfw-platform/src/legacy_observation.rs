use std::time::Duration;

use anyhow::{Result, bail};

use crate::bounded_command::{BoundedCommandError, BoundedCommandOutput, run_bounded_command};

const PROCESS_LIST: &str = "/bin/ps";
const TCP_LISTENERS: &str = "/usr/sbin/netstat";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3);
/// `ps` writes whole command lines when its output is a pipe, so the table
/// grows with every process's arguments: with browsers, Electron apps and
/// parallel compilers running, one Mac's table measured 2.3 MB. The bound
/// still limits what one observation holds in memory.
const PROCESS_TABLE_MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const LISTENER_TABLE_MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;

pub fn observe_legacy_process_table() -> Result<String> {
    observe_process_table(PROCESS_LIST, &["-axo", "uid=,pid=,lstart=,command="])
}

fn observe_process_table(program: &str, arguments: &[&str]) -> Result<String> {
    finish_observation(
        "legacy process table",
        run_bounded_command(
            program,
            arguments,
            OBSERVATION_TIMEOUT,
            PROCESS_TABLE_MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
        ),
    )
}

pub fn observe_legacy_tcp_listener_table() -> Result<String> {
    finish_observation(
        "legacy TCP listener table",
        run_bounded_command(
            TCP_LISTENERS,
            &["-anv", "-p", "tcp"],
            OBSERVATION_TIMEOUT,
            LISTENER_TABLE_MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
        ),
    )
}

fn finish_observation(
    label: &str,
    result: Result<BoundedCommandOutput, BoundedCommandError>,
) -> Result<String> {
    let output = result.map_err(|error| anyhow::anyhow!("{label} failed: {error}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("{label} stdout is not UTF-8"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| anyhow::anyhow!("{label} stderr is not UTF-8"))?;
    if !output.status.success() {
        bail!(
            "{label} failed with status {}: {}",
            output.status,
            stderr.trim()
        )
    }
    if !stderr.trim().is_empty() {
        bail!(
            "{label} succeeded with unexpected stderr: {}",
            stderr.trim()
        )
    }
    Ok(stdout.trim().to_owned())
}

#[cfg(test)]
mod tests;
