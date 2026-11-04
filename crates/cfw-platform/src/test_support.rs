//! Command outcomes for the tests of the modules that interpret them.

use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;
use std::time::Duration;

use crate::bounded_command::{BoundedCommandError, BoundedCommandOutput};

/// A command that exited with `code` after writing `stdout` and `stderr`.
pub(crate) fn exited(code: i32, stdout: &[u8], stderr: &[u8]) -> BoundedCommandOutput {
    BoundedCommandOutput {
        status: ExitStatus::from_raw(code << 8),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}

/// A command that `signal` ended before it wrote anything.
pub(crate) fn signalled(signal: i32) -> BoundedCommandOutput {
    BoundedCommandOutput {
        status: ExitStatus::from_raw(signal),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

/// A command that did not finish within its deadline.
pub(crate) fn timed_out(program: &str) -> BoundedCommandError {
    BoundedCommandError::TimedOut {
        program: program.into(),
        timeout: Duration::from_secs(3),
        cleanup: "group kill: ok; child kill: ok; wait: signal: 9 (SIGKILL)".into(),
    }
}
