use std::fmt;
use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Captured output from a deterministic, read-only platform observation.
#[derive(Debug)]
pub(crate) struct BoundedCommandOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum BoundedCommandError {
    Spawn {
        program: String,
        source: std::io::Error,
    },
    PipeUnavailable {
        program: String,
        stream: &'static str,
        cleanup: String,
    },
    Observe {
        program: String,
        source: std::io::Error,
        cleanup: String,
    },
    TimedOut {
        program: String,
        timeout: Duration,
        cleanup: String,
    },
    InvalidTimeout {
        program: String,
        timeout: Duration,
    },
    Read {
        program: String,
        stream: &'static str,
        source: std::io::Error,
    },
    OutputExceeded {
        program: String,
        stream: &'static str,
        limit: usize,
    },
    ReaderPanicked {
        program: String,
        stream: &'static str,
    },
}

impl fmt::Display for BoundedCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, source } => {
                write!(formatter, "failed to execute {program}: {source}")
            }
            Self::PipeUnavailable {
                program,
                stream,
                cleanup,
            } => write!(
                formatter,
                "{program} {stream} pipe was unavailable ({cleanup})"
            ),
            Self::Observe {
                program,
                source,
                cleanup,
            } => write!(
                formatter,
                "failed to observe {program}: {source} ({cleanup})"
            ),
            Self::TimedOut {
                program,
                timeout,
                cleanup,
            } => write!(
                formatter,
                "{program} exceeded its {}ms timeout ({cleanup})",
                timeout.as_millis()
            ),
            Self::InvalidTimeout { program, timeout } => write!(
                formatter,
                "{program} timeout of {}ms exceeds the platform clock range",
                timeout.as_millis()
            ),
            Self::Read {
                program,
                stream,
                source,
            } => write!(formatter, "failed to read {program} {stream}: {source}"),
            Self::OutputExceeded {
                program,
                stream,
                limit,
            } => write!(
                formatter,
                "{program} {stream} exceeded its {limit}-byte safety bound"
            ),
            Self::ReaderPanicked { program, stream } => {
                write!(formatter, "{program} {stream} reader panicked")
            }
        }
    }
}

impl std::error::Error for BoundedCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. }
            | Self::Observe { source, .. }
            | Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Runs an absolute platform tool with closed environment, bounded output, and
/// a hard timeout. Both pipes are drained concurrently so a noisy command
/// cannot deadlock while the parent waits.
pub(crate) fn run_bounded_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
) -> Result<BoundedCommandOutput, BoundedCommandError> {
    let deadline =
        Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| BoundedCommandError::InvalidTimeout {
                program: program.to_owned(),
                timeout,
            })?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| BoundedCommandError::Spawn {
            program: program.to_owned(),
            source,
        })?;

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(BoundedCommandError::PipeUnavailable {
                program: program.to_owned(),
                stream: "stdout",
                cleanup: terminate_and_wait(&mut child),
            });
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err(BoundedCommandError::PipeUnavailable {
                program: program.to_owned(),
                stream: "stderr",
                cleanup: terminate_and_wait(&mut child),
            });
        }
    };

    let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum_stdout_bytes));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, maximum_stderr_bytes));
    let mut exited = None;
    let process_result = loop {
        if exited.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exited = Some(status),
                Ok(None) => {}
                Err(source) => {
                    break Err(BoundedCommandError::Observe {
                        program: program.to_owned(),
                        source,
                        cleanup: terminate_and_wait(&mut child),
                    });
                }
            }
        }
        if stdout_reader.is_finished()
            && stderr_reader.is_finished()
            && let Some(status) = exited
        {
            break Ok(status);
        }
        if Instant::now() >= deadline {
            break Err(BoundedCommandError::TimedOut {
                program: program.to_owned(),
                timeout,
                cleanup: terminate_and_wait(&mut child),
            });
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_reader(program, "stdout", stdout_reader)?;
    let stderr = join_reader(program, "stderr", stderr_reader)?;
    let status = process_result?;
    let stdout = finish_read(program, "stdout", maximum_stdout_bytes, stdout)?;
    let stderr = finish_read(program, "stderr", maximum_stderr_bytes, stderr)?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[derive(Debug)]
struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<BoundedRead, std::io::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) <= limit {
            bytes.extend_from_slice(&buffer[..count]);
        } else {
            exceeded = true;
        }
    }
    Ok(BoundedRead { bytes, exceeded })
}

fn join_reader(
    program: &str,
    stream: &'static str,
    reader: thread::JoinHandle<Result<BoundedRead, std::io::Error>>,
) -> Result<Result<BoundedRead, std::io::Error>, BoundedCommandError> {
    reader
        .join()
        .map_err(|_| BoundedCommandError::ReaderPanicked {
            program: program.to_owned(),
            stream,
        })
}

fn finish_read(
    program: &str,
    stream: &'static str,
    limit: usize,
    read: Result<BoundedRead, std::io::Error>,
) -> Result<Vec<u8>, BoundedCommandError> {
    let read = read.map_err(|source| BoundedCommandError::Read {
        program: program.to_owned(),
        stream,
        source,
    })?;
    if read.exceeded {
        Err(BoundedCommandError::OutputExceeded {
            program: program.to_owned(),
            stream,
            limit,
        })
    } else {
        Ok(read.bytes)
    }
}

fn terminate_and_wait(child: &mut std::process::Child) -> String {
    let group_kill = i32::try_from(child.id()).map_or_else(
        |_| "child pid is outside the process-group range".to_owned(),
        |process_group| {
            let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
            if result == 0 {
                "ok".into()
            } else {
                std::io::Error::last_os_error().to_string()
            }
        },
    );
    let child_kill = child
        .kill()
        .map_or_else(|error| error.to_string(), |()| "ok".into());
    let wait = child
        .wait()
        .map_or_else(|error| error.to_string(), |status| status.to_string());
    format!("group kill: {group_kill}; child kill: {child_kill}; wait: {wait}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_exit_status_and_bounded_streams() {
        let output = run_bounded_command(
            "/bin/sh",
            &["-c", "printf output; printf warning >&2; exit 7"],
            Duration::from_secs(1),
            64,
            64,
        )
        .expect("bounded command output");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"output");
        assert_eq!(output.stderr, b"warning");
    }

    #[test]
    fn rejects_output_after_draining_the_child() {
        let error = run_bounded_command(
            "/bin/sh",
            &[
                "-c",
                "i=0; while [ \"$i\" -lt 32 ]; do printf 12345678; i=$((i+1)); done",
            ],
            Duration::from_secs(1),
            32,
            32,
        )
        .expect_err("oversized stdout must fail");
        assert!(matches!(
            error,
            BoundedCommandError::OutputExceeded {
                stream: "stdout",
                limit: 32,
                ..
            }
        ));
    }

    #[test]
    fn terminates_a_hung_command() {
        let error = run_bounded_command(
            "/bin/sh",
            &["-c", "while :; do :; done"],
            Duration::from_millis(40),
            32,
            32,
        )
        .expect_err("hung command must time out");
        assert!(matches!(error, BoundedCommandError::TimedOut { .. }));
    }

    #[test]
    fn timeout_kills_descendants_that_inherit_output_pipes() {
        let started = Instant::now();
        let error = run_bounded_command(
            "/bin/sh",
            &["-c", "(sleep 5) & while :; do :; done"],
            Duration::from_millis(40),
            32,
            32,
        )
        .expect_err("the complete observation process group must time out");
        assert!(matches!(error, BoundedCommandError::TimedOut { .. }));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "inherited pipes must not extend the hard timeout"
        );
    }

    #[test]
    fn exited_parent_cannot_leave_inherited_pipes_past_the_deadline() {
        let started = Instant::now();
        let error = run_bounded_command(
            "/bin/sh",
            &["-c", "(sleep 5) & exit 0"],
            Duration::from_millis(40),
            32,
            32,
        )
        .expect_err("inherited pipes must remain covered after parent exit");
        assert!(matches!(error, BoundedCommandError::TimedOut { .. }));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "reader completion must remain inside the hard timeout"
        );
    }

    #[test]
    fn rejects_an_unrepresentable_deadline_before_spawning() {
        let error = run_bounded_command("/path/that/must/not/run", &[], Duration::MAX, 0, 0)
            .expect_err("overflowing timeout must fail before spawn");
        assert!(matches!(error, BoundedCommandError::InvalidTimeout { .. }));
    }
}
