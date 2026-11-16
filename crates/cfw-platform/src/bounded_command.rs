use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How often a running command is checked and, once it has timed out, how
/// often its process group is signalled again while the output pipes are open.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// How long a timed-out process group has to die and close the output pipes.
/// Whatever holds them longer is outside the group, and they are closed here.
const SIGNAL_GRACE: Duration = Duration::from_millis(500);
/// The most read from one pipe before the deadline is checked again, so a
/// command that writes without pause cannot keep the call reading.
const READS_PER_WAKE: usize = 16;

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
/// a hard timeout. Both pipes are drained while the command runs, so a noisy
/// command cannot deadlock while the parent waits, and the call returns by the
/// timeout plus at most [`SIGNAL_GRACE`] whatever the command's descendants do.
pub(crate) fn run_bounded_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
) -> Result<BoundedCommandOutput, BoundedCommandError> {
    run_bounded_command_with_environment(
        program,
        args,
        CommandEnvironment::Closed(&[]),
        timeout,
        maximum_stdout_bytes,
        maximum_stderr_bytes,
    )
}

/// What a bounded command sees of this process's environment.
#[derive(Clone, Copy)]
pub(crate) enum CommandEnvironment<'a> {
    /// The fixed defaults and the named variables; nothing else of the
    /// caller's environment reaches the child.
    Closed(&'a [(&'a str, &'a std::ffi::OsStr)]),
    /// This process's own environment, unchanged: for a command that starts
    /// something meant to live in the user's session, not in a tool's.
    Inherited,
}

/// Like [`run_bounded_command`], with the stated environment.
pub(crate) fn run_bounded_command_with_environment(
    program: &str,
    args: &[&str],
    environment: CommandEnvironment<'_>,
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
    let mut command = Command::new(program);
    command.args(args);
    if let CommandEnvironment::Closed(additions) = environment {
        command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .envs(additions.iter().copied());
    }
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| BoundedCommandError::Spawn {
            program: program.to_owned(),
            source,
        })?;

    let mut pipes = match OutputPipes::take(&mut child, maximum_stdout_bytes, maximum_stderr_bytes)
    {
        Ok(pipes) => pipes,
        Err(PipeSetup::Unavailable(stream)) => {
            return Err(BoundedCommandError::PipeUnavailable {
                program: program.to_owned(),
                stream,
                cleanup: terminate(&mut child, None),
            });
        }
        Err(PipeSetup::Failed(source)) => {
            return Err(BoundedCommandError::Observe {
                program: program.to_owned(),
                source,
                cleanup: terminate(&mut child, None),
            });
        }
    };
    let status = loop {
        // The command has finished once both pipes have ended and its own
        // process has exited, and its exit is checked only then. Reaping it
        // earlier would let the id of its process group be reused while the
        // group may still have to be signalled, and each check takes the
        // kernel's process list lock, which streaming output would otherwise
        // take thousands of times a second.
        if pipes.closed() {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(source) => {
                    return Err(BoundedCommandError::Observe {
                        program: program.to_owned(),
                        source,
                        cleanup: terminate(&mut child, Some(&mut pipes)),
                    });
                }
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(BoundedCommandError::TimedOut {
                program: program.to_owned(),
                timeout,
                cleanup: terminate(&mut child, Some(&mut pipes)),
            });
        }
        if let Err(source) = pipes.wait(POLL_INTERVAL.min(deadline - now)) {
            return Err(BoundedCommandError::Observe {
                program: program.to_owned(),
                source,
                cleanup: terminate(&mut child, Some(&mut pipes)),
            });
        }
    };

    let OutputPipes { stdout, stderr } = pipes;
    let stdout = stdout.finish(program)?;
    let stderr = stderr.finish(program)?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

/// Ends the command's process group and reports how, for the error message.
///
/// The command's own process is reaped last: until then its id, which is the
/// group's id, cannot be reused, so signalling the group again cannot reach
/// anything but the command's own processes. A child that the group forks
/// while the first signal is delivered can escape it, so the group is
/// signalled again while the output pipes stay open, for at most
/// [`SIGNAL_GRACE`]. Pipes still open after that are held by a process outside
/// the group, and are closed on this side; nothing waits for that process.
fn terminate(child: &mut Child, pipes: Option<&mut OutputPipes>) -> String {
    let group = libc::pid_t::try_from(child.id()).ok();
    let group_kill = group.map_or_else(
        || "child pid is outside the process-group range".to_owned(),
        |group| outcome(signal_group(group)),
    );
    let child_kill = outcome(child.kill());
    let mut signalled_again = 0_u32;
    let output = match pipes {
        None => "not opened".to_owned(),
        Some(pipes) => {
            let grace_ends = Instant::now() + SIGNAL_GRACE;
            loop {
                if pipes.closed() {
                    break "closed".to_owned();
                }
                let now = Instant::now();
                if now >= grace_ends {
                    pipes.close();
                    break "still open after the group was signalled; closed here".to_owned();
                }
                if let Err(error) = pipes.wait(POLL_INTERVAL.min(grace_ends - now)) {
                    pipes.close();
                    break format!("unreadable ({error}); closed here");
                }
                if !pipes.closed()
                    && let Some(group) = group
                    && signal_group(group).is_ok()
                {
                    signalled_again += 1;
                }
            }
        }
    };
    let wait = child
        .wait()
        .map_or_else(|error| error.to_string(), |status| status.to_string());
    format!(
        "group kill: {group_kill}; child kill: {child_kill}; signalled again: {signalled_again}; wait: {wait}; output: {output}"
    )
}

fn signal_group(group: libc::pid_t) -> io::Result<()> {
    // SAFETY: kill only sends a signal. `-group` names the command's own
    // process group, whose id its unreaped leader keeps reserved.
    if unsafe { libc::kill(-group, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn outcome(result: io::Result<()>) -> String {
    result.map_or_else(|error| error.to_string(), |()| "ok".to_owned())
}

/// Why the command's output pipes could not be read.
enum PipeSetup {
    Unavailable(&'static str),
    Failed(io::Error),
}

/// The command's stdout and stderr, read by the calling thread without
/// blocking, so that nothing reading them can outlive the call.
struct OutputPipes {
    stdout: OutputPipe,
    stderr: OutputPipe,
}

impl OutputPipes {
    fn take(
        child: &mut Child,
        maximum_stdout_bytes: usize,
        maximum_stderr_bytes: usize,
    ) -> Result<Self, PipeSetup> {
        let stdout = child
            .stdout
            .take()
            .ok_or(PipeSetup::Unavailable("stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or(PipeSetup::Unavailable("stderr"))?;
        Ok(Self {
            stdout: OutputPipe::new("stdout", stdout.into(), maximum_stdout_bytes)
                .map_err(PipeSetup::Failed)?,
            stderr: OutputPipe::new("stderr", stderr.into(), maximum_stderr_bytes)
                .map_err(PipeSetup::Failed)?,
        })
    }

    fn closed(&self) -> bool {
        self.stdout.file.is_none() && self.stderr.file.is_none()
    }

    /// Waits until a pipe has data or has reached end of file, or until `wait`
    /// has passed, then reads what the pipes hold.
    fn wait(&mut self, wait: Duration) -> io::Result<()> {
        // A closed pipe's entry holds -1, which poll ignores.
        let mut entries = [self.stdout.poll_entry(), self.stderr.poll_entry()];
        let timeout =
            libc::c_int::try_from(wait.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX);
        // SAFETY: `entries` holds the two pollfd values that the count names,
        // for descriptors this value owns; poll only writes their revents.
        if unsafe { libc::poll(entries.as_mut_ptr(), 2, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        self.stdout.drain();
        self.stderr.drain();
        Ok(())
    }

    fn close(&mut self) {
        self.stdout.file = None;
        self.stderr.file = None;
    }
}

/// One output pipe of the command.
struct OutputPipe {
    stream: &'static str,
    limit: usize,
    /// `None` once the pipe reached end of file, failed, or was closed here.
    file: Option<File>,
    read: BoundedRead,
    failure: Option<io::Error>,
}

impl OutputPipe {
    fn new(stream: &'static str, descriptor: OwnedFd, limit: usize) -> io::Result<Self> {
        set_nonblocking(&descriptor)?;
        Ok(Self {
            stream,
            limit,
            file: Some(File::from(descriptor)),
            read: BoundedRead::default(),
            failure: None,
        })
    }

    fn poll_entry(&self) -> libc::pollfd {
        libc::pollfd {
            fd: self.file.as_ref().map_or(-1, |file| file.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        }
    }

    fn drain(&mut self) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        match read_available(file, &mut self.read, self.limit) {
            Ok(Drained::Open) => {}
            Ok(Drained::Ended) => self.file = None,
            Err(error) => {
                self.failure = Some(error);
                self.file = None;
            }
        }
    }

    fn finish(self, program: &str) -> Result<Vec<u8>, BoundedCommandError> {
        let read = self.failure.map_or(Ok(self.read), Err);
        finish_read(program, self.stream, self.limit, read)
    }
}

fn set_nonblocking(descriptor: &OwnedFd) -> io::Result<()> {
    let descriptor = descriptor.as_raw_fd();
    // SAFETY: fcntl reads the status flags of a descriptor this process owns.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above, adding O_NONBLOCK to the flags just read.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Drained {
    Open,
    Ended,
}

#[derive(Debug, Default)]
struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl BoundedRead {
    fn absorb(&mut self, chunk: &[u8], limit: usize) {
        if self.bytes.len().saturating_add(chunk.len()) <= limit {
            self.bytes.extend_from_slice(chunk);
        } else {
            self.exceeded = true;
        }
    }
}

/// Reads what `reader` holds now, at most [`READS_PER_WAKE`] times. A
/// non-blocking pipe answers `WouldBlock` once it is empty.
fn read_available(
    reader: &mut impl Read,
    read: &mut BoundedRead,
    limit: usize,
) -> io::Result<Drained> {
    let mut buffer = [0_u8; 4096];
    for _ in 0..READS_PER_WAKE {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(Drained::Ended),
            Ok(count) => read.absorb(&buffer[..count], limit),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(Drained::Open),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Drained::Open)
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

#[cfg(test)]
mod tests;
