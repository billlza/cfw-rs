use super::*;
use std::thread;

/// Serialises the tests that start commands. On macOS std makes a pipe
/// close-on-exec only after `pipe()` has returned, so a command that another
/// thread starts at that moment inherits it: one test's long-lived holder
/// would then keep another test's pipes open.
static COMMANDS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_command_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    COMMANDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn preserves_exit_status_and_bounded_streams() {
    let _serial = one_command_at_a_time();
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
    let _serial = one_command_at_a_time();
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

/// With both pipes at their end, the command itself is still waited for.
#[test]
fn a_command_that_closes_its_output_is_waited_for_until_it_exits() {
    let _serial = one_command_at_a_time();
    let started = Instant::now();
    let output = run_bounded_command(
        "/bin/sh",
        &["-c", "exec >&- 2>&-; /bin/sleep 0.2; exit 3"],
        Duration::from_secs(2),
        32,
        32,
    )
    .expect("the command's exit");
    let elapsed = started.elapsed();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
}

#[test]
fn terminates_a_hung_command() {
    let _serial = one_command_at_a_time();
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
    let _serial = one_command_at_a_time();
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
    let _serial = one_command_at_a_time();
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

fn cleanup(error: &BoundedCommandError) -> &str {
    match error {
        BoundedCommandError::TimedOut { cleanup, .. } => cleanup,
        other => panic!("expected a timeout, got {other}"),
    }
}

mod holders;

/// A command that writes without pause must not keep the call reading past
/// its deadline.
#[test]
fn a_command_that_writes_without_pause_still_times_out() {
    let _serial = one_command_at_a_time();
    let started = Instant::now();
    let error = run_bounded_command("/usr/bin/yes", &[], Duration::from_millis(40), 32, 32)
        .expect_err("endless output must time out");
    let elapsed = started.elapsed();
    assert!(
        cleanup(&error).ends_with("output: closed"),
        "{error} after {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[test]
fn rejects_an_unrepresentable_deadline_before_spawning() {
    let error = run_bounded_command("/path/that/must/not/run", &[], Duration::MAX, 0, 0)
        .expect_err("overflowing timeout must fail before spawn");
    assert!(matches!(error, BoundedCommandError::InvalidTimeout { .. }));
}

#[test]
fn only_the_named_variables_join_the_closed_environment() {
    let _serial = one_command_at_a_time();
    // The test process itself runs with a far larger environment.
    assert!(std::env::vars_os().count() > 4);
    let output = run_bounded_command_with_environment(
        "/usr/bin/env",
        &[],
        CommandEnvironment::Closed(&[("HOME", std::ffi::OsStr::new("/Users/example"))]),
        Duration::from_secs(5),
        1024,
        32,
    )
    .expect("environment listing");
    let mut variables = String::from_utf8(output.stdout)
        .expect("UTF-8 environment")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    variables.sort();
    assert_eq!(
        variables,
        [
            "HOME=/Users/example",
            "LANG=C",
            "LC_ALL=C",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        ]
    );

    let closed = run_bounded_command("/usr/bin/env", &[], Duration::from_secs(5), 1024, 32)
        .expect("environment listing");
    assert!(!String::from_utf8_lossy(&closed.stdout).contains("HOME="));
}

#[test]
fn an_inherited_environment_is_this_process_own_and_nothing_is_forced_into_it() {
    let _serial = one_command_at_a_time();
    let own = std::env::vars()
        .filter(|(name, value)| !name.starts_with("DYLD_") && !value.contains('\n'))
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    assert!(own.iter().any(|variable| variable.starts_with("HOME=")));
    let output = run_bounded_command_with_environment(
        "/usr/bin/env",
        &[],
        CommandEnvironment::Inherited,
        Duration::from_secs(5),
        256 * 1024,
        32,
    )
    .expect("environment listing");
    let listed = String::from_utf8(output.stdout).expect("UTF-8 environment");
    let listed = listed.lines().collect::<Vec<_>>();
    for variable in &own {
        assert!(
            listed.contains(&variable.as_str()),
            "{variable} was not inherited"
        );
    }
    for forced in ["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"] {
        assert_eq!(
            listed.contains(&forced),
            own.iter().any(|variable| variable == forced),
            "{forced}"
        );
    }
}

#[test]
fn every_error_names_its_program_and_cause() {
    let program = || "/bin/tool".to_owned();
    let cleanup = || "group kill: ok".to_owned();
    let broken = || std::io::Error::other("broken");
    for (error, message, has_source) in [
        (
            BoundedCommandError::Spawn {
                program: program(),
                source: broken(),
            },
            "failed to execute /bin/tool: broken",
            true,
        ),
        (
            BoundedCommandError::PipeUnavailable {
                program: program(),
                stream: "stdout",
                cleanup: cleanup(),
            },
            "/bin/tool stdout pipe was unavailable (group kill: ok)",
            false,
        ),
        (
            BoundedCommandError::Observe {
                program: program(),
                source: broken(),
                cleanup: cleanup(),
            },
            "failed to observe /bin/tool: broken (group kill: ok)",
            true,
        ),
        (
            BoundedCommandError::TimedOut {
                program: program(),
                timeout: Duration::from_millis(40),
                cleanup: cleanup(),
            },
            "/bin/tool exceeded its 40ms timeout (group kill: ok)",
            false,
        ),
        (
            BoundedCommandError::InvalidTimeout {
                program: program(),
                timeout: Duration::from_secs(5),
            },
            "/bin/tool timeout of 5000ms exceeds the platform clock range",
            false,
        ),
        (
            BoundedCommandError::Read {
                program: program(),
                stream: "stderr",
                source: broken(),
            },
            "failed to read /bin/tool stderr: broken",
            true,
        ),
        (
            BoundedCommandError::OutputExceeded {
                program: program(),
                stream: "stdout",
                limit: 32,
            },
            "/bin/tool stdout exceeded its 32-byte safety bound",
            false,
        ),
    ] {
        assert_eq!(error.to_string(), message);
        assert_eq!(
            std::error::Error::source(&error).is_some(),
            has_source,
            "{message}"
        );
    }
}

#[test]
fn a_program_that_cannot_start_is_a_spawn_error() {
    let _serial = one_command_at_a_time();
    let error = run_bounded_command("/nonexistent/cfw-tool", &[], Duration::from_secs(1), 32, 32)
        .expect_err("no such program");
    assert!(
        matches!(&error, BoundedCommandError::Spawn { program, .. } if program == "/nonexistent/cfw-tool"),
        "{error}"
    );
}

/// A pipe that gives the stated answers in order, then `WouldBlock`.
struct ScriptedPipe(std::collections::VecDeque<std::io::Result<&'static [u8]>>);

impl Read for ScriptedPipe {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.0.pop_front() {
            None => Err(std::io::ErrorKind::WouldBlock.into()),
            Some(Ok(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            Some(Err(error)) => Err(error),
        }
    }
}

#[test]
fn a_pipe_is_read_until_it_is_empty_ends_or_fails() {
    let mut read = BoundedRead::default();
    let mut waiting = ScriptedPipe(
        [
            Ok(&b"ab"[..]),
            Err(std::io::ErrorKind::Interrupted.into()),
            Ok(&b"c"[..]),
        ]
        .into(),
    );
    let drained = read_available(&mut waiting, &mut read, 8).expect("an empty pipe");
    assert_eq!(
        (drained, read.bytes.as_slice()),
        (Drained::Open, &b"abc"[..])
    );

    let mut ending = ScriptedPipe([Ok(&b"d"[..]), Ok(&b""[..])].into());
    let drained = read_available(&mut ending, &mut read, 8).expect("a pipe at its end");
    assert_eq!(
        (drained, read.bytes.as_slice()),
        (Drained::Ended, &b"abcd"[..])
    );

    let mut failing = ScriptedPipe([Err(std::io::Error::other("closed"))].into());
    let failure = read_available(&mut failing, &mut read, 8).expect_err("a failed read");
    let error = finish_read("/bin/tool", "stdout", 8, Err(failure)).expect_err("reported");
    assert_eq!(error.to_string(), "failed to read /bin/tool stdout: closed");
}

#[test]
fn a_pipe_that_never_empties_is_read_a_bounded_number_of_times_per_wake() {
    struct Endless(usize);

    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0 += 1;
            buffer[0] = b'y';
            Ok(1)
        }
    }

    let mut pipe = Endless(0);
    let mut read = BoundedRead::default();
    let drained = read_available(&mut pipe, &mut read, 4).expect("an endless pipe");
    assert_eq!((drained, pipe.0), (Drained::Open, READS_PER_WAKE));
    assert!(read.exceeded);
    assert_eq!(read.bytes, b"yyyy");
}
