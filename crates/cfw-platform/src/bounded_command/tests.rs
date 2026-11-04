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

#[test]
fn only_the_named_variables_join_the_closed_environment() {
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
        (
            BoundedCommandError::ReaderPanicked {
                program: program(),
                stream: "stderr",
            },
            "/bin/tool stderr reader panicked",
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
    let error = run_bounded_command("/nonexistent/cfw-tool", &[], Duration::from_secs(1), 32, 32)
        .expect_err("no such program");
    assert!(
        matches!(&error, BoundedCommandError::Spawn { program, .. } if program == "/nonexistent/cfw-tool"),
        "{error}"
    );
}

#[test]
fn a_stream_that_fails_or_a_reader_that_panics_is_reported() {
    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
    }

    let error =
        finish_read("/bin/tool", "stdout", 8, read_bounded(Failing, 8)).expect_err("a failed read");
    assert_eq!(error.to_string(), "failed to read /bin/tool stdout: closed");

    let reader = thread::spawn(|| -> Result<BoundedRead, std::io::Error> {
        panic!("the reader failed");
    });
    let error = join_reader("/bin/tool", "stderr", reader).expect_err("a panicked reader");
    assert!(matches!(
        error,
        BoundedCommandError::ReaderPanicked {
            stream: "stderr",
            ..
        }
    ));
}
