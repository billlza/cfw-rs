use super::*;

#[test]
fn typed_observations_propagate_timeout_and_output_bounds() {
    let timeout = finish_observation(
        "legacy process table",
        Err(BoundedCommandError::TimedOut {
            program: PROCESS_LIST.into(),
            timeout: OBSERVATION_TIMEOUT,
            cleanup: "terminated and reaped".into(),
        }),
    )
    .expect_err("timeout");
    assert!(timeout.to_string().contains("exceeded its 3000ms timeout"));

    let oversized = finish_observation(
        "legacy TCP listener table",
        Err(BoundedCommandError::OutputExceeded {
            program: TCP_LISTENERS.into(),
            stream: "stdout",
            limit: LISTENER_TABLE_MAX_STDOUT_BYTES,
        }),
    )
    .expect_err("oversized output");
    assert!(oversized.to_string().contains("1048576-byte safety bound"));
}

#[test]
fn an_observation_is_the_trimmed_output_of_a_clean_run() {
    use crate::test_support::exited;

    assert_eq!(
        finish_observation(
            "legacy process table",
            Ok(exited(0, b"\n  501 1 ps\n\n", b"  \n"))
        )
        .expect("observation"),
        "501 1 ps"
    );
    for (output, message) in [
        (
            exited(0, b"\xff", b""),
            "legacy process table stdout is not UTF-8",
        ),
        (
            exited(0, b"", b"\xff"),
            "legacy process table stderr is not UTF-8",
        ),
        (
            exited(1, b"partial", b" ps: illegal option \n"),
            "legacy process table failed with status exit status: 1: ps: illegal option",
        ),
        (
            exited(0, b"501 1 ps", b"ps: warning\n"),
            "legacy process table succeeded with unexpected stderr: ps: warning",
        ),
    ] {
        let error = finish_observation("legacy process table", Ok(output)).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

/// Writes `bytes` copies of `x` to stdout, as one long row of a table.
fn table_of(bytes: usize) -> String {
    format!("head -c {bytes} /dev/zero | tr '\\0' x")
}

#[test]
fn a_busy_macs_process_table_is_read_whole() {
    // `ps` writes whole command lines to a pipe; with browsers, Electron apps
    // and parallel compilers running, one Mac's table measured 2.3 MB.
    let bytes = 4 * 1024 * 1024;
    let table = observe_process_table("/bin/sh", &["-c", &table_of(bytes)])
        .expect("a busy Mac's process table");
    assert_eq!(table.len(), bytes);
}

#[test]
fn a_process_table_past_its_bound_fails_closed() {
    let error = observe_process_table(
        "/bin/sh",
        &["-c", &table_of(PROCESS_TABLE_MAX_STDOUT_BYTES + 1)],
    )
    .expect_err("an unbounded process table");
    assert!(
        error
            .to_string()
            .starts_with("legacy process table failed:")
            && error.to_string().contains(&format!(
                "{PROCESS_TABLE_MAX_STDOUT_BYTES}-byte safety bound"
            )),
        "{error}"
    );
}

#[test]
fn the_process_table_lists_this_process() {
    let table = observe_legacy_process_table().expect("process table");
    let pid = std::process::id().to_string();
    assert!(
        table
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some(pid.as_str())),
        "pid {pid} is missing from the process table"
    );
}

#[test]
fn the_listener_table_is_the_netstat_output_or_hidden() {
    // macOS 27 hides the socket tables from descendants of an ad-hoc signed
    // process, such as this test binary, so netstat prints nothing here. The
    // signed application sees the rows; its caller requires the expected
    // listener, so an empty table fails closed there.
    let table = observe_legacy_tcp_listener_table().expect("listener table");
    assert!(
        table.is_empty() || table.starts_with("Active Internet connections"),
        "{table}"
    );
}
