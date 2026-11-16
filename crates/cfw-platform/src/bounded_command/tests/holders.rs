//! Commands whose descendants hold the output pipes: a holder outside the
//! command's process group, and holders that join the group late.
use super::*;

/// The file in which a test's background holder records itself.
struct HolderRecord(std::path::PathBuf);

impl HolderRecord {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cfw-platform-bounded-command-{name}-{}",
            std::process::id()
        ));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("stale holder record {}: {error}", path.display()),
        }
        Self(path)
    }

    /// Waits up to five seconds for the holder to write `count` lines, and
    /// returns what it has written by then.
    fn lines(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = match std::fs::read_to_string(&self.0) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => panic!("holder record {}: {error}", self.0.display()),
            };
            let lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
            if lines.len() >= count || Instant::now() >= deadline {
                return lines;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn remove(self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove holder record {}: {error}", self.0.display()),
        }
    }
}

/// The process id that a holder recorded on its first line.
fn recorded_pid(lines: &[String]) -> Option<libc::pid_t> {
    lines
        .first()
        .map(|line| line.parse().expect("the holder's process id"))
}

/// Whether the process still exists, waiting up to two seconds for a process
/// that has died to be reaped by its new parent.
fn still_exists(pid: libc::pid_t) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: signal 0 only checks that `pid` exists.
        if unsafe { libc::kill(pid, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ESRCH), "{error}");
            return false;
        }
        if Instant::now() >= deadline {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// How often a timed-out command's group was signalled again and reached a
/// process, as its cleanup reports.
fn signalled_again(cleanup: &str) -> u32 {
    cleanup
        .split("; ")
        .find_map(|part| part.strip_prefix("signalled again: "))
        .expect("the cleanup counts repeated signals")
        .parse()
        .expect("a count of repeated signals")
}

/// A descendant that starts a process group of its own is out of reach of
/// every signal sent to the command's group, yet holds the output pipes. The
/// call must still end at its bound, and say that it closed the pipes itself.
#[test]
fn a_descendant_outside_the_group_cannot_hold_the_call_past_its_bound() {
    let _serial = one_command_at_a_time();
    let record = HolderRecord::new("outside");
    let started = Instant::now();
    let error = run_bounded_command_with_environment(
        "/bin/sh",
        &[
            "-c",
            r#"set -m; /bin/sh -c 'echo $$ > "$HOLDER"; exec /bin/sleep 5' & exec /bin/sleep 5"#,
        ],
        CommandEnvironment::Closed(&[("HOLDER", record.0.as_os_str())]),
        Duration::from_millis(300),
        32,
        32,
    )
    .expect_err("held pipes must end in a timeout");
    let elapsed = started.elapsed();
    let lines = record.lines(1);
    record.remove();
    let holder = recorded_pid(&lines).unwrap_or_else(|| {
        panic!("no holder recorded itself; the call: {error} after {elapsed:?}")
    });
    // SAFETY: signal 0 only checks that the holder exists.
    let running = unsafe { libc::kill(holder, 0) } == 0;
    if running {
        // SAFETY: the holder is this test's own descendant, recorded by itself.
        assert_eq!(
            unsafe { libc::kill(holder, libc::SIGKILL) },
            0,
            "end the holder"
        );
    }
    assert!(
        running,
        "the call waited {elapsed:?} for the holder to exit: {error}"
    );
    assert!(
        cleanup(&error).ends_with("output: still open after the group was signalled; closed here"),
        "{error}"
    );
    let bound = Duration::from_millis(300) + SIGNAL_GRACE + Duration::from_millis(500);
    assert!(elapsed < bound, "{elapsed:?}");
}

/// The command of the joining-holder tests. It starts a holder outside its
/// process group; once the command's own process has ended, by
/// `END_OF_COMMAND`, the holder waits a moment and joins the group. A holder
/// whose join is refused records why and lives on outside the group.
const JOINING_HOLDER: &str = r#"
    pipe(my $death, my $life) or die "pipe: $!";
    my $group = $$;
    defined(my $holder = fork()) or die "fork: $!";
    if ($holder == 0) {
        close($life);
        setpgrp(0, 0) or die "leave: $!";
        open(my $record, ">", $ENV{HOLDER}) or die "record: $!";
        print $record "$$\n";
        close($record) or die "record: $!";
        # End of file arrives when the command's own process has ended.
        sysread($death, my $byte, 1);
        select(undef, undef, undef, 0.1);
        if (!setpgrp(0, $group)) {
            my $refused = "$!";
            open($record, ">>", $ENV{HOLDER}) or die "record: $!";
            print $record "join refused: $refused\n";
            close($record) or die "record: $!";
        }
        sleep 5;
        exit 0;
    }
    close($death);
    END_OF_COMMAND
"#;

/// What a joining-holder command left behind.
struct JoiningRun {
    error: BoundedCommandError,
    elapsed: Duration,
    lines: Vec<String>,
    holder: Option<libc::pid_t>,
    survived: Option<libc::pid_t>,
}

impl JoiningRun {
    fn start(name: &str, end_of_command: &str) -> Self {
        let record = HolderRecord::new(name);
        let program = JOINING_HOLDER.replace("END_OF_COMMAND", end_of_command);
        let started = Instant::now();
        let error = run_bounded_command_with_environment(
            "/usr/bin/perl",
            &["-e", &program],
            CommandEnvironment::Closed(&[("HOLDER", record.0.as_os_str())]),
            Duration::from_millis(300),
            32,
            32,
        )
        .expect_err("the command must time out");
        let elapsed = started.elapsed();
        let holder = recorded_pid(&record.lines(1));
        let survived = holder.filter(|holder| still_exists(*holder));
        if let Some(holder) = survived {
            // SAFETY: the holder is this test's own descendant, recorded by itself.
            assert_eq!(
                unsafe { libc::kill(holder, libc::SIGKILL) },
                0,
                "end the holder"
            );
        }
        // Read again: a refused join is recorded before the holder sleeps.
        let lines = record.lines(1);
        record.remove();
        Self {
            error,
            elapsed,
            lines,
            holder,
            survived,
        }
    }

    /// The holder joined the group and died with the command, and the call
    /// ended inside its bound.
    fn assert_ended_with_the_command(&self) {
        let context = format!(
            "the holder recorded {:?}; the call: {} after {:?}",
            self.lines, self.error, self.elapsed
        );
        assert!(
            self.holder.is_some(),
            "no holder recorded itself: {context}"
        );
        assert_eq!(self.lines.len(), 1, "{context}");
        assert!(
            self.survived.is_none(),
            "the holder outlived the call: {context}"
        );
        assert!(
            cleanup(&self.error).ends_with("output: closed"),
            "{context}"
        );
        let bound = Duration::from_millis(300) + SIGNAL_GRACE + Duration::from_millis(500);
        assert!(self.elapsed < bound, "{context}");
    }
}

/// A member that the group gains after the timeout's first signal stands for
/// a child that the group forks while that signal is delivered, which can
/// escape it. Signalling the group again while the pipes stay open must end
/// it too, so that nothing of the command outlives the call.
#[test]
fn a_member_that_joins_the_group_after_the_first_signal_is_signalled_again() {
    let _serial = one_command_at_a_time();
    let run = JoiningRun::start("joined", "sleep 5;");
    run.assert_ended_with_the_command();
    assert!(signalled_again(cleanup(&run.error)) >= 1, "{}", run.error);
}

/// The command's own process is not reaped while its group may still be
/// signalled, so the group outlives that process: a holder that joins it
/// after the process has exited is a member, and ends at the timeout.
#[test]
fn an_exited_command_keeps_its_group_until_the_group_is_signalled() {
    let _serial = one_command_at_a_time();
    JoiningRun::start("exited", "exit 0;").assert_ended_with_the_command();
}
