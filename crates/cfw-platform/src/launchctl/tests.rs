use super::*;
use crate::test_support::{exited, signalled, timed_out};

/// A system job no installation defines. Printing it is a read-only query.
const ABSENT: &str = "system/com.bill.clashformac.coverage-absent";
/// A system job every macOS installation keeps loaded.
const LOADED: &str = "system/com.apple.logd";

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
        .is_missing_bootout_target("system/com.example.missing")
    );
    assert!(
        !failure("bootout system/x", 5, "Boot-out failed: 5").is_missing_bootout_target("system/x")
    );
    assert!(
        !failure("disable system/x", 3, "Boot-out failed: 3: No such process")
            .is_missing_bootout_target("system/x")
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
        .is_missing_print_target("gui/501/com.example.missing")
    );
    assert!(!failure("print gui/501/x", 5, "Load failed: 5").is_missing_print_target("gui/501/x"));
    assert!(!failure("print gui/501/x", 113, "Bad request.").is_missing_print_target("gui/501/x"));
}

#[test]
fn print_missing_result_is_bound_to_the_exact_target() {
    let error = failure(
        "print system/com.example.one",
        113,
        "Bad request.\nCould not find service \"com.example.one\" in domain for system",
    );
    assert!(error.is_missing_print_target("system/com.example.one"));
    assert!(!error.is_missing_print_target("system/com.example.two"));
}

#[test]
fn a_missing_print_result_is_expected_only_for_a_single_label_in_a_known_domain() {
    assert_eq!(
        expected_missing_print_error("system/com.example.one").as_deref(),
        Some("Bad request.\nCould not find service \"com.example.one\" in domain for system")
    );
    assert_eq!(
        expected_missing_print_error("gui/501/com.example.one").as_deref(),
        Some(
            "Bad request.\nCould not find service \"com.example.one\" in domain for user gui: 501"
        )
    );
    for target in [
        "system/",
        "system/com.example/one",
        "gui/501",
        "gui//com.example.one",
        "gui/50x/com.example.one",
        "gui/501/",
        "gui/501/com.example/one",
        "user/501/com.example.one",
    ] {
        assert_eq!(expected_missing_print_error(target), None, "{target}");
    }
}

#[test]
fn the_current_uid_is_this_process_own() {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    assert_eq!(current_uid().expect("uid"), uid.to_string());
}

#[test]
fn a_uid_is_the_decimal_output_of_a_successful_run() {
    assert_eq!(parse_uid(Ok(exited(0, b"501\n", b""))).expect("uid"), "501");
    for (output, message) in [
        (
            exited(1, b"", b"id: illegal option\n"),
            "/usr/bin/id -u failed with status exit status: 1: id: illegal option",
        ),
        (
            exited(0, b"\n", b""),
            "/usr/bin/id -u returned an invalid uid: \"\"",
        ),
        (
            exited(0, b"-1\n", b""),
            "/usr/bin/id -u returned an invalid uid: \"-1\"",
        ),
        (
            exited(0, b"501 20\n", b""),
            "/usr/bin/id -u returned an invalid uid: \"501 20\"",
        ),
    ] {
        let error = parse_uid(Ok(output)).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
    let error = parse_uid(Err(timed_out(ID))).expect_err("a timed-out run");
    assert_eq!(error.to_string(), "failed to run /usr/bin/id -u");
    assert!(
        format!("{error:#}").contains("/usr/bin/id exceeded its 3000ms timeout"),
        "{error:#}"
    );
}

#[test]
fn a_run_succeeds_only_with_a_zero_status_and_silent_diagnostics() {
    assert_eq!(
        finish(
            "version".into(),
            Ok(exited(0, b"Darwin Bootstrapper\n", b" \n"))
        )
        .expect("output"),
        "Darwin Bootstrapper\n"
    );
    for (result, message) in [
        (
            Err(timed_out(LAUNCHCTL)),
            "/bin/launchctl print x failed without an exit status: /bin/launchctl exceeded its 3000ms timeout (group kill: ok; child kill: ok; wait: signal: 9 (SIGKILL))",
        ),
        (
            Ok(signalled(9)),
            "/bin/launchctl print x failed without an exit status",
        ),
        (
            Ok(exited(3, b" partial \n", b" Boot-out failed: 3 \n")),
            "/bin/launchctl print x failed with status 3: Boot-out failed: 3; standard output: partial",
        ),
        (
            Ok(exited(1, b"partial", b"")),
            "/bin/launchctl print x failed with status 1; standard output: partial",
        ),
        (
            Ok(exited(0, b"text\n", b"Warning: deprecated\n")),
            "/bin/launchctl print x failed with status 0: launchctl succeeded with unexpected stderr: Warning: deprecated; standard output: text",
        ),
        (
            Ok(exited(0, b"\xff", b"")),
            "/bin/launchctl print x failed with status 0: launchctl stdout was not valid UTF-8",
        ),
        (
            Ok(exited(0, b"text", b"\xff")),
            "/bin/launchctl print x failed with status 0: launchctl stderr was not valid UTF-8; standard output: text",
        ),
    ] {
        let error = finish("print x".into(), result).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn only_booting_out_a_job_that_is_not_loaded_may_fail() {
    let missing = || failure("bootout system/x", 3, "Boot-out failed: 3: No such process");
    allow_absent(&["bootout", "system/x"], Ok(String::new())).expect("a success");
    allow_absent(&["bootout", "system/x"], Err(missing())).expect("not loaded");
    for args in [
        &["bootout", "system/y"][..],
        &["disable", "system/x"][..],
        &["bootout", "system/x", "extra"][..],
        &["bootout"][..],
    ] {
        let error = allow_absent(args, Err(missing())).expect_err("not this missing job");
        assert_eq!(
            error.to_string(),
            "/bin/launchctl bootout system/x failed with status 3: Boot-out failed: 3: No such process"
        );
    }
    run_allow_absent(&["version"]).expect("a read-only run succeeds");
}

#[test]
fn a_job_that_is_not_defined_prints_as_absent() {
    assert_eq!(print_target(ABSENT).expect("absent"), None);
    ensure_unloaded(ABSENT).expect("an absent job is unloaded");
}

#[test]
fn a_loaded_job_prints_its_description_and_is_not_unloaded() {
    let printed = print_target(LOADED).expect("print").expect("loaded");
    assert!(printed.starts_with(&format!("{LOADED} = {{")), "{printed}");
    let error = ensure_unloaded(LOADED).expect_err("loaded");
    assert_eq!(
        error.to_string(),
        format!("legacy launchd service remains loaded: {LOADED}")
    );
}

#[test]
fn a_malformed_target_is_an_error_not_an_absence() {
    let target = "domain/com.bill.clashformac.coverage-absent";
    let error = print_target(target).expect_err("malformed");
    assert!(
        error.to_string().starts_with(&format!(
            "/bin/launchctl print {target} failed with status 64: Unrecognized target specifier."
        )),
        "{error}"
    );
    let error = run_allow_absent(&["print", target]).expect_err("malformed");
    assert!(error.to_string().contains("status 64"), "{error}");
}
