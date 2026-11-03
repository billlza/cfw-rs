use std::os::unix::fs::PermissionsExt as _;

use super::*;

fn authorization(version: &str) -> UpdateAuthorization {
    UpdateAuthorization {
        version: version.to_owned(),
        archive_name: format!("Clash.for.Mac_{version}_aarch64.app.tar.gz"),
        download_url: format!(
            "https://github.com/billlza/cfw-rs/releases/download/v{version}/archive.tar.gz"
        ),
        signature: "signature".to_owned(),
    }
}

#[test]
fn release_page_is_derived_only_from_a_canonical_version() {
    assert_eq!(
        release_page_url(&authorization("0.4.1")).expect("canonical release"),
        "https://github.com/billlza/cfw-rs/releases/tag/v0.4.1"
    );
    for rejected in ["01.4.1", "0.4", "0.4.1+build.1/"] {
        assert!(
            release_page_url(&authorization(rejected)).is_err(),
            "accepted unsafe release version {rejected:?}"
        );
    }
}

#[test]
fn an_installation_outside_applications_reports_why_it_cannot_update_itself() {
    // Test binaries never run from the installed bundle.
    assert_eq!(
        install_support(false),
        serde_json::json!({ "supported": false, "code": "not_in_applications" })
    );
    assert!(!runs_from_installed_location().expect("current executable observed"));
}

#[test]
fn a_release_that_failed_authentication_is_not_offered_for_installation() {
    assert_eq!(
        install_support(true),
        serde_json::json!({
            "supported": false,
            "code": "release_failed_authentication",
        })
    );
}

fn installer(program: &str, argument: &str) -> Child {
    Command::new(program)
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("stand-in installer process")
}

fn stop(mut installer: Child) {
    installer.kill().expect("stop the stand-in installer");
    installer.wait().expect("reap the stand-in installer");
}

#[test]
fn one_passing_probe_of_the_lease_is_not_an_admitted_installer() {
    let mut watch = LeaseWatch::default();
    let observed = [true, false, true, false, false, true, true, true]
        .map(|held| watch.held_by_the_installer(held));
    assert_eq!(
        observed,
        [false, false, false, false, false, false, true, true]
    );
}

#[tokio::test]
async fn the_dashboard_exits_only_for_a_running_installer_that_holds_the_lease() {
    let home = tempfile::tempdir().expect("app home");
    let admitted = UpdateInstallLease::acquire(home.path()).expect("the installer's lease");
    let mut running = installer("/bin/sleep", "30");
    assert_eq!(
        wait_for_installer_admission(&mut running, home.path(), Duration::from_secs(10)).await,
        Ok(())
    );
    stop(running);
    drop(admitted);
}

#[tokio::test]
async fn an_installer_that_never_takes_the_lease_is_not_waited_for_forever() {
    let home = tempfile::tempdir().expect("app home");
    let mut idle = installer("/bin/sleep", "30");
    let waited = Instant::now();
    assert_eq!(
        wait_for_installer_admission(&mut idle, home.path(), Duration::from_millis(300)).await,
        Err("installer process was not admitted in time".into())
    );
    assert!(waited.elapsed() >= Duration::from_millis(300));
    stop(idle);
    UpdateInstallLease::acquire(home.path()).expect("the probe never keeps the lease");
}

#[tokio::test]
async fn an_installer_that_ended_is_not_mistaken_for_an_admitted_one() {
    let home = tempfile::tempdir().expect("app home");
    // Something else holds the lease, as a second installer would.
    let other = UpdateInstallLease::acquire(home.path()).expect("another holder");
    let mut ended = installer("/usr/bin/false", "ignored");
    ended.wait().expect("the stand-in installer ended");
    let verdict =
        wait_for_installer_admission(&mut ended, home.path(), Duration::from_secs(10)).await;
    assert!(
        matches!(&verdict, Err(detail) if detail.contains("ended before it was admitted")),
        "{verdict:?}"
    );
    drop(other);
}

#[test]
fn a_preparation_owns_the_slot_before_its_slow_checks_and_honours_a_cancellation() {
    let source = include_str!("../updater.rs")
        .split("\nmod tests {")
        .next()
        .expect("production source");
    let prepare = source
        .split("async fn prepare_update_install_inner(")
        .nth(1)
        .expect("preparation")
        .split("\n}\n")
        .next()
        .expect("preparation body");
    let order = [
        "admit_running_installation()",
        "ensure_previous_attempt_reviewed(app)",
        ".begin_preparation(&expected_version)",
        "lease.cancellation.cancelled() => return Err(UpdateError::DownloadCancelled)",
        "recheck_presented_update(",
        "security.is_rejected(",
        "require_removable_services",
        "lease.cancellation.is_cancelled()",
        "StagingArea::create(",
        "stage_release(",
    ]
    .map(|step| {
        prepare
            .find(step)
            .unwrap_or_else(|| panic!("{step} is part of the preparation"))
    });
    assert!(
        order.is_sorted(),
        "the steps of a preparation are out of order: {order:?}"
    );
    assert!(
        prepare.contains("tokio::select! {\n        biased;"),
        "the cancellation is checked before each poll of the recheck"
    );
}

#[test]
fn the_hand_off_opens_the_installer_log_before_it_owns_the_lifecycle() {
    let source = include_str!("macos_install.rs")
        .split("\nmod tests {")
        .next()
        .expect("production source");
    let hand_off = source
        .split("async fn hand_off(")
        .nth(1)
        .expect("hand-off")
        .split("\n}\n")
        .next()
        .expect("hand-off body");
    let order = [
        "require_removable_services",
        "open_installer_log(&app_home)",
        "begin_update_lifecycle(app)",
        "journal\n        .begin(",
        "prepare_update_exit(app, &mut lifecycle).await",
    ]
    .map(|step| {
        hand_off
            .find(step)
            .unwrap_or_else(|| panic!("{step} is part of the hand-off"))
    });
    assert!(order.is_sorted(), "{order:?}");
    let opening = source
        .split("fn open_installer_log(")
        .nth(1)
        .expect("log opening")
        .split("\n}\n")
        .next()
        .expect("log opening body");
    assert!(opening.contains(".mode(0o600)"));
    assert!(opening.contains(".custom_flags(libc::O_NOFOLLOW)"));
    assert!(opening.contains(".append(!outgrown)"));
}

#[test]
fn the_installer_log_is_appended_to_until_it_outgrows_its_bound_and_never_a_link() {
    let home = tempfile::tempdir().expect("app home");
    let path = home.path().join(INSTALLER_LOG);
    {
        use std::io::Write as _;
        let mut log = open_installer_log(home.path()).expect("new log");
        log.write_all(b"first\n").expect("write");
    }
    {
        use std::io::Write as _;
        let mut log = open_installer_log(home.path()).expect("existing log");
        log.write_all(b"second\n").expect("write");
    }
    assert_eq!(std::fs::read(&path).expect("log"), b"first\nsecond\n");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let oversized = vec![b'x'; INSTALLER_LOG_LIMIT as usize + 1];
    std::fs::write(&path, &oversized).expect("outgrown log");
    {
        use std::io::Write as _;
        let mut log = open_installer_log(home.path()).expect("log started over");
        log.write_all(b"third\n").expect("write");
    }
    assert_eq!(std::fs::read(&path).expect("log"), b"third\n");

    std::fs::remove_file(&path).expect("remove");
    let elsewhere = home.path().join("elsewhere");
    std::fs::write(&elsewhere, b"").expect("target");
    std::os::unix::fs::symlink(&elsewhere, &path).expect("link in place");
    assert!(open_installer_log(home.path()).is_err());
    assert_eq!(std::fs::read(&elsewhere).expect("untouched"), b"");
}

#[test]
fn nothing_can_fail_out_of_the_hand_off_once_the_core_is_stopped() {
    let source = include_str!("macos_install.rs")
        .split("\nmod tests {")
        .next()
        .expect("production source");
    let hand_off = source
        .split("async fn hand_off(")
        .nth(1)
        .expect("hand-off")
        .split("\n}\n")
        .next()
        .expect("hand-off body");
    let (before, after) = hand_off
        .split_once("prepare_update_exit(app, &mut lifecycle).await")
        .expect("the core is stopped inside the hand-off");
    assert!(before.contains("journal\n        .begin("));
    let after = after
        .split_once("// From here the core is Off")
        .expect("the point of no return is marked")
        .1;
    assert!(
        !after.contains('?'),
        "a propagated error would leave a stopped application running: {after}"
    );
    assert!(
        after.contains("engine_stop_reported_error"),
        "a shutdown error with the core Off is recorded, not propagated"
    );
    assert!(after.contains("HandOff::Started"));
    assert!(after.contains("HandOff::InstallerDidNotStart"));
}

#[test]
fn the_installer_is_started_only_as_its_exact_mode_with_a_private_log() {
    // The installation is split between the updater root and its macOS
    // module; together they start exactly one process.
    let source = [
        include_str!("../updater.rs"),
        include_str!("macos_install.rs"),
    ]
    .map(|file| {
        file.split("\nmod tests {")
            .next()
            .expect("production source")
    })
    .concat();
    let spawn = source
        .split("fn spawn_installer")
        .nth(1)
        .expect("installer spawn")
        .split("\n}\n")
        .next()
        .expect("installer spawn body");
    assert!(spawn.contains("ReleaseSignedComponent::MainExecutable.path()"));
    assert!(spawn.contains(".arg(FINISH_UPDATE_FLAG)"));
    assert!(spawn.contains(".process_group(0)"));
    assert!(spawn.contains("Stdio::from(log"));
    assert_eq!(source.matches("Command::new(").count(), 1);
    assert_eq!(
        source.matches("spawn_installer(").count(),
        2,
        "the installer is started from exactly one place"
    );
}
