//! The finisher's steps in order: decommissioning, the exchange and the start,
//! the installation lease over every step up to the exchange, and the
//! directory exchange itself.

use super::*;

#[test]
fn a_registered_installation_is_decommissioned_exchanged_and_started_in_order() {
    let attempt = attempt();
    let mut machine = Machine::registered();
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.log,
        steps(&steps(&DECOMMISSION, &["exchange"]), &STARTED)
    );
    assert_eq!(recorded(&attempt), (InstallPhase::Swapped, None));
    assert!(machine.started);
}

#[test]
fn the_lease_covers_every_step_up_to_the_exchange_and_no_started_application() {
    let installed = attempt();
    let mut machine = Machine {
        lease_home: Some(installed.app_home.clone()),
        ..Machine::registered()
    };
    assert_eq!(finish(&installed, &mut machine), FinishOutcome::Installed);
    let expected = steps(&DECOMMISSION, &["exchange"])
        .into_iter()
        .map(|step| (step, true))
        .chain([("start", false), ("processes", false)])
        .collect::<Vec<_>>();
    assert_eq!(machine.lease_held_during, expected);

    let aborted = attempt();
    let mut machine = Machine {
        lease_home: Some(aborted.app_home.clone()),
        exchange_failure: Some(std::io::ErrorKind::PermissionDenied),
        ..Machine::registered()
    };
    assert_eq!(
        finish(&aborted, &mut machine),
        FinishOutcome::Aborted("exchange_failed")
    );
    let (before_start, from_start) = machine
        .lease_held_during
        .split_at(machine.lease_held_during.len() - 2);
    assert_eq!(
        from_start,
        [("start", false), ("processes", false)],
        "a dashboard refuses to start while the lease is held"
    );
    assert!(before_start.iter().all(|(_, held)| *held));
}

#[test]
fn services_that_were_never_registered_are_not_touched() {
    let attempt = attempt();
    let mut machine = Machine {
        statuses: vec![pair(ABSENT, ABSENT), pair(ABSENT, ABSENT)],
        ..Machine::default()
    };
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.log,
        [
            "processes",
            "verify",
            "status",
            "status",
            "processes",
            "exchange",
            "start",
            "processes"
        ]
    );
}

#[test]
fn exchanging_directories_swaps_their_contents_atomically_and_keeps_both() {
    let scratch = tempfile::tempdir().expect("scratch");
    let staged = scratch.path().join("staging/payload/Clash for Mac.app");
    let installed = scratch.path().join("Applications/Clash for Mac.app");
    fs::create_dir_all(staged.join("Contents")).expect("staged bundle");
    fs::create_dir_all(installed.join("Contents")).expect("installed bundle");
    fs::write(staged.join("Contents/version"), b"new").expect("new version");
    fs::write(installed.join("Contents/version"), b"old").expect("old version");

    exchange_directories(&staged, &installed).expect("exchange");
    assert_eq!(
        fs::read(installed.join("Contents/version")).expect("installed"),
        b"new"
    );
    assert_eq!(
        fs::read(staged.join("Contents/version")).expect("retained"),
        b"old"
    );

    fs::remove_dir_all(&staged).expect("remove retained bundle");
    assert_eq!(
        exchange_directories(&staged, &installed),
        Err(std::io::ErrorKind::NotFound)
    );
    assert_eq!(
        fs::read(installed.join("Contents/version")).expect("untouched"),
        b"new",
        "a failed exchange leaves the installed bundle as it was"
    );
}
