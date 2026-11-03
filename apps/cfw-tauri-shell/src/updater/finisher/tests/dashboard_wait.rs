//! The finisher waits for the dashboard that handed off to end, and tells a
//! reopened application from the one it replaces.

use super::*;

#[test]
fn the_installer_waits_for_the_dashboard_and_gives_up_without_touching_anything() {
    let attempt = attempt();
    let mut machine = Machine {
        dashboard_polls_until_exit: 3,
        ..Machine::registered()
    };
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.waited,
        DASHBOARD_EXIT_POLL * 3 + START_CONFIRMATION_DELAY
    );

    for (mut stuck, code) in [
        (
            Machine {
                dashboard_polls_until_exit: usize::MAX,
                ..Machine::registered()
            },
            "dashboard_still_running",
        ),
        (
            Machine {
                dashboard_observation_fails: true,
                ..Machine::registered()
            },
            "process_observation_failed",
        ),
    ] {
        let attempt = self::attempt();
        assert_eq!(finish(&attempt, &mut stuck), FinishOutcome::Aborted(code));
        assert!(
            stuck.log.is_empty(),
            "nothing runs beside a dashboard that may still be running, and it is not opened: {:?}",
            stuck.log
        );
        assert!(!stuck.started);
        assert!(
            stuck.waited
                <= DASHBOARD_EXIT_TIMEOUT
                    + DASHBOARD_EXIT_POLL
                    + START_RETRY_DELAY * (START_ATTEMPTS - 1)
        );
        assert_eq!(
            recorded(&attempt),
            (InstallPhase::Aborted, Some(code.into()))
        );
    }
}

#[test]
fn a_dashboard_seen_only_once_is_not_a_reopened_application() {
    for (passing_at, extra) in [(1, 1), (2, 7)] {
        let attempt = attempt();
        let mut machine = Machine {
            passing_dashboard_at: Some(passing_at),
            ..Machine::registered()
        };
        assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
        let mut expected = DECOMMISSION.to_vec();
        expected.insert(extra, "processes");
        assert_eq!(
            machine.log,
            steps(&steps(&expected, &["exchange"]), &STARTED),
            "a second observation decides"
        );
        assert_eq!(
            machine.waited,
            REOBSERVATION_DELAY + START_CONFIRMATION_DELAY
        );
    }
}

#[test]
fn an_opened_application_that_is_not_running_afterwards_is_started_again() {
    let attempt = attempt();
    let mut machine = Machine {
        starts_without_a_dashboard: 1,
        ..Machine::registered()
    };
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.log,
        steps(
            &steps(&DECOMMISSION, &["exchange"]),
            &[STARTED, STARTED].concat()
        )
    );
    assert_eq!(
        machine.waited,
        START_CONFIRMATION_DELAY * 2 + START_RETRY_DELAY
    );
    assert!(machine.started);
}

#[test]
fn the_dashboard_that_handed_off_never_counts_as_the_started_application() {
    let attempt = attempt();
    let mut machine = Machine {
        previous_dashboard_listed_from: Some(3),
        starts_without_a_dashboard: START_ATTEMPTS,
        ..Machine::registered()
    };
    assert_eq!(
        finish(&attempt, &mut machine),
        FinishOutcome::InstalledNotStarted
    );
    assert_eq!(
        machine.log.iter().filter(|step| **step == "start").count(),
        START_ATTEMPTS as usize
    );

    let attempt = self::attempt();
    let mut machine = Machine {
        previous_dashboard_listed_from: Some(3),
        ..Machine::registered()
    };
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.log.iter().filter(|step| **step == "start").count(),
        1,
        "a dashboard other than the previous one confirms the start"
    );
}
