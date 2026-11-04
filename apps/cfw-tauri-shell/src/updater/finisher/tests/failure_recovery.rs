//! Failures before and at the exchange leave or restore a working
//! application, and starting it is retried before it is given up.

use super::*;

#[test]
fn every_failure_before_the_exchange_leaves_the_application_and_restarts_it() {
    let cases: Vec<(&str, Machine, Vec<&str>)> = vec![
        (
            "application_reopened",
            Machine {
                other_dashboard_from: Some(1),
                ..Machine::registered()
            },
            vec!["processes", "processes"],
        ),
        (
            "process_observation_failed",
            Machine {
                process_observation_fails_at: Some(1),
                ..Machine::registered()
            },
            vec!["processes"],
        ),
        (
            "bundle_signature_rejected",
            Machine {
                staged_verdict: Some("bundle_signature_rejected"),
                ..Machine::registered()
            },
            vec!["processes", "verify"],
        ),
        (
            "service_status_unavailable",
            Machine {
                status_failure: true,
                ..Machine::registered()
            },
            vec!["processes", "verify", "status"],
        ),
        (
            "services_not_in_a_removable_state",
            Machine {
                statuses: vec![pair(
                    ENABLED,
                    NativeServiceRegistrationStatus::RequiresApproval,
                )],
                ..Machine::default()
            },
            vec!["processes", "verify", "status"],
        ),
        (
            "services_not_in_a_removable_state",
            Machine {
                statuses: vec![pair(ENABLED, ABSENT)],
                ..Machine::default()
            },
            vec!["processes", "verify", "status"],
        ),
        (
            "proxy_agent_unregistration_failed",
            Machine {
                proxy_unregistration: Some("proxy_agent_unregistration_failed"),
                ..Machine::registered()
            },
            DECOMMISSION[..4].to_vec(),
        ),
        (
            "global_authority_unregistration_failed",
            Machine {
                authority_unregistration: Some("global_authority_unregistration_failed"),
                ..Machine::registered()
            },
            DECOMMISSION[..5].to_vec(),
        ),
        (
            "services_still_registered",
            Machine {
                statuses: vec![pair(ABSENT, ENABLED), pair(ENABLED, ENABLED)],
                ..Machine::default()
            },
            DECOMMISSION[..6].to_vec(),
        ),
        (
            "application_reopened",
            Machine {
                other_dashboard_from: Some(2),
                ..Machine::registered()
            },
            steps(&DECOMMISSION, &["processes"]),
        ),
        (
            "process_observation_failed",
            Machine {
                process_observation_fails_at: Some(2),
                ..Machine::registered()
            },
            DECOMMISSION.to_vec(),
        ),
    ];
    for (code, mut machine, before_restart) in cases {
        let attempt = attempt();
        assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Aborted(code));
        assert_eq!(machine.log, steps(&before_restart, &STARTED), "{code}");
        assert!(machine.started, "{code}: the application runs again");
        assert_eq!(
            recorded(&attempt),
            (InstallPhase::Aborted, Some(code.into())),
            "{code}"
        );
    }
}

#[test]
fn a_failed_exchange_is_recorded_after_decommissioning_and_restarts_the_old_application() {
    let attempt = attempt();
    let mut machine = Machine {
        exchange_failure: Some(std::io::ErrorKind::PermissionDenied),
        ..Machine::registered()
    };
    assert_eq!(
        finish(&attempt, &mut machine),
        FinishOutcome::Aborted("exchange_failed")
    );
    assert_eq!(
        machine.log,
        steps(&steps(&DECOMMISSION, &["exchange"]), &STARTED)
    );
    assert!(machine.started);
    assert_eq!(
        recorded(&attempt),
        (InstallPhase::Aborted, Some("exchange_failed".into()))
    );
}

#[test]
fn starting_the_application_is_retried_before_it_is_given_up() {
    let attempt = attempt();
    let mut machine = Machine {
        failing_starts: START_ATTEMPTS - 1,
        ..Machine::registered()
    };
    assert_eq!(finish(&attempt, &mut machine), FinishOutcome::Installed);
    assert_eq!(
        machine.log.iter().filter(|step| **step == "start").count(),
        START_ATTEMPTS as usize
    );
    assert_eq!(
        machine.waited,
        START_RETRY_DELAY * (START_ATTEMPTS - 1) + START_CONFIRMATION_DELAY
    );
}

#[test]
fn a_completed_exchange_stays_recorded_when_the_application_cannot_be_started() {
    let attempt = attempt();
    let mut machine = Machine {
        failing_starts: START_ATTEMPTS,
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
    assert_eq!(recorded(&attempt), (InstallPhase::Swapped, None));
}
