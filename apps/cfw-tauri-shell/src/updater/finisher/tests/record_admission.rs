//! The finisher acts only on the record of its own transaction and phase, under
//! a lease it can hold, and refuses a malformed invocation.

use super::*;

#[test]
fn a_record_that_stopped_naming_the_transaction_never_lets_the_exchange_happen() {
    /// Replaces the record underneath the installer once the services
    /// are gone, as another process clearing and reusing it would.
    struct RecordReplaced<'a> {
        machine: Machine,
        journal: &'a InstallJournal,
        transaction: Uuid,
    }

    impl FinisherPorts for RecordReplaced<'_> {
        fn dashboard_running(&mut self, dashboard: &ProcessIdentity) -> Result<bool, String> {
            self.machine.dashboard_running(dashboard)
        }
        fn wait(&mut self, duration: Duration) {
            self.machine.wait(duration);
        }
        fn verify_staged(&mut self, record: &InstallRecord) -> Result<(), &'static str> {
            self.machine.verify_staged(record)
        }
        fn service_status(&mut self) -> Result<ServicePair, &'static str> {
            self.machine.service_status()
        }
        fn unregister_proxy_agent(&mut self) -> Result<(), &'static str> {
            self.machine.unregister_proxy_agent()
        }
        fn unregister_global_authority(&mut self) -> Result<(), &'static str> {
            self.journal.clear(&self.transaction).expect("clear");
            self.journal.begin(&record(77)).expect("another hand-off");
            self.machine.unregister_global_authority()
        }
        fn dashboards(&mut self) -> Result<Vec<ProcessIdentity>, String> {
            self.machine.dashboards()
        }
        fn exchange_bundles(&mut self) -> Result<(), std::io::ErrorKind> {
            self.machine.exchange_bundles()
        }
        fn start_application(&mut self) -> Result<(), String> {
            self.machine.start_application()
        }
    }

    let attempt = attempt();
    let mut ports = RecordReplaced {
        machine: Machine::registered(),
        journal: &attempt.journal,
        transaction: attempt.transaction,
    };
    let lease = UpdateInstallLease::acquire(&attempt.app_home).expect("lease");
    assert_eq!(
        finish_installation(&attempt.journal, &attempt.transaction, lease, &mut ports),
        FinishOutcome::RecordUnavailable,
        "neither the advance nor the abort can be recorded"
    );
    assert_eq!(ports.machine.log, steps(&DECOMMISSION, &STARTED));
    assert_eq!(
        attempt.journal.load().expect("load"),
        Some(record(77)),
        "a record of another attempt is never rewritten"
    );
}

#[test]
fn a_record_for_another_transaction_or_phase_is_never_acted_on() {
    let attempt = attempt();
    let mut machine = Machine::registered();
    let lease = UpdateInstallLease::acquire(&attempt.app_home).expect("lease");
    assert_eq!(
        finish_installation(&attempt.journal, &Uuid::from_u128(99), lease, &mut machine),
        FinishOutcome::RecordUnavailable
    );
    assert_eq!(
        machine.log, STARTED,
        "the unchanged application is started and nothing else is done"
    );

    attempt
        .journal
        .abort(&attempt.transaction, "earlier")
        .expect("already aborted");
    let mut machine = Machine::registered();
    assert_eq!(
        finish(&attempt, &mut machine),
        FinishOutcome::RecordUnavailable
    );
    assert_eq!(machine.log, STARTED);
    assert_eq!(
        recorded(&attempt),
        (InstallPhase::Aborted, Some("earlier".into()))
    );

    let empty = tempfile::tempdir().expect("empty home");
    let lease = UpdateInstallLease::acquire(empty.path()).expect("lease");
    let mut machine = Machine::registered();
    assert_eq!(
        finish_installation(
            &InstallJournal::new(empty.path()),
            &Uuid::from_u128(21),
            lease,
            &mut machine
        ),
        FinishOutcome::RecordUnavailable
    );
    assert_eq!(machine.log, STARTED);
}

#[test]
fn a_briefly_held_lease_is_retried_and_a_lasting_one_refuses_the_installer() {
    let home = tempfile::tempdir().expect("app home");
    let probe = UpdateInstallLease::acquire(home.path()).expect("a dashboard probe");
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        drop(probe);
    });
    let admitted = acquire_lease(home.path(), 200, Duration::from_millis(10));
    release.join().expect("probe thread");
    let lease = admitted.expect("admitted once the probe is gone");

    assert_eq!(
        acquire_lease(home.path(), 3, Duration::from_millis(1)).map(|_| ()),
        Err(UpdateInstallLeaseError::Held),
        "another installation holds the lease for good"
    );
    drop(lease);
}

#[test]
fn a_malformed_transaction_argument_is_a_usage_error() {
    for argument in [
        "x",
        "",
        "00000000-0000-0000-0000-00000000002",
        "00000000000000000000000000000021",
        "00000000-0000-0000-0000-00000000002A",
    ] {
        assert_eq!(
            run(argument),
            crate::launch::STARTUP_USAGE_EXIT_CODE,
            "{argument:?}"
        );
    }
    // A test binary never is the installed application.
    assert_eq!(
        run("00000000-0000-0000-0000-000000000021"),
        crate::launch::STARTUP_ADMISSION_EXIT_CODE
    );
}
