use std::fs;
use std::path::PathBuf;

use cfw_engine_api::NativeServiceRegistrationStatus;

use super::super::journal::tests::{dashboard, record};
use super::*;

#[derive(Default)]
struct Machine {
    log: Vec<&'static str>,
    dashboard_polls_until_exit: usize,
    dashboard_observation_fails: bool,
    staged_verdict: Option<&'static str>,
    statuses: Vec<ServicePair>,
    status_failure: bool,
    proxy_unregistration: Option<&'static str>,
    authority_unregistration: Option<&'static str>,
    /// The observation (counted from one) from which another dashboard
    /// is running.
    other_dashboard_from: Option<usize>,
    /// The one observation (counted from one) that sees a dashboard
    /// which is gone again at the next.
    passing_dashboard_at: Option<usize>,
    /// The observation (counted from one) from which the dashboard that
    /// handed off is listed again, as a reused process identity would be.
    previous_dashboard_listed_from: Option<usize>,
    /// The observation (counted from one) that cannot be made.
    process_observation_fails_at: Option<usize>,
    process_observations: usize,
    exchange_failure: Option<std::io::ErrorKind>,
    failing_starts: u32,
    /// Starts that `open` reports as successful although nothing runs
    /// afterwards.
    starts_without_a_dashboard: u32,
    /// A dashboard from a successful start is running.
    started: bool,
    waited: Duration,
    /// Where the installation lease lives, to observe who holds it.
    lease_home: Option<PathBuf>,
    lease_held_during: Vec<(&'static str, bool)>,
}

const ENABLED: NativeServiceRegistrationStatus = NativeServiceRegistrationStatus::Enabled;
const ABSENT: NativeServiceRegistrationStatus = NativeServiceRegistrationStatus::NotRegistered;

fn pair(
    proxy_agent: NativeServiceRegistrationStatus,
    global_authority: NativeServiceRegistrationStatus,
) -> ServicePair {
    ServicePair {
        proxy_agent,
        global_authority,
    }
}

/// A dashboard process other than the recorded one (`dashboard()`, PID
/// 4242).
fn dashboard_with_pid(pid: u32) -> ProcessIdentity {
    serde_json::from_value(serde_json::json!({
        "uid": unsafe { libc::geteuid() },
        "pid": pid,
        "start_identity": { "seconds": 1_790_000_000_u64, "microseconds": 7 },
        "executable": "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
    }))
    .expect("dashboard identity")
}

const OTHER_DASHBOARD: u32 = 6000;
const PASSING_DASHBOARD: u32 = 7000;
const STARTED_DASHBOARD: u32 = 5000;

impl Machine {
    /// Both services enabled before, both absent afterwards.
    fn registered() -> Self {
        Self {
            statuses: vec![pair(ABSENT, ABSENT), pair(ENABLED, ENABLED)],
            ..Self::default()
        }
    }

    fn step(&mut self, name: &'static str) {
        self.log.push(name);
        if let Some(home) = &self.lease_home {
            let held = matches!(
                UpdateInstallLease::acquire(home),
                Err(UpdateInstallLeaseError::Held)
            );
            self.lease_held_during.push((name, held));
        }
    }
}

impl FinisherPorts for Machine {
    fn dashboard_running(&mut self, _: &ProcessIdentity) -> Result<bool, String> {
        if self.dashboard_observation_fails {
            return Err("observation failed".into());
        }
        if self.dashboard_polls_until_exit == 0 {
            return Ok(false);
        }
        self.dashboard_polls_until_exit -= 1;
        Ok(true)
    }

    fn wait(&mut self, duration: Duration) {
        self.waited += duration;
    }

    fn verify_staged(&mut self, _: &InstallRecord) -> Result<(), &'static str> {
        self.step("verify");
        self.staged_verdict.map_or(Ok(()), Err)
    }

    fn service_status(&mut self) -> Result<ServicePair, &'static str> {
        self.step("status");
        if self.status_failure {
            return Err("service_status_unavailable");
        }
        Ok(self.statuses.pop().expect("a status was scripted"))
    }

    fn unregister_proxy_agent(&mut self) -> Result<(), &'static str> {
        self.step("unregister-proxy-agent");
        self.proxy_unregistration.map_or(Ok(()), Err)
    }

    fn unregister_global_authority(&mut self) -> Result<(), &'static str> {
        self.step("unregister-global-authority");
        self.authority_unregistration.map_or(Ok(()), Err)
    }

    fn dashboards(&mut self) -> Result<Vec<ProcessIdentity>, String> {
        self.step("processes");
        self.process_observations += 1;
        let observation = self.process_observations;
        if self.process_observation_fails_at == Some(observation) {
            return Err("observation failed".into());
        }
        let mut running = Vec::new();
        if self
            .other_dashboard_from
            .is_some_and(|from| observation >= from)
        {
            running.push(dashboard_with_pid(OTHER_DASHBOARD));
        }
        if self.passing_dashboard_at == Some(observation) {
            running.push(dashboard_with_pid(PASSING_DASHBOARD));
        }
        if self
            .previous_dashboard_listed_from
            .is_some_and(|from| observation >= from)
        {
            running.push(dashboard());
        }
        if self.started {
            running.push(dashboard_with_pid(STARTED_DASHBOARD));
        }
        Ok(running)
    }

    fn exchange_bundles(&mut self) -> Result<(), std::io::ErrorKind> {
        self.step("exchange");
        self.exchange_failure.map_or(Ok(()), Err)
    }

    fn start_application(&mut self) -> Result<(), String> {
        self.step("start");
        if self.failing_starts > 0 {
            self.failing_starts -= 1;
            return Err("launch failed".into());
        }
        if self.starts_without_a_dashboard > 0 {
            self.starts_without_a_dashboard -= 1;
            return Ok(());
        }
        self.started = true;
        Ok(())
    }
}

struct Attempt {
    _home: tempfile::TempDir,
    journal: InstallJournal,
    transaction: Uuid,
    app_home: PathBuf,
}

fn attempt() -> Attempt {
    let home = tempfile::tempdir().expect("app home");
    let journal = InstallJournal::new(home.path());
    journal.begin(&record(21)).expect("hand-off record");
    Attempt {
        app_home: home.path().to_path_buf(),
        _home: home,
        journal,
        transaction: Uuid::from_u128(21),
    }
}

fn finish(attempt: &Attempt, machine: &mut Machine) -> FinishOutcome {
    let lease = UpdateInstallLease::acquire(&attempt.app_home).expect("lease");
    let outcome = finish_installation(&attempt.journal, &attempt.transaction, lease, machine);
    UpdateInstallLease::acquire(&attempt.app_home)
        .expect("the lease is released when the installer returns");
    outcome
}

fn recorded(attempt: &Attempt) -> (InstallPhase, Option<String>) {
    let record = attempt.journal.load().expect("load").expect("record");
    (record.phase, record.failure)
}

const DECOMMISSION: [&str; 7] = [
    "processes",
    "verify",
    "status",
    "unregister-proxy-agent",
    "unregister-global-authority",
    "status",
    "processes",
];
/// One start of the application and the observation that confirms it.
const STARTED: [&str; 2] = ["start", "processes"];

fn steps(prefix: &[&'static str], suffix: &[&'static str]) -> Vec<&'static str> {
    [prefix, suffix].concat()
}

mod dashboard_wait;
mod failure_recovery;
mod record_admission;
mod step_order;
