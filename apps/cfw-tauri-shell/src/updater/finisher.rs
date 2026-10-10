//! The out-of-process half of an installation.
//!
//! The dashboard records the hand-off, stops the core and starts this mode of
//! its own executable; it exits once this process holds the installation
//! lease. From here no window or renderer code runs: the installer unregisters
//! the background services through the same maintenance entry points the
//! release tooling uses, exchanges the bundles atomically, and starts the new
//! application. Whatever ends the attempt, the user gets an application back.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Duration;

use cfw_platform::{ReleaseSignedComponent, open_installed_application, operating_system_version};
use uuid::Uuid;

use super::admission::{BundleIdentity, read_bundle_identity, runs_from_installed_location};
use super::journal::{
    InstallJournal, InstallPhase, InstallRecord, UpdateInstallLease, UpdateInstallLeaseError,
};
use super::services::{self, ServicePair};
use super::staged_bundle::{StagedExpectation, verify_staged_bundle};
use super::staging::StagingArea;
use crate::legacy::{ProcessIdentity, exact_processes, process_identity_exists};

pub(crate) const FINISH_UPDATE_FLAG: &str = "--finish-update-v1";

const DASHBOARD_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const DASHBOARD_EXIT_POLL: Duration = Duration::from_millis(100);
/// LaunchServices can refuse a bundle for a moment right after it changed.
const START_ATTEMPTS: u32 = 3;
const START_RETRY_DELAY: Duration = Duration::from_secs(2);
/// How long after `open` returned a started dashboard must still be running:
/// `open` reports success for an application that ended right away.
const START_CONFIRMATION_DELAY: Duration = Duration::from_secs(2);
/// A dashboard that is refused the lease ends within moments; only one seen
/// on two observations this far apart is running beside the installer.
const REOBSERVATION_DELAY: Duration = Duration::from_millis(500);
const LEASE_ATTEMPTS: u32 = 50;
const LEASE_RETRY_DELAY: Duration = Duration::from_millis(100);
/// The new application is installed but could not be started.
const EXIT_INSTALLED_NOT_STARTED: i32 = 69;
/// The attempt was aborted and its reason recorded.
const EXIT_ABORTED: i32 = 70;

/// How an installation attempt ended in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FinishOutcome {
    /// The new bundle is installed and was started.
    Installed,
    /// The new bundle is installed but could not be started automatically.
    InstalledNotStarted,
    /// The installed application was not replaced. The code is recorded.
    Aborted(&'static str),
    /// The record could not be read or advanced; nothing was exchanged.
    RecordUnavailable,
}

/// Everything the installer does to the machine, so each step and each failure
/// can be exercised without a signed installation.
pub(super) trait FinisherPorts {
    fn dashboard_running(&mut self, dashboard: &ProcessIdentity) -> Result<bool, String>;
    fn wait(&mut self, duration: Duration);
    fn verify_staged(&mut self, record: &InstallRecord) -> Result<(), &'static str>;
    fn service_status(&mut self) -> Result<ServicePair, &'static str>;
    fn unregister_proxy_agent(&mut self) -> Result<(), &'static str>;
    fn unregister_global_authority(&mut self) -> Result<(), &'static str>;
    /// Every dashboard process of this user other than this installer.
    fn dashboards(&mut self) -> Result<Vec<ProcessIdentity>, String>;
    fn exchange_bundles(&mut self) -> Result<(), std::io::ErrorKind>;
    fn start_application(&mut self) -> Result<(), String>;
}

/// Runs one recorded transaction to its end.
///
/// Every step before the exchange can fail and leaves the installed
/// application untouched. The lease is held until the exchange is over or the
/// attempt is aborted, so no dashboard starts underneath either; it is
/// released before an application is started, because a dashboard refuses to
/// start while it is held.
pub(super) fn finish_installation(
    journal: &InstallJournal,
    transaction: &Uuid,
    lease: UpdateInstallLease,
    ports: &mut impl FinisherPorts,
) -> FinishOutcome {
    let record = match journal.load() {
        Ok(Some(record))
            if record.transaction == *transaction && record.phase == InstallPhase::HandedOff =>
        {
            record
        }
        unusable => {
            match unusable {
                Ok(_) => eprintln!("update installation record does not name this hand-off"),
                Err(error) => eprintln!("update installation record is unreadable: {error}"),
            }
            // The dashboard exits once this process holds the lease, so the
            // unchanged application is started again even without a record.
            drop(lease);
            restart_unchanged_application(None, ports);
            return FinishOutcome::RecordUnavailable;
        }
    };
    let dashboard = &record.dashboard;

    if let Err(code) = decommission(&record, ports) {
        return abort_installation(journal, transaction, code, lease, dashboard, ports);
    }
    if let Err(error) = journal.advance(
        transaction,
        InstallPhase::HandedOff,
        InstallPhase::Decommissioned,
    ) {
        eprintln!("update installation record could not be advanced: {error}");
        let code = "record_write_failed";
        return abort_installation(journal, transaction, code, lease, dashboard, ports);
    }
    if let Err(kind) = ports.exchange_bundles() {
        eprintln!("application bundles could not be exchanged ({kind:?})");
        let code = "exchange_failed";
        return abort_installation(journal, transaction, code, lease, dashboard, ports);
    }
    // The exchange is done and cannot be undone here. If this write fails,
    // the next launch still recognizes the outcome by the version it runs.
    if let Err(error) = journal.advance(
        transaction,
        InstallPhase::Decommissioned,
        InstallPhase::Swapped,
    ) {
        eprintln!("the completed exchange could not be recorded: {error}");
    }

    drop(lease);
    match start_application(Some(dashboard), ports) {
        Ok(()) => FinishOutcome::Installed,
        Err(error) => {
            eprintln!("the updated application could not be started: {error}");
            FinishOutcome::InstalledNotStarted
        }
    }
}

/// Everything that must hold before the bundles may be exchanged, in order.
/// A failure names the reason the attempt is aborted with.
fn decommission(
    record: &InstallRecord,
    ports: &mut impl FinisherPorts,
) -> Result<(), &'static str> {
    wait_for_dashboard_exit(&record.dashboard, ports)?;
    // A second copy that was already running keeps using the services.
    require_no_other_dashboard(ports)?;
    ports.verify_staged(record)?;
    decommission_services(ports)?;
    // Nothing may have started that would register the services again
    // underneath the exchange.
    require_no_other_dashboard(ports)
}

fn abort_installation(
    journal: &InstallJournal,
    transaction: &Uuid,
    code: &'static str,
    lease: UpdateInstallLease,
    dashboard: &ProcessIdentity,
    ports: &mut impl FinisherPorts,
) -> FinishOutcome {
    let recorded = journal.abort(transaction, code);
    if let Err(error) = &recorded {
        eprintln!("the aborted update installation could not be recorded: {error}");
    }
    drop(lease);
    restart_unchanged_application(Some(dashboard), ports);
    match recorded {
        Ok(_) => FinishOutcome::Aborted(code),
        Err(_) => FinishOutcome::RecordUnavailable,
    }
}

/// Starts the application that was not replaced, so an aborted attempt never
/// leaves the user without it.
fn restart_unchanged_application(
    previous: Option<&ProcessIdentity>,
    ports: &mut impl FinisherPorts,
) {
    if let Err(error) = start_application(previous, ports) {
        eprintln!("the application could not be restarted after an aborted update: {error}");
    }
}

/// Starts the installed application and confirms that a dashboard runs
/// afterwards. `open` reports success for an application that ended right
/// away, and for one that still runs it only brings that one forward: the
/// dashboard that handed off, while it is still on its way out, is therefore
/// never opened and never counts as the started application.
fn start_application(
    previous: Option<&ProcessIdentity>,
    ports: &mut impl FinisherPorts,
) -> Result<(), String> {
    let mut attempt = 1;
    loop {
        match start_once(previous, ports) {
            Ok(()) => return Ok(()),
            Err(error) if attempt == START_ATTEMPTS => return Err(error),
            Err(error) => {
                eprintln!("starting the application failed (attempt {attempt}): {error}");
                ports.wait(START_RETRY_DELAY);
                attempt += 1;
            }
        }
    }
}

fn start_once(
    previous: Option<&ProcessIdentity>,
    ports: &mut impl FinisherPorts,
) -> Result<(), String> {
    if let Some(previous) = previous
        && ports.dashboard_running(previous)?
    {
        return Err("the dashboard that handed off is still running".into());
    }
    ports.start_application()?;
    ports.wait(START_CONFIRMATION_DELAY);
    if ports
        .dashboards()?
        .iter()
        .any(|dashboard| Some(dashboard) != previous)
    {
        return Ok(());
    }
    Err("no dashboard is running after the application was opened".into())
}

fn wait_for_dashboard_exit(
    dashboard: &ProcessIdentity,
    ports: &mut impl FinisherPorts,
) -> Result<(), &'static str> {
    let mut waited = Duration::ZERO;
    loop {
        match ports.dashboard_running(dashboard) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(error) => {
                eprintln!("the dashboard process could not be observed: {error}");
                return Err("process_observation_failed");
            }
        }
        if waited >= DASHBOARD_EXIT_TIMEOUT {
            return Err("dashboard_still_running");
        }
        ports.wait(DASHBOARD_EXIT_POLL);
        waited += DASHBOARD_EXIT_POLL;
    }
}

/// No dashboard may run beside the installer. One that was just refused the
/// lease is gone within moments, so only a dashboard still present on a second
/// observation counts.
fn require_no_other_dashboard(ports: &mut impl FinisherPorts) -> Result<(), &'static str> {
    let first = observe_dashboards(ports)?;
    if first.is_empty() {
        return Ok(());
    }
    ports.wait(REOBSERVATION_DELAY);
    let second = observe_dashboards(ports)?;
    if second.iter().any(|dashboard| first.contains(dashboard)) {
        return Err("application_reopened");
    }
    Ok(())
}

fn observe_dashboards(
    ports: &mut impl FinisherPorts,
) -> Result<Vec<ProcessIdentity>, &'static str> {
    ports.dashboards().map_err(|error| {
        eprintln!("running applications could not be observed: {error}");
        "process_observation_failed"
    })
}

/// Brings both background services to NotRegistered, in the order the release
/// installer uses: the agent while the authority can still prove the engine
/// Off, then the authority.
fn decommission_services(ports: &mut impl FinisherPorts) -> Result<(), &'static str> {
    let before = ports.service_status()?;
    if !before.removable() {
        return Err("services_not_in_a_removable_state");
    }
    if !before.dormant() {
        ports.unregister_proxy_agent()?;
        ports.unregister_global_authority()?;
    }
    if !ports.service_status()?.dormant() {
        return Err("services_still_registered");
    }
    Ok(())
}

/// Runs the installer mode named by `--finish-update-v1 <transaction>` and
/// returns the process exit code.
///
/// Until this process holds the lease the dashboard is still waiting for it:
/// a failure before that point only has to end this process, and the
/// dashboard restarts itself.
pub(crate) fn run(transaction: &str) -> i32 {
    const USAGE: i32 = crate::launch::STARTUP_USAGE_EXIT_CODE;
    const ADMISSION: i32 = crate::launch::STARTUP_ADMISSION_EXIT_CODE;

    let Some(transaction) = Uuid::parse_str(transaction)
        .ok()
        .filter(|parsed| parsed.hyphenated().to_string() == transaction)
    else {
        eprintln!("update installer requires one canonical transaction identifier");
        return USAGE;
    };
    if !runs_from_installed_location() {
        eprintln!("update installer must run from the installed application");
        return ADMISSION;
    }
    let app_home = match crate::settings_store() {
        Ok(store) => store.paths().app_home.clone(),
        Err(error) => {
            eprintln!("update installer cannot locate application data: {error}");
            return ADMISSION;
        }
    };
    let lease = match acquire_lease(&app_home, LEASE_ATTEMPTS, LEASE_RETRY_DELAY) {
        Ok(lease) => lease,
        Err(error) => {
            eprintln!("update installer was not admitted: {error}");
            return ADMISSION;
        }
    };
    let journal = InstallJournal::new(&app_home);
    let mut ports = InstalledApplication {
        staging: StagingArea::path(&app_home, &transaction),
    };
    match finish_installation(&journal, &transaction, lease, &mut ports) {
        FinishOutcome::Installed => 0,
        FinishOutcome::InstalledNotStarted => EXIT_INSTALLED_NOT_STARTED,
        FinishOutcome::Aborted(code) => {
            eprintln!("update installation was aborted: {code}");
            EXIT_ABORTED
        }
        FinishOutcome::RecordUnavailable => ADMISSION,
    }
}

/// Takes the installation lease. A dashboard probes it when it starts and
/// while it waits for this process; such a holder is gone within moments, so
/// a held lease is retried for a bounded time before it means that another
/// installation is in progress.
fn acquire_lease(
    app_home: &Path,
    attempts: u32,
    retry_delay: Duration,
) -> Result<UpdateInstallLease, UpdateInstallLeaseError> {
    let mut attempt = 1;
    loop {
        match UpdateInstallLease::acquire(app_home) {
            Err(UpdateInstallLeaseError::Held) if attempt < attempts => {
                std::thread::sleep(retry_delay);
                attempt += 1;
            }
            admission => return admission,
        }
    }
}

/// The real machine: the installed bundle, its maintenance modes and the
/// staging area of this transaction.
struct InstalledApplication {
    staging: StagingArea,
}

impl FinisherPorts for InstalledApplication {
    fn dashboard_running(&mut self, dashboard: &ProcessIdentity) -> Result<bool, String> {
        process_identity_exists(dashboard)
    }

    fn wait(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn verify_staged(&mut self, record: &InstallRecord) -> Result<(), &'static str> {
        let installed = read_bundle_identity(ReleaseSignedComponent::Application.path())
            .map_err(|_| "installed_identity_invalid")?;
        let from = BundleIdentity {
            version: record.from.version.clone(),
            build: record.from.build,
        };
        if installed != from {
            return Err("installed_application_changed");
        }
        let system_version =
            operating_system_version().map_err(|_| "system_version_unavailable")?;
        let staged = verify_staged_bundle(
            &self.staging.bundle(),
            StagedExpectation {
                version: &record.to.version,
                installed_build: installed.build,
                system_version: &system_version,
            },
        )
        .map_err(|error| error.code())?;
        if staged.build != record.to.build {
            return Err("staged_bundle_changed");
        }
        Ok(())
    }

    fn service_status(&mut self) -> Result<ServicePair, &'static str> {
        services::status().map_err(logged("service_status_unavailable"))
    }

    fn unregister_proxy_agent(&mut self) -> Result<(), &'static str> {
        services::unregister_proxy_agent().map_err(logged("proxy_agent_unregistration_failed"))
    }

    fn unregister_global_authority(&mut self) -> Result<(), &'static str> {
        services::unregister_global_authority()
            .map_err(logged("global_authority_unregistration_failed"))
    }

    fn dashboards(&mut self) -> Result<Vec<ProcessIdentity>, String> {
        // After the exchange this process runs from the replaced bundle, so
        // it is told apart by its process, not by its executable's path.
        let mut processes = exact_processes(ReleaseSignedComponent::MainExecutable.path())?;
        processes.retain(|process| !process.is_this_process());
        Ok(processes)
    }

    fn exchange_bundles(&mut self) -> Result<(), std::io::ErrorKind> {
        exchange_directories(
            &self.staging.bundle(),
            ReleaseSignedComponent::Application.path(),
        )
    }

    fn start_application(&mut self) -> Result<(), String> {
        open_installed_application().map_err(|error| error.to_string())
    }
}

/// Keeps the detail of a failed maintenance step in the installer log and
/// reduces it to the stable code the record carries.
fn logged(code: &'static str) -> impl Fn(String) -> &'static str {
    move |detail| {
        eprintln!("{detail}");
        code
    }
}

/// Atomically exchanges two directories on one volume. Afterwards each path
/// names what the other named before; there is no intermediate state.
fn exchange_directories(staged: &Path, installed: &Path) -> Result<(), std::io::ErrorKind> {
    let c_path = |path: &Path| {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| std::io::ErrorKind::InvalidInput)
    };
    let staged_path = c_path(staged)?;
    let installed_path = c_path(installed)?;
    // SAFETY: both strings are NUL-terminated and live for the call, and
    // AT_FDCWD requires no descriptor ownership.
    let status = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            staged_path.as_ptr(),
            libc::AT_FDCWD,
            installed_path.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error().kind());
    }
    // Durability only: the exchange is already visible, and the next launch
    // recognizes either durable outcome by the version it runs.
    for directory in [staged.parent(), installed.parent()].into_iter().flatten() {
        if let Err(error) = std::fs::File::open(directory).and_then(|file| file.sync_all()) {
            eprintln!("directory sync after the bundle exchange failed: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
