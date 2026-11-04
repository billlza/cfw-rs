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
use crate::process_identity::{ProcessIdentity, exact_processes, process_identity_exists};

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
    match runs_from_installed_location() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("update installer must run from the installed application");
            return ADMISSION;
        }
        Err(error) => {
            eprintln!("update installer location could not be observed: {error}");
            return ADMISSION;
        }
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
mod tests;
