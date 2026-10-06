mod admission;
mod archive;
mod contract;
mod download;
mod error;
mod finisher;
mod journal;
mod metadata;
mod outcome;
mod services;
mod staged_bundle;
mod staging;
mod state;

use std::fs::File;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cfw_core::DiagnosticTopic;
use cfw_platform::{ReleaseSignedComponent, operating_system_version};
use semver::Version;
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

use crate::commands::open_trusted_external_url;
use crate::legacy::{current_process_identity, process_identity_exists};
use crate::lifecycle::{begin_update_lifecycle, prepare_update_exit};
use admission::{
    BundleIdentity, InstallAdmissionError, admit_running_installation, runs_from_installed_location,
};
use archive::extract_bundle;
use contract::UpdateAuthorization;
use download::download_verified_archive;
use error::{FailureCategory, Result, UpdateError, UpdateFailure};
use journal::{InstallJournal, InstallRecord, UpdateInstallLeaseError};
use metadata::check_bounded_update;
use outcome::{InstallOutcome, ReviewError, review_previous_attempt};
use services::require_removable_services;
use staged_bundle::{StagedBundleError, StagedExpectation, verify_staged_bundle};
use staging::StagingArea;
use state::{Cancelled, DownloadCancellation, StagedUpdate};

pub(crate) use finisher::{FINISH_UPDATE_FLAG, run as run_update_finisher};
pub(crate) use journal::UpdateInstallLease;
pub(crate) use state::UpdaterSecurityState;

const RELEASE_PAGE_PREFIX: &str = "https://github.com/billlza/cfw-rs/releases/tag/v";
const PROGRESS_EVENT: &str = "cfw://update-progress";
const INSTALLER_LOG: &str = "update-installer.log";
/// Earlier attempts stay in the installer log until it outgrows this.
const INSTALLER_LOG_LIMIT: u64 = 1024 * 1024;
/// Lets the renderer receive the hand-off result before the window closes.
const EXIT_AFTER_HANDOFF: Duration = Duration::from_millis(250);
/// The installer waits for this process to end before it touches anything
/// and gives the attempt up if the wait is in vain. An exit that hangs in the
/// window teardown must not be the reason, so the process ends by then.
const EXIT_DEADLINE: Duration = Duration::from_secs(5);
/// How long the installer process may take to hold the installation lease.
const INSTALLER_ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);
const INSTALLER_ADMISSION_POLL: Duration = Duration::from_millis(50);

#[tauri::command]
pub(crate) async fn check_for_updates(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, String> {
    check_for_updates_inner(app)
        .await
        .map_err(|error| error.to_string())
}

async fn check_for_updates_inner(app: AppHandle) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let _serialized_check = security.try_serialize_checks()?;
    security.clear_authorization()?;
    let update = check_bounded_update().await?;
    let payload = match update {
        Some(update) => {
            security.authorize(update.authorization.clone())?;
            serde_json::json!({
                "available": true,
                "current": env!("CARGO_PKG_VERSION"),
                "version": update.authorization.version,
                "notes": update.notes,
                "date": update.publication_date,
                "install": install_support(security.is_rejected(&update.authorization)?),
            })
        }
        None => serde_json::json!({
            "available": false,
            "current": env!("CARGO_PKG_VERSION"),
        }),
    };
    if app.emit("cfw://update-available", payload.clone()).is_err() {
        security.clear_authorization()?;
        return Err(UpdateError::ProgressEvent);
    }
    Ok(payload)
}

/// Whether this installation can install the presented release itself, so
/// the renderer offers the in-app installation only where it can succeed.
fn install_support(release_rejected: bool) -> serde_json::Value {
    let refusal = if release_rejected {
        Some(UpdateError::ReleaseRejected.failure().code)
    } else {
        admission_refusal().err().map(|error| error.failure().code)
    };
    match refusal {
        None => serde_json::json!({ "supported": true }),
        Some(code) => serde_json::json!({ "supported": false, "code": code }),
    }
}

/// Everything that refuses an installation before anything is downloaded:
/// the running bundle's identity and location, and the volume the staged
/// release would have to share with it.
fn admission_refusal() -> Result<()> {
    admit_running_installation()?;
    if !staging::on_installed_volume(&app_home()?, ReleaseSignedComponent::Application.path())? {
        return Err(InstallAdmissionError::StagingVolumeMismatch.into());
    }
    Ok(())
}

/// Opens the exact GitHub release page authorized by the update metadata.
///
/// This remains available beside the in-app installation: it is the only path
/// for an installation that cannot replace itself, and always an explicit user
/// choice.
#[tauri::command]
pub(crate) async fn open_available_update(
    app: AppHandle,
    expected_version: String,
) -> std::result::Result<serde_json::Value, String> {
    open_available_update_inner(app, expected_version)
        .await
        .map_err(|error| error.to_string())
}

async fn open_available_update_inner(
    app: AppHandle,
    expected_version: String,
) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let update = recheck_presented_update(&security, &expected_version).await?;
    if security.is_rejected(&update)? {
        // Its download page offers the same release that failed authentication.
        return Err(UpdateError::ReleaseRejected);
    }
    let release_url = release_page_url(&update)?;
    open_trusted_external_url(&release_url).map_err(|_| UpdateError::OpenReleasePage)?;
    Ok(serde_json::json!({
        "opened": true,
        "installed": false,
        "version": update.version,
    }))
}

/// Confirms that the release the user was shown is still the published one
/// and consumes the authorization. Every action therefore needs a fresh check
/// and can never replay metadata that changed after it was presented.
async fn recheck_presented_update(
    security: &UpdaterSecurityState,
    expected_version: &str,
) -> Result<UpdateAuthorization> {
    let _serialized_check = security.try_serialize_checks()?;
    let authorized = security.authorization(expected_version)?;
    let update = match check_bounded_update().await {
        Ok(Some(update)) => update,
        Ok(None) => {
            security.clear_authorization()?;
            return Err(UpdateError::AuthorizationChanged);
        }
        Err(error) => {
            security.clear_authorization()?;
            return Err(error);
        }
    };
    security.consume_if_current(&authorized, &update.authorization)?;
    Ok(update.authorization)
}

fn release_page_url(authorization: &UpdateAuthorization) -> Result<String> {
    let parsed =
        Version::parse(&authorization.version).map_err(|_| UpdateError::InvalidReleaseVersion)?;
    if parsed.to_string() != authorization.version {
        return Err(UpdateError::InvalidReleaseVersion);
    }
    Ok(format!("{RELEASE_PAGE_PREFIX}{}", authorization.version))
}

/// Downloads, authenticates and stages the presented release. The core keeps
/// running; nothing changes outside the private staging area.
#[tauri::command]
pub(crate) async fn prepare_update_install(
    app: AppHandle,
    expected_version: String,
) -> std::result::Result<serde_json::Value, UpdateFailure> {
    prepare_update_install_inner(&app, expected_version)
        .await
        .map_err(|error| report(&app, &error))
}

async fn prepare_update_install_inner(
    app: &AppHandle,
    expected_version: String,
) -> Result<serde_json::Value> {
    let security = app.state::<UpdaterSecurityState>();
    let installed = admit_running_installation()?;
    ensure_previous_attempt_reviewed(app).await?;
    // The slot is claimed before anything slow runs, so a cancellation during
    // the checks below reaches this preparation instead of finding nothing.
    let lease = security.begin_preparation(&expected_version)?;
    let authorization = tokio::select! {
        biased;
        () = lease.cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
        rechecked = recheck_presented_update(&security, &expected_version) => rechecked?,
    };
    if security.is_rejected(&authorization)? {
        return Err(UpdateError::ReleaseRejected);
    }
    blocking(require_removable_services).await??;
    if lease.cancellation.is_cancelled() {
        return Err(UpdateError::DownloadCancelled);
    }
    let transaction = Uuid::new_v4();
    let staging = StagingArea::create(
        &app_home()?,
        &transaction,
        ReleaseSignedComponent::Application.path(),
    )?;

    let staged = stage_release(
        app,
        &authorization,
        &staging,
        &installed,
        &lease.cancellation,
    )
    .await;
    let recorded = staged.and_then(|staged| {
        lease.stage(StagedUpdate {
            transaction,
            installed,
            staged: staged.clone(),
        })?;
        Ok(staged)
    });
    match recorded {
        Ok(staged) => Ok(serde_json::json!({ "version": staged.version })),
        Err(error) => {
            if error.failure().category == FailureCategory::Authenticity {
                security.reject_release(&authorization)?;
            }
            if let Err(removal) = staging.remove() {
                // The next review removes what is left. The user is told why
                // the preparation failed, not that its leftovers remain.
                crate::diagnostics::record(
                    app,
                    DiagnosticTopic::Update,
                    "staging_discard_failed",
                    &format!("{:?}", removal.kind()),
                );
            }
            Err(error)
        }
    }
}

async fn stage_release(
    app: &AppHandle,
    authorization: &UpdateAuthorization,
    staging: &StagingArea,
    installed: &BundleIdentity,
    cancellation: &DownloadCancellation,
) -> Result<BundleIdentity> {
    let version = authorization.version.as_str();
    emit_progress(app, "downloading", version, 0, None)?;
    let archive = staging.archive();
    let mut last_percent = None;
    download_verified_archive(
        authorization,
        &archive,
        cancellation,
        |downloaded, total| {
            let percent = total
                .filter(|total| *total > 0)
                .map(|total| downloaded.saturating_mul(100) / total);
            if percent.is_some() && last_percent == percent {
                return Ok(());
            }
            last_percent = percent;
            emit_progress(app, "downloading", version, downloaded, total)
        },
    )
    .await?;
    if cancellation.is_cancelled() {
        return Err(UpdateError::DownloadCancelled);
    }

    emit_progress(app, "verifying", version, 0, None)?;
    let payload = staging.payload();
    let expected_version = version.to_owned();
    let installed_build = installed.build;
    let staged = blocking(move || -> Result<BundleIdentity> {
        let bundle = extract_bundle(&archive, &payload)?;
        std::fs::remove_file(&archive).map_err(|error| UpdateError::Staging {
            stage: "remove-archive",
            kind: error.kind(),
        })?;
        let system_version =
            operating_system_version().map_err(|_| StagedBundleError::SystemVersionUnavailable)?;
        Ok(verify_staged_bundle(
            &bundle,
            StagedExpectation {
                version: &expected_version,
                installed_build,
                system_version: &system_version,
            },
        )?)
    })
    .await??;
    if cancellation.is_cancelled() {
        return Err(UpdateError::DownloadCancelled);
    }
    Ok(staged)
}

/// Stops a running download or discards a staged release, and says which.
#[tauri::command]
pub(crate) async fn cancel_update_install(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, UpdateFailure> {
    cancel_update_install_inner(&app).map_err(|error| report(&app, &error))
}

fn cancel_update_install_inner(app: &AppHandle) -> Result<serde_json::Value> {
    let app_home = app_home()?;
    let cancelled = match app.state::<UpdaterSecurityState>().cancel_install()? {
        Cancelled::Nothing => "nothing",
        Cancelled::Preparation => "preparation",
        Cancelled::Staged(transaction) => {
            // The release is no longer staged either way; the next review
            // removes what a failed removal left.
            if let Err(removal) = StagingArea::path(&app_home, &transaction).remove() {
                crate::diagnostics::record(
                    app,
                    DiagnosticTopic::Update,
                    "staging_discard_failed",
                    &format!("{:?}", removal.kind()),
                );
            }
            "staged"
        }
    };
    Ok(serde_json::json!({ "cancelled": cancelled }))
}

/// Installs the staged release: stops the core, hands the installation to the
/// installer process and exits. The installer starts the new application.
///
/// A failure is returned only while the application still runs normally; the
/// release then stays staged. Once the core is stopped this process ends
/// either way.
#[tauri::command]
pub(crate) async fn commit_update_install(
    app: AppHandle,
    expected_version: String,
) -> std::result::Result<serde_json::Value, UpdateFailure> {
    let commit = app
        .state::<UpdaterSecurityState>()
        .begin_commit(&expected_version)
        .map_err(|error| report(&app, &error))?;
    match hand_off(&app, commit.staged()).await {
        Ok(HandOff::Started) => {
            let version = commit.staged().staged.version.clone();
            commit.handed_off();
            let exiting = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(EXIT_AFTER_HANDOFF).await;
                exiting.exit(0);
            });
            std::thread::spawn(|| {
                std::thread::sleep(EXIT_DEADLINE);
                eprintln!(
                    "the dashboard did not exit after the update hand-off; ending the process"
                );
                std::process::exit(0);
            });
            Ok(serde_json::json!({ "version": version }))
        }
        Ok(HandOff::InstallerDidNotStart(error)) => {
            // The core is stopped and this process may only exit. Start the
            // unchanged application again; it reports the recorded failure.
            report(&app, &error);
            commit.handed_off();
            app.restart()
        }
        Err(error) => Err(report(&app, &error)),
    }
}

enum HandOff {
    Started,
    /// The core is already stopped for exit, but no installer process holds
    /// the installation. The attempt is recorded as aborted when possible.
    InstallerDidNotStart(UpdateError),
}

async fn hand_off(app: &AppHandle, staged: &StagedUpdate) -> Result<HandOff> {
    if admit_running_installation()? != staged.installed {
        return Err(InstallAdmissionError::InstalledIdentityInvalid.into());
    }
    blocking(require_removable_services).await??;
    let app_home = app_home()?;
    // Opened while the application still runs normally: a log that cannot
    // be opened refuses the installation instead of ending the process.
    let log =
        open_installer_log(&app_home).map_err(|error| UpdateError::InstallerLog(error.kind()))?;
    // Owned only from here, so quitting is not refused during the checks above.
    let mut lifecycle = begin_update_lifecycle(app).map_err(UpdateError::Lifecycle)?;
    let dashboard = current_process_identity(ReleaseSignedComponent::MainExecutable.path())
        .map_err(UpdateError::ProcessIdentity)?;
    let journal = InstallJournal::new(&app_home);
    journal
        .begin(&InstallRecord::handed_off(
            staged.transaction,
            &staged.installed,
            &staged.staged,
            dashboard,
        ))
        .map_err(UpdateError::Journal)?;

    let shutdown_warning = match prepare_update_exit(app, &mut lifecycle).await {
        Ok(warning) => warning,
        Err(error) => {
            let stopping = UpdateError::EngineStop(error);
            return Err(match journal.clear(&staged.transaction) {
                Ok(()) => stopping,
                Err(clearing) => {
                    report(app, &stopping);
                    UpdateError::Journal(clearing)
                }
            });
        }
    };

    // From here the core is Off under a retained reservation and the
    // lifecycle only permits exit: every outcome ends this process.
    if let Some(warning) = shutdown_warning {
        crate::diagnostics::record(
            app,
            DiagnosticTopic::Update,
            "engine_stop_reported_error",
            &format!("the core is Off but its shutdown reported an error: {warning}"),
        );
    }
    Ok(
        match start_installer(&app_home, &staged.transaction, log).await {
            Ok(()) => HandOff::Started,
            Err(detail) => {
                if let Err(error) = journal.abort(&staged.transaction, "installer_start_failed") {
                    // The next launch then reports the attempt as interrupted.
                    report(app, &UpdateError::Journal(error));
                }
                HandOff::InstallerDidNotStart(UpdateError::InstallerStart(detail))
            }
        },
    )
}

/// Starts the installer process and waits until it holds the installation
/// lease. Only then may this process exit: an installer that never got that
/// far would leave the user without an application.
async fn start_installer(
    app_home: &Path,
    transaction: &Uuid,
    log: File,
) -> std::result::Result<(), String> {
    let mut installer = spawn_installer(transaction, log)
        .map_err(|error| format!("installer process could not be started: {error}"))?;
    let admitted =
        wait_for_installer_admission(&mut installer, app_home, INSTALLER_ADMISSION_TIMEOUT).await;
    if admitted.is_err()
        && let Err(error) = installer.kill().and_then(|()| installer.wait())
    {
        // Left running it still cannot install: its record is aborted next.
        eprintln!("an unadmitted update installer could not be stopped: {error}");
    }
    admitted
}

async fn wait_for_installer_admission(
    installer: &mut Child,
    app_home: &Path,
    timeout: Duration,
) -> std::result::Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut lease = LeaseWatch::default();
    loop {
        if let Some(status) = installer
            .try_wait()
            .map_err(|error| format!("installer process could not be observed: {error}"))?
        {
            return Err(format!(
                "installer process ended before it was admitted ({status})"
            ));
        }
        let held = match UpdateInstallLease::acquire(app_home) {
            Err(UpdateInstallLeaseError::Held) => true,
            Ok(probe) => {
                drop(probe);
                false
            }
            Err(UpdateInstallLeaseError::Unavailable(detail)) => {
                return Err(format!(
                    "installation lease could not be observed: {detail}"
                ));
            }
        };
        if lease.held_by_the_installer(held) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("installer process was not admitted in time".into());
        }
        tokio::time::sleep(INSTALLER_ADMISSION_POLL).await;
    }
}

/// Tells the installer's lasting hold on the lease from the momentary probe
/// of another dashboard that is just starting: only a lease found held on two
/// consecutive observations counts.
#[derive(Default)]
struct LeaseWatch {
    held_before: bool,
}

impl LeaseWatch {
    fn held_by_the_installer(&mut self, held: bool) -> bool {
        let lasting = held && self.held_before;
        self.held_before = held;
        lasting
    }
}

/// Opens the installer's private log for appending, never through a link.
/// Earlier attempts stay readable until the log outgrows its bound; then it
/// starts over.
fn open_installer_log(app_home: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = app_home.join(INSTALLER_LOG);
    let outgrown = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata.len() > INSTALLER_LOG_LIMIT,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    std::fs::OpenOptions::new()
        .write(true)
        .append(!outgrown)
        .truncate(outgrown)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
}

/// Starts the installer mode of the installed executable in its own process
/// group, so it outlives this dashboard. Its diagnostics go to the log.
fn spawn_installer(transaction: &Uuid, log: File) -> std::io::Result<Child> {
    Command::new(ReleaseSignedComponent::MainExecutable.path())
        .arg(FINISH_UPDATE_FLAG)
        .arg(transaction.hyphenated().to_string())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
}

/// Reports what the previous installation attempt left behind, once, and
/// which installation this process is still holding.
///
/// A dashboard asks this every time it loads, including after a reload in the
/// middle of an installation. The previous attempt is reviewed once per
/// process and only while nothing is being installed, so a reload can neither
/// remove a staged release nor clear the record of a running hand-off.
#[tauri::command]
pub(crate) async fn resolve_update_install(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, UpdateFailure> {
    resolve_update_install_inner(&app)
        .await
        .map_err(|error| report(&app, &error))
}

async fn resolve_update_install_inner(app: &AppHandle) -> Result<serde_json::Value> {
    if runs_from_installed_location() {
        ensure_previous_attempt_reviewed(app).await?;
    }
    let security = app.state::<UpdaterSecurityState>();
    Ok(serde_json::json!({
        "outcome": security.take_unreported_outcome()?,
        "pending": security.pending()?,
    }))
}

/// Deals with the attempt an earlier run recorded before anything new is
/// staged: its outcome is kept for the dashboard and its leftovers are removed.
/// It runs after native startup succeeded, so the replaced bundle is kept
/// until the new application is known to start.
async fn ensure_previous_attempt_reviewed(app: &AppHandle) -> Result<()> {
    let Some(review) = app.state::<UpdaterSecurityState>().begin_review()? else {
        return Ok(());
    };
    let app_home = app_home()?;
    let reviewed = blocking(move || {
        review_previous_attempt(
            &app_home,
            env!("CARGO_PKG_VERSION"),
            process_identity_exists,
        )
    })
    .await?;
    match reviewed {
        Ok(outcome) => {
            record_reviewed_outcome(app, &outcome);
            review.complete(outcome)
        }
        Err(discarded @ ReviewError::RecordDiscarded(_)) => {
            // Reported as the failure it is, but dealt with: nothing is left
            // that a later installation could trip over.
            review.complete(InstallOutcome::None)?;
            Err(discarded.into())
        }
        Err(error) => Err(error.into()),
    }
}

/// The renderer shows the previous attempt's outcome once; the diagnostic
/// journal keeps it.
fn record_reviewed_outcome(app: &AppHandle, outcome: &InstallOutcome) {
    let (code, message) = match outcome {
        InstallOutcome::None => return,
        InstallOutcome::Installed { version } => (
            "update_installed",
            format!("version {version} is running after its in-app installation"),
        ),
        InstallOutcome::Failed { version, code } => (
            code.as_str(),
            format!("the in-app installation of version {version} was aborted: {code}"),
        ),
    };
    crate::diagnostics::record(app, DiagnosticTopic::Update, code, &message);
}

/// Runs blocking work off the async runtime's worker threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| UpdateError::TaskFailed)
}

fn app_home() -> Result<std::path::PathBuf> {
    crate::settings_store()
        .map(|store| store.paths().app_home.clone())
        .map_err(UpdateError::AppHome)
}

fn emit_progress(
    app: &AppHandle,
    phase: &str,
    version: &str,
    downloaded: u64,
    total: Option<u64>,
) -> Result<()> {
    app.emit(
        PROGRESS_EVENT,
        serde_json::json!({
            "phase": phase,
            "version": version,
            "downloaded": downloaded,
            "total": total,
        }),
    )
    .map_err(|_| UpdateError::ProgressEvent)
}

/// Converts a failure to its renderer-visible form and keeps the detailed
/// cause in the diagnostic journal. A cancellation the user asked for is not
/// a fault and is not recorded.
fn report(app: &AppHandle, error: &UpdateError) -> UpdateFailure {
    let failure = error.failure();
    if !matches!(error, UpdateError::DownloadCancelled) {
        crate::diagnostics::record(
            app,
            DiagnosticTopic::Update,
            failure.code,
            &error.to_string(),
        );
    }
    failure
}

#[cfg(test)]
mod tests {
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
        assert!(!runs_from_installed_location());
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
        let source = include_str!("updater.rs")
            .split("#[cfg(test)]")
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
        let source = include_str!("updater.rs")
            .split("#[cfg(test)]")
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
        let source = include_str!("updater.rs")
            .split("#[cfg(test)]")
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
        let source = include_str!("updater.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
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
}
