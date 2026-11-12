mod admission;
#[cfg(target_os = "macos")]
mod archive;
mod check;
mod contract;
mod download;
mod error;
#[cfg(target_os = "macos")]
mod finisher;
mod install_lease;
#[cfg(target_os = "macos")]
mod journal;
#[cfg(target_os = "macos")]
mod macos_install;
mod metadata;
mod outcome;
#[cfg(target_os = "macos")]
mod services;
#[cfg(target_os = "macos")]
mod staged_bundle;
#[cfg(target_os = "macos")]
mod staging;
mod state;
#[cfg(windows)]
mod windows_staged;
#[cfg(windows)]
mod windows_update;

#[cfg(windows)]
type StagedResources = windows_staged::WindowsStagedResources;
#[cfg(target_os = "macos")]
type StagedResources = ();

#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt as _;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Child;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

use cfw_core::DiagnosticTopic;
#[cfg(target_os = "macos")]
use cfw_platform::ReleaseSignedComponent;
#[cfg(target_os = "macos")]
use cfw_platform::operating_system_version;
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

use crate::commands::open_trusted_external_url;
#[cfg(target_os = "macos")]
use crate::lifecycle::{begin_update_lifecycle, prepare_update_exit};
#[cfg(target_os = "macos")]
use crate::process_identity::{current_process_identity, process_identity_exists};
use admission::{
    BundleIdentity, InstallAdmissionError, admit_running_installation, runs_from_installed_location,
};
#[cfg(target_os = "macos")]
use archive::extract_bundle;
use check::{check_for_updates_inner, open_available_update_inner, recheck_presented_update};
use contract::UpdateAuthorization;
use download::download_verified_archive;
use error::{FailureCategory, Result, UpdateError, UpdateFailure};
#[cfg(target_os = "macos")]
use journal::{InstallJournal, InstallRecord, UpdateInstallLeaseError};
#[cfg(all(test, target_os = "macos"))]
use macos_install::{
    INSTALLER_LOG, INSTALLER_LOG_LIMIT, LeaseWatch, open_installer_log,
    wait_for_installer_admission,
};
#[cfg(target_os = "macos")]
use macos_install::{hand_off, stage_release};
use metadata::check_bounded_update;
#[cfg(target_os = "macos")]
use outcome::review_previous_attempt;
use outcome::{InstallOutcome, ReviewError};
#[cfg(target_os = "macos")]
use services::require_removable_services;
#[cfg(target_os = "macos")]
use staged_bundle::{StagedBundleError, StagedExpectation, verify_staged_bundle};
#[cfg(target_os = "macos")]
use staging::StagingArea;
#[cfg(target_os = "macos")]
use state::DownloadCancellation;
use state::{Cancelled, StagedUpdate};

#[cfg(target_os = "macos")]
use crate::launch::FINISH_UPDATE_FLAG;
#[cfg(target_os = "macos")]
pub(crate) use finisher::run as run_update_finisher;
pub(crate) use install_lease::UpdateInstallLease;
#[cfg(windows)]
pub(crate) use windows_update::{
    admit_dashboard_startup, run as run_update_finisher, wait_for_finisher_exit,
};
pub(crate) type UpdaterSecurityState = state::UpdaterSecurityState<StagedResources>;

const PROGRESS_EVENT: &str = "cfw://update-progress";

/// Lets the renderer receive the hand-off result before the window closes.
const EXIT_AFTER_HANDOFF: Duration = Duration::from_millis(250);
/// The installer waits for this process to end before it touches anything
/// and gives the attempt up if the wait is in vain. An exit that hangs in the
/// window teardown must not be the reason, so the process ends by then.
const EXIT_DEADLINE: Duration = Duration::from_secs(5);

#[tauri::command]
pub(crate) async fn check_for_updates(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, String> {
    check_for_updates_inner(app)
        .await
        .map_err(|error| error.to_string())
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
    #[cfg(windows)]
    {
        prepare_windows_release(app, installed, authorization, lease).await
    }

    #[cfg(target_os = "macos")]
    {
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
                offer_version: authorization.version.clone(),
                installed,
                staged,
                resources: (),
            })
        });
        match recorded {
            Ok(()) => Ok(serde_json::json!({ "version": authorization.version })),
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
}

#[cfg(windows)]
async fn prepare_windows_release(
    app: &AppHandle,
    installed: BundleIdentity,
    authorization: UpdateAuthorization,
    lease: state::PreparationLease<StagedResources>,
) -> Result<serde_json::Value> {
    use cfw_windows_engine::{runtime_host::InstalledRuntime, update_package::UpdateStaging};
    let home = app_home()?;
    let transaction = Uuid::new_v4();
    let staging = UpdateStaging::create(&home, transaction)?;
    let prepared: Result<serde_json::Value> = async {
        let version = authorization.version.as_str();
        emit_progress(app, "downloading", version, 0, None)?;
        let mut last_percent = None;
        let authenticated_digest = download_verified_archive(
            &authorization,
            &staging.package(),
            &lease.cancellation,
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
        if lease.cancellation.is_cancelled() {
            return Err(UpdateError::DownloadCancelled);
        }
        emit_progress(app, "verifying", version, 0, None)?;
        let requested = authorization.version.clone();
        let staged_authorization = authorization.clone();
        let expected = installed.clone();
        let cancellation = lease.cancellation.clone();
        let (identity, resources) = blocking(move || -> Result<_> {
            // The installed worker, publisher and build floor are re-observed
            // from the protected installation, never from downloaded claims.
            let current = InstalledRuntime::open().map_err(|e| {
                InstallAdmissionError::WindowsInstallationUnavailable(e.to_string())
            })?;
            current.require_desktop_process().map_err(|e| {
                InstallAdmissionError::WindowsInstallationUnavailable(e.to_string())
            })?;
            let release = current.release();
            let original = current.snapshot();
            if release.version != expected.version || release.build != expected.build {
                return Err(InstallAdmissionError::InstalledIdentityInvalid.into());
            }
            let inspector = current.package_inspector().map_err(|e| {
                InstallAdmissionError::WindowsInstallationUnavailable(e.to_string())
            })?;
            let package = inspector.inspect(
                &staging.package(),
                &requested,
                staging.root(),
                Duration::from_secs(30),
                || cancellation.is_cancelled(),
            )?;
            if package.sha256() != authenticated_digest {
                return Err(UpdateError::SignatureVerification);
            }
            let identity = BundleIdentity {
                version: package.identity().version.clone(),
                build: package.identity().build,
            };
            let resources = StagedResources::new(staging, package, staged_authorization, original)?;
            Ok((identity, resources))
        })
        .await??;
        let version = identity.version.clone();
        lease.stage(StagedUpdate {
            transaction,
            offer_version: version.clone(),
            installed,
            staged: identity,
            resources,
        })?;
        Ok(serde_json::json!({"version":version}))
    }
    .await;
    match prepared {
        Ok(result) => Ok(result),
        Err(error) => {
            // Every moved owner has retired before reopening this exact UUID.
            // Keep both the original error and any failed cleanup diagnostic.
            if error.failure().category == FailureCategory::Authenticity {
                app.state::<UpdaterSecurityState>()
                    .reject_release(&authorization)?;
            }
            let cleanup =
                UpdateStaging::open_existing(&home, transaction).and_then(
                    |staging| match staging {
                        Some(staging) => staging.remove(),
                        None => Ok(()),
                    },
                );
            if let Err(cleanup) = cleanup {
                crate::diagnostics::record(
                    app,
                    DiagnosticTopic::Update,
                    "staging_discard_failed",
                    &cleanup.to_string(),
                );
            }
            Err(error)
        }
    }
}

/// Stops a running download or discards a staged release, and says which.
#[tauri::command]
pub(crate) async fn cancel_update_install(
    app: AppHandle,
) -> std::result::Result<serde_json::Value, UpdateFailure> {
    cancel_update_install_inner(&app).map_err(|error| report(&app, &error))
}

fn cancel_update_install_inner(app: &AppHandle) -> Result<serde_json::Value> {
    #[cfg(target_os = "macos")]
    let app_home = app_home()?;
    let cancelled = match app.state::<UpdaterSecurityState>().cancel_install()? {
        Cancelled::Nothing => "nothing",
        Cancelled::Preparation => "preparation",
        Cancelled::Staged(staged) => {
            #[cfg(windows)]
            staged.resources.discard()?;
            #[cfg(target_os = "macos")]
            {
                // The release is no longer staged either way; the next review
                // removes what a failed removal left.
                if let Err(removal) = StagingArea::path(&app_home, &staged.transaction).remove() {
                    crate::diagnostics::record(
                        app,
                        DiagnosticTopic::Update,
                        "staging_discard_failed",
                        &format!("{:?}", removal.kind()),
                    );
                }
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
    match hand_off(&app, commit.staged().map_err(|error| report(&app, &error))?).await {
        Ok(HandOff::Started) => {
            let version = commit
                .staged()
                .map_err(|error| report(&app, &error))?
                .offer_version
                .clone();
            commit.handed_off();
            exit_after_handoff(app.clone());
            Ok(serde_json::json!({ "version": version }))
        }
        Ok(HandOff::InstallerDidNotStart(error)) => {
            // The core is stopped and this process may only exit. Start the
            // unchanged application again; it reports the recorded failure.
            report(&app, &error);
            commit.handed_off();
            app.restart()
        }
        #[cfg(windows)]
        Ok(HandOff::ExitRequired(error)) => {
            let failure = report(&app, &error);
            commit.handed_off();
            exit_after_handoff(app.clone());
            Err(failure)
        }
        Err(error) => Err(report(&app, &error)),
    }
}

fn exit_after_handoff(app: AppHandle) {
    let exiting = app;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(EXIT_AFTER_HANDOFF).await;
        exiting.exit(0);
    });
    std::thread::spawn(|| {
        std::thread::sleep(EXIT_DEADLINE);
        eprintln!("the dashboard did not exit after the update hand-off; ending the process");
        std::process::exit(0);
    });
}

#[cfg(windows)]
use windows_update::hand_off;

enum HandOff {
    Started,
    /// The core is already stopped for exit, but no installer process holds
    /// the installation. The attempt is recorded as aborted when possible.
    InstallerDidNotStart(UpdateError),
    #[cfg(windows)]
    ExitRequired(UpdateError),
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
    if runs_from_installed_location()? {
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
    #[cfg(target_os = "macos")]
    let reviewed = {
        let running = admission::running_bundle_identity()?;
        blocking(move || review_previous_attempt(&app_home, &running, process_identity_exists))
            .await?
    };
    #[cfg(windows)]
    let reviewed = blocking(move || windows_update::review(&app_home)).await?;
    match reviewed {
        Ok(outcome) => {
            record_reviewed_outcome(app, &outcome);
            review.complete(outcome)
        }
        #[cfg(target_os = "macos")]
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

#[cfg(all(test, target_os = "macos"))]
mod tests;
