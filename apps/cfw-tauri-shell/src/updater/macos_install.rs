//! The macOS installation: the presented release is downloaded, authenticated
//! and extracted into the private staging area, then handed to the installer
//! process, which replaces the bundle once this process has ended.

use super::*;

#[cfg(target_os = "macos")]
pub(super) const INSTALLER_LOG: &str = "update-installer.log";
/// Earlier attempts stay in the installer log until it outgrows this.
#[cfg(target_os = "macos")]
pub(super) const INSTALLER_LOG_LIMIT: u64 = 1024 * 1024;

/// How long the installer process may take to hold the installation lease.
#[cfg(target_os = "macos")]
pub(super) const INSTALLER_ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "macos")]
pub(super) const INSTALLER_ADMISSION_POLL: Duration = Duration::from_millis(50);

#[cfg(target_os = "macos")]
pub(super) async fn stage_release(
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
    let (expected_version, expected_build) = authorization.macos_bundle_identity()?;
    let expected_version = expected_version.to_string();
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
                expected_build,
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

#[cfg(target_os = "macos")]
pub(super) async fn hand_off(app: &AppHandle, staged: &StagedUpdate) -> Result<HandOff> {
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
#[cfg(target_os = "macos")]
pub(super) async fn start_installer(
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

#[cfg(target_os = "macos")]
pub(super) async fn wait_for_installer_admission(
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
#[cfg(target_os = "macos")]
#[derive(Default)]
pub(super) struct LeaseWatch {
    held_before: bool,
}

#[cfg(target_os = "macos")]
impl LeaseWatch {
    pub(super) fn held_by_the_installer(&mut self, held: bool) -> bool {
        let lasting = held && self.held_before;
        self.held_before = held;
        lasting
    }
}

/// Opens the installer's private log for appending, never through a link.
/// Earlier attempts stay readable until the log outgrows its bound; then it
/// starts over.
#[cfg(target_os = "macos")]
pub(super) fn open_installer_log(app_home: &Path) -> std::io::Result<File> {
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
#[cfg(target_os = "macos")]
pub(super) fn spawn_installer(transaction: &Uuid, log: File) -> std::io::Result<Child> {
    Command::new(ReleaseSignedComponent::MainExecutable.path())
        .arg(FINISH_UPDATE_FLAG)
        .arg(transaction.hyphenated().to_string())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
}
