//! Medium-integrity Windows update handoff. Only Windows Installer performs
//! privileged changes; the copied GUI never elevates itself or controls SCM.
mod journal;
use super::{
    HandOff, InstallOutcome, ReviewError, StagedUpdate, UpdateError, UpdateInstallLease,
    install_lease::UpdateInstallLeaseError,
};
use crate::process_identity::{
    ProcessIdentity, current_process_identity, exact_processes, process_identity,
    process_identity_exists,
};
use cfw_windows_engine::{
    runtime_host::{InstalledRuntime, ObservedInstallation},
    update_package::{UpdateHandoff, UpdateStaging},
};
use journal::{Disposition, Journal, Phase, Record};
use std::{
    fs::File,
    io::{Seek, SeekFrom},
    os::windows::{ffi::OsStringExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tauri::AppHandle;
use uuid::Uuid;
use windows_sys::Win32::{
    System::{
        SystemInformation::GetSystemDirectoryW,
        Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW},
    },
    UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
};

const HANDOFF_WAIT: Duration = Duration::from_secs(45);
const EXIT_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(100);
const INSTALL_NOTICE: Duration = Duration::from_secs(15 * 60);
const LOG_LIMIT: usize = 16 * 1024 * 1024;

pub(super) async fn hand_off(app: &AppHandle, staged: &StagedUpdate) -> super::Result<HandOff> {
    let home = super::app_home()?;
    let current = InstalledRuntime::open().map_err(host)?;
    if current.snapshot() != staged.resources.original {
        return Err(UpdateError::InstallerStart(
            "installed package changed after staging".into(),
        ));
    }
    // Verify registration as well as the protected source images before stopping.
    let original = ObservedInstallation::open(&staged.resources.original).map_err(host)?;
    let image = current
        .prepare_update_finisher(&staged.resources.staging)
        .map_err(host)?;
    let executable = image.path().to_owned();
    let mut log = staged
        .resources
        .staging
        .directory()
        .open_shared_log("finisher.log", LOG_LIMIT)
        .map_err(|source| UpdateError::WindowsStorage {
            stage: "open-finisher-log",
            source,
        })?;
    log.seek(SeekFrom::End(0))
        .map_err(|e| UpdateError::Staging {
            stage: "append-finisher-log",
            kind: e.kind(),
        })?;
    let dashboard = current_process_identity(&InstalledRuntime::desktop_path().map_err(host)?)
        .map_err(UpdateError::ProcessIdentity)?;
    let record = Record::new(
        staged.transaction,
        current.snapshot(),
        staged.resources.package.identity().clone(),
        staged.resources.authorization.clone(),
        staged.resources.package.sha256(),
        dashboard,
    );
    let journal = Journal::new(&home);
    let mut lifecycle =
        crate::lifecycle::begin_update_lifecycle(app).map_err(UpdateError::Lifecycle)?;
    journal.begin(&record).map_err(UpdateError::Journal)?;
    let warning = match crate::lifecycle::prepare_update_exit(app, &mut lifecycle).await {
        Ok(warning) => warning,
        Err(error) => {
            let stopped = UpdateError::EngineStop(error);
            if let Err(error) = journal.clear(&record) {
                super::report(app, &stopped);
                return Err(UpdateError::Journal(error));
            }
            return Err(stopped);
        }
    };
    if let Some(warning) = warning {
        crate::diagnostics::record(
            app,
            cfw_core::DiagnosticTopic::Update,
            "engine_stop_reported_error",
            &warning,
        );
    }
    // The original installation and copied image remain pinned until the child
    // owns the candidate and publishes its exact native identity under the lease.
    let launched = spawn(&executable, &staged.transaction, log).map_err(|e| e.to_string());
    let mut retired = true;
    let admitted = match launched {
        Ok(mut child) => {
            let result = admit_child(&mut child, &home, &executable, &record.transaction).await;
            if result.is_err() && !matches!(child.try_wait(), Ok(Some(_))) {
                // The dashboard is still alive: this mode cannot yet launch MSI.
                if let Err(error) = child.kill().and_then(|()| child.wait()) {
                    eprintln!("unadmitted Windows finisher retirement failed: {error}");
                    retired = false;
                }
            }
            result
        }
        Err(error) => Err(error),
    };
    drop((image, original, current));
    Ok(match admitted {
        Ok(()) => HandOff::Started,
        Err(error) => {
            match journal.load() {
                Ok(Some(latest)) if latest.same_request(&record) => {
                    if let Err(error) = journal.change(
                        &latest,
                        Phase::Finished {
                            process: None,
                            exit_code: None,
                            disposition: Disposition::Original,
                            code: Some("installer_start_failed".into()),
                        },
                    ) {
                        super::report(app, &UpdateError::Journal(error));
                    }
                }
                Ok(_) => {
                    super::report(
                        app,
                        &UpdateError::Journal("Windows handoff record changed before abort".into()),
                    );
                }
                Err(error) => {
                    super::report(app, &UpdateError::Journal(error));
                }
            }
            if retired {
                HandOff::InstallerDidNotStart(UpdateError::InstallerStart(error))
            } else {
                HandOff::ExitRequired(UpdateError::InstallerStart(error))
            }
        }
    })
}
fn host(error: cfw_windows_engine::runtime_host::HostError) -> UpdateError {
    UpdateError::InstallerStart(error.to_string())
}
fn spawn(executable: &Path, transaction: &Uuid, log: File) -> std::io::Result<Child> {
    Command::new(executable)
        .arg(crate::launch::FINISH_UPDATE_FLAG)
        .arg(transaction.to_string())
        .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
}
async fn admit_child(
    child: &mut Child,
    home: &Path,
    executable: &Path,
    transaction: &Uuid,
) -> Result<(), String> {
    let deadline = Instant::now() + HANDOFF_WAIT;
    let identity = process_identity(child.id(), executable)?;
    let journal = Journal::new(home);
    let mut previous = false;
    loop {
        if let Some(code) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("Windows finisher ended before admission: {code}"));
        }
        let held = match UpdateInstallLease::acquire(home) {
            Err(UpdateInstallLeaseError::Held) => true,
            Ok(lease) => {
                drop(lease);
                false
            }
            Err(error) => return Err(error.to_string()),
        };
        let recorded = journal.load()?.is_some_and(|r| {
            r.transaction == *transaction
                && r.finisher() == Some(&identity)
                && matches!(r.phase, Phase::Finishing { .. })
        });
        if held && recorded && previous {
            return Ok(());
        }
        previous = held && recorded;
        if Instant::now() >= deadline {
            return Err("Windows finisher admission timed out".into());
        }
        tokio::time::sleep(POLL).await;
    }
}

pub(crate) fn run(transaction: &str) -> i32 {
    let transaction = match parse_transaction(transaction) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Windows update argument admission: {error}");
            return crate::launch::STARTUP_USAGE_EXIT_CODE;
        }
    };
    let mut handed_off = false;
    let result = run_inner(transaction, &mut handed_off);
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Windows update finisher: {error}");
            // Before admission the still-running dashboard handles the failure.
            // Only a finisher that could have taken over needs its own dialog.
            if handed_off {
                show_failure(&error);
            }
            70
        }
    }
}
fn run_inner(transaction: Uuid, handed_off: &mut bool) -> Result<(), String> {
    let home = super::app_home().map_err(|e| e.to_string())?;
    let handoff = UpdateHandoff::open(&home, transaction).map_err(|e| e.to_string())?;
    let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
    let _image = installed
        .admit_update_finisher(&handoff, transaction)
        .map_err(|e| e.to_string())?;
    let original = installed.snapshot();
    // Release protected source pins before MSI can replace that installation.
    drop(installed);
    let process = current_process_identity(&handoff.finisher())?;
    let _lease = UpdateInstallLease::acquire(&home).map_err(|e| e.to_string())?;
    let journal = Journal::new(&home);
    let record = journal.load()?.ok_or("Windows handoff record is absent")?;
    if record.transaction != transaction
        || record.original != original
        || record.phase != Phase::HandedOff
    {
        return Err("Windows finisher does not match this handoff".into());
    }
    *handed_off = true;
    let mut record = journal.change(
        &record,
        Phase::Finishing {
            process: process.clone(),
        },
    )?;
    let result = install(&home, &handoff, &journal, &mut record, &process);
    let (exit_code, disposition, code, observed) = match result {
        Ok((exit, observed)) => (Some(exit), Disposition::Installed, None, Some(observed)),
        Err(failure) => {
            eprintln!("Windows MSI attempt: {}", failure.detail);
            // A spawned installer is always observed through its terminal exit
            // before install() returns. Unknown outcomes preserve all staging.
            match ObservedInstallation::open(&record.original) {
                Ok(original) if !failure.uncertain => (
                    failure.exit,
                    Disposition::Original,
                    Some(failure.code.to_owned()),
                    Some(original),
                ),
                Ok(_) => (
                    failure.exit,
                    Disposition::Uncertain,
                    Some("installation_unconfirmed".into()),
                    None,
                ),
                Err(error) => {
                    eprintln!("original installation could not be confirmed: {error}");
                    (
                        failure.exit,
                        Disposition::Uncertain,
                        Some("installation_unconfirmed".into()),
                        None,
                    )
                }
            }
        }
    };
    let phase = Phase::Finished {
        process: Some(process),
        exit_code,
        disposition,
        code,
    };
    // One bounded recovery read after any intermediate uncertain publication.
    // Only the phase may differ; changed expectations cannot authorize a result.
    let latest = journal
        .load()?
        .ok_or("Windows update disappeared before completion")?;
    if !record.same_request(&latest) {
        return Err("Windows update request changed before completion".into());
    }
    journal.change(&latest, phase)?;
    drop(handoff);
    let Some(observed) = observed else {
        return Err("The installer outcome could not be verified. Update files and the transaction record were retained for recovery.".into());
    };
    // The new GUI waits for this exact process to exit before reviewing and
    // deleting its staging (which still contains this running executable).
    let _child = observed
        .start_dashboard_after_update(transaction)
        .map_err(|e| e.to_string())?;
    Ok(())
}

struct Failure {
    code: &'static str,
    detail: String,
    exit: Option<u32>,
    uncertain: bool,
}
impl Failure {
    fn before(detail: impl ToString) -> Self {
        Self {
            code: "installation_failed",
            detail: detail.to_string(),
            exit: None,
            uncertain: false,
        }
    }
}
fn install(
    home: &Path,
    handoff: &UpdateHandoff,
    journal: &Journal,
    record: &mut Record,
    process: &ProcessIdentity,
) -> Result<(u32, ObservedInstallation), Failure> {
    wait_process_exit(&record.dashboard, EXIT_WAIT).map_err(Failure::before)?;
    let path = InstalledRuntime::desktop_path().map_err(Failure::before)?;
    if !exact_processes(&path).map_err(Failure::before)?.is_empty() {
        return Err(Failure::before(
            "another desktop in this logon still uses the installation",
        ));
    }
    let staging = UpdateStaging::open_existing(home, record.transaction)
        .map_err(Failure::before)?
        .ok_or_else(|| Failure::before("Windows update staging disappeared"))?;
    if staging.root() != handoff.root() {
        return Err(Failure::before("Windows staging identity changed"));
    }
    let digest = super::download::verify_existing_archive(&record.authorization, handoff.package())
        .map_err(Failure::before)?;
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if hex != record.package_sha256 {
        return Err(Failure::before("authorized package changed during handoff"));
    }
    let installed = InstalledRuntime::open().map_err(Failure::before)?;
    if installed.snapshot() != record.original {
        return Err(Failure::before(
            "original installation changed during handoff",
        ));
    }
    let package = installed
        .package_inspector()
        .map_err(Failure::before)?
        .inspect(
            handoff.package(),
            &record.authorization.version,
            staging.root(),
            Duration::from_secs(30),
            || false,
        )
        .map_err(Failure::before)?;
    if package.identity() != &record.target || package.sha256() != digest {
        return Err(Failure::before(
            "native package identity changed after staging",
        ));
    }
    let _log = staging
        .directory()
        .open_shared_log("msi.log", LOG_LIMIT)
        .map_err(Failure::before)?;
    let executable = msiexec_path().map_err(Failure::before)?;
    *record = journal
        .change(
            record,
            Phase::Launching {
                process: process.clone(),
            },
        )
        .map_err(Failure::before)?;
    let mut child = Command::new(&executable)
        .arg("/i")
        .arg(package.path())
        .arg("/qb")
        .arg("/norestart")
        .arg("/l*vx+")
        .arg(staging.root().join("msi.log"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Failure::before)?;
    let identity = process_identity(child.id(), &executable);
    match identity {
        Ok(installer) => match journal.change(
            record,
            Phase::Installing {
                process: process.clone(),
                installer,
                overdue: false,
            },
        ) {
            Ok(next) => *record = next,
            Err(error) => {
                eprintln!("MSI identity publication failed; retaining the launch handle: {error}")
            }
        },
        Err(error) => {
            eprintln!("MSI identity could not be serialized; retaining the launch handle: {error}")
        }
    }
    let notice = Instant::now() + INSTALL_NOTICE;
    let mut overdue = false;
    let mut last_observation_error = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                last_observation_error = None;
            }
            Err(error) => {
                // No observation failure proves exit. Keep this one process,
                // lease and pinned package; never launch competing recovery.
                let detail = error.to_string();
                if last_observation_error.as_ref() != Some(&detail) {
                    eprintln!("MSI process observation failed; retaining ownership: {detail}");
                    last_observation_error = Some(detail);
                }
            }
        }
        if !overdue && Instant::now() >= notice {
            overdue = true;
            eprintln!(
                "MSI exceeded its 15-minute notice deadline; retaining ownership until its actual exit, without starting a competing transaction"
            );
            if let Phase::Installing { installer, .. } = &record.phase {
                match journal.change(
                    record,
                    Phase::Installing {
                        process: process.clone(),
                        installer: installer.clone(),
                        overdue: true,
                    },
                ) {
                    Ok(next) => *record = next,
                    Err(error) => eprintln!("MSI deadline notice could not be stored: {error}"),
                }
            }
        }
        std::thread::sleep(if last_observation_error.is_some() {
            Duration::from_secs(1)
        } else {
            POLL
        });
    };
    let exit = status
        .code()
        .map(|code| code as u32)
        .ok_or_else(|| Failure {
            code: "installation_unconfirmed",
            detail: "MSI had no exit code".into(),
            exit: None,
            uncertain: true,
        })?;
    if exit != 0 {
        return Err(Failure {
            code: if exit == 1602 {
                "install_cancelled"
            } else {
                "installer_failed"
            },
            detail: format!("Windows Installer returned {exit}"),
            exit: Some(exit),
            uncertain: matches!(exit, 1641 | 3010),
        });
    }
    let observed = ObservedInstallation::open(&record.target_snapshot()).map_err(|e| Failure {
        code: "target_verification_failed",
        detail: e.to_string(),
        exit: Some(exit),
        uncertain: false,
    })?;
    Ok((exit, observed))
}

fn msiexec_path() -> Result<PathBuf, String> {
    let mut buffer = [0_u16; 32768];
    let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if count == 0 || count >= buffer.len() {
        return Err("Windows system directory is unavailable".into());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..count])).join("msiexec.exe"))
}
fn parse_transaction(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
        .ok_or_else(|| "Windows update transaction is not a canonical UUID".into())
}
fn wait_process_exit(process: &ProcessIdentity, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while process_identity_exists(process)? {
        if process.is_this_process() {
            return Err("an update process cannot wait for its own exit".into());
        }
        if Instant::now() >= deadline {
            return Err("the previous update process has not exited".into());
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}
pub(crate) fn wait_for_finisher_exit(value: &str) -> Result<(), String> {
    let transaction = parse_transaction(value)?;
    let home = super::app_home().map_err(|e| e.to_string())?;
    let record = Journal::new(&home)
        .load()?
        .ok_or("update restart has no transaction record")?;
    if record.transaction != transaction
        || !matches!(
            record.phase,
            Phase::Finished {
                disposition: Disposition::Installed | Disposition::Original,
                ..
            }
        )
    {
        return Err("update restart has no confirmed terminal outcome".into());
    }
    if let Some(process) = record.finisher() {
        wait_process_exit(process, EXIT_WAIT)?;
    }
    Ok(())
}

pub(super) fn review(home: &Path) -> Result<InstallOutcome, ReviewError> {
    let _lease = UpdateInstallLease::acquire(home).map_err(|e| match e {
        UpdateInstallLeaseError::Held => ReviewError::InstallationInProgress,
        UpdateInstallLeaseError::Unavailable(e) => ReviewError::Unavailable(e),
    })?;
    let journal = Journal::new(home);
    let record = journal.load().map_err(ReviewError::Unavailable)?;
    let Some(record) = record else {
        UpdateStaging::recover(home).map_err(|e| ReviewError::Unavailable(e.to_string()))?;
        return Ok(InstallOutcome::None);
    };
    if let Some(process) = record.finisher() {
        if process_identity_exists(process).map_err(ReviewError::Unavailable)? {
            return Err(ReviewError::InstallationInProgress);
        }
    }
    let (expected, outcome) = match &record.phase {
        Phase::Finished {
            disposition: Disposition::Installed,
            ..
        } => (
            record.target_snapshot(),
            InstallOutcome::Installed {
                version: record.target.version.clone(),
            },
        ),
        Phase::Finished {
            disposition: Disposition::Original,
            code,
            ..
        } => (
            record.original.clone(),
            InstallOutcome::Failed {
                version: record.target.version.clone(),
                code: code.clone().ok_or_else(|| {
                    ReviewError::Unavailable("failed update has no reason".into())
                })?,
            },
        ),
        Phase::HandedOff => {
            if process_identity_exists(&record.dashboard).map_err(ReviewError::Unavailable)? {
                return Err(ReviewError::InstallationInProgress);
            }
            (
                record.original.clone(),
                InstallOutcome::Failed {
                    version: record.target.version.clone(),
                    code: "install_interrupted".into(),
                },
            )
        }
        Phase::Installing { installer, .. }
            if process_identity_exists(installer).map_err(ReviewError::Unavailable)? =>
        {
            return Err(ReviewError::InstallationInProgress);
        }
        _ => {
            return Err(ReviewError::Unavailable(
                "Windows installation outcome is unconfirmed; transaction files were retained"
                    .into(),
            ));
        }
    };
    let observed = ObservedInstallation::open(&expected)
        .map_err(|e| ReviewError::Unavailable(e.to_string()))?;
    let current = InstalledRuntime::open().map_err(|e| ReviewError::Unavailable(e.to_string()))?;
    current
        .require_desktop_process()
        .map_err(|e| ReviewError::Unavailable(e.to_string()))?;
    if current.snapshot() != observed.snapshot() {
        return Err(ReviewError::Unavailable(
            "running GUI is not the observed update outcome".into(),
        ));
    }
    UpdateStaging::recover(home).map_err(|e| ReviewError::Unavailable(e.to_string()))?;
    journal.clear(&record).map_err(ReviewError::Unavailable)?;
    Ok(outcome)
}
fn show_failure(error: &str) {
    let message = format!(
        "Clash for Windows could not complete its update.\n\n{}\n\nThe update files and installer logs have been retained.",
        super::error::bounded_diagnostic(error)
    );
    let title: Vec<_> = "Clash for Windows".encode_utf16().chain([0]).collect();
    let message: Vec<_> = message.encode_utf16().chain([0]).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
