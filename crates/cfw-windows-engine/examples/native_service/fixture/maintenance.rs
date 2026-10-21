//! Disposable SYSTEM exercise of the installed product's maintenance APIs.
//! Product file replacement, MSI commit and other-user GUI retirement remain
//! outside this fixture. It leaves the product stopped with its startup restored.
use super::*;
use cfw_windows_engine::runtime_host::{InstalledRuntime, SERVICE_NAME, ServiceMaintenanceFault};
use cfw_windows_storage::PrivateMachineRecord;
use std::io::Write;
use uuid::Uuid;

const RECORD_SCOPE: &str = "CFWAuthorityMaintenance";
fn record() -> Result<Option<serde_json::Value>> {
    let value = PrivateMachineRecord::new(RECORD_SCOPE).map_err(|e| e.to_string())?;
    let guard = value.lock(LIMIT).map_err(|e| e.to_string())?;
    let bytes = guard.read().map_err(|e| e.to_string());
    let released = guard.release().map_err(|e| e.to_string());
    let bytes = match (bytes, released) {
        (Ok(bytes), Ok(())) => bytes,
        (Err(e), Ok(())) | (Ok(_), Err(e)) => return Err(e),
        (Err(e), Err(r)) => return Err(format!("{e}; record release: {r}")),
    };
    bytes
        .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .transpose()
}
fn start_type(service: &Installed, value: u32) -> Result<()> {
    if unsafe {
        ChangeServiceConfigW(
            service.handle.0,
            SERVICE_NO_CHANGE,
            value,
            SERVICE_NO_CHANGE,
            null(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            null(),
        )
    } == 0
    {
        return Err(error(
            "change disposable product startup for counterexample",
        ));
    }
    Ok(())
}
fn start(service: &Installed) -> Result<()> {
    if unsafe { StartServiceW(service.handle.0, 0, null()) } == 0 {
        return Err(error("restart disposable product"));
    }
    service.wait(SERVICE_RUNNING)
}
fn wait_runtime_quiet(installation: &InstalledRuntime) -> Result<()> {
    // Keep the admitted bytes pinned while querying the public fixed layout;
    // the executable capability's internal path accessor stays private.
    let _held_image = installation.runtime().map_err(|e| e.to_string())?;
    let path = InstalledRuntime::desktop_path()
        .map_err(|e| e.to_string())?
        .with_file_name(cfw_windows_engine::runtime_host::RUNTIME_FILE);
    let observer = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + LIMIT;
    loop {
        let users = observer
            .processes_using_file(&path)
            .map_err(|e| e.to_string())?;
        if users
            .iter()
            .all(|p| p.process_id() == observer.process_id())
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("blocked startup process did not retire".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
pub(super) fn exercise() -> Result<()> {
    let installation = InstalledRuntime::open().map_err(|e| e.to_string())?;
    if record()?.is_some() {
        return Err("refusing existing product maintenance state".into());
    }
    let product = Installed::open_existing(SERVICE_NAME.to_owned())?;
    let transaction = Uuid::new_v4();
    let mut phase = "early_intent_failure";
    let operation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<serde_json::Value> {
            assert!(
                installation
                    .prepare_service_maintenance_for_validation(
                        transaction,
                        ServiceMaintenanceFault::IntentPublished
                    )
                    .is_err()
            );
            assert_eq!(
                record()?.ok_or("missing early interruption marker")?["phase"]["state"],
                "preparing"
            );
            assert_eq!(product.query()?.dwCurrentState, SERVICE_RUNNING);
            let early_rollback = installation
                .rollback_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(early_rollback["startup_restored"], true);
            assert_eq!(early_rollback["runtime_started"], false);
            assert!(record()?.is_none());

            phase = "prepare_and_repeat";
            let prepared = installation
                .prepare_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(prepared["retained_process_exit_observed"], true);
            assert_eq!(prepared["caller_session_id"], 0);
            assert_eq!(prepared["original_start_type"], SERVICE_DEMAND_START);
            assert_eq!(prepared["authority"]["state"], "off");
            assert_eq!(prepared["service_start_disabled"], true);
            assert_eq!(prepared["replacement_authorized"], false);
            assert_eq!(product.query()?.dwCurrentState, SERVICE_STOPPED);
            let repeated = installation
                .prepare_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(repeated["retained_process_exit_observed"], false);
            assert_eq!(repeated["authority"], prepared["authority"]);
            phase = "foreign_transaction";
            let foreign = Uuid::new_v4();
            assert!(installation.prepare_service_maintenance(foreign).is_err());
            assert!(installation.rollback_service_maintenance(foreign).is_err());
            phase = "disabled_start";
            if unsafe { StartServiceW(product.handle.0, 0, null()) } != 0
                || io::Error::last_os_error().raw_os_error() != Some(ERROR_SERVICE_DISABLED as i32)
            {
                return Err("disabled product startup was not refused".into());
            }
            // Temporarily restore the original start type solely to exercise the
            // independent product startup gate against the still-pending marker.
            phase = "pending_startup_gate";
            start_type(&product, SERVICE_DEMAND_START)?;
            let started = unsafe { StartServiceW(product.handle.0, 0, null()) };
            if started == 0 {
                let code = io::Error::last_os_error().raw_os_error();
                if !matches!(code, Some(c) if c == ERROR_SERVICE_SPECIFIC_ERROR as i32 || c == ERROR_PROCESS_ABORTED as i32)
                {
                    return Err(error("attempt product start while maintenance pending"));
                }
            }
            product.wait(SERVICE_STOPPED)?;
            let stopped = product.query()?;
            assert_eq!(stopped.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR);
            assert_eq!(stopped.dwServiceSpecificExitCode, 1);
            wait_runtime_quiet(&installation)?;
            start_type(&product, SERVICE_DISABLED)?;
            assert_eq!(
                record()?.ok_or("maintenance marker lost")?["transaction"],
                transaction.to_string()
            );

            phase = "foreign_startup_configuration";
            start_type(&product, SERVICE_AUTO_START)?;
            assert!(
                installation
                    .rollback_service_maintenance(transaction)
                    .is_err()
            );
            assert!(record()?.is_some());
            start_type(&product, SERVICE_DISABLED)?;
            let rollback = installation
                .rollback_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(rollback["startup_restored"], true);
            assert_eq!(rollback["runtime_started"], false);
            assert!(record()?.is_none());
            phase = "rollback_and_restart";
            start(&product)?;
            assert!(
                installation
                    .prepare_service_maintenance_for_validation(
                        transaction,
                        ServiceMaintenanceFault::RestartDisabled
                    )
                    .is_err()
            );
            phase = "late_interruption_record";
            let late = record()?.ok_or("missing late interruption marker")?;
            assert_eq!(late["phase"]["state"], "preparing");
            assert_eq!(product.query()?.dwCurrentState, SERVICE_STOPPED);
            let resumed = installation
                .prepare_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(resumed["retained_process_exit_observed"], false);
            assert_eq!(resumed["authority"]["root"], prepared["authority"]["root"]);
            let revision = prepared["authority"]["revision"]
                .as_u64()
                .ok_or("missing prepared revision")?;
            assert_eq!(
                resumed["authority"]["revision"].as_u64(),
                revision.checked_add(1)
            );
            let rollback = installation
                .rollback_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(rollback["startup_restored"], true);
            assert_eq!(rollback["runtime_started"], false);
            assert!(record()?.is_none());
            let idle = installation
                .rollback_service_maintenance(transaction)
                .map_err(|e| e.to_string())?;
            assert_eq!(idle["pending"], false);
            assert_eq!(idle["startup_restored"], false);
            Ok(
                serde_json::json!({"source":transport::installation()?.source,
            "document":"cfw-installed-service-maintenance-v1","prepared":prepared,"resumed":resumed,
            "late_preparation_resumed":true,
            "injected_failure_after_intent_retained":true,"injected_failure_after_disable_retained":true,
            "prepared_idempotent":true,"foreign_transaction_rejected":true,
            "disabled_start_refused":true,"pending_marker_blocks_startup":true,
            "foreign_start_type_preserved":true,"rollback_restored_startup":true,
            "restart_after_rollback":true,"maintenance_record_removed":true,
            "runtime_started_by_rollback":false,"other_user_gui_retirement_proven":false,
            "msi_installation_exercised":false,"release_accepted":false}),
            )
        },
    ));
    let operation = match operation {
        Ok(value) => value,
        Err(payload) => Err(payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "maintenance assertion panicked".into())),
    };
    // Never erase a foreign transaction. Restore only this test's original
    // configuration, and retain both errors if fixture cleanup also fails.
    let operation = operation.map_err(|e| format!("installed maintenance {phase}: {e}"));
    let cleanup = installation
        .rollback_service_maintenance(transaction)
        .map_err(|e| e.to_string());
    let report = match (operation, cleanup) {
        (Ok(report), Ok(_)) => report,
        (Err(e), Ok(_)) | (Ok(_), Err(e)) => return Err(e),
        (Err(e), Err(c)) => return Err(format!("{e}; maintenance rollback: {c}")),
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(authority_journal::root()?.join("installed-service-maintenance.json"))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&report).map_err(|e| e.to_string())?)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

pub(super) fn run() -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("maintenance validation requires disposable CI opt-in".into());
    }
    let receipts = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing maintenance receipts")?,
    );
    if !receipts.is_absolute() || !receipts.is_dir() {
        return Err("invalid maintenance receipts".into());
    }
    let root = tempfile::tempdir().map_err(|e| e.to_string())?;
    diagnostics::with_diagnostics(root.path(), &receipts, || {
        let image = root.path().join("service-fixture.exe");
        std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
            .map_err(|e| e.to_string())?;
        let expected = digest(&image)?;
        transport::write_installation(root.path(), &image, expected)?;
        let manager = Sc(unsafe {
            OpenSCManagerW(
                null(),
                null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        });
        if manager.0.is_null() {
            return Err(error("open maintenance fixture SCM"));
        }
        let name = format!("CFW-scm-fixture-{}-a", Uuid::new_v4());
        let mut service = Installed::create(&manager, name.clone(), &image)?;
        let result = transport::run_maintenance_desktop(root.path(), &name, expected);
        let cleanup = service.remove();
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(e), Err(c)) => Err(format!("{e}; fixture service removal: {c}")),
        }
    })
}

pub(super) fn client(name: &str, hex: &str) -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("maintenance Desktop requires disposable CI opt-in".into());
    }
    let id = name
        .strip_prefix("CFW-scm-fixture-")
        .and_then(|s| s.strip_suffix("-a"))
        .ok_or("invalid maintenance fixture service")?;
    let parsed = Uuid::parse_str(id).map_err(|e| e.to_string())?;
    if parsed.is_nil() || parsed.to_string() != id {
        return Err("noncanonical fixture service".into());
    }
    let (image, expected) = transport::service_image()?;
    let expected_hex: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex != expected_hex {
        return Err("maintenance fixture source mismatch".into());
    }
    let mut channel = ServiceChannel::connect(
        name,
        ServiceClientRole::Desktop,
        verified(&image, expected)?,
    )
    .map_err(|e| e.to_string())?;
    let reply = channel
        .request(
            b"installed-maintenance",
            Instant::now() + Duration::from_secs(90),
        )
        .map_err(|e| e.to_string())?;
    if reply.as_bytes() != b"maintenance-ok" {
        return Err("maintenance receipt reply mismatch".into());
    }
    let root = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = root.parent().ok_or("missing admitted Desktop directory")?;
    let report = serde_json::json!({"success":true,"role":"desktop","maintenance_request_acknowledged":true});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{name}-desktop-client.json")))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&report).map_err(|e| e.to_string())?)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
