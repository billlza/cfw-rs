use cfw_windows_engine::{
    LiveConsoleSession, LocalServiceListener, LocalServicePipe, NativePeerProcess,
    NativeUserSession, ServiceAuthorizationError, ServiceChannel, ServiceClientRole,
    ServicePeerError, ServiceTransportError, UserAgentLeaseRequirement, VerifiedExecutable,
    WindowsServicePeer, authorize_service_request, configure_service_process_observation,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{Services::*, Threading::*},
};

mod attacks;
mod authority_journal;
mod authority_state;
mod authority_wire;
mod desktop;
mod machine_record;
mod restricted;
mod stress;
mod transport;
mod user_agent;
type Result<T> = std::result::Result<T, String>;
const LIMIT: Duration = Duration::from_secs(15);
const POST_STOP_EXCHANGES: usize = 256;
const SERVICE_ACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)";
// SCM invokes process-wide ABI callbacks. Each fixture process hosts one
// service, so these bounded callback cells live until the process exits.
static STOP: AtomicBool = AtomicBool::new(false);
static SERVICE_EXIT: AtomicU32 = AtomicU32::new(0);

enum ServiceCompletion {
    Clean,
    Failed,
}

fn error(operation: &str) -> String {
    format!("{operation}: {}", io::Error::last_os_error())
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}
fn digest(path: &Path) -> Result<[u8; 32]> {
    Ok(Sha256::digest(std::fs::read(path).map_err(|e| e.to_string())?).into())
}
fn verified(path: &Path, expected: [u8; 32]) -> Result<VerifiedExecutable> {
    VerifiedExecutable::open(path, expected, "0.5.0").map_err(|e| e.to_string())
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}
struct Descriptor(*mut c_void);
impl Descriptor {
    fn new(text: &str) -> Result<Self> {
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(text).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(error("build fixture ACL"));
        }
        Ok(Self(descriptor))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--runtime-validation" {
        return user_agent::run_validation();
    }
    if args.len() == 4 {
        let case = match args[1].as_str() {
            "--local-agent-runtime" => Some(restricted::ClientCase::RuntimeLocal),
            "--system-agent-runtime" => Some(restricted::ClientCase::RuntimeSystem),
            "--rejected-agent-runtime" => Some(restricted::ClientCase::RejectedRuntime),
            _ => None,
        };
        if let Some(case) = case {
            return restricted::client(&args[2], &args[3], case);
        }
    }
    if args.len() == 4 && args[1] == "--runtime-desktop" {
        if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
            return Err("runtime desktop requires the disposable CI opt-in".into());
        }
        return user_agent::desktop(&args[2], &args[3]);
    }
    if args.len() == 4 && args[1] == "--desktop-validation" {
        if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
            return Err("desktop fixture validation requires the disposable CI opt-in".into());
        }
        return transport::desktop_validation(&args[2], &args[3]);
    }
    if args.len() == 4 && args[1] == "--client" {
        return restricted::client(&args[2], &args[3], restricted::ClientCase::UserAgent);
    }
    if args.len() == 4 && args[1] == "--rejected-client" {
        return restricted::client(&args[2], &args[3], restricted::ClientCase::CopiedImage);
    }
    if args.len() == 4 && args[1] == "--authority-runtime" {
        return restricted::client(&args[2], &args[3], restricted::ClientCase::AuthorityRuntime);
    }
    if args.len() != 1 {
        return Err("unknown fixture arguments".into());
    }
    let mut name = wide("CFWNativeServiceValidation");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
        return if SERVICE_EXIT.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err("SCM fixture service failed".into())
        };
    }
    if io::Error::last_os_error().raw_os_error()
        != Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32)
    {
        return Err(error("connect service dispatcher"));
    }
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("SCM mutation requires an explicitly designated disposable CI user".into());
    }
    run_validation()
}

unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP => {
            STOP.store(true, Ordering::SeqCst);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    // Never unwind across the SCM callback ABI.
    let result = std::panic::catch_unwind(|| unsafe { service_body(argc, argv) });
    let failure = match result {
        // The completed callback has already persisted its outcome before
        // publishing SERVICE_STOPPED. No work is safe after that publication.
        Ok(Ok(ServiceCompletion::Clean | ServiceCompletion::Failed)) => None,
        Ok(Err(error)) => Some(error),
        Err(payload) => Some(if let Some(text) = payload.downcast_ref::<String>() {
            text.clone()
        } else if let Some(text) = payload.downcast_ref::<&str>() {
            (*text).to_owned()
        } else {
            "service callback panicked with a non-string payload".into()
        }),
    };
    if let Some(error) = failure {
        if let Err(record_error) = record_service_failure(&error) {
            eprintln!("service failure ({error}); recording failed ({record_error})");
        }
        SERVICE_EXIT.store(1, Ordering::SeqCst);
        // A failed fixture must terminate rather than leave SCM reporting a
        // live server whose validation thread no longer exists.
        std::process::exit(2);
    }
}

fn record_service_failure(error: &str) -> Result<()> {
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = image
        .parent()
        .ok_or("missing fixture image parent")?
        .join(format!(
            "service-process-{}.failure.txt",
            std::process::id()
        ));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let text: String = error.chars().take(4096).collect();
    let bytes =
        serde_json::to_vec(&serde_json::json!({"process_id":std::process::id(),"error":text}))
            .map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut output, &bytes).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())
}

unsafe fn service_body(argc: u32, argv: *mut *mut u16) -> Result<ServiceCompletion> {
    if argc != 1 || argv.is_null() {
        return Err("invalid SCM fixture invocation".into());
    }
    let pointer = unsafe { *argv };
    if pointer.is_null() {
        return Err("missing SCM service name".into());
    }
    let mut units = Vec::new();
    for index in 0..=80 {
        let unit = unsafe { *pointer.add(index) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    let name = String::from_utf16(&units).map_err(|e| e.to_string())?;
    if !name.starts_with("CFW-scm-fixture-") || name.len() > 80 {
        return Err("unexpected fixture service name".into());
    }
    let identity = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    if !identity.identity().is_local_system() || identity.identity().session_id() != 0 {
        return Err("fixture service is not SYSTEM in session zero".into());
    }
    configure_service_process_observation().map_err(|e| e.to_string())?;
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(wide(&name).as_ptr(), Some(control), null()) };
    if handle.is_null() {
        return Err(error("register fixture service control"));
    }
    let result = transport::serve(&name, handle);
    // The second fixture owns cleanup of their shared, uniquely named record.
    // The first leaves it for observation after its process has exited.
    let cleanup = if name.ends_with("-b") {
        let machine = machine_record::cleanup(&name);
        let journal = authority_journal::cleanup_shared(&name);
        match (machine, journal) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(machine), Err(journal)) => Err(format!("{machine}; journal cleanup: {journal}")),
        }
    } else {
        Ok(())
    };
    let result = match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(format!("{operation}; record cleanup: {cleanup}")),
    };
    drop(identity);
    let completion = match result {
        Ok(()) => ServiceCompletion::Clean,
        Err(error) => {
            record_service_failure(&error)?;
            SERVICE_EXIT.store(1, Ordering::SeqCst);
            ServiceCompletion::Failed
        }
    };
    status(
        handle,
        SERVICE_STOPPED,
        match completion {
            ServiceCompletion::Clean => 0,
            ServiceCompletion::Failed => ERROR_SERVICE_SPECIFIC_ERROR,
        },
    )?;
    Ok(completion)
}

fn status(handle: SERVICE_STATUS_HANDLE, state: u32, exit: u32) -> Result<()> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP
        } else {
            0
        },
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: u32::from(exit != 0),
        dwWaitHint: if state == SERVICE_STOP_PENDING {
            5000
        } else {
            0
        },
        ..Default::default()
    };
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        return Err(error("publish fixture service status"));
    }
    Ok(())
}

async fn connect(name: &str) -> Result<LocalServicePipe> {
    let deadline = Instant::now() + LIMIT;
    loop {
        match LocalServicePipe::open(name, ServiceClientRole::Desktop) {
            Ok(pipe) => return Ok(pipe),
            Err(ServicePeerError::Native { source, .. })
                if matches!(source.raw_os_error(), Some(2 | 231)) && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn ping(pipe: &mut LocalServicePipe) -> Result<()> {
    let deadline = Instant::now() + LIMIT;
    pipe.write_message(b"ping", deadline)
        .map_err(|e| format!("fixture ping write: {e}"))?;
    let reply = pipe
        .read_message(deadline)
        .map_err(|e| format!("fixture ping read: {e}"))?;
    if reply.as_bytes() != b"pong" {
        return Err("fixture response mismatch".into());
    }
    Ok(())
}

fn finish(pipe: &mut LocalServicePipe) -> Result<()> {
    finish_with_read_delay(pipe, Duration::ZERO)
}

fn finish_with_read_delay(pipe: &mut LocalServicePipe, delay: Duration) -> Result<()> {
    let deadline = Instant::now() + LIMIT;
    pipe.write_message(b"done", deadline)
        .map_err(|e| format!("fixture finish write: {e}"))?;
    thread::sleep(delay);
    let reply = pipe
        .read_message(deadline)
        .map_err(|e| format!("fixture finish read: {e}"))?;
    if reply.as_bytes() != b"end!" {
        return Err("fixture completion mismatch".into());
    }
    Ok(())
}

struct Installed {
    handle: Sc,
    name: String,
    removed: bool,
    cleanup_on_drop: bool,
    process: Option<OwnedHandle>,
}
impl Installed {
    fn open_existing(name: String) -> Result<Self> {
        let manager = Sc(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(error("open fixture SCM for desktop checks"));
        }
        let handle =
            Sc(unsafe { OpenServiceW(manager.0, wide(&name).as_ptr(), SERVICE_ALL_ACCESS) });
        if handle.0.is_null() {
            return Err(error("open existing disposable service"));
        }
        let mut result = Self {
            handle,
            name,
            removed: false,
            cleanup_on_drop: false,
            process: None,
        };
        let status = result.query()?;
        if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err("existing disposable service is not running".into());
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                status.dwProcessId,
            )
        };
        if process.is_null() {
            return Err(error("retain existing disposable service process"));
        }
        result.process = Some(unsafe { OwnedHandle::from_raw_handle(process) });
        Ok(result)
    }

    fn create(manager: &Sc, name: String, path: &Path) -> Result<Self> {
        let command = wide(&format!("\"{}\"", path.display()));
        let handle = Sc(unsafe {
            CreateServiceW(
                manager.0,
                wide(&name).as_ptr(),
                wide(&name).as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        });
        if handle.0.is_null() {
            return Err(error("create disposable service"));
        }
        let mut result = Self {
            handle,
            name,
            removed: false,
            cleanup_on_drop: true,
            process: None,
        };
        let owner = Descriptor::new("O:BA")?;
        if unsafe { SetServiceObjectSecurity(result.handle.0, OWNER_SECURITY_INFORMATION, owner.0) }
            == 0
        {
            return Err(error("set disposable service owner"));
        }
        result.acl(SERVICE_ACL)?;
        if unsafe { StartServiceW(result.handle.0, 0, null()) } == 0 {
            return Err(error("start disposable service"));
        }
        result.wait(SERVICE_RUNNING)?;
        let process = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                result.query()?.dwProcessId,
            )
        };
        if process.is_null() {
            return Err(error("retain disposable service process"));
        }
        result.process = Some(unsafe { OwnedHandle::from_raw_handle(process) });
        Ok(result)
    }
    fn binary(&self, image: &Path) -> Result<()> {
        let command = wide(&format!("\"{}\"", image.display()));
        if unsafe {
            ChangeServiceConfigW(
                self.handle.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } == 0
        {
            return Err(error("change disposable service next-start image"));
        }
        Ok(())
    }
    fn acl(&self, text: &str) -> Result<()> {
        let descriptor = Descriptor::new(text)?;
        if unsafe {
            SetServiceObjectSecurity(self.handle.0, DACL_SECURITY_INFORMATION, descriptor.0)
        } == 0
        {
            return Err(error("set disposable service ACL"));
        }
        Ok(())
    }
    fn query(&self) -> Result<SERVICE_STATUS_PROCESS> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                self.handle.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(error("query disposable service"));
        }
        Ok(status)
    }
    fn wait(&self, expected: u32) -> Result<()> {
        let deadline = Instant::now() + LIMIT;
        loop {
            let status = self.query()?;
            if status.dwCurrentState == expected {
                return Ok(());
            }
            if (expected == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
                || Instant::now() >= deadline
            {
                return Err(format!(
                    "fixture service state={}, exit={}, expected={expected}",
                    status.dwCurrentState, status.dwWin32ExitCode
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&self) -> Result<()> {
        if self.query()?.dwCurrentState != SERVICE_STOPPED {
            let mut status = SERVICE_STATUS::default();
            if unsafe { ControlService(self.handle.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
                return Err(error("stop disposable service"));
            }
            self.wait(SERVICE_STOPPED)?;
        }
        if let Some(process) = &self.process
            && cfw_windows_storage::wait_until(process, Instant::now() + LIMIT)
                .map_err(|e| e.to_string())?
                != cfw_windows_storage::WaitOutcome::Signaled
        {
            return Err("disposable service process remained after SCM stop".into());
        }
        Ok(())
    }
    fn normal_stop(&self) -> Result<()> {
        if self.query()?.dwCurrentState != SERVICE_RUNNING {
            return Err("fixture service exited before its requested stop".into());
        }
        self.stop()?;
        let status = self.query()?;
        let process = self
            .process
            .as_ref()
            .ok_or("missing service process identity")?;
        let mut exit = u32::MAX;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
            return Err(error("read stopped fixture process exit"));
        }
        if status.dwWin32ExitCode != 0 || status.dwServiceSpecificExitCode != 0 || exit != 0 {
            return Err(format!(
                "fixture service failed during stop: win32={}, service={}, process={exit}",
                status.dwWin32ExitCode, status.dwServiceSpecificExitCode
            ));
        }
        Ok(())
    }
    fn remove(&mut self) -> Result<()> {
        self.stop()?;
        if unsafe { DeleteService(self.handle.0) } == 0 {
            return Err(error("delete disposable service"));
        }
        self.removed = true;
        Ok(())
    }
}
impl Drop for Installed {
    fn drop(&mut self) {
        if self.cleanup_on_drop
            && !self.removed
            && let Err(e) = self.remove()
        {
            panic!("disposable service cleanup failed: {e}");
        }
    }
}

fn run_validation() -> Result<()> {
    let source = std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?;
    if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid service receipt source".into());
    }
    let receipt_root = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS")
            .ok_or("missing service receipt directory")?,
    );
    if !receipt_root.is_absolute() || !receipt_root.is_dir() {
        return Err("invalid service receipt directory".into());
    }
    let root = tempfile::tempdir().map_err(|e| e.to_string())?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_in_directory(root.path(), &receipt_root, &source)
    }));
    collect_fixture_diagnostics(root.path(), &receipt_root)?;
    match result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn collect_fixture_diagnostics(root: &Path, output: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            return Err("non-Unicode fixture diagnostic filename".into());
        };
        if !text.ends_with(".failure.txt")
            && !text.ends_with("-client.json")
            && !text.ends_with("-client-output.txt")
            && !text.ends_with(".rejection.json")
            && !text.ends_with(".journal-validation.json")
            && !text.ends_with(".authority-validation.json")
            && !text.ends_with(".wire-validation.json")
            && !text.ends_with(".stress-validation.json")
        {
            continue;
        }
        if !entry.file_type().map_err(|e| e.to_string())?.is_file()
            || entry.metadata().map_err(|e| e.to_string())?.len() > 16384
        {
            return Err("invalid fixture diagnostic file".into());
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut target, &bytes).map_err(|e| e.to_string())?;
        target.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run_in_directory(root: &Path, receipt_root: &Path, source: &str) -> Result<()> {
    let image = root.join("service-fixture.exe");
    std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
        .map_err(|e| e.to_string())?;
    let expected = digest(&image)?;
    let replacement = root.join("same-bytes-other-file.exe");
    std::fs::copy(&image, &replacement).map_err(|e| e.to_string())?;
    assert_eq!(digest(&replacement)?, expected);
    transport::write_installation(root, &image, expected)?;
    let manager = Sc(unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    });
    if manager.0.is_null() {
        return Err(error("open fixture SCM"));
    }
    let prefix = format!("CFW-scm-fixture-{}", uuid::Uuid::new_v4());
    let mut first = Installed::create(&manager, format!("{prefix}-a"), &image)?;
    let mut second = Installed::create(&manager, format!("{prefix}-b"), &image)?;
    let tests = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transport::run_desktop_validation(root, &prefix, expected)
    }));
    let restored_first = first.remove();
    let restored_second = second.remove();
    restored_first?;
    restored_second?;
    drop((first, second));
    match tests {
        Ok(result) => result?,
        Err(payload) => std::panic::resume_unwind(payload),
    }
    authority_journal::require_reports(root)?;
    authority_state::require_report(root)?;
    authority_wire::require_report(root)?;
    for suffix in ["a", "b"] {
        let check = Sc(unsafe {
            OpenServiceW(
                manager.0,
                wide(&format!("{prefix}-{suffix}")).as_ptr(),
                SERVICE_QUERY_STATUS,
            )
        });
        if !check.0.is_null()
            || io::Error::last_os_error().raw_os_error()
                != Some(ERROR_SERVICE_DOES_NOT_EXIST as i32)
        {
            return Err("fixture service deletion was not observed".into());
        }
    }
    let receipt = serde_json::json!({"product_source":source,"cases_passed":["scm_image_and_pipe_identity","delayed_terminal_reply_preserved","different_system_service_rejected","unsafe_service_acl_rejected","changed_configuration_revokes_peer","identical_copy_is_not_the_running_image","missing_service_remains_an_error","unprivileged_client_admitted","desktop_role_client_authenticated","wrong_client_role_rejected","identical_client_copy_rejected","unprivileged_pipe_instance_creation_rejected","queued_message_identity_rejected","oversized_message_rejected","client_message_timeout_poisoned","server_message_timeout_released","live_console_session_authorized","agent_without_lease_rejected","foreign_logon_lease_rejected","agent_observation_without_lease_admitted","stopped_service_is_not_authority","post_stop_connection_stress","system_machine_record_publication","casefolded_machine_record_mutex","malformed_machine_record_rejected","unsafe_machine_record_acl_rejected","unprivileged_machine_record_access_rejected","machine_record_survives_service_exit","machine_records_removed","authority_journal_crash_recovery","authority_journal_survives_service_exit","authority_policy_publication_and_request_lifetime","authority_wire_native_user_agent_binding","temporary_services_removed"],"service_fixture_only":true,"post_stop_exchange_repetitions":POST_STOP_EXCHANGES,"full_service_backend_proven":false,"release_accepted":false});
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipt_root.join("service-peer-receipt.json"))
        .map_err(|e| e.to_string())?;
    std::io::Write::write_all(
        &mut output,
        serde_json::to_string_pretty(&receipt)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn exercise_services(
    first: &Installed,
    second: &Installed,
    prefix: &str,
    image: &Path,
    expected: [u8; 32],
) -> Result<()> {
    let replacement = image
        .parent()
        .ok_or("missing fixture image parent")?
        .join("same-bytes-other-file.exe");
    runtime()?.block_on(async {
        println!("service fixture stage: scm_image_and_pipe_identity");
        let mut pipe = connect(&first.name).await?;
        let peer = WindowsServicePeer::from_pipe_server(
            &first.name,
            verified(image, expected)?,
            &pipe,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(peer.process_id(), first.query()?.dwProcessId);
        assert!(peer.process_creation_time() > 0);
        ping(&mut pipe)?;
        peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
        println!("service fixture stage: delayed_terminal_reply_preserved");
        finish_with_read_delay(&mut pipe, Duration::from_millis(200))?;
        drop((peer, pipe));

        println!("service fixture stage: system_machine_record_publication");
        machine_record::request(&first.name, image, expected, b"machine-record-seed")?;
        println!("service fixture stage: authority_journal_crash_recovery");
        authority_journal::request(&first.name, image, expected, b"authority-journal")?;
        println!("service fixture stage: authority_policy_publication_and_request_lifetime");
        authority_state::request(&first.name, image, expected)?;
        println!("service fixture stage: authority_wire_native_user_agent_binding");
        authority_wire::run(&first.name,image,expected)?;

        println!("service fixture stage: different_system_service_rejected");
        let mut other = connect(&second.name).await?;
        assert!(matches!(
            WindowsServicePeer::from_pipe_server(
                &first.name,
                verified(image, expected)?,
                &other
            ),
            Err(ServicePeerError::WrongProcess)
        ));
        ping(&mut other)?;
        finish(&mut other)?;
        drop(other);

        println!("service fixture stage: unsafe_service_acl_rejected");
        let mut pipe = connect(&first.name).await?;
        let peer = WindowsServicePeer::from_pipe_server(&first.name, verified(image, expected)?, &pipe).map_err(|e| e.to_string())?;
        first.acl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORCWP;;;AU)")?;
        assert!(matches!(peer.verify_pipe_server(&pipe), Err(ServicePeerError::UnsafeServiceSecurity)));
        assert!(matches!(
            WindowsServicePeer::from_pipe_server(
                &first.name,
                verified(image, expected)?,
                &pipe
            ),
            Err(ServicePeerError::UnsafeServiceSecurity)
        ));
        first.acl(SERVICE_ACL)?;
        peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
        println!("service fixture stage: changed_configuration_revokes_peer");
        first.binary(&replacement)?;
        assert!(matches!(peer.verify_pipe_server(&pipe), Err(ServicePeerError::ConfigurationMismatch)));
        // SCM now describes the next launch of an identical file copy.
        // The running process still maps the original file, so matching
        // a registry command and hash alone must not admit that identity.
        match WindowsServicePeer::from_pipe_server(&first.name, verified(&replacement, expected)?, &pipe) {
            Err(ServicePeerError::Executable(cfw_windows_engine::Error::ExecutableIdentity)) => {}
            Err(error) => panic!("live image mismatch returned a different failure: {error:?}"),
            Ok(_) => panic!("the next-start copy was admitted as the running image"),
        }
        first.binary(image)?;
        peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
        assert!(matches!(WindowsServicePeer::from_pipe_server(&format!("{prefix}-missing"), verified(image, expected)?, &pipe),
            Err(ServicePeerError::Native { source, .. }) if source.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32)));
        ping(&mut pipe)?;
        finish(&mut pipe)?;
        drop((peer, pipe));
        Ok::<_, String>(())
    })?;
    println!("service fixture stage: unprivileged_client_admitted");
    restricted::run(image, &first.name, expected)?;
    let root = image.parent().ok_or("missing fixture image parent")?;
    transport::require_rejection(
        root,
        &first.name,
        ServiceClientRole::Desktop,
        "executable_mismatch",
    )?;
    for rejection in ["lease_required", "lease_owner_mismatch"] {
        transport::require_rejection(root, &first.name, ServiceClientRole::UserAgent, rejection)?;
    }
    println!("service fixture stage: identical_client_copy_rejected");
    restricted::run_rejected_copy(&replacement, &first.name, expected)?;
    transport::require_rejection(
        root,
        &first.name,
        ServiceClientRole::UserAgent,
        "executable_mismatch",
    )?;
    println!("service fixture stage: queued_message_identity_rejected");
    attacks::queued_identity(root, &first.name, first.query()?.dwProcessId)?;
    println!("service fixture stage: oversized_message_rejected");
    attacks::oversized(root, &first.name, first.query()?.dwProcessId)?;
    println!("service fixture stage: client_message_timeout_poisoned");
    attacks::client_deadline(&first.name, image, expected)?;
    println!("service fixture stage: server_message_timeout_released");
    attacks::server_deadline(root, &first.name, first.query()?.dwProcessId)?;
    runtime()?.block_on(async {
        let mut pipe = connect(&first.name).await?;
        ping(&mut pipe)?;
        finish(&mut pipe)
    })?;
    println!("service fixture stage: stopped_service_is_not_authority");
    first.normal_stop()?;
    println!("service fixture stage: first_service_stopped");
    println!("service fixture stage: machine_record_survives_service_exit");
    machine_record::request(&second.name, image, expected, b"machine-record-observe")?;
    println!("service fixture stage: authority_journal_survives_service_exit");
    authority_journal::request(&second.name, image, expected, b"authority-journal-observe")?;
    println!("service fixture stage: post_stop_connection_stress");
    stress::run(&first.name, &second.name, image, expected)?;
    println!("service fixture post-stop exchanges passed: {POST_STOP_EXCHANGES}");
    second.normal_stop()?;
    Ok(())
}
