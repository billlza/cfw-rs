use cfw_windows_engine::{
    LocalServicePipe, NativePeerProcess, ServicePeerError, VerifiedExecutable, WindowsServicePeer,
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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{Services::*, Threading::*},
};

mod restricted;
type Result<T> = std::result::Result<T, String>;
const LIMIT: Duration = Duration::from_secs(15);
const SERVICE_ACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)";
// SCM invokes process-wide ABI callbacks. Each fixture process hosts one
// service, so these bounded callback cells live until the process exits.
static STOP: AtomicBool = AtomicBool::new(false);
static SERVICE_EXIT: AtomicU32 = AtomicU32::new(0);

fn error(operation: &str) -> String {
    format!("{operation}: {}", io::Error::last_os_error())
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}
fn pipe_name(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
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
    if args.len() == 4 && args[1] == "--client" {
        return restricted::client(&args[2], &args[3]);
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
    if !matches!(result, Ok(Ok(()))) {
        SERVICE_EXIT.store(1, Ordering::SeqCst);
        // A failed fixture must terminate rather than leave SCM reporting a
        // live server whose validation thread no longer exists.
        std::process::exit(2);
    }
}

unsafe fn service_body(argc: u32, argv: *mut *mut u16) -> Result<()> {
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
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(wide(&name).as_ptr(), Some(control), null()) };
    if handle.is_null() {
        return Err(error("register fixture service control"));
    }
    let runtime = runtime()?;
    let result = runtime.block_on(async {
        let mut pipe = server(&name)?;
        status(handle, SERVICE_RUNNING, 0)?;
        while !STOP.load(Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(50), pipe.connect()).await {
                Err(_) => continue,
                Ok(Err(e)) => return Err(e.to_string()),
                Ok(Ok(())) => {}
            }
            let conversation = tokio::time::timeout(LIMIT, async {
                let mut bytes = [0; 4];
                pipe.read_exact(&mut bytes)
                    .await
                    .map_err(|e| e.to_string())?;
                if bytes != *b"ping" {
                    return Err("unexpected fixture request".into());
                }
                pipe.write_all(b"pong").await.map_err(|e| e.to_string())?;
                pipe.read_exact(&mut bytes)
                    .await
                    .map_err(|e| e.to_string())?;
                if bytes != *b"done" {
                    return Err("fixture completion mismatch".into());
                }
                Ok(())
            });
            let conversation = tokio::select! {
                result = conversation => result,
                () = async {
                    while !STOP.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                } => break,
            };
            match conversation {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err("fixture client conversation timed out".into()),
            }
            pipe.disconnect().map_err(|e| e.to_string())?;
        }
        status(handle, SERVICE_STOP_PENDING, 0)?;
        Ok(())
    });
    status(
        handle,
        SERVICE_STOPPED,
        if result.is_ok() {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
    )?;
    result
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

fn server(name: &str) -> Result<NamedPipeServer> {
    let descriptor = Descriptor::new("O:SYD:P(A;;GA;;;SY)(A;;GRGW;;;AU)")?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                pipe_name(name),
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
    .map_err(|e| e.to_string())
}

async fn connect(name: &str) -> Result<LocalServicePipe> {
    let deadline = Instant::now() + LIMIT;
    loop {
        match LocalServicePipe::open(name) {
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

async fn ping(pipe: &mut LocalServicePipe) -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        pipe.write_all(b"ping").await.map_err(|e| e.to_string())?;
        let mut reply = [0; 4];
        pipe.read_exact(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        if reply != *b"pong" {
            return Err("fixture response mismatch".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "fixture response deadline".to_string())?
}

async fn finish(pipe: &mut LocalServicePipe) -> Result<()> {
    tokio::time::timeout(LIMIT, pipe.write_all(b"done"))
        .await
        .map_err(|_| "fixture completion deadline".to_string())?
        .map_err(|e| e.to_string())
}

struct Installed {
    handle: Sc,
    name: String,
    removed: bool,
    process: Option<OwnedHandle>,
}
impl Installed {
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
        let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, result.query()?.dwProcessId) };
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
        if !self.removed
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
    let image = root.path().join("service-fixture.exe");
    std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &image)
        .map_err(|e| e.to_string())?;
    let expected = digest(&image)?;
    let replacement = root.path().join("same-bytes-other-file.exe");
    std::fs::copy(&image, &replacement).map_err(|e| e.to_string())?;
    assert_eq!(digest(&replacement)?, expected);
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
    let tests = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        runtime()?.block_on(async {
            let mut pipe = connect(&first.name).await?;
            let peer = WindowsServicePeer::from_pipe_server(
                &first.name,
                verified(&image, expected)?,
                &pipe,
            )
            .map_err(|e| e.to_string())?;
            assert_eq!(peer.process_id(), first.query()?.dwProcessId);
            assert!(peer.process_creation_time() > 0);
            ping(&mut pipe).await?;
            peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
            finish(&mut pipe).await?;
            drop((peer, pipe));

            let mut other = connect(&second.name).await?;
            assert!(matches!(
                WindowsServicePeer::from_pipe_server(
                    &first.name,
                    verified(&image, expected)?,
                    &other
                ),
                Err(ServicePeerError::WrongProcess)
            ));
            ping(&mut other).await?;
            finish(&mut other).await?;
            drop(other);

            let mut pipe = connect(&first.name).await?;
            let peer = WindowsServicePeer::from_pipe_server(&first.name, verified(&image, expected)?, &pipe).map_err(|e| e.to_string())?;
            first.acl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORCWP;;;AU)")?;
            assert!(matches!(peer.verify_pipe_server(&pipe), Err(ServicePeerError::UnsafeServiceSecurity)));
            assert!(matches!(
                WindowsServicePeer::from_pipe_server(
                    &first.name,
                    verified(&image, expected)?,
                    &pipe
                ),
                Err(ServicePeerError::UnsafeServiceSecurity)
            ));
            first.acl(SERVICE_ACL)?;
            peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
            first.binary(&replacement)?;
            assert!(matches!(peer.verify_pipe_server(&pipe), Err(ServicePeerError::ConfigurationMismatch)));
            // SCM now describes the next launch of an identical file copy.
            // The running process still maps the original file, so matching
            // a registry command and hash alone must not admit that identity.
            assert!(matches!(WindowsServicePeer::from_pipe_server(&first.name, verified(&replacement, expected)?, &pipe),
                Err(ServicePeerError::Executable(cfw_windows_engine::Error::ExecutableIdentity))));
            first.binary(&image)?;
            peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
            assert!(matches!(WindowsServicePeer::from_pipe_server(&format!("{prefix}-missing"), verified(&image, expected)?, &pipe),
                Err(ServicePeerError::Native { source, .. }) if source.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32)));
            ping(&mut pipe).await?;
            finish(&mut pipe).await?;
            drop((peer, pipe));
            Ok::<_, String>(())
        })?;
        restricted::run(&image, &first.name, expected)?;
        first.stop()?;
        runtime()?.block_on(async {
            let mut pipe = connect(&second.name).await?;
            assert!(matches!(
                WindowsServicePeer::from_pipe_server(
                    &first.name,
                    verified(&image, expected)?,
                    &pipe
                ),
                Err(ServicePeerError::NotRunning)
            ));
            ping(&mut pipe).await?;
            finish(&mut pipe).await
        })?;
        Ok(())
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
    let receipt = serde_json::json!({"product_source":source,"cases_passed":["scm_image_and_pipe_identity","different_system_service_rejected","unsafe_service_acl_rejected","changed_configuration_revokes_peer","identical_copy_is_not_the_running_image","missing_service_remains_an_error","unprivileged_client_admitted","stopped_service_is_not_authority","temporary_services_removed"],"service_fixture_only":true,"full_service_backend_proven":false,"release_accepted":false});
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
