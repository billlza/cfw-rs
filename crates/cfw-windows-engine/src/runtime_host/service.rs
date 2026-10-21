use super::*;
use crate::{
    LocalServiceConnection, LocalServiceListener, ServiceClientRole, ServiceTransportError,
    authority::WindowsAuthority,
};
use cfw_engine_api::authority_v1::AuthorityState;
use cfw_windows_storage::PrivateDirectory;
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR},
    System::Services::*,
};

// SCM invokes C callbacks without a Rust receiver. Exactly one service is
// hosted in this process; only the stop request and terminal exit cross the ABI.
static STOP: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
const TICK: Duration = Duration::from_millis(100);
const COMMAND: Duration = Duration::from_secs(5);
const SHUTDOWN: Duration = Duration::from_secs(30);
struct WakeOnExit(Arc<AtomicBool>);
impl Drop for WakeOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub fn run_service() -> Result<()> {
    let mut name: Vec<u16> = SERVICE_NAME.encode_utf16().chain([0]).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if FAILED.load(Ordering::Acquire) {
        return Err(HostError::State(
            "SCM runtime ended with a recorded failure",
        ));
    }
    Ok(())
}
unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP => {
            STOP.store(true, Ordering::Release);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    let name: Vec<_> = SERVICE_NAME.encode_utf16().chain([0]).collect();
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if handle.is_null() {
        FAILED.store(true, Ordering::Release);
        return;
    }
    let operated = std::panic::catch_unwind(|| -> Result<()> {
        report_status(handle, SERVICE_START_PENDING, 0, 1)?;
        // SCM supplies a service name, never a configuration path or request.
        if argc != 1 || argv.is_null() {
            return Err(HostError::State("invalid SCM invocation"));
        }
        let supplied = unsafe { *argv };
        if supplied.is_null() {
            return Err(HostError::State("missing SCM service name"));
        }
        for (index, unit) in name.iter().enumerate() {
            if unsafe { *supplied.add(index) } != *unit {
                return Err(HostError::State("unexpected SCM service name"));
            }
        }
        crate::configure_service_process_observation()?;
        let installation = InstalledRuntime::open()?;
        installation.require_runtime_process()?;
        super::maintenance::require_service_start_allowed(&installation)?;
        serve(installation, handle)
    });
    let failed = match operated {
        Ok(Ok(())) => false,
        Ok(Err(error)) => {
            eprintln!("{error}");
            true
        }
        Err(_) => {
            eprintln!("Windows runtime service panicked");
            true
        }
    };
    FAILED.store(failed, Ordering::Release);
    // Terminal status is last: SCM may terminate the process immediately.
    if report_status(
        handle,
        SERVICE_STOPPED,
        if failed {
            ERROR_SERVICE_SPECIFIC_ERROR
        } else {
            0
        },
        0,
    )
    .is_err()
    {
        FAILED.store(true, Ordering::Release);
    }
}
fn report_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    exit: u32,
    checkpoint: u32,
) -> Result<()> {
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
        dwCheckPoint: checkpoint,
        dwWaitHint: if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            5000
        } else {
            0
        },
    };
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn serve(installation: InstalledRuntime, status: SERVICE_STATUS_HANDLE) -> Result<()> {
    let root = InstalledRuntime::machine_root()?;
    let diagnostics = Arc::new(PrivateDirectory::open_or_create(&root.join("diagnostics"))?);
    let mut controller = WindowsAuthority::open(&root.join("journal"), SERVICE_NAME)?;
    if controller
        .recovery_target()
        .is_some_and(|m| m.state() == AuthorityState::Off)
    {
        controller.verify_recorded_off()?;
    }
    let authority = Arc::new(Mutex::new(controller));
    let done = Arc::new(AtomicBool::new(false));
    let operated = thread::scope(|scope| -> Result<()> {
        let _wake = WakeOnExit(Arc::clone(&done));
        let (ready_send, ready_receive) = mpsc::sync_channel(2);
        let mut listeners = Vec::new();
        for (role, image) in [
            (ServiceClientRole::Desktop, installation.desktop()?),
            (ServiceClientRole::UserAgent, installation.runtime()?),
        ] {
            let authority = Arc::clone(&authority);
            let done = Arc::clone(&done);
            let diagnostics = Arc::clone(&diagnostics);
            let ready = ready_send.clone();
            listeners.push(
                scope.spawn(move || listen(role, image, authority, done, diagnostics, ready)),
            );
        }
        drop(ready_send);
        let running = (|| -> Result<()> {
            for _ in 0..2 {
                ready_receive
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|_| HostError::State("service listeners did not initialize"))??;
            }
            report_status(status, SERVICE_RUNNING, 0, 0)?;
            let mut drain = None;
            let mut last_error = None;
            loop {
                if listeners.iter().any(|worker| worker.is_finished()) {
                    return Err(HostError::State("service listener stopped unexpectedly"));
                }
                let mut state = authority
                    .lock()
                    .map_err(|_| HostError::State("authority guard poisoned"))?;
                if STOP.load(Ordering::Acquire) && drain.is_none() {
                    state.start_service_drain()?;
                    drain = Some(Instant::now() + SHUTDOWN);
                }
                match state.supervise() {
                    Ok(_) => {
                        last_error = None;
                    }
                    Err(error) => {
                        let text = error.to_string();
                        if last_error.as_ref() != Some(&text) {
                            record(&diagnostics, "supervision", &text)?;
                            last_error = Some(text);
                        }
                    }
                }
                let snapshot = state.snapshot();
                if drain.is_some()
                    && snapshot.state == AuthorityState::Off
                    && snapshot.revision.is_some()
                {
                    break;
                }
                if drain.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(HostError::State(
                        "service stop could not prove global Off before its deadline",
                    ));
                }
                drop(state);
                thread::sleep(TICK);
            }
            // Keep SCM Running throughout restoration so authenticated user
            // cleanup remains available; StopPending begins only after Off.
            report_status(status, SERVICE_STOP_PENDING, 0, 1)
        })();
        done.store(true, Ordering::Release);
        let mut cleanup = Ok(());
        for worker in listeners {
            let joined = worker
                .join()
                .map_err(|_| HostError::State("service listener panicked"))
                .and_then(|r| r);
            cleanup = combine(cleanup, joined);
        }
        combine(running, cleanup)
    });
    match operated {
        Ok(()) => Ok(()),
        Err(error) => {
            let recording = record(&diagnostics, "service", &error.to_string());
            combine(Err(error), recording)
        }
    }
}
fn listen(
    role: ServiceClientRole,
    image: crate::VerifiedExecutable,
    authority: Arc<Mutex<WindowsAuthority>>,
    done: Arc<AtomicBool>,
    diagnostics: Arc<PrivateDirectory>,
    ready: mpsc::SyncSender<Result<()>>,
) -> Result<()> {
    let listener = LocalServiceListener::bind(SERVICE_NAME, role, image);
    let mut listener = match listener {
        Ok(value) => value,
        Err(error) => {
            ready
                .send(Err(error.into()))
                .map_err(|_| HostError::State("service initialization receiver closed"))?;
            return Ok(());
        }
    };
    ready
        .send(Ok(()))
        .map_err(|_| HostError::State("service initialization receiver closed"))?;
    thread::scope(|scope| -> Result<()> {
        let _wake = WakeOnExit(Arc::clone(&done));
        let mut workers: Vec<thread::ScopedJoinHandle<'_, Result<()>>> = Vec::new();
        let operation = (|| -> Result<()> {
            while !done.load(Ordering::Acquire) {
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        workers.swap_remove(index).join().map_err(|_| {
                            HostError::State("service connection worker panicked")
                        })??;
                    } else {
                        index += 1;
                    }
                }
                match listener.accept(Instant::now() + TICK) {
                    Ok(connection) => {
                        let authority = Arc::clone(&authority);
                        let done = Arc::clone(&done);
                        let diagnostics = Arc::clone(&diagnostics);
                        workers.push(scope.spawn(move || {
                            connection_loop(connection, &authority, &done, &diagnostics)
                        }));
                    }
                    Err(ServiceTransportError::Deadline) => {}
                    Err(ServiceTransportError::Capacity) => thread::sleep(TICK),
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        done.store(true, Ordering::Release);
        let mut cleanup = listener.close().map_err(HostError::from);
        for worker in workers {
            cleanup = combine(
                cleanup,
                worker
                    .join()
                    .map_err(|_| HostError::State("service connection worker panicked"))
                    .and_then(|r| r),
            );
        }
        combine(operation, cleanup)
    })
}
fn connection_loop(
    mut connection: LocalServiceConnection,
    authority: &Mutex<WindowsAuthority>,
    done: &AtomicBool,
    diagnostics: &PrivateDirectory,
) -> Result<()> {
    let operation = (|| -> Result<()> {
        while !done.load(Ordering::Acquire) {
            let request = match connection
                .receive_cancellable(Instant::now() + Duration::from_secs(15), done)
            {
                Ok(request) => request,
                Err(ServiceTransportError::Cancelled) if done.load(Ordering::Acquire) => {
                    return Ok(());
                }
                Err(ServiceTransportError::Closed) => return Ok(()),
                Err(error) => {
                    record(diagnostics, "connection", &error.to_string())?;
                    return Ok(());
                }
            };
            let mut state = authority
                .lock()
                .map_err(|_| HostError::State("authority guard poisoned"))?;
            let reply = match state.handle(&mut connection, request, Instant::now() + COMMAND) {
                Ok(reply) => reply,
                Err(error) => {
                    record(diagnostics, "request_admission", &error.to_string())?;
                    return Ok(());
                }
            };
            if let Some(error) = reply.rejection() {
                record(diagnostics, "request_rejection", &error.to_string())?;
            }
            if let Err(error) = reply.send(&mut connection, Instant::now() + COMMAND) {
                record(diagnostics, "reply", &error.to_string())?;
                return Ok(());
            }
        }
        Ok(())
    })();
    connection.close();
    operation
}
fn record(directory: &PrivateDirectory, stage: &str, error: &str) -> Result<()> {
    let error: String = error.chars().take(2048).collect();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"stage":stage,"error":error,"process_id":std::process::id()}),
    )
    .map_err(|_| HostError::State("diagnostic encoding failed"))?;
    directory
        .write()?
        .replace("last-runtime-error.json", &bytes, 16384)?;
    Ok(())
}
fn combine(operation: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (operation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(HostError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}
