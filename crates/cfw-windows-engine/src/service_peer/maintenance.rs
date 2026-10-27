//! SYSTEM-only control of the fixed installed authority. Disabled services
//! remain forbidden to ordinary peer authentication in the parent module.
use super::*;
use std::{
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Threading::GetExitCodeProcess;

type Result<T> = std::result::Result<T, ServicePeerError>;

pub(crate) struct ServiceControl {
    service: ServiceHandle,
    image: VerifiedExecutable,
    command: Vec<u16>,
}
pub(crate) struct StartedService {
    process: OwnedHandle,
    process_id: u32,
    created_at: u64,
    started_by_action: bool,
}
#[derive(serde::Serialize)]
pub(crate) struct RetiredService {
    process_id: u32,
    process_creation_time: u64,
}
impl StartedService {
    pub(crate) fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"process_id":self.process_id,"process_creation_time":self.created_at,
            "started_by_action":self.started_by_action})
    }
}
impl ServiceControl {
    /// A missing service is observed only from SCM's explicit not-found code.
    /// Marked-for-deletion, access and I/O errors cannot admit a fresh install.
    pub(crate) fn require_absent() -> Result<()> {
        require_system_maintenance_identity()?;
        let manager = ServiceHandle(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(native("open fresh-install SCM"));
        }
        let name = service_name_wide(crate::runtime_host::SERVICE_NAME)?;
        let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if !service.is_null() {
            let _held = ServiceHandle(service);
            return Err(ServicePeerError::Maintenance(
                "fresh installation requires an absent service",
            ));
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error()
            == Some(windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST as i32)
        {
            Ok(())
        } else {
            Err(ServicePeerError::Native {
                operation: "observe fresh-install service absence",
                source,
            })
        }
    }

    pub(crate) fn open(image: VerifiedExecutable) -> Result<Self> {
        require_system_maintenance_identity()?;
        let manager = ServiceHandle(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(native("open maintenance SCM"));
        }
        let name = service_name_wide(crate::runtime_host::SERVICE_NAME)?;
        let service = ServiceHandle(unsafe {
            OpenServiceW(
                manager.0,
                name.as_ptr(),
                SERVICE_QUERY_CONFIG
                    | SERVICE_QUERY_STATUS
                    | SERVICE_STOP
                    | SERVICE_START
                    | SERVICE_CHANGE_CONFIG
                    | READ_CONTROL,
            )
        });
        if service.0.is_null() {
            return Err(native("open installed maintenance service"));
        }
        let value = Self {
            command: executable_command(image.path())?,
            service,
            image,
        };
        value.start_type()?;
        Ok(value)
    }
    pub(crate) fn start_type(&self) -> Result<u32> {
        require_system_maintenance_identity()?;
        verify_service_security(&self.service)?;
        let buffer = configuration_buffer(&self.service)?;
        let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
        validate_configuration_identity(&buffer, config, &self.command)?;
        if !matches!(
            config.dwStartType,
            SERVICE_AUTO_START | SERVICE_DEMAND_START | SERVICE_DISABLED
        ) {
            return Err(ServicePeerError::ConfigurationMismatch);
        }
        Ok(config.dwStartType)
    }
    fn status(&self) -> Result<SERVICE_STATUS_PROCESS> {
        let status = service_status(&self.service)?;
        if status.dwServiceType != SERVICE_WIN32_OWN_PROCESS || status.dwServiceFlags != 0 {
            return Err(ServicePeerError::ConfigurationMismatch);
        }
        Ok(status)
    }
    fn retain_running(&self, started_by_action: bool) -> Result<StartedService> {
        let pid = validate_status(&self.status()?)?;
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            return Err(native("retain maintenance service process"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let created_at = process_creation(&process, pid)?;
        verify_process_image(&self.image, &process)?;
        let peer = crate::NativePeerProcess::open(pid)?;
        let identity = peer.identity();
        if identity.process_creation_time() != created_at
            || !identity.is_local_system()
            || identity.session_id() != 0
            || identity.integrity_rid() != 0x4000
            || identity.is_restricted()
            || identity.is_app_container()
        {
            return Err(ServicePeerError::WrongProcess);
        }
        let running = StartedService {
            process,
            process_id: pid,
            created_at,
            started_by_action,
        };
        self.verify_running(&running)?;
        Ok(running)
    }
    pub(crate) fn verify_running(&self, running: &StartedService) -> Result<()> {
        self.start_type()?;
        if running_process(&self.service)? != running.process_id
            || process_creation(&running.process, running.process_id)? != running.created_at
        {
            return Err(ServicePeerError::WrongProcess);
        }
        match unsafe { WaitForSingleObject(running.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(ServicePeerError::Exited),
            _ => Err(native("observe maintenance service liveness")),
        }
    }
    /// Capture the original stable state before publishing maintenance intent.
    /// Pending states are not silently classified as stopped.
    pub(crate) fn is_running(&self) -> Result<bool> {
        let start = self.start_type()?;
        match self.status()?.dwCurrentState {
            SERVICE_RUNNING => {
                self.retain_running(false)?;
                Ok(true)
            }
            SERVICE_STOPPED => {
                self.require_stopped(start)?;
                Ok(false)
            }
            _ => Err(ServicePeerError::Maintenance(
                "service is changing state before maintenance",
            )),
        }
    }
    /// SYSTEM only; callers must release the maintenance record lock before
    /// this call, since the service authenticates that record during startup.
    pub(crate) fn start(&self, expected_start: u32, deadline: Instant) -> Result<StartedService> {
        if !matches!(expected_start, SERVICE_AUTO_START | SERVICE_DEMAND_START)
            || self.start_type()? != expected_start
        {
            return Err(ServicePeerError::ConfigurationMismatch);
        }
        let started_by_action = match self.status()?.dwCurrentState {
            SERVICE_RUNNING => return self.retain_running(false),
            // A retry may observe startup initiated before its caller exited.
            SERVICE_START_PENDING => false,
            SERVICE_STOPPED => {
                self.require_stopped(expected_start)?;
                if unsafe { StartServiceW(self.service.0, 0, null()) } == 0 {
                    return Err(native("start installed service"));
                }
                true
            }
            _ => {
                return Err(ServicePeerError::Maintenance(
                    "service cannot start from its current state",
                ));
            }
        };
        loop {
            if Instant::now() >= deadline {
                return Err(ServicePeerError::Maintenance(
                    "service startup exceeded its deadline",
                ));
            }
            if self.start_type()? != expected_start {
                return Err(ServicePeerError::ConfigurationMismatch);
            }
            match self.status()?.dwCurrentState {
                SERVICE_RUNNING => return self.retain_running(started_by_action),
                SERVICE_START_PENDING => thread::sleep(Duration::from_millis(50)),
                _ => {
                    return Err(ServicePeerError::Maintenance(
                        "service did not reach Running during startup",
                    ));
                }
            }
        }
    }
    /// Stop exactly one admitted live process. Already-stopped services use
    /// the separate native absence check, never a fabricated process exit.
    pub(crate) fn drain(
        &self,
        expected_start: u32,
        deadline: Instant,
    ) -> Result<Option<RetiredService>> {
        if !matches!(expected_start, SERVICE_AUTO_START | SERVICE_DEMAND_START)
            || self.start_type()? != expected_start
        {
            return Err(ServicePeerError::ConfigurationMismatch);
        }
        let status = loop {
            let status = self.status()?;
            if status.dwCurrentState != SERVICE_START_PENDING {
                break status;
            }
            if Instant::now() >= deadline {
                return Err(ServicePeerError::Maintenance(
                    "service initialization did not settle before drain",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        };
        if status.dwCurrentState == SERVICE_STOPPED {
            self.require_stopped(expected_start)?;
            return Ok(None);
        }
        let running = self.retain_running(false)?;
        let pid = running.process_id;
        let created = running.created_at;
        let process = running.process;
        if self.start_type()? != expected_start || running_process(&self.service)? != pid {
            return Err(ServicePeerError::WrongProcess);
        }
        // Calibrate the service-session resource view against this retained,
        // still-live SCM process before relying on its absence after stopping.
        // An MSI caller in another session must not accidentally query only
        // its own session and turn an empty list into retirement evidence.
        let observer = require_system_maintenance_identity()?;
        if !observer
            .system_service_processes_using_file(self.image.path())?
            .iter()
            .any(|p| p.process_id() == pid && p.identity().process_creation_time() == created)
        {
            return Err(ServicePeerError::Maintenance(
                "service-session file users did not include the retained SCM process",
            ));
        }
        let mut reported = SERVICE_STATUS::default();
        if unsafe { ControlService(self.service.0, SERVICE_CONTROL_STOP, &mut reported) } == 0 {
            return Err(native("request installed service drain"));
        }
        loop {
            if Instant::now() >= deadline {
                return Err(ServicePeerError::Maintenance(
                    "service drain exceeded its deadline",
                ));
            }
            if self.start_type()? != expected_start {
                return Err(ServicePeerError::ConfigurationMismatch);
            }
            let status = self.status()?;
            if !matches!(
                status.dwCurrentState,
                SERVICE_RUNNING | SERVICE_STOP_PENDING | SERVICE_STOPPED
            ) || (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != pid)
            {
                return Err(ServicePeerError::Maintenance(
                    "service changed during drain",
                ));
            }
            match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
                        return Err(native("read drained service exit"));
                    }
                    if code != 0 {
                        return Err(ServicePeerError::Maintenance(
                            "drained service exited unsuccessfully",
                        ));
                    }
                    if status.dwCurrentState == SERVICE_STOPPED {
                        self.require_stopped(expected_start)?;
                        return Ok(Some(RetiredService {
                            process_id: pid,
                            process_creation_time: created,
                        }));
                    }
                }
                WAIT_TIMEOUT => {}
                _ => return Err(native("wait for drained service process")),
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    pub(crate) fn require_stopped(&self, expected_start: u32) -> Result<()> {
        if self.start_type()? != expected_start || self.status()?.dwCurrentState != SERVICE_STOPPED
        {
            return Err(ServicePeerError::Maintenance(
                "service is not stopped with the expected configuration",
            ));
        }
        // A valid product SCM process is SYSTEM in session zero. This existing
        // resource observer explicitly targets that logon, even when MSI runs
        // SYSTEM in an interactive session. It does not claim that
        // GUI/Agent processes in other user sessions have all exited.
        let observer = require_system_maintenance_identity()?;
        if observer
            .system_service_processes_using_file(self.image.path())?
            .iter()
            .any(|p| p.process_id() != observer.process_id())
        {
            return Err(ServicePeerError::Maintenance(
                "an installed runtime file user remains in the SYSTEM logon",
            ));
        }
        if self.start_type()? != expected_start || self.status()?.dwCurrentState != SERVICE_STOPPED
        {
            return Err(ServicePeerError::Maintenance(
                "service restarted during retirement observation",
            ));
        }
        Ok(())
    }
    pub(crate) fn change_start(&self, expected: u32, replacement: u32) -> Result<()> {
        if !matches!(
            replacement,
            SERVICE_AUTO_START | SERVICE_DEMAND_START | SERVICE_DISABLED
        ) {
            return Err(ServicePeerError::InvalidExpectation);
        }
        self.require_stopped(expected)?;
        if unsafe {
            ChangeServiceConfigW(
                self.service.0,
                SERVICE_NO_CHANGE,
                replacement,
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
            return Err(native("change maintenance service startup"));
        }
        // Keep the durable maintenance record on every failure, including a
        // successful mutation followed by a failed status/config readback.
        self.require_stopped(replacement)
    }
}
