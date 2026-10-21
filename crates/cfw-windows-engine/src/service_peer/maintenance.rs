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
impl ServiceControl {
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
    /// Stop exactly one admitted live process. Already-stopped services use
    /// the separate native absence check, never a fabricated process exit.
    pub(crate) fn drain(&self, expected_start: u32, deadline: Instant) -> Result<bool> {
        if !matches!(expected_start, SERVICE_AUTO_START | SERVICE_DEMAND_START)
            || self.start_type()? != expected_start
        {
            return Err(ServicePeerError::ConfigurationMismatch);
        }
        let status = self.status()?;
        if status.dwCurrentState == SERVICE_STOPPED {
            self.require_stopped(expected_start)?;
            return Ok(false);
        }
        let pid = validate_status(&status)?;
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
        let created = process_creation(&process, pid)?;
        verify_process_image(&self.image, &process)?;
        let peer = crate::NativePeerProcess::open(pid)?;
        let identity = peer.identity();
        if identity.process_creation_time() != created
            || !identity.is_local_system()
            || identity.session_id() != 0
            || identity.integrity_rid() != 0x4000
            || identity.is_restricted()
            || identity.is_app_container()
        {
            return Err(ServicePeerError::WrongProcess);
        }
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
                        return Ok(true);
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
