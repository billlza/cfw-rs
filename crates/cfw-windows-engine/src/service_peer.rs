//! Read-only authentication of a connected, dedicated SCM service process.
//! The UI never requests service mutation or SYSTEM-token access. The expected
//! name and executable identity must come from the trusted installation, not IPC.
use std::{
    ffi::OsString,
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    pin::Pin,
    ptr::{null, null_mut},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
};

use windows_sys::Win32::{
    Foundation::{FILETIME, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_SERVICE},
        DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GetAce, GetAclInformation, GetLengthSid,
        INHERIT_ONLY_ACE, IsValidAcl, IsValidSid, IsWellKnownSid, MapGenericMask,
        OWNER_SECURITY_INFORMATION, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        RemoteDesktop::ProcessIdToSessionId,
        Services::*,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{
            GetProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
};

use crate::VerifiedExecutable;

mod observation;
pub use observation::configure_service_process_observation;

const MAX_CONFIG_BYTES: usize = 8192;
const MAX_IMAGE_UNITS: usize = 32768;

#[derive(Debug, thiserror::Error)]
pub enum ServicePeerError {
    #[error("Windows service peer {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows service installation expectation is invalid")]
    InvalidExpectation,
    #[error(
        "Windows service observation setup requires the SYSTEM primary identity in session zero"
    )]
    InvalidServiceProcessIdentity,
    #[error("Windows service process observation permissions did not match after setup")]
    ObservationSecurityMismatch,
    #[error("Windows service primary identity: {0}")]
    ServiceIdentity(#[from] crate::PeerIdentityError),
    #[error("Windows service configuration does not match the installation")]
    ConfigurationMismatch,
    #[error("Windows service can be controlled or reconfigured by an untrusted principal")]
    UnsafeServiceSecurity,
    #[error(
        "Windows service is not running as a dedicated service process (type={service_type:#x}, state={state}, pid={process_id}, flags={flags:#x})"
    )]
    NotRunning {
        service_type: u32,
        state: u32,
        process_id: u32,
        flags: u32,
    },
    #[error("Windows service pipe, process or creation identity does not match")]
    WrongProcess,
    #[error("Windows service process has exited")]
    Exited,
    #[error("Windows service process image: {0}")]
    Executable(#[from] crate::Error),
    #[error("Windows service observer identity: {0}")]
    Observer(#[from] cfw_windows_storage::Error),
}

fn native(operation: &'static str) -> ServicePeerError {
    ServicePeerError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// A connected local pipe opened with identification-only SQOS. No raw-handle
/// import or mutable inner-client access can substitute a remote connection.
pub struct LocalServicePipe {
    client: NamedPipeClient,
    identity: Arc<()>,
}
impl LocalServicePipe {
    /// One connection attempt. The caller owns bounded retry policy for an
    /// expected service startup; native errors are returned without fallback.
    pub fn open(service_name: &str) -> Result<Self, ServicePeerError> {
        cfw_windows_storage::require_process_identity()?;
        service_name_wide(service_name)?;
        let client = ClientOptions::new()
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(format!(r"\\.\pipe\{service_name}"))
            .map_err(|source| ServicePeerError::Native {
                operation: "open local service pipe",
                source,
            })?;
        Ok(Self {
            client,
            identity: Arc::new(()),
        })
    }
}
impl AsRawHandle for LocalServicePipe {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.client.as_raw_handle()
    }
}
impl AsyncRead for LocalServicePipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().client).poll_read(cx, buffer)
    }
}
impl AsyncWrite for LocalServicePipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().client).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().client).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().client).poll_shutdown(cx)
    }
}

/// Retains the SCM object, process and hash-verified executable for one fixed
/// pipe instance. Reconnection needs new admission. This is a synchronous,
/// thread-owned native adapter; keep it on the dedicated IPC worker.
///
/// Configuration describes the next SCM start, so it is checked together with
/// the live process image and session. This does not read the service token or
/// certify its current privileges. The trusted service must verify its own
/// SYSTEM primary identity before publishing its endpoint.
pub struct WindowsServicePeer {
    service: ServiceHandle,
    executable: VerifiedExecutable,
    expected_command: Vec<u16>,
    process: OwnedHandle,
    process_id: u32,
    created_at: u64,
    pipe_identity: Arc<()>,
}

impl WindowsServicePeer {
    /// No network request is sent before native identity admission. The
    /// installation uses a quoted absolute executable with no command arguments.
    /// Missing services, inaccessible objects and pending states remain errors.
    pub fn from_pipe_server(
        service_name: &str,
        executable: VerifiedExecutable,
        pipe: &LocalServicePipe,
    ) -> Result<Self, ServicePeerError> {
        cfw_windows_storage::require_process_identity()?;
        let name = service_name_wide(service_name)?;
        let expected_command = executable_command(executable.path())?;
        let manager = ServiceHandle(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err(native("open local SCM"));
        }
        let service = ServiceHandle(unsafe {
            OpenServiceW(
                manager.0,
                name.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL,
            )
        });
        if service.0.is_null() {
            return Err(native("open expected service"));
        }
        verify_service_security(&service)?;
        verify_configuration(&service, &expected_command)?;
        let process_id = running_process(&service)?;
        if pipe_process(pipe)? != process_id {
            return Err(ServicePeerError::WrongProcess);
        }
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        if raw.is_null() {
            return Err(native("open service process"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let created_at = process_creation(&process, process_id)?;
        verify_process_image(&executable, &process)?;
        let peer = Self {
            service,
            executable,
            expected_command,
            process,
            process_id,
            created_at,
            pipe_identity: pipe.identity.clone(),
        };
        peer.verify_pipe_server(pipe)?;
        Ok(peer)
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    pub fn process_creation_time(&self) -> u64 {
        self.created_at
    }

    /// Recheck before consuming a response or sending sensitive material over
    /// this same connected pipe. SCM status is not a cached readiness receipt.
    pub fn verify_pipe_server(&self, pipe: &LocalServicePipe) -> Result<(), ServicePeerError> {
        cfw_windows_storage::require_process_identity()?;
        if !Arc::ptr_eq(&self.pipe_identity, &pipe.identity) {
            return Err(ServicePeerError::WrongProcess);
        }
        if process_creation(&self.process, self.process_id)? != self.created_at {
            return Err(ServicePeerError::WrongProcess);
        }
        verify_service_security(&self.service)?;
        verify_configuration(&self.service, &self.expected_command)?;
        if running_process(&self.service)? != self.process_id
            || pipe_process(pipe)? != self.process_id
        {
            return Err(ServicePeerError::WrongProcess);
        }
        verify_process_image(&self.executable, &self.process)?;
        if running_process(&self.service)? != self.process_id
            || pipe_process(pipe)? != self.process_id
            || process_creation(&self.process, self.process_id)? != self.created_at
        {
            return Err(ServicePeerError::WrongProcess);
        }
        Ok(())
    }
}

fn service_name_wide(name: &str) -> Result<Vec<u16>, ServicePeerError> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(ServicePeerError::InvalidExpectation);
    }
    Ok(name.encode_utf16().chain([0]).collect())
}

fn executable_command(path: &Path) -> Result<Vec<u16>, ServicePeerError> {
    let units: Vec<_> = path.as_os_str().encode_wide().collect();
    if !path.is_absolute()
        || units.is_empty()
        || units.len() > 2048
        || units.iter().any(|c| *c == 0 || *c == u16::from(b'"'))
    {
        return Err(ServicePeerError::InvalidExpectation);
    }
    Ok([vec![u16::from(b'"')], units, vec![u16::from(b'"')]].concat())
}

fn verify_configuration(
    service: &ServiceHandle,
    expected_command: &[u16],
) -> Result<(), ServicePeerError> {
    // Windows documents an 8 KiB maximum. usize storage provides the native
    // structure alignment; all returned string pointers must stay in it.
    let mut buffer = vec![0usize; MAX_CONFIG_BYTES / size_of::<usize>()];
    let mut needed = 0;
    if unsafe {
        QueryServiceConfigW(
            service.0,
            buffer.as_mut_ptr().cast(),
            MAX_CONFIG_BYTES as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(native("query service configuration"));
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    validate_configuration(&buffer, config, expected_command)
}

fn config_string(buffer: &[usize], pointer: *const u16) -> Result<&[u16], ServicePeerError> {
    let offset = pointer
        .addr()
        .checked_sub(buffer.as_ptr().addr())
        .ok_or(ServicePeerError::ConfigurationMismatch)?;
    let bytes = std::mem::size_of_val(buffer);
    if offset < size_of::<QUERY_SERVICE_CONFIGW>() || offset >= bytes || offset % 2 != 0 {
        return Err(ServicePeerError::ConfigurationMismatch);
    }
    let units = unsafe { std::slice::from_raw_parts(pointer, (bytes - offset) / 2) };
    let end = units
        .iter()
        .position(|c| *c == 0)
        .ok_or(ServicePeerError::ConfigurationMismatch)?;
    Ok(&units[..end])
}

fn validate_configuration(
    buffer: &[usize],
    config: &QUERY_SERVICE_CONFIGW,
    expected_command: &[u16],
) -> Result<(), ServicePeerError> {
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || !matches!(
            config.dwStartType,
            SERVICE_AUTO_START | SERVICE_DEMAND_START
        )
        || config_string(buffer, config.lpBinaryPathName)? != expected_command
        || config_string(buffer, config.lpServiceStartName)?
            != "LocalSystem".encode_utf16().collect::<Vec<_>>()
    {
        return Err(ServicePeerError::ConfigurationMismatch);
    }
    Ok(())
}

fn running_process(service: &ServiceHandle) -> Result<u32, ServicePeerError> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(native("query service status"));
    }
    validate_status(&status)
}

fn validate_status(status: &SERVICE_STATUS_PROCESS) -> Result<u32, ServicePeerError> {
    if status.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || status.dwCurrentState != SERVICE_RUNNING
        || status.dwProcessId == 0
        || status.dwServiceFlags != 0
    {
        return Err(ServicePeerError::NotRunning {
            service_type: status.dwServiceType,
            state: status.dwCurrentState,
            process_id: status.dwProcessId,
            flags: status.dwServiceFlags,
        });
    }
    Ok(status.dwProcessId)
}

fn pipe_process(pipe: &impl AsRawHandle) -> Result<u32, ServicePeerError> {
    let mut id = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut id) } == 0 {
        return Err(native("query pipe server process"));
    }
    if id == 0 {
        return Err(ServicePeerError::WrongProcess);
    }
    Ok(id)
}

fn process_creation(process: &OwnedHandle, id: u32) -> Result<u64, ServicePeerError> {
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => {}
        WAIT_OBJECT_0 => return Err(ServicePeerError::Exited),
        _ => return Err(native("observe service process lifetime")),
    }
    if unsafe { GetProcessId(process.as_raw_handle()) } != id {
        return Err(ServicePeerError::WrongProcess);
    }
    let mut session = u32::MAX;
    if unsafe { ProcessIdToSessionId(id, &mut session) } == 0 {
        return Err(native("query service process session"));
    }
    if session != 0 {
        return Err(ServicePeerError::WrongProcess);
    }
    let mut times = [FILETIME::default(); 4];
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut times[0],
            &mut times[1],
            &mut times[2],
            &mut times[3],
        )
    } == 0
    {
        return Err(native("query service process creation"));
    }
    let created = u64::from(times[0].dwLowDateTime) | (u64::from(times[0].dwHighDateTime) << 32);
    if created == 0 {
        return Err(ServicePeerError::WrongProcess);
    }
    Ok(created)
}

fn verify_process_image(
    executable: &VerifiedExecutable,
    process: &OwnedHandle,
) -> Result<(), ServicePeerError> {
    let mut buffer = vec![0; MAX_IMAGE_UNITS];
    let mut length = MAX_IMAGE_UNITS as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, buffer.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(native("query live service image"));
    }
    let length = length as usize;
    if length == 0 || length >= buffer.len() || buffer[..length].contains(&0) {
        return Err(ServicePeerError::WrongProcess);
    }
    let path = OsString::from_wide(&buffer[..length]);
    executable.verify_image_file(Path::new(&path))?;
    Ok(())
}

fn trusted_admin_sid(sid: PSID) -> bool {
    !sid.is_null()
        && unsafe { IsValidSid(sid) } != 0
        && (unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0
            || unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0)
}

fn verify_service_security(service: &ServiceHandle) -> Result<(), ServicePeerError> {
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            service.0,
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(ServicePeerError::Native {
            operation: "query service security",
            source: io::Error::from_raw_os_error(result as i32),
        });
    }
    struct Allocation(*mut std::ffi::c_void);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }
    let _allocation = Allocation(descriptor);
    validate_security(owner, acl)
}

fn validate_security(
    owner: PSID,
    acl: *const windows_sys::Win32::Security::ACL,
) -> Result<(), ServicePeerError> {
    if !trusted_admin_sid(owner) || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(ServicePeerError::UnsafeServiceSecurity);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(native("query service ACL"));
    }
    let read = READ_CONTROL
        | SERVICE_QUERY_CONFIG
        | SERVICE_QUERY_STATUS
        | SERVICE_ENUMERATE_DEPENDENTS
        | SERVICE_INTERROGATE;
    let mapping = GENERIC_MAPPING {
        GenericRead: read,
        GenericWrite: READ_CONTROL | SERVICE_CHANGE_CONFIG,
        GenericExecute: READ_CONTROL
            | SERVICE_START
            | SERVICE_STOP
            | SERVICE_PAUSE_CONTINUE
            | SERVICE_USER_DEFINED_CONTROL,
        GenericAll: SERVICE_ALL_ACCESS,
    };
    for index in 0..info.AceCount {
        let mut pointer = null_mut();
        if unsafe { GetAce(acl, index, &mut pointer) } == 0 {
            return Err(native("read service ACE"));
        }
        // The OS-produced descriptor, IsValidAcl and GetAce bound this ACE.
        let header = unsafe { &*pointer.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
            || header.AceType == ACCESS_DENIED_ACE_TYPE as u8
        {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
        {
            return Err(ServicePeerError::UnsafeServiceSecurity);
        }
        let ace = unsafe { &*pointer.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0
            || unsafe { GetLengthSid(sid) } as usize
                > usize::from(header.AceSize) - offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        {
            return Err(ServicePeerError::UnsafeServiceSecurity);
        }
        let mut mask = ace.Mask;
        unsafe { MapGenericMask(&mut mask, &mapping) };
        if !trusted_admin_sid(sid) && mask & !read != 0 {
            return Err(ServicePeerError::UnsafeServiceSecurity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
