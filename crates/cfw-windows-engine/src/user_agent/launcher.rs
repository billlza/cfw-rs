//! Retained, non-elevated UserAgent process and one startup handoff. This is
//! below the Desktop lifecycle supervisor: delivery is not Ready, process exit
//! is not global cleanup, and resumed agents are never force-killed here.
use super::{
    handoff::UserAgentLaunch,
    launch_channel::{LaunchChannelError, LaunchSender},
};
use crate::{
    NativePeerProcess, PeerIdentityError, ServiceAuthorizationError, VerifiedExecutable,
    authority::LeaseContext,
    process_handles::ProcessHandleList,
    service_transport::{ServiceTransportError, check_deadline},
};
use cfw_windows_storage::{WaitOutcome, wait_until};
use std::{
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        CREATE_NO_WINDOW, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
        GetExitCodeProcess, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        STARTUPINFOW, WaitForSingleObject,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("Windows UserAgent launcher I/O: {0}")]
    Io(#[from] io::Error),
    #[error("Windows UserAgent launcher peer: {0}")]
    Peer(#[from] PeerIdentityError),
    #[error("Windows UserAgent launcher console: {0}")]
    Console(#[from] ServiceAuthorizationError),
    #[error("Windows UserAgent launcher transport: {0}")]
    Transport(#[from] ServiceTransportError),
    #[error("Windows UserAgent launch handoff: {0}")]
    Handoff(Arc<LaunchChannelError>),
    #[error("Windows UserAgent launcher requires the exact medium-integrity lease owner")]
    Identity,
    #[error("Windows UserAgent invocation is invalid")]
    Invocation,
    #[error("Windows UserAgent launch deadline expired")]
    Deadline,
    #[error("Windows UserAgent launch was cancelled")]
    Cancelled,
    #[error("Windows UserAgent launch worker panicked")]
    WorkerPanicked,
    #[error("Windows UserAgent launch state does not permit this observation")]
    State,
    #[error("Windows UserAgent exited unsuccessfully ({0:#x})")]
    Exit(u32),
}
pub type Result<T> = std::result::Result<T, LaunchError>;

pub struct UserAgentInvocation {
    arguments: String,
    service: String,
}
impl UserAgentInvocation {
    pub fn installed(service: &str) -> Result<Self> {
        Self::checked("--user-agent", service, None)
    }
    fn checked(flag: &str, service: &str, digest: Option<[u8; 32]>) -> Result<Self> {
        if service.is_empty()
            || service.starts_with('-')
            || service.len() > 200
            || !service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(LaunchError::Invocation);
        }
        let mut arguments = format!(" {flag} {service}");
        if let Some(digest) = digest {
            arguments.push(' ');
            for byte in digest {
                use std::fmt::Write;
                write!(&mut arguments, "{byte:02x}").map_err(|_| LaunchError::Invocation)?;
            }
        }
        Ok(Self {
            arguments,
            service: service.into(),
        })
    }
    pub(super) fn service(&self) -> &str {
        &self.service
    }
    #[cfg(feature = "native-service-validation")]
    pub fn for_validation(service: &str, case: ValidationAgent, digest: [u8; 32]) -> Result<Self> {
        let flag = match case {
            ValidationAgent::Local => "--local-agent-runtime",
            ValidationAgent::System => "--system-agent-runtime",
            ValidationAgent::RestartSystem => "--restart-system-agent-runtime",
            ValidationAgent::Rejected => "--rejected-agent-runtime",
        };
        Self::checked(flag, service, Some(digest))
    }
}
#[cfg(feature = "native-service-validation")]
pub enum ValidationAgent {
    Local,
    System,
    RestartSystem,
    Rejected,
}

pub struct LaunchFailure {
    pub error: LaunchError,
    pub owner: Option<Box<UserAgentChild>>,
    pub context: Box<LeaseContext>,
}
impl LaunchFailure {
    fn uncreated(error: LaunchError, context: &LeaseContext) -> Self {
        Self {
            error,
            owner: None,
            context: Box::new(context.clone()),
        }
    }
}

#[derive(Clone, Copy)]
pub struct AgentExit {
    process_id: u32,
    exit_code: u32,
}
impl AgentExit {
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }
}
enum Delivery {
    Absent,
    Pending,
    Accepted,
    Failed(Arc<LaunchChannelError>),
    Panicked,
}
pub struct UserAgentChild {
    process: OwnedHandle,
    process_id: u32,
    context: LeaseContext,
    _executable: Arc<VerifiedExecutable>,
    peer: Option<NativePeerProcess>,
    worker: Option<JoinHandle<std::result::Result<(), LaunchChannelError>>>,
    cancel: Arc<AtomicBool>,
    delivery: Delivery,
    exit: Option<AgentExit>,
}
impl UserAgentChild {
    /// The output file is an installation-owned diagnostic sink; it is not
    /// selected by the launch frame. The caller retains the Authority channel
    /// that prepared this lease and owns stop/recovery when launch fails.
    pub fn launch(
        executable: impl Into<Arc<VerifiedExecutable>>,
        invocation: UserAgentInvocation,
        launch: UserAgentLaunch,
        diagnostics: &File,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> std::result::Result<Self, LaunchFailure> {
        let executable = executable.into();
        let prepared = (|| -> Result<_> {
            check_deadline(deadline)?;
            if cancel.load(Ordering::Acquire) {
                return Err(LaunchError::Cancelled);
            }
            let parent = medium_owner(launch.context())?;
            let message = launch
                .encode()
                .map_err(|e| LaunchError::Handoff(Arc::new(LaunchChannelError::Frame(e))))?;
            let (sender, input) =
                LaunchSender::create().map_err(|e| LaunchError::Handoff(Arc::new(e)))?;
            let input = inherit(input.as_handle())?;
            let output = inherit(diagnostics.as_handle())?;
            let mut attributes = ProcessHandleList::new(&[input.as_handle(), output.as_handle()])?;
            let path: Vec<_> = executable.path().as_os_str().encode_wide().collect();
            if path.contains(&0) || path.contains(&u16::from(b'"')) {
                return Err(LaunchError::Invocation);
            }
            let mut command = vec![u16::from(b'"')];
            command.extend_from_slice(&path);
            command.push(u16::from(b'"'));
            command.extend(invocation.arguments.encode_utf16());
            command.push(0);
            let mut application = path;
            application.push(0);
            let directory: Vec<_> = executable
                .path()
                .parent()
                .ok_or(LaunchError::Invocation)?
                .as_os_str()
                .encode_wide()
                .chain([0])
                .collect();
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdInput: input.as_raw_handle(),
                    hStdOutput: output.as_raw_handle(),
                    hStdError: output.as_raw_handle(),
                    ..Default::default()
                },
                lpAttributeList: attributes.pointer(),
            };
            check_deadline(deadline)?;
            parent.revalidate()?;
            if cancel.load(Ordering::Acquire) {
                return Err(LaunchError::Cancelled);
            }
            let mut process = PROCESS_INFORMATION::default();
            if unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    null(),
                    directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut process,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
            let _thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
            Ok((process_handle, process.dwProcessId, parent, sender, message))
        })()
        .map_err(|error| LaunchFailure::uncreated(error, launch.context()))?;
        let (process, process_id, parent, sender, message) = prepared;
        let mut owner = Self {
            process,
            process_id,
            context: launch.context().clone(),
            _executable: executable,
            peer: None,
            worker: None,
            cancel,
            delivery: Delivery::Absent,
            exit: None,
        };
        let initialized = (|| -> Result<()> {
            let child = NativePeerProcess::open(process_id)?;
            if child.identity().integrity_rid() != 0x2000
                || child.identity().user_session() != parent.identity().user_session()
                || child.identity().is_app_container()
                || child.identity().is_restricted()
            {
                return Err(LaunchError::Identity);
            }
            child.verify_executable(&owner._executable)?;
            owner.peer = Some(child);
            let signal = Arc::clone(&owner.cancel);
            owner.worker = Some(
                thread::Builder::new()
                    .name("cfw-user-agent-launch".into())
                    .spawn(move || sender.send(message, deadline, &signal))?,
            );
            owner.delivery = Delivery::Pending;
            owner.wait_handoff(deadline)
        })();
        match initialized {
            Ok(()) => Ok(owner),
            Err(error) => {
                owner.cancel_handoff();
                Err(LaunchFailure {
                    error,
                    context: Box::new(owner.context.clone()),
                    owner: Some(Box::new(owner)),
                })
            }
        }
    }
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn verify_live(&self) -> Result<()> {
        let peer = self.peer.as_ref().ok_or(LaunchError::State)?;
        peer.revalidate()?;
        peer.verify_executable(&self._executable)?;
        Ok(())
    }
    pub fn cancel_handoff(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    /// This does not stop an engine. The lifecycle supervisor first revokes
    /// the native lease, then calls wait_for_exit while retaining this owner.
    pub fn wait_for_exit(&mut self, deadline: Instant) -> Result<AgentExit> {
        check_deadline(deadline)?;
        if self.exit.is_none() {
            match wait_until(&self.process, deadline)? {
                WaitOutcome::Signaled => self.record_exit()?,
                WaitOutcome::TimedOut => return Err(LaunchError::Deadline),
                _ => return Err(io::Error::other("agent process wait reported abandonment").into()),
            }
        }
        self.finish_worker(deadline)?;
        check_deadline(deadline)?;
        let observed = self.exit.ok_or(LaunchError::State)?;
        if observed.exit_code != 0 {
            return Err(LaunchError::Exit(observed.exit_code));
        }
        Ok(observed)
    }
    pub fn exit_observation(&self) -> Option<&AgentExit> {
        self.exit.as_ref()
    }
    fn record_exit(&mut self) -> Result<()> {
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.exit = Some(AgentExit {
            process_id: self.process_id,
            exit_code: code,
        });
        Ok(())
    }
    fn wait_handoff(&mut self, deadline: Instant) -> Result<()> {
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if self.cancel.load(Ordering::Acquire) {
                return Err(LaunchError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(LaunchError::Deadline);
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.finish_worker(deadline)?;
        check_deadline(deadline)?;
        Ok(())
    }
    fn finish_worker(&mut self, deadline: Instant) -> Result<()> {
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if Instant::now() >= deadline {
                return Err(LaunchError::Deadline);
            }
            thread::sleep(Duration::from_millis(5));
        }
        if let Some(worker) = self.worker.take() {
            self.delivery = match worker.join() {
                Ok(Ok(())) => Delivery::Accepted,
                Ok(Err(error)) => Delivery::Failed(Arc::new(error)),
                Err(_) => Delivery::Panicked,
            };
        }
        match &self.delivery {
            Delivery::Accepted => Ok(()),
            Delivery::Failed(error) => Err(LaunchError::Handoff(Arc::clone(error))),
            Delivery::Panicked => Err(LaunchError::WorkerPanicked),
            Delivery::Absent | Delivery::Pending => Err(LaunchError::State),
        }
    }
}
impl AsRawHandle for UserAgentChild {
    fn as_raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}
impl Drop for UserAgentChild {
    fn drop(&mut self) {
        self.cancel_handoff();
        if let Some(worker) = self.worker.take() {
            if worker.is_finished() {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("UserAgent handoff retirement failed: {error}"),
                    Err(_) => eprintln!("UserAgent handoff worker panicked"),
                }
            } else {
                eprintln!("UserAgent handoff owner dropped before worker retirement");
            }
        }
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => eprintln!(
                "UserAgent process owner dropped while live; Authority cleanup remains required"
            ),
            _ => eprintln!("UserAgent process exit could not be observed on owner drop"),
        }
    }
}
fn medium_owner(context: &LeaseContext) -> Result<NativePeerProcess> {
    let current = medium_process()?;
    let identity = current.identity();
    if !context
        .operation
        .owner
        .matches_native(identity.user_session())
    {
        return Err(LaunchError::Identity);
    }
    current.require_current_console_session()?;
    Ok(current)
}
pub(super) fn medium_process() -> Result<NativePeerProcess> {
    let current = NativePeerProcess::open(std::process::id())?;
    let identity = current.identity();
    if identity.integrity_rid() != 0x2000 || identity.is_app_container() || identity.is_restricted()
    {
        return Err(LaunchError::Identity);
    }
    Ok(current)
}
fn inherit(handle: BorrowedHandle<'_>) -> io::Result<OwnedHandle> {
    let mut inherited = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle(),
            GetCurrentProcess(),
            &mut inherited,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(inherited) })
}

#[cfg(test)]
mod tests;
