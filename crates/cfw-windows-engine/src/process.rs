use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr::null,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use cfw_windows_storage::PrivateDirectory;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Threading::{CREATE_NO_WINDOW, WaitForSingleObject},
    },
};
use zeroize::Zeroizing;

use crate::{
    Error, PreparedConfig,
    protocol::{self, Response},
};

/// A byte identity supplied by a trusted installation descriptor. An adjacent
/// receipt is not a trust root. Publisher-signature admission belongs to the
/// installer; this component verifies bytes and holds the original path open.
pub struct VerifiedExecutable {
    path: PathBuf,
    _handles: Vec<File>,
    version: String,
}

impl VerifiedExecutable {
    pub fn open(path: &Path, expected_sha256: [u8; 32], version: &str) -> Result<Self, Error> {
        if version.is_empty()
            || version.len() > 32
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(Error::ExecutableIdentity);
        }
        let mut handles = hold_path(path, false)?;
        let file = handles.last_mut().ok_or(Error::ExecutableIdentity)?;
        let size = file.metadata()?.len();
        if !(64..=256 * 1024 * 1024).contains(&size) {
            return Err(Error::ExecutableIdentity);
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let size = file.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            hash.update(&buffer[..size]);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != expected_sha256 {
            return Err(Error::ExecutableIdentity);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut dos = [0; 64];
        file.read_exact(&mut dos)?;
        if &dos[..2] != b"MZ" {
            return Err(Error::ExecutableIdentity);
        }
        let offset = u32::from_le_bytes(
            dos[60..64]
                .try_into()
                .map_err(|_| Error::ExecutableIdentity)?,
        ) as u64;
        if offset < 64 || offset > size - 6 {
            return Err(Error::ExecutableIdentity);
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut pe = [0; 6];
        file.read_exact(&mut pe)?;
        if pe != [b'P', b'E', 0, 0, 0x64, 0x86] {
            return Err(Error::ExecutableIdentity);
        }
        Ok(Self {
            path: path.to_owned(),
            _handles: handles,
            version: version.to_owned(),
        })
    }
}

/// Keep every ancestor non-replaceable while a path is consumed by CreateProcess.
/// Reparse points, hard-linked executables and relative/parent paths are refused.
fn hold_path(path: &Path, directory: bool) -> Result<Vec<File>, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(Error::ExecutableIdentity);
    }
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    let mut handles = Vec::new();
    for ancestor in ancestors {
        let is_directory = ancestor != path || directory;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | if is_directory { FILE_SHARE_WRITE } else { 0 })
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(ancestor)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle stays owned by `file`, and the output has the API's layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory
            || (!is_directory && info.nNumberOfLinks != 1)
        {
            return Err(Error::ExecutableIdentity);
        }
        handles.push(file);
    }
    Ok(handles)
}

struct Exchange {
    bytes: Zeroizing<Vec<u8>>,
    result: SyncSender<Result<Response, Error>>,
}

/// Holds the live process handle and private pipe. Not serializable/reconnectable.
pub struct EngineProcess {
    child: Child,
    job: OwnedHandle,
    _executable: VerifiedExecutable,
    _runtime_directory: PrivateDirectory,
    _runtime_path: Vec<File>,
    sender: Option<SyncSender<Exchange>>,
    worker: Option<JoinHandle<()>>,
    session: String,
    sequence: u64,
    digest: Option<String>,
    listeners: Vec<std::net::SocketAddr>,
    assigned: bool,
    closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningChild {
    pub process_id: u32,
    pub configuration_digest: String,
}

/// Only the owned child returned Close success and then exited with status 0.
/// It makes no claim about another process or global proxy/TUN restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoppedChild {
    pub process_id: u32,
    pub configuration_digest: String,
}

impl EngineProcess {
    pub fn spawn(
        executable: VerifiedExecutable,
        runtime_directory: &Path,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let deadline = deadline(timeout)?;
        let parent = runtime_directory
            .parent()
            .ok_or(Error::ExecutableIdentity)?;
        let mut runtime_path = hold_path(parent, true)?;
        let private = PrivateDirectory::open_or_create(runtime_directory)
            .map_err(|_| Error::Configuration("runtime directory is not private"))?;
        // Parent identities were retained before the private leaf opened, so
        // the ACL-checked directory and CreateProcess working directory agree.
        runtime_path.extend(hold_path(runtime_directory, true)?);
        // An unnamed, non-inheritable job prevents child escape on owner loss.
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let child = Command::new(&executable.path)
            .current_dir(runtime_directory)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Unstructured diagnostics may include node secrets. The private
            // control reply returns stable error codes; runtime logs remain
            // available through the authenticated, observable Clash API.
            .stderr(Stdio::null())
            .spawn()?;
        let mut owner = Self {
            child,
            job,
            _executable: executable,
            _runtime_directory: private,
            _runtime_path: runtime_path,
            sender: None,
            worker: None,
            session: uuid::Uuid::new_v4().simple().to_string(),
            sequence: 0,
            digest: None,
            listeners: Vec::new(),
            assigned: false,
            closed: false,
        };
        // The worker cannot start an engine before receiving a request. No
        // request or configuration leaves this process until job assignment.
        if unsafe {
            AssignProcessToJobObject(owner.job.as_raw_handle(), owner.child.as_raw_handle())
        } == 0
        {
            let error = Error::Io(std::io::Error::last_os_error());
            return match owner.finish_operation::<()>(Err(error)) {
                Err(error) => Err(error),
                Ok(()) => unreachable!("failed assignment cannot succeed"),
            };
        }
        owner.assigned = true;
        let mut input = owner
            .child
            .stdin
            .take()
            .ok_or(Error::Protocol("missing child stdin"))?;
        let mut output = owner
            .child
            .stdout
            .take()
            .ok_or(Error::Protocol("missing child stdout"))?;
        let (sender, receiver) = mpsc::sync_channel::<Exchange>(1);
        let worker = thread::Builder::new()
            .name("cfw-engine-control".into())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    let result = protocol::exchange(&mut input, &mut output, &work.bytes);
                    let failed = result.is_err();
                    // A disappeared receiver means owner cancellation; close pipes.
                    if work.result.send(result).is_err() || failed {
                        break;
                    }
                }
            })?;
        owner.sender = Some(sender);
        owner.worker = Some(worker);
        let result = owner.rpc("hello", None, "idle", "", deadline);
        owner.finish_operation(result)?;
        Ok(owner)
    }

    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub fn start(
        &mut self,
        config: &PreparedConfig,
        timeout: Duration,
    ) -> Result<RunningChild, Error> {
        let deadline = deadline(timeout)?;
        if self.closed || self.digest.is_some() {
            return Err(Error::Protocol("child is not idle"));
        }
        let result = self.rpc("start", Some(config), "running", config.digest(), deadline);
        self.finish_operation(result)?;
        self.digest = Some(config.digest().to_owned());
        self.listeners = config.listeners.clone();
        self.observe_remaining(deadline)
    }

    pub fn observe(&mut self, timeout: Duration) -> Result<RunningChild, Error> {
        self.observe_remaining(deadline(timeout)?)
    }

    fn observe_remaining(&mut self, deadline: Instant) -> Result<RunningChild, Error> {
        let digest = self
            .digest
            .clone()
            .ok_or(Error::Protocol("child is not running"))?;
        let result = self
            .rpc("observe", None, "running", &digest, deadline)
            .and_then(|()| {
                if self.child.try_wait()?.is_some() {
                    return Err(Error::Exited);
                }
                let observed = crate::listeners::owned(self.child.id())?;
                if !self
                    .listeners
                    .iter()
                    .all(|address| observed.contains(address))
                {
                    return Err(Error::Protocol(
                        "projected listener is not owned by this process",
                    ));
                }
                Ok(())
            });
        self.finish_operation(result)?;
        Ok(RunningChild {
            process_id: self.child.id(),
            configuration_digest: digest,
        })
    }

    pub fn stop(mut self, timeout: Duration) -> Result<StoppedChild, Error> {
        let deadline = deadline(timeout)?;
        let digest = self
            .digest
            .clone()
            .ok_or(Error::Protocol("child is not running"))?;
        let result = self
            .rpc("stop", None, "stopped", &digest, deadline)
            .and_then(|()| {
                wait_process(&self.child, deadline)?;
                if !self.child.wait()?.success() {
                    return Err(Error::Exited);
                }
                self.finish_io(deadline)?;
                while active_processes(&self.job)? != 0 {
                    remaining(deadline)?;
                    thread::sleep(Duration::from_millis(1));
                }
                if !crate::listeners::owned(self.child.id())?.is_empty() {
                    return Err(Error::Cleanup);
                }
                Ok(())
            });
        self.finish_operation(result)?;
        self.closed = true;
        Ok(StoppedChild {
            process_id: self.child.id(),
            configuration_digest: digest,
        })
    }

    fn rpc(
        &mut self,
        operation: &str,
        config: Option<&PreparedConfig>,
        state: &str,
        digest: &str,
        deadline: Instant,
    ) -> Result<(), Error> {
        if self.closed || self.child.try_wait()?.is_some() {
            return Err(Error::Exited);
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Protocol("request sequence exhausted"))?;
        let bytes = protocol::request(
            &self.session,
            self.sequence,
            operation,
            (!digest.is_empty()).then_some(digest),
            config,
        )?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or(Error::Exited)?
            .try_send(Exchange {
                bytes,
                result: sender,
            })
            .map_err(|_| Error::Protocol("control channel unavailable"))?;
        let response =
            receiver
                .recv_timeout(remaining(deadline)?)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => Error::Timeout,
                    mpsc::RecvTimeoutError::Disconnected => Error::Exited,
                })??;
        response.validate(
            &self.session,
            self.sequence,
            self.child.id(),
            &self._executable.version,
            state,
            digest,
        )
    }

    fn finish_operation<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Ok(value) => Ok(value),
            Err(operation) => match self.abort() {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(Error::CleanupFailed {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                }),
            },
        }
    }

    fn finish_io(&mut self, deadline: Instant) -> Result<(), Error> {
        self.sender.take();
        if let Some(worker) = self.worker.as_ref() {
            while !worker.is_finished() {
                remaining(deadline)?;
                thread::sleep(Duration::from_millis(1));
            }
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| Error::Cleanup)?;
        }
        Ok(())
    }

    fn abort(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        if self.assigned {
            if unsafe { TerminateJobObject(self.job.as_raw_handle(), 2) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        } else if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        wait_process(&self.child, deadline)?;
        self.child.wait()?;
        while active_processes(&self.job)? != 0 {
            remaining(deadline)?;
            thread::sleep(Duration::from_millis(1));
        }
        self.finish_io(deadline)?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        // Best effort only; an explicit operation reports cleanup failures.
        // Closing the retained job is the final OS cleanup on owner drop.
        let _ = self.abort();
    }
}

fn deadline(timeout: Duration) -> Result<Instant, Error> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(Error::Protocol("deadline must be within 120 seconds"));
    }
    Ok(Instant::now() + timeout)
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::Timeout)
}

fn wait_process(child: &Child, deadline: Instant) -> Result<(), Error> {
    let wait = remaining(deadline)?.as_millis().clamp(1, 120_000) as u32;
    match unsafe { WaitForSingleObject(child.as_raw_handle(), wait) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(Error::Timeout),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

fn active_processes(job: &OwnedHandle) -> Result<u32, Error> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(accounting.ActiveProcesses)
}
