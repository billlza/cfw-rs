use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    os::windows::{
        ffi::OsStringExt,
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf},
    ptr::null,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    Error, PreparedConfig, ResolvedProjection,
    protocol::{self, Exchange},
};
use cfw_windows_storage::{PrivateDirectory, WaitOutcome, wait_until};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Threading::QueryFullProcessImageNameW,
    },
};

mod child;
use child::NativeChild;

/// A byte identity supplied by a trusted installation descriptor. An adjacent
/// receipt is not a trust root. Publisher-signature admission belongs to the
/// installer; this component verifies bytes and holds the original path open.
pub struct VerifiedExecutable {
    path: PathBuf,
    _handles: Vec<File>,
    version: String,
}

impl VerifiedExecutable {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify_process_image(&self, process: &OwnedHandle) -> Result<(), Error> {
        let mut buffer = vec![0; 32768];
        let mut length = buffer.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(process.as_raw_handle(), 0, buffer.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(Error::Operation {
                operation: "query live process image",
                source: std::io::Error::last_os_error(),
            });
        }
        let length = length as usize;
        if length == 0 || length >= buffer.len() || buffer[..length].contains(&0) {
            return Err(Error::ExecutableIdentity);
        }
        let path = OsString::from_wide(&buffer[..length]);
        self.verify_image_file(Path::new(&path))
    }

    /// Compare the live process image to the already hash-verified, retained
    /// file. A byte-identical copy at another file identity is not this install.
    pub(crate) fn verify_image_file(&self, image: &Path) -> Result<(), Error> {
        let handles = hold_path(image, false)?;
        let expected = self._handles.last().ok_or(Error::ExecutableIdentity)?;
        let actual = handles.last().ok_or(Error::ExecutableIdentity)?;
        let mut identities = [BY_HANDLE_FILE_INFORMATION::default(); 2];
        for (file, info) in [expected, actual].into_iter().zip(&mut identities) {
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let [left, right] = identities;
        if left.dwVolumeSerialNumber != right.dwVolumeSerialNumber
            || left.nFileIndexHigh != right.nFileIndexHigh
            || left.nFileIndexLow != right.nFileIndexLow
        {
            return Err(Error::ExecutableIdentity);
        }
        Ok(())
    }

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
pub(crate) fn hold_path(path: &Path, directory: bool) -> Result<Vec<File>, Error> {
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
            .open(ancestor)
            .map_err(|source| Error::Operation {
                operation: if is_directory {
                    "retain directory path"
                } else {
                    "retain executable path"
                },
                source,
            })?;
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

/// Holds the live process handle and private pipe. Not serializable/reconnectable.
pub struct EngineProcess {
    child: NativeChild,
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
    proxy_cleanup: Option<crate::system_proxy::ProxyCleanup>,
    restored_proxy: Option<crate::system_proxy::ProxyCleanup>,
    cancellation: Option<Arc<AtomicBool>>,
}

/// Internal launch result preserves a partially created owner so the agent can
/// prove cleanup instead of treating an unsuccessful spawn as an absent child.
pub(crate) struct ChildLaunchFailure {
    pub(crate) error: Error,
    pub(crate) owner: Option<Box<EngineProcess>>,
}
impl ChildLaunchFailure {
    fn uncreated(error: Error) -> Self {
        Self { error, owner: None }
    }
}

/// Only a fresh observation of this held process/job/control channel constructs
/// this value. It makes no claim about another operation or global Authority.
pub(crate) struct ChildCleanupObservation {
    process_id: u32,
    configuration_digest: Option<String>,
}
impl ChildCleanupObservation {
    pub(crate) fn process_id(&self) -> u32 {
        self.process_id
    }
    pub(crate) fn configuration_digest(&self) -> Option<&str> {
        self.configuration_digest.as_deref()
    }
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

/// The actual parser constructed and closed this candidate without starting it.
/// This says nothing about active runtime readiness or system network state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedConfiguration {
    pub process_id: u32,
    pub configuration_digest: String,
}

impl EngineProcess {
    pub fn spawn(
        executable: VerifiedExecutable,
        runtime_directory: &Path,
        timeout: Duration,
    ) -> Result<Self, Error> {
        match Self::spawn_retained(executable, runtime_directory, timeout, None, None) {
            Ok(owner) => Ok(owner),
            Err(failure) => {
                let ChildLaunchFailure { error, owner } = failure;
                match owner {
                    None => Err(error),
                    Some(mut owner) => match owner.abort() {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(Error::CleanupFailed {
                            operation: Box::new(error),
                            cleanup: Box::new(cleanup),
                        }),
                    },
                }
            }
        }
    }
    pub(crate) fn spawn_retained(
        executable: VerifiedExecutable,
        runtime_directory: &Path,
        timeout: Duration,
        cancellation: Option<Arc<AtomicBool>>,
        keeper: Option<&crate::authority::RuntimeKeeper>,
    ) -> Result<Self, ChildLaunchFailure> {
        let deadline = deadline(timeout).map_err(ChildLaunchFailure::uncreated)?;
        if cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            return Err(ChildLaunchFailure::uncreated(Error::Cancelled));
        }
        let session = uuid::Uuid::new_v4().simple().to_string();
        let assets = spawn_assets(executable, runtime_directory, keeper)
            .map_err(ChildLaunchFailure::uncreated)?;
        let mut owner = Self {
            child: assets.child,
            job: assets.job,
            _executable: assets.executable,
            _runtime_directory: assets.private,
            _runtime_path: assets.runtime_path,
            sender: None,
            worker: None,
            session,
            sequence: 0,
            digest: None,
            listeners: Vec::new(),
            assigned: false,
            closed: false,
            proxy_cleanup: None,
            restored_proxy: None,
            cancellation,
        };
        match owner.initialize(deadline) {
            Ok(()) => Ok(owner),
            Err(error) => Err(ChildLaunchFailure {
                error,
                owner: Some(Box::new(owner)),
            }),
        }
    }
    fn initialize(&mut self, deadline: Instant) -> Result<(), Error> {
        // CreateProcess assigned the local Job while creating a suspended
        // thread. Confirm that ownership before any worker code/configuration.
        let mut member = 0;
        if unsafe {
            IsProcessInJob(
                self.child.as_raw_handle(),
                self.job.as_raw_handle(),
                &mut member,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if member == 0 {
            return Err(Error::Protocol("worker was not created in its cleanup job"));
        }
        self.assigned = true;
        self.child.verify(&self._executable)?;
        remaining(deadline)?;
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        self.child.resume()?;
        let mut input = self
            .child
            .stdin
            .take()
            .ok_or(Error::Protocol("missing child stdin"))?;
        let mut output = self
            .child
            .stdout
            .take()
            .ok_or(Error::Protocol("missing child stdout"))?;
        let (sender, receiver) = mpsc::sync_channel::<Exchange>(1);
        let worker = thread::Builder::new()
            .name("cfw-engine-control".into())
            .spawn(move || protocol::run_control(&mut input, &mut output, receiver))?;
        self.sender = Some(sender);
        self.worker = Some(worker);
        self.rpc("hello", None, "idle", "", deadline)
    }

    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    /// Uses a disposable worker. Success requires parser/constructor/Close
    /// success, exit 0, drained control I/O, an empty job and no owned listeners.
    pub fn check(
        mut self,
        config: &ResolvedProjection,
        timeout: Duration,
    ) -> Result<CheckedConfiguration, Error> {
        let deadline = match deadline(timeout) {
            Ok(deadline) => deadline,
            Err(error) => return self.finish_operation(Err(error)),
        };
        self.check_until(config, deadline)
    }

    pub(crate) fn check_until(
        mut self,
        config: &ResolvedProjection,
        deadline: Instant,
    ) -> Result<CheckedConfiguration, Error> {
        let result = (|| {
            remaining(deadline)?;
            if self.closed || self.digest.is_some() {
                return Err(Error::Protocol("child is not idle"));
            }
            self.rpc("check", Some(config), "checked", config.digest(), deadline)?;
            self.finish_normal_exit(deadline)
        })();
        self.finish_operation(result)?;
        self.closed = true;
        Ok(CheckedConfiguration {
            process_id: self.child.id(),
            configuration_digest: config.digest().to_owned(),
        })
    }

    pub fn start(
        &mut self,
        config: &PreparedConfig,
        timeout: Duration,
    ) -> Result<RunningChild, Error> {
        // Invalid caller admission must not tear down an already running child.
        deadline(timeout)?;
        if self.closed || self.digest.is_some() {
            return Err(Error::Protocol("child is not idle"));
        }
        let result = self.start_retained(config, timeout);
        self.finish_operation(result)
    }

    pub(crate) fn start_retained(
        &mut self,
        config: &PreparedConfig,
        timeout: Duration,
    ) -> Result<RunningChild, Error> {
        let deadline = deadline(timeout)?;
        if self.closed || self.digest.is_some() {
            return Err(Error::Protocol("child is not idle"));
        }
        self.rpc(
            "start",
            Some(&config.resolved),
            "running",
            config.digest(),
            deadline,
        )?;
        self.digest = Some(config.digest().to_owned());
        self.listeners = config.listeners.clone();
        self.observe_native(deadline)
    }

    pub fn observe(&mut self, timeout: Duration) -> Result<RunningChild, Error> {
        self.observe_remaining(deadline(timeout)?)
    }

    pub(crate) fn observe_retained(&mut self, timeout: Duration) -> Result<RunningChild, Error> {
        self.observe_native(deadline(timeout)?)
    }

    fn observe_remaining(&mut self, deadline: Instant) -> Result<RunningChild, Error> {
        let result = self.observe_native(deadline);
        self.finish_operation(result)
    }

    /// Activation already holds the proxy journal lock. Return the failure to
    /// that owner without recursive cleanup; it retains this process and the
    /// durable recovery record until the outer transaction releases its lock.
    pub(crate) fn observe_under_proxy_lock(
        &mut self,
        timeout: Duration,
    ) -> Result<RunningChild, Error> {
        self.observe_native(deadline(timeout)?)
    }

    fn observe_native(&mut self, deadline: Instant) -> Result<RunningChild, Error> {
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
        result?;
        Ok(RunningChild {
            process_id: self.child.id(),
            configuration_digest: digest,
        })
    }

    pub fn stop(&mut self, timeout: Duration) -> Result<StoppedChild, Error> {
        // Validate before any effect. The child cleanup deadline starts only
        // after the distinct settings restoration operation has completed.
        deadline(timeout)?;
        self.restore_proxy()?;
        let deadline = deadline(timeout)?;
        let digest = self
            .digest
            .clone()
            .ok_or(Error::Protocol("child is not running"))?;
        let result = self
            .rpc_controlled("stop", None, "stopped", &digest, deadline, false)
            .and_then(|()| self.finish_normal_exit(deadline));
        self.finish_operation(result)?;
        self.closed = true;
        Ok(StoppedChild {
            process_id: self.child.id(),
            configuration_digest: digest,
        })
    }

    fn finish_normal_exit(&mut self, deadline: Instant) -> Result<(), Error> {
        wait_process(&self.child, deadline)?;
        if !self.child.exit_status()?.success() {
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
    }

    fn rpc(
        &mut self,
        operation: &str,
        config: Option<&ResolvedProjection>,
        state: &str,
        digest: &str,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.rpc_controlled(operation, config, state, digest, deadline, true)
    }
    fn rpc_controlled(
        &mut self,
        operation: &str,
        config: Option<&ResolvedProjection>,
        state: &str,
        digest: &str,
        deadline: Instant,
        cancellable: bool,
    ) -> Result<(), Error> {
        if cancellable && self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if self.closed || self.child.try_wait()?.is_some() {
            return Err(Error::Exited);
        }
        let receiver = protocol::submit(
            self.sender.as_ref().ok_or(Error::Exited)?,
            &mut self.sequence,
            &self.session,
            operation,
            (!digest.is_empty()).then_some(digest),
            config,
            deadline,
        )?;
        let response = loop {
            if cancellable && self.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let left = remaining(deadline)?;
            let wait = if cancellable && self.cancellation.is_some() {
                left.min(Duration::from_millis(25))
            } else {
                left
            };
            match receiver.recv_timeout(wait) {
                Ok(response) => break response?,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Error::Exited),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    remaining(deadline)?;
                }
            }
        };
        if cancellable && self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        response.validate(
            &self.session,
            self.sequence,
            self.child.id(),
            &self._executable.version,
            state,
            digest,
        )
    }
    fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
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

    pub(crate) fn bind_proxy_cleanup(
        &mut self,
        cleanup: crate::system_proxy::ProxyCleanup,
    ) -> Result<(), Error> {
        if self.digest.as_deref() != Some(cleanup.config_digest.as_str())
            || self
                .proxy_cleanup
                .as_ref()
                .is_some_and(|current| !current.same_binding(&cleanup))
        {
            return Err(Error::Protocol(
                "proxy cleanup does not match this engine ownership",
            ));
        }
        self.proxy_cleanup = Some(cleanup);
        Ok(())
    }

    fn restore_proxy(&mut self) -> Result<(), Error> {
        if let Some(cleanup) = &self.proxy_cleanup {
            cleanup
                .restore()
                .map_err(|error| Error::ProxyRestoration(Box::new(error)))?;
            self.restored_proxy = self.proxy_cleanup.take();
        }
        Ok(())
    }

    pub(crate) fn force_cleanup(&mut self) -> Result<ChildCleanupObservation, Error> {
        self.abort()?;
        self.observe_cleanup()
    }
    pub(crate) fn observe_cleanup(&mut self) -> Result<ChildCleanupObservation, Error> {
        if !self.closed
            || self.child.try_wait()?.is_none()
            || self.sender.is_some()
            || self.worker.is_some()
            || self.proxy_cleanup.is_some()
            || active_processes(&self.job)? != 0
            || !crate::listeners::owned(self.child.id())?.is_empty()
        {
            return Err(Error::Cleanup);
        }
        if let Some(restored) = &self.restored_proxy {
            restored
                .verify_restored()
                .map_err(|error| Error::ProxyRestoration(Box::new(error)))?;
        }
        Ok(ChildCleanupObservation {
            process_id: self.child.id(),
            configuration_digest: self.digest.clone(),
        })
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
        self.restore_proxy()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        if self.assigned {
            if unsafe { TerminateJobObject(self.job.as_raw_handle(), 2) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        } else if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        wait_process(&self.child, deadline)?;
        self.child.exit_status()?;
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
        // Explicit operations retain this owner on restoration failure. Drop
        // is abnormal ownership loss: attempt restoration, then kernel handle
        // closure is the final cleanup. A surviving journal still requires the
        // supervising authority's recovery; Drop never proves global Off.
        let _ = self.abort();
    }
}

struct SpawnAssets {
    child: NativeChild,
    job: OwnedHandle,
    executable: VerifiedExecutable,
    private: PrivateDirectory,
    runtime_path: Vec<File>,
}
fn spawn_assets(
    executable: VerifiedExecutable,
    runtime_directory: &Path,
    keeper: Option<&crate::authority::RuntimeKeeper>,
) -> Result<SpawnAssets, Error> {
    let parent = runtime_directory
        .parent()
        .ok_or(Error::ExecutableIdentity)?;
    let mut runtime_path = hold_path(parent, true)?;
    let private = PrivateDirectory::open_or_create(runtime_directory)?;
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
    let child = NativeChild::spawn(&executable, runtime_directory, job.as_handle(), keeper)?;
    Ok(SpawnAssets {
        child,
        job,
        executable,
        private,
        runtime_path,
    })
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

fn wait_process(child: &NativeChild, deadline: Instant) -> Result<(), Error> {
    match wait_until(child, deadline)? {
        WaitOutcome::Signaled => Ok(()),
        WaitOutcome::TimedOut => Err(Error::Timeout),
        WaitOutcome::Abandoned => Err(Error::Protocol("process wait reported abandonment")),
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
