use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const HANDOFF_DIRECTORY: &str = ".migration-handoff-v2";
const HANDOFF_FLAG: &str = "--migration-handoff";
const TICKET_FLAG: &str = "--migration-ticket";
const TICKET_SCHEMA_VERSION: u16 = 2;
const READY_SCHEMA_VERSION: u16 = 2;
const TICKET_DOCUMENT: &str = "migration-handoff-startup-ticket-v2";
const READY_DOCUMENT: &str = "migration-handoff-renderer-ready-v2";
const READY_WINDOW_LABEL: &str = "main";
const RENDERER_CHALLENGE_COUNT: usize = 16;
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024;
const MAX_PROCESS_LIST_BYTES: usize = 1024 * 1024;
const MAX_HANDOFF_DOCUMENTS: usize = 64;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const TICKET_LIFETIME: Duration = Duration::from_secs(60);
const TICKET_CLOCK_SKEW: Duration = Duration::from_secs(5);
const STALE_DOCUMENT_GRACE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessStartIdentity {
    pub(super) seconds: u64,
    pub(super) microseconds: u32,
}

impl ProcessStartIdentity {
    pub(super) fn is_valid(self) -> bool {
        self.seconds > 0 && self.microseconds < 1_000_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub(super) uid: u32,
    pub(super) pid: u32,
    pub(super) start_identity: ProcessStartIdentity,
    pub(super) executable: PathBuf,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LaunchArguments {
    Dashboard,
    MigrationHandoff { token: String },
}

impl std::fmt::Debug for LaunchArguments {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dashboard => formatter.write_str("Dashboard"),
            Self::MigrationHandoff { .. } => formatter
                .debug_struct("MigrationHandoff")
                .field("token", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupTicket {
    schema_version: u16,
    document: String,
    token: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    parent: ProcessIdentity,
    child_executable: PathBuf,
    child_argv: Vec<String>,
    renderer_challenges: Vec<RendererReadyChallenge>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RendererReadyChallenge {
    pub(crate) generation: u32,
    pub(crate) challenge: String,
}

impl RendererReadyChallenge {
    pub(crate) fn from_renderer_input(generation: u32, challenge: String) -> Result<Self, String> {
        if generation == 0
            || usize::try_from(generation)
                .ok()
                .is_none_or(|value| value > RENDERER_CHALLENGE_COUNT)
            || require_canonical_renderer_challenge(&challenge).is_err()
        {
            return Err("renderer-ready acknowledgement input is invalid".into());
        }
        Ok(Self {
            generation,
            challenge,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyAcknowledgement {
    schema_version: u16,
    document: String,
    token: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    child: ProcessIdentity,
    window_label: String,
    renderer: RendererReadyChallenge,
}

pub(super) struct PendingHandoff {
    root: PathBuf,
    ticket: StartupTicket,
}

#[derive(Clone)]
struct HandoffCleanup {
    root: PathBuf,
    token: String,
}

trait CleanupBoundary {
    fn cleanup(&mut self) -> Result<(), String>;
}

/// Owns one fail-closed cleanup boundary. It is armed before the blocking task
/// is spawned, so dropping an unstarted closure, unwinding a worker, or aborting
/// its async caller all execute the same bounded cleanup. Only the successful
/// parent shutdown path may call `disarm`.
struct ArmedCleanup<T: CleanupBoundary> {
    resource: Option<T>,
}

impl<T: CleanupBoundary> ArmedCleanup<T> {
    fn new(resource: T) -> Self {
        Self {
            resource: Some(resource),
        }
    }

    fn resource_mut(&mut self) -> &mut T {
        self.resource
            .as_mut()
            .expect("armed handoff cleanup resource")
    }

    fn cleanup_now(&mut self) -> Result<(), String> {
        let Some(resource) = self.resource.as_mut() else {
            return Ok(());
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.cleanup()));
        self.resource = None;
        match outcome {
            Ok(result) => result,
            Err(_) => Err("migration handoff cleanup panicked".into()),
        }
    }

    fn disarm(&mut self) {
        self.resource = None;
    }
}

impl<T: CleanupBoundary> Drop for ArmedCleanup<T> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup_now() {
            eprintln!("migration handoff cleanup after task termination failed: {error}");
        }
    }
}

struct PendingHandoffResources {
    pending: PendingHandoff,
    child: Option<Child>,
}

impl CleanupBoundary for PendingHandoffResources {
    fn cleanup(&mut self) -> Result<(), String> {
        let executable = self.pending.ticket.child_executable.clone();
        let documents = self.pending.cleanup_handle();
        cleanup_handoff_resources(
            self.child
                .as_mut()
                .map(|child| child as &mut dyn ChildProcess),
            &executable,
            &SystemProcessOperations,
            || documents.cleanup(),
        )
    }
}

pub(super) struct PendingHandoffChild {
    cleanup: ArmedCleanup<PendingHandoffResources>,
}

pub(crate) struct ConsumedHandoffTicket {
    root: PathBuf,
    ticket: StartupTicket,
    child: ProcessIdentity,
    _locked_ticket: File,
    ready_failure_quarantine: Mutex<Option<File>>,
}

pub(crate) fn parse_launch_arguments(arguments: &[OsString]) -> Result<LaunchArguments, String> {
    let migration_requested = arguments
        .iter()
        .any(|argument| argument == HANDOFF_FLAG || argument == TICKET_FLAG);
    if !migration_requested {
        return Ok(LaunchArguments::Dashboard);
    }
    let [handoff, ticket_flag, token] = arguments else {
        return Err("migration handoff requires the exact three-argument startup contract".into());
    };
    if handoff != HANDOFF_FLAG || ticket_flag != TICKET_FLAG {
        return Err("migration handoff startup arguments are out of order".into());
    }
    let token = token
        .to_str()
        .ok_or_else(|| "migration handoff token is not UTF-8".to_owned())?;
    require_canonical_token(token)?;
    Ok(LaunchArguments::MigrationHandoff {
        token: token.to_owned(),
    })
}

impl PendingHandoff {
    pub(super) fn create(root: &Path, executable: &Path) -> Result<Self, String> {
        let issued_at_unix_ms = current_unix_ms()?;
        let expires_at_unix_ms = issued_at_unix_ms
            .checked_add(duration_millis(TICKET_LIFETIME)?)
            .ok_or_else(|| "migration handoff ticket expiry overflowed".to_owned())?;
        let token = Uuid::new_v4().hyphenated().to_string();
        let renderer_challenges = new_renderer_challenges(&token)?;
        let parent = observe_exact_process(std::process::id(), executable)?
            .ok_or_else(|| "running dashboard process identity is not exact".to_owned())?;
        let child_argv = child_argv(&token);
        let ticket = StartupTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            document: TICKET_DOCUMENT.into(),
            token,
            issued_at_unix_ms,
            expires_at_unix_ms,
            parent,
            child_executable: executable.to_path_buf(),
            child_argv,
            renderer_challenges,
        };
        ticket.validate_at(issued_at_unix_ms)?;
        let directory = PrivateDirectory::open_or_create(root)?;
        directory.sweep_stale(issued_at_unix_ms)?;
        directory.write_new(&ticket_filename(&ticket.token), &canonical_bytes(&ticket)?)?;
        Ok(Self {
            root: root.to_path_buf(),
            ticket,
        })
    }

    fn spawn(&self) -> Result<Child, String> {
        Command::new(&self.ticket.child_executable)
            .args(&self.ticket.child_argv)
            .spawn()
            .map_err(|error| format!("failed to launch the migration handoff instance: {error}"))
    }

    pub(super) fn child_guard(self) -> PendingHandoffChild {
        PendingHandoffChild::new(self)
    }

    fn cleanup_handle(&self) -> HandoffCleanup {
        HandoffCleanup {
            root: self.root.clone(),
            token: self.ticket.token.clone(),
        }
    }

    fn wait_until_ready(&self, child: &mut Child) -> Result<(), String> {
        if child.id() == 0 {
            return Err("migration handoff child has no process identity".into());
        }
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match self.read_ready(child.id()) {
                Ok(Some(())) => return Ok(()),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "migration handoff exited before readiness with status {status}"
                    ));
                }
                Ok(None) => {}
                Err(error) => return Err(format!("failed to observe migration child: {error}")),
            }
            if Instant::now() >= deadline {
                return Err("migration handoff did not become ready within 20 seconds".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn read_ready(&self, expected_pid: u32) -> Result<Option<()>, String> {
        let directory = PrivateDirectory::open_or_create(&self.root)?;
        let Some((file, bytes)) =
            directory.read_ready_locked_optional(&ready_filename(&self.ticket.token))?
        else {
            return Ok(None);
        };
        let ready: ReadyAcknowledgement =
            decode_canonical(&bytes, "handoff ready acknowledgement")?;
        ready.validate(&self.ticket, expected_pid)?;
        let observed = observe_exact_process(ready.child.pid, &self.ticket.child_executable)?;
        if observed.as_ref() != Some(&ready.child) {
            return Err("migration handoff ready identity does not match the live child".into());
        }
        directory.unlink_locked(&ready_filename(&self.ticket.token), file)?;
        Ok(Some(()))
    }
}

impl PendingHandoffChild {
    fn new(pending: PendingHandoff) -> Self {
        Self {
            cleanup: ArmedCleanup::new(PendingHandoffResources {
                pending,
                child: None,
            }),
        }
    }

    pub(super) fn launch_until_ready(mut self) -> Result<Self, String> {
        let launch = self.cleanup.resource_mut().pending.spawn();
        match launch {
            Ok(child) => self.cleanup.resource_mut().child = Some(child),
            Err(error) => return self.fail(error),
        }
        let readiness = {
            let resources = self.cleanup.resource_mut();
            resources.pending.wait_until_ready(
                resources
                    .child
                    .as_mut()
                    .expect("launched migration handoff child"),
            )
        };
        match readiness {
            Ok(()) => Ok(self),
            Err(error) => self.fail(error),
        }
    }

    pub(super) fn fail<T>(mut self, operation: String) -> Result<T, String> {
        match self.cleanup.cleanup_now() {
            Ok(()) => Err(operation),
            Err(cleanup) => Err(format!(
                "{operation}; migration handoff cleanup also failed: {cleanup}"
            )),
        }
    }

    pub(super) fn disarm(mut self) {
        self.cleanup.disarm();
    }
}

impl HandoffCleanup {
    fn cleanup(&self) -> Result<(), String> {
        let directory = PrivateDirectory::open_or_create(&self.root)?;
        let mut failures = Vec::new();
        for (kind, name) in [
            ("startup ticket", ticket_filename(&self.token)),
            ("readiness acknowledgement", ready_filename(&self.token)),
        ] {
            if let Err(error) = directory.unlink_optional(&name) {
                failures.push(format!("{kind}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

impl ConsumedHandoffTicket {
    pub(crate) fn consume(
        root: &Path,
        token: &str,
        executable: &Path,
        actual_argv: &[OsString],
    ) -> Result<Self, String> {
        require_canonical_token(token)?;
        let directory = PrivateDirectory::open_or_create(root)?;
        let (file, bytes) = directory
            .read_locked_optional(&ticket_filename(token))?
            .ok_or_else(|| {
                "migration handoff startup ticket is missing or was already consumed".to_owned()
            })?;
        let ticket: StartupTicket = decode_canonical(&bytes, "handoff startup ticket")?;
        ticket.validate_at(current_unix_ms()?)?;
        if ticket.token != token
            || ticket.child_executable != executable
            || actual_argv
                != ticket
                    .child_argv
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
        {
            return Err(
                "migration handoff ticket does not bind the exact executable and argv".into(),
            );
        }
        if observe_exact_process(ticket.parent.pid, &ticket.parent.executable)?.as_ref()
            != Some(&ticket.parent)
        {
            return Err("migration handoff parent identity is no longer exact".into());
        }
        let child = observe_exact_process(std::process::id(), executable)?
            .ok_or_else(|| "migration handoff child process identity is not exact".to_owned())?;
        directory.unlink_locked(
            &ticket_filename(token),
            file.try_clone()
                .map_err(|error| format!("failed to retain the locked startup ticket: {error}"))?,
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            ticket,
            child,
            _locked_ticket: file,
            ready_failure_quarantine: Mutex::new(None),
        })
    }

    pub(crate) fn parent_identity(&self) -> &ProcessIdentity {
        &self.ticket.parent
    }

    pub(crate) fn renderer_challenges(&self) -> &[RendererReadyChallenge] {
        &self.ticket.renderer_challenges
    }

    pub(crate) fn require_child_identity(&self) -> Result<ProcessIdentity, String> {
        let observed = observe_exact_process(std::process::id(), &self.ticket.child_executable)?
            .ok_or_else(|| "migration handoff child process identity is not exact".to_owned())?;
        if observed != self.child {
            return Err("migration handoff child process identity is not exact".into());
        }
        Ok(observed)
    }

    pub(crate) fn publish_ready(&self, renderer: &RendererReadyChallenge) -> Result<(), String> {
        let child = self.require_child_identity()?;
        let ready = ReadyAcknowledgement {
            schema_version: READY_SCHEMA_VERSION,
            document: READY_DOCUMENT.into(),
            token: self.ticket.token.clone(),
            issued_at_unix_ms: self.ticket.issued_at_unix_ms,
            expires_at_unix_ms: self.ticket.expires_at_unix_ms,
            child,
            window_label: READY_WINDOW_LABEL.into(),
            renderer: renderer.clone(),
        };
        ready.validate(&self.ticket, std::process::id())?;
        let directory = PrivateDirectory::open_or_create(&self.root)?;
        let mut quarantine = self
            .ready_failure_quarantine
            .lock()
            .map_err(|_| "migration handoff ready quarantine lock failed".to_owned())?;
        if quarantine.is_some() {
            return Err(
                "migration handoff ready publication is quarantined after a prior failure".into(),
            );
        }
        match directory.write_new_retaining_ambiguous_failure(
            &ready_filename(&self.ticket.token),
            &canonical_bytes(&ready)?,
        ) {
            Ok(()) => Ok(()),
            Err(mut failure) => {
                *quarantine = failure.quarantine.take();
                Err(failure.message)
            }
        }
    }

    pub(crate) fn require_parent_absent(&self) -> Result<(), String> {
        if identity_exists(&self.ticket.parent)? {
            Err(
                "the ticket-bound 0.4.0 dashboard parent is still running; cutover remains blocked"
                    .into(),
            )
        } else {
            Ok(())
        }
    }
}

impl StartupTicket {
    fn validate_at(&self, now_unix_ms: u64) -> Result<(), String> {
        if self.schema_version != TICKET_SCHEMA_VERSION
            || self.document != TICKET_DOCUMENT
            || require_canonical_token(&self.token).is_err()
            || !valid_ticket_window(self.issued_at_unix_ms, self.expires_at_unix_ms, now_unix_ms)
            || self.parent.uid != unsafe { libc::geteuid() }
            || self.parent.pid == 0
            || !self.parent.start_identity.is_valid()
            || self.parent.executable != self.child_executable
            || !self.child_executable.is_absolute()
            || self.child_argv != child_argv(&self.token)
            || validate_renderer_challenges(&self.token, &self.renderer_challenges).is_err()
        {
            return Err("migration handoff startup ticket is invalid".into());
        }
        Ok(())
    }
}

impl ReadyAcknowledgement {
    fn validate(&self, ticket: &StartupTicket, expected_pid: u32) -> Result<(), String> {
        if self.schema_version != READY_SCHEMA_VERSION
            || self.document != READY_DOCUMENT
            || self.token != ticket.token
            || self.issued_at_unix_ms != ticket.issued_at_unix_ms
            || self.expires_at_unix_ms != ticket.expires_at_unix_ms
            || !valid_ticket_window(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                current_unix_ms()?,
            )
            || self.child.uid != unsafe { libc::geteuid() }
            || self.child.pid == 0
            || self.child.pid != expected_pid
            || !self.child.start_identity.is_valid()
            || self.child.executable != ticket.child_executable
            || self.window_label != READY_WINDOW_LABEL
            || !ticket.renderer_challenges.contains(&self.renderer)
        {
            return Err("migration handoff ready acknowledgement is invalid".into());
        }
        Ok(())
    }
}

pub(super) fn list_exact_processes(executable: &Path) -> Result<Vec<ProcessIdentity>, String> {
    let mut matches = process_ids()?
        .into_iter()
        .filter_map(|pid| observe_exact_process(pid, executable).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if matches.len() > 8 {
        return Err("more than eight exact GUI process identities were observed".into());
    }
    matches.sort_by_key(|identity| identity.pid);
    Ok(matches)
}

pub(super) fn identity_exists(expected: &ProcessIdentity) -> Result<bool, String> {
    Ok(observe_exact_process(expected.pid, &expected.executable)?.as_ref() == Some(expected))
}

pub(super) fn identity_is_stopped(expected: &ProcessIdentity) -> Result<bool, String> {
    let Some(observed) = observe_kernel_process(expected.pid, &expected.executable)? else {
        return Err("persisted process identity no longer exists".into());
    };
    if &observed.identity != expected {
        return Err("persisted process identity changed during state observation".into());
    }
    Ok(observed.status == 4) // SSTOP from <sys/proc.h>.
}

fn observe_exact_process(pid: u32, executable: &Path) -> Result<Option<ProcessIdentity>, String> {
    Ok(observe_kernel_process(pid, executable)?.map(|observed| observed.identity))
}

#[derive(Debug)]
struct KernelProcessObservation {
    identity: ProcessIdentity,
    status: u32,
}

fn observe_kernel_process(
    pid: u32,
    expected_executable: &Path,
) -> Result<Option<KernelProcessObservation>, String> {
    let Ok(pid_signed) = libc::pid_t::try_from(pid) else {
        return Err("process PID is outside Darwin's signed PID range".into());
    };
    if pid_signed <= 0 {
        return Ok(None);
    }
    let Some(before) = process_bsd_info(pid_signed)? else {
        return Ok(None);
    };
    if before.pbi_uid != unsafe { libc::geteuid() } || before.pbi_pid != pid {
        return Ok(None);
    }
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let path_length = unsafe {
        libc::proc_pidpath(
            pid_signed,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).expect("Darwin process path bound fits u32"),
        )
    };
    if path_length <= 0 {
        if process_bsd_info(pid_signed)?.is_none() {
            return Ok(None);
        }
        return Err(format!(
            "failed to resolve kernel executable identity for process {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if path_length as usize >= path.len() {
        return Err("kernel process executable path reached its truncation bound".into());
    }
    path.truncate(path_length as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    let executable = PathBuf::from(OsString::from_vec(path));
    if executable != expected_executable {
        return Ok(None);
    }
    let Some(after) = process_bsd_info(pid_signed)? else {
        return Ok(None);
    };
    if !same_process_incarnation(&before, &after) {
        return Err("process identity changed during kernel observation".into());
    }
    Ok(Some(KernelProcessObservation {
        identity: ProcessIdentity {
            uid: after.pbi_uid,
            pid: after.pbi_pid,
            start_identity: ProcessStartIdentity {
                seconds: after.pbi_start_tvsec,
                microseconds: u32::try_from(after.pbi_start_tvusec)
                    .map_err(|_| "kernel process start microseconds overflowed".to_owned())?,
            },
            executable,
        },
        status: after.pbi_status,
    }))
}

fn process_bsd_info(pid: libc::pid_t) -> Result<Option<libc::proc_bsdinfo>, String> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).expect("proc_bsdinfo size fits i32"),
        )
    };
    if result == 0 {
        if unsafe { libc::kill(pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return Ok(None);
        }
        return Err(format!(
            "failed to read kernel process identity for PID {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result as usize != expected {
        return Err(format!(
            "kernel process identity for PID {pid} had unexpected size {result}"
        ));
    }
    Ok(Some(unsafe { info.assume_init() }))
}

fn same_process_incarnation(left: &libc::proc_bsdinfo, right: &libc::proc_bsdinfo) -> bool {
    left.pbi_pid == right.pbi_pid
        && left.pbi_uid == right.pbi_uid
        && left.pbi_start_tvsec == right.pbi_start_tvsec
        && left.pbi_start_tvusec == right.pbi_start_tvusec
}

fn process_ids() -> Result<Vec<u32>, String> {
    const PROC_ALL_PIDS: u32 = 1;
    let mut pids = vec![0_i32; MAX_PROCESS_LIST_BYTES / std::mem::size_of::<i32>()];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            i32::try_from(MAX_PROCESS_LIST_BYTES).expect("process list bound fits i32"),
        )
    };
    if bytes < 0 {
        return Err(format!(
            "failed to enumerate kernel process identities: {}",
            std::io::Error::last_os_error()
        ));
    }
    if bytes as usize >= MAX_PROCESS_LIST_BYTES
        || !(bytes as usize).is_multiple_of(std::mem::size_of::<i32>())
    {
        return Err("kernel process enumeration exceeded its bound or was malformed".into());
    }
    pids.truncate(bytes as usize / std::mem::size_of::<i32>());
    Ok(pids
        .into_iter()
        .filter_map(|pid| u32::try_from(pid).ok().filter(|pid| *pid > 0))
        .collect())
}

trait ChildProcess {
    fn process_id(&self) -> u32;
    fn has_exited(&mut self) -> Result<bool, String>;
    fn reap(&mut self) -> Result<(), String>;
}

impl ChildProcess for Child {
    fn process_id(&self) -> u32 {
        self.id()
    }

    fn has_exited(&mut self) -> Result<bool, String> {
        self.try_wait()
            .map(|status| status.is_some())
            .map_err(|error| format!("failed to observe migration child exit: {error}"))
    }

    fn reap(&mut self) -> Result<(), String> {
        self.wait()
            .map(|_| ())
            .map_err(|error| format!("failed to reap migration child: {error}"))
    }
}

trait ProcessOperations {
    fn observe(&self, pid: u32, executable: &Path) -> Result<Option<ProcessIdentity>, String>;
    fn signal(&self, pid: u32, signal: libc::c_int) -> Result<(), String>;
    fn wait_bounded(&self, child: &mut dyn ChildProcess, timeout: Duration)
    -> Result<bool, String>;
}

struct SystemProcessOperations;

impl ProcessOperations for SystemProcessOperations {
    fn observe(&self, pid: u32, executable: &Path) -> Result<Option<ProcessIdentity>, String> {
        observe_exact_process(pid, executable)
    }

    fn signal(&self, pid: u32, signal: libc::c_int) -> Result<(), String> {
        if unsafe { libc::kill(pid as libc::pid_t, signal) } == -1 {
            Err(format!(
                "failed to signal migration child: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn wait_bounded(
        &self,
        child: &mut dyn ChildProcess,
        timeout: Duration,
    ) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if child.has_exited()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn cleanup_handoff_resources<F>(
    child: Option<&mut dyn ChildProcess>,
    executable: &Path,
    operations: &dyn ProcessOperations,
    cleanup_documents: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let termination = child
        .map(|child| terminate_exact_process_with(child, executable, operations))
        .unwrap_or(Ok(()));
    let documents = cleanup_documents();
    match (termination, documents) {
        (Ok(()), Ok(())) => Ok(()),
        (termination, documents) => Err(format!(
            "termination={termination:?}, documents={documents:?}"
        )),
    }
}

fn terminate_exact_process_with(
    child: &mut dyn ChildProcess,
    executable: &Path,
    operations: &dyn ProcessOperations,
) -> Result<(), String> {
    if child.has_exited()? {
        return child.reap();
    }
    // This PID belongs to our Child and remains unreaped throughout each
    // signal boundary, so Darwin cannot recycle it. Kernel incarnation checks
    // are still repeated before SIGTERM and SIGKILL to bind the ticket path.
    let pid = child.process_id();
    let identity = operations
        .observe(pid, executable)?
        .ok_or_else(|| "migration child identity changed; no signal was sent".to_owned())?;
    if operations.observe(pid, executable)?.as_ref() != Some(&identity) {
        return Err("migration child identity changed at the graceful signal boundary".into());
    }
    operations.signal(identity.pid, libc::SIGTERM)?;
    if operations.wait_bounded(child, TERMINATION_TIMEOUT)? {
        return child.reap();
    }
    if operations.observe(pid, executable)?.as_ref() != Some(&identity) {
        return Err("migration child identity changed before forced termination".into());
    }
    operations.signal(pid, libc::SIGKILL)?;
    child.reap()
}

fn child_argv(token: &str) -> Vec<String> {
    vec![HANDOFF_FLAG.into(), TICKET_FLAG.into(), token.into()]
}

fn require_canonical_token(value: &str) -> Result<(), String> {
    if Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value) {
        Ok(())
    } else {
        Err("migration handoff token is not a canonical lowercase UUID".into())
    }
}

fn new_renderer_challenges(startup_token: &str) -> Result<Vec<RendererReadyChallenge>, String> {
    let mut seen = std::collections::BTreeSet::from([startup_token.to_owned()]);
    let mut challenges = Vec::with_capacity(RENDERER_CHALLENGE_COUNT);
    for index in 0..RENDERER_CHALLENGE_COUNT {
        let challenge = Uuid::new_v4().hyphenated().to_string();
        if !seen.insert(challenge.clone()) {
            return Err(
                "renderer-ready challenge generation collided with existing authority".into(),
            );
        }
        challenges.push(RendererReadyChallenge {
            generation: u32::try_from(index + 1)
                .map_err(|_| "renderer-ready generation exceeds u32".to_owned())?,
            challenge,
        });
    }
    validate_renderer_challenges(startup_token, &challenges)?;
    Ok(challenges)
}

fn validate_renderer_challenges(
    startup_token: &str,
    challenges: &[RendererReadyChallenge],
) -> Result<(), String> {
    if challenges.len() != RENDERER_CHALLENGE_COUNT {
        return Err("migration handoff renderer challenge count is invalid".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, challenge) in challenges.iter().enumerate() {
        let expected_generation = u32::try_from(index + 1)
            .map_err(|_| "renderer-ready generation exceeds u32".to_owned())?;
        if challenge.generation != expected_generation
            || require_canonical_renderer_challenge(&challenge.challenge).is_err()
            || challenge.challenge == startup_token
            || !seen.insert(challenge.challenge.as_str())
        {
            return Err(
                "migration handoff renderer challenges are not canonical and unique".into(),
            );
        }
    }
    Ok(())
}

fn require_canonical_renderer_challenge(value: &str) -> Result<(), String> {
    if value.len() != 36 {
        return Err("renderer-ready challenge has the wrong length".into());
    }
    let parsed = Uuid::parse_str(value)
        .map_err(|_| "renderer-ready challenge is not a canonical UUIDv4".to_owned())?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err("renderer-ready challenge is not a canonical UUIDv4".into());
    }
    Ok(())
}

fn current_unix_ms() -> Result<u64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_owned())?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| "system clock does not fit the handoff timestamp format".to_owned())
}

fn duration_millis(duration: Duration) -> Result<u64, String> {
    u64::try_from(duration.as_millis())
        .map_err(|_| "handoff duration does not fit the timestamp format".to_owned())
}

fn valid_ticket_window(issued_at_unix_ms: u64, expires_at_unix_ms: u64, now: u64) -> bool {
    let Ok(skew_ms) = duration_millis(TICKET_CLOCK_SKEW) else {
        return false;
    };
    canonical_ticket_window(issued_at_unix_ms, expires_at_unix_ms)
        && issued_at_unix_ms <= now.saturating_add(skew_ms)
        && now <= expires_at_unix_ms
}

fn canonical_ticket_window(issued_at_unix_ms: u64, expires_at_unix_ms: u64) -> bool {
    let Ok(lifetime_ms) = duration_millis(TICKET_LIFETIME) else {
        return false;
    };
    issued_at_unix_ms > 0
        && issued_at_unix_ms
            .checked_add(lifetime_ms)
            .is_some_and(|expiry| expiry == expires_at_unix_ms)
}

fn ticket_filename(token: &str) -> String {
    format!("ticket-{token}.json")
}

fn ready_filename(token: &str) -> String {
    format!("ready-{token}.json")
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to encode migration handoff document: {error}"))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("migration handoff document exceeds 16 KiB".into());
    }
    Ok(bytes)
}

fn decode_canonical<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(format!("{label} is empty or oversized"));
    }
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    if canonical_bytes(&value)? != bytes {
        return Err(format!("{label} is not canonical JSON"));
    }
    Ok(value)
}

struct PrivateDirectory {
    file: File,
}

struct WriteNewFailure {
    message: String,
    quarantine: Option<File>,
}

impl PrivateDirectory {
    fn open_or_create(root: &Path) -> Result<Self, String> {
        let root_path = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| "handoff root path contains NUL".to_owned())?;
        let root_descriptor = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_descriptor == -1 {
            return Err(format!(
                "failed to open handoff root: {}",
                std::io::Error::last_os_error()
            ));
        }
        let root_file = unsafe { File::from_raw_fd(root_descriptor) };
        let root_metadata = root_file
            .metadata()
            .map_err(|error| format!("failed to inspect handoff root: {error}"))?;
        if !root_metadata.file_type().is_dir()
            || root_metadata.uid() != unsafe { libc::geteuid() }
            || root_metadata.mode() & 0o077 != 0
        {
            return Err("handoff root is not a private user-owned real directory".into());
        }
        let name = CString::new(HANDOFF_DIRECTORY).expect("fixed handoff directory name");
        let created = if unsafe { libc::mkdirat(root_file.as_raw_fd(), name.as_ptr(), 0o700) } == 0
        {
            true
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                false
            } else {
                return Err(format!("failed to create handoff directory: {error}"));
            }
        };
        let descriptor = unsafe {
            libc::openat(
                root_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to open handoff directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect handoff directory: {error}"))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("handoff directory is not a private user-owned real directory".into());
        }
        if created {
            root_file
                .sync_all()
                .map_err(|error| format!("failed to fsync handoff root: {error}"))?;
        }
        Ok(Self { file })
    }

    fn sweep_stale(&self, now_unix_ms: u64) -> Result<(), String> {
        let entries = self.entry_names()?;
        let grace = duration_millis(STALE_DOCUMENT_GRACE)?;
        for name in entries {
            let Some((file, bytes)) = self.read_locked_optional(&name)? else {
                continue;
            };
            let (token, expires_at_unix_ms) = if let Some(token) = document_token(&name, "ticket-")
            {
                let ticket: StartupTicket = decode_canonical(&bytes, "stale startup ticket")?;
                if ticket.schema_version != TICKET_SCHEMA_VERSION
                    || ticket.document != TICKET_DOCUMENT
                    || ticket.token != token
                    || !canonical_ticket_window(ticket.issued_at_unix_ms, ticket.expires_at_unix_ms)
                {
                    return Err("stale startup ticket identity is invalid".into());
                }
                (ticket.token, ticket.expires_at_unix_ms)
            } else if let Some(token) = document_token(&name, "ready-") {
                let ready: ReadyAcknowledgement =
                    decode_canonical(&bytes, "stale readiness acknowledgement")?;
                if ready.schema_version != READY_SCHEMA_VERSION
                    || ready.document != READY_DOCUMENT
                    || ready.token != token
                    || !canonical_ticket_window(ready.issued_at_unix_ms, ready.expires_at_unix_ms)
                {
                    return Err("stale readiness acknowledgement identity is invalid".into());
                }
                (ready.token, ready.expires_at_unix_ms)
            } else {
                return Err(format!(
                    "handoff directory contains unexpected document {name:?}"
                ));
            };
            debug_assert!(name.contains(&token));
            if now_unix_ms > expires_at_unix_ms.saturating_add(grace) {
                self.unlink_locked(&name, file)?;
            }
        }
        Ok(())
    }

    fn entry_names(&self) -> Result<Vec<String>, String> {
        let current = CString::new(".").expect("fixed current-directory name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                current.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to reopen handoff directory for enumeration: {}",
                std::io::Error::last_os_error()
            ));
        }
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(descriptor);
            }
            return Err(format!(
                "failed to enumerate the handoff directory descriptor: {error}"
            ));
        }
        let operation = (|| -> Result<Vec<String>, String> {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let errno = unsafe { *libc::__error() };
                    return if errno == 0 {
                        Ok(names)
                    } else {
                        Err(format!(
                            "failed while enumerating handoff documents: {}",
                            std::io::Error::from_raw_os_error(errno)
                        ))
                    };
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = name
                    .to_str()
                    .map_err(|_| "handoff directory contains a non-UTF-8 document name".to_owned())?
                    .to_owned();
                names.push(name);
                if names.len() > MAX_HANDOFF_DOCUMENTS {
                    return Err(format!(
                        "handoff directory contains more than {MAX_HANDOFF_DOCUMENTS} documents"
                    ));
                }
            }
        })();
        let closed = unsafe { libc::closedir(stream) };
        match (operation, closed) {
            (Ok(names), 0) => Ok(names),
            (Err(error), 0) => Err(error),
            (Ok(_), _) => Err(format!(
                "failed to close handoff directory enumeration: {}",
                std::io::Error::last_os_error()
            )),
            (Err(error), _) => Err(format!(
                "{error}; handoff directory enumeration close also failed: {}",
                std::io::Error::last_os_error()
            )),
        }
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.write_new_retaining_ambiguous_failure(name, bytes)
            .map_err(|failure| failure.message)
    }

    fn write_new_retaining_ambiguous_failure(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), WriteNewFailure> {
        let name = safe_name(name).map_err(|message| WriteNewFailure {
            message,
            quarantine: None,
        })?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_EXLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(WriteNewFailure {
                message: format!(
                    "failed to create handoff document: {}",
                    std::io::Error::last_os_error()
                ),
                quarantine: None,
            });
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        if let Err(operation) = validate_private_file(&file) {
            let cleanup = self.unlink_created(&name);
            return Err(write_failure_after_cleanup(
                operation,
                "unsafe handoff document cleanup",
                cleanup,
                file,
            ));
        }
        let persisted = file.write_all(bytes).and_then(|()| file.sync_all());
        let operation = match persisted {
            Ok(()) => self
                .file
                .sync_all()
                .map_err(|error| format!("failed to fsync handoff directory: {error}")),
            Err(error) => Err(format!("failed to persist handoff document: {error}")),
        };
        if let Err(operation) = operation {
            let cleanup = self.unlink_created(&name);
            return Err(write_failure_after_cleanup(
                operation,
                "failed handoff document cleanup",
                cleanup,
                file,
            ));
        }
        drop(file);
        Ok(())
    }

    fn read_locked_optional(&self, name: &str) -> Result<Option<(File, Vec<u8>)>, String> {
        self.read_locked_optional_with_busy(name, false)
    }

    fn read_ready_locked_optional(&self, name: &str) -> Result<Option<(File, Vec<u8>)>, String> {
        self.read_locked_optional_with_busy(name, true)
    }

    fn read_locked_optional_with_busy(
        &self,
        name: &str,
        writer_busy_is_pending: bool,
    ) -> Result<Option<(File, Vec<u8>)>, String> {
        let name = safe_name(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("failed to open handoff document: {error}"));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            let error = std::io::Error::last_os_error();
            if writer_busy_is_pending && error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("handoff document is already locked: {error}"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read handoff document: {error}"))?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err("handoff document exceeds 16 KiB".into());
        }
        Ok(Some((file, bytes)))
    }

    fn unlink_locked(&self, name: &str, file: File) -> Result<(), String> {
        validate_private_file(&file)?;
        let name = safe_name(name)?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to consume handoff document: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| format!("failed to fsync handoff consumption: {error}"))
    }

    fn unlink_optional(&self, name: &str) -> Result<(), String> {
        let Some((file, _)) = self.read_locked_optional(name)? else {
            return Ok(());
        };
        self.unlink_locked(name, file)
    }

    fn unlink_created(&self, name: &CString) -> Result<(), String> {
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to remove an incomplete handoff document: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| format!("failed to fsync incomplete document removal: {error}"))
    }
}

fn write_failure_after_cleanup(
    operation: String,
    cleanup_label: &str,
    cleanup: Result<(), String>,
    file: File,
) -> WriteNewFailure {
    match cleanup {
        Ok(()) => WriteNewFailure {
            message: operation,
            quarantine: None,
        },
        Err(cleanup) => WriteNewFailure {
            message: format!("{operation}; {cleanup_label} also failed: {cleanup}"),
            quarantine: Some(file),
        },
    }
}

fn validate_private_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect handoff document: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("handoff document is not a private user-owned single-link file".into());
    }
    Ok(())
}

fn safe_name(name: &str) -> Result<CString, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err("handoff document name is invalid".into());
    }
    CString::new(name).map_err(|_| "handoff document name contains NUL".into())
}

fn document_token(name: &str, prefix: &str) -> Option<String> {
    let token = name.strip_prefix(prefix)?.strip_suffix(".json")?;
    require_canonical_token(token).ok()?;
    Some(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingCleanup {
        calls: Arc<AtomicUsize>,
    }

    impl CleanupBoundary for CountingCleanup {
        fn cleanup(&mut self) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[test]
    fn armed_cleanup_runs_during_unwind_and_only_disarms_explicitly() {
        let panic_calls = Arc::new(AtomicUsize::new(0));
        let observed = panic_calls.clone();
        let unwind = std::panic::catch_unwind(move || {
            let _cleanup = ArmedCleanup::new(CountingCleanup { calls: observed });
            panic!("injected handoff panic");
        });
        assert!(unwind.is_err());
        assert_eq!(panic_calls.load(Ordering::Acquire), 1);

        let disarmed_calls = Arc::new(AtomicUsize::new(0));
        let mut cleanup = ArmedCleanup::new(CountingCleanup {
            calls: disarmed_calls.clone(),
        });
        cleanup.disarm();
        drop(cleanup);
        assert_eq!(disarmed_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn armed_cleanup_runs_when_its_owning_task_is_cancelled() {
        let calls = Arc::new(AtomicUsize::new(0));
        let task_calls = calls.clone();
        let (started, start) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _cleanup = ArmedCleanup::new(CountingCleanup { calls: task_calls });
            started.send(()).expect("start cleanup owner");
            std::future::pending::<()>().await;
        });
        start.await.expect("cleanup owner started");
        task.abort();
        assert!(task.await.expect_err("cancelled task").is_cancelled());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    fn fixture_identity(pid: u32, executable: &Path) -> ProcessIdentity {
        ProcessIdentity {
            uid: unsafe { libc::geteuid() },
            pid,
            start_identity: ProcessStartIdentity {
                seconds: 1_721_599_857,
                microseconds: 123_456,
            },
            executable: executable.to_path_buf(),
        }
    }

    fn fixture_ticket(token: &str, issued_at_unix_ms: u64) -> StartupTicket {
        let executable = Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac");
        StartupTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            document: TICKET_DOCUMENT.into(),
            token: token.into(),
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms + duration_millis(TICKET_LIFETIME).expect("ttl"),
            parent: fixture_identity(42, executable),
            child_executable: executable.to_path_buf(),
            child_argv: child_argv(token),
            renderer_challenges: (1..=RENDERER_CHALLENGE_COUNT)
                .map(|generation| RendererReadyChallenge {
                    generation: u32::try_from(generation).expect("fixture generation"),
                    challenge: format!("00000000-0000-4000-8000-{generation:012x}"),
                })
                .collect(),
        }
    }

    #[test]
    fn handoff_arguments_are_exact_and_reject_extra_or_replayed_shapes() {
        let token = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(
            parse_launch_arguments(
                &child_argv(token)
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            )
            .expect("exact args"),
            LaunchArguments::MigrationHandoff {
                token: token.into()
            }
        );
        assert!(
            !format!(
                "{:?}",
                LaunchArguments::MigrationHandoff {
                    token: token.into()
                }
            )
            .contains(token)
        );
        for invalid in [
            vec![HANDOFF_FLAG, TICKET_FLAG],
            vec![HANDOFF_FLAG, TICKET_FLAG, token, "--extra"],
            vec![TICKET_FLAG, HANDOFF_FLAG, token],
            vec![
                HANDOFF_FLAG,
                TICKET_FLAG,
                "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            ],
        ] {
            assert!(
                parse_launch_arguments(
                    &invalid.into_iter().map(OsString::from).collect::<Vec<_>>()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ticket_window_is_exact_bounded_and_expires() {
        let token = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let now = 1_800_000_000_000;
        let ticket = fixture_ticket(token, now);
        ticket.validate_at(now).expect("current ticket");

        let mut leading_future = ticket.clone();
        leading_future.issued_at_unix_ms =
            now + duration_millis(TICKET_CLOCK_SKEW).expect("skew") + 1;
        leading_future.expires_at_unix_ms =
            leading_future.issued_at_unix_ms + duration_millis(TICKET_LIFETIME).expect("ttl");
        assert!(leading_future.validate_at(now).is_err());

        let mut noncanonical_lifetime = ticket.clone();
        noncanonical_lifetime.expires_at_unix_ms += 1;
        assert!(noncanonical_lifetime.validate_at(now).is_err());
        assert!(ticket.validate_at(ticket.expires_at_unix_ms + 1).is_err());
    }

    #[test]
    fn renderer_challenges_are_parent_bound_canonical_unique_and_independent() {
        let token = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let now = 1_800_000_000_000;
        let ticket = fixture_ticket(token, now);
        ticket.validate_at(now).expect("ticket challenge pool");
        assert_eq!(ticket.renderer_challenges.len(), RENDERER_CHALLENGE_COUNT);
        assert!(
            ticket
                .renderer_challenges
                .iter()
                .all(|challenge| challenge.challenge != token)
        );

        let mut duplicate = ticket.clone();
        duplicate.renderer_challenges[1].challenge =
            duplicate.renderer_challenges[0].challenge.clone();
        assert!(duplicate.validate_at(now).is_err());

        let mut reordered = ticket.clone();
        reordered.renderer_challenges[0].generation = 2;
        assert!(reordered.validate_at(now).is_err());
    }

    #[test]
    fn renderer_acknowledgement_input_is_bounded_and_canonical_before_gate_lookup() {
        let canonical = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
        assert!(RendererReadyChallenge::from_renderer_input(1, canonical.into()).is_ok());
        for (generation, challenge) in [
            (0, canonical.to_owned()),
            (
                u32::try_from(RENDERER_CHALLENGE_COUNT + 1).expect("bounded generation"),
                canonical.to_owned(),
            ),
            (1, canonical.to_uppercase()),
            (1, "00000000-0000-1000-8000-000000000001".into()),
            (1, "x".repeat(4096)),
        ] {
            assert!(RendererReadyChallenge::from_renderer_input(generation, challenge).is_err());
        }
    }

    #[test]
    fn ready_v2_binds_main_window_exact_child_and_parent_committed_challenge() {
        let now = current_unix_ms().expect("clock");
        let ticket = fixture_ticket("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now);
        let child = fixture_identity(77, &ticket.child_executable);
        let ready = ReadyAcknowledgement {
            schema_version: READY_SCHEMA_VERSION,
            document: READY_DOCUMENT.into(),
            token: ticket.token.clone(),
            issued_at_unix_ms: ticket.issued_at_unix_ms,
            expires_at_unix_ms: ticket.expires_at_unix_ms,
            child,
            window_label: READY_WINDOW_LABEL.into(),
            renderer: ticket.renderer_challenges[0].clone(),
        };
        ready.validate(&ticket, 77).expect("ready v2");

        let mut native_only_v1 = ready.clone();
        native_only_v1.schema_version = 1;
        native_only_v1.document = "migration-handoff-ready-v1".into();
        assert!(native_only_v1.validate(&ticket, 77).is_err());

        let mut wrong_window = ready.clone();
        wrong_window.window_label = "other".into();
        assert!(wrong_window.validate(&ticket, 77).is_err());

        let mut uncommitted = ready;
        uncommitted.renderer.challenge = "ffffffff-ffff-4fff-8fff-ffffffffffff".into();
        assert!(uncommitted.validate(&ticket, 77).is_err());
    }

    #[test]
    fn ambiguous_ready_write_failure_retains_the_exclusive_file_lock() {
        let fixture = tempfile::NamedTempFile::new().expect("fixture");
        let locked = fixture.reopen().expect("locked descriptor");
        assert_eq!(
            unsafe { libc::flock(locked.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let failure = write_failure_after_cleanup(
            "injected persistence failure".into(),
            "failed handoff document cleanup",
            Err("injected unlink failure".into()),
            locked,
        );
        assert!(failure.quarantine.is_some());

        let competing = fixture.reopen().expect("competing descriptor");
        assert_eq!(
            unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1,
            "parent reader must observe writer-busy while the child quarantines failure"
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(failure);
        assert_eq!(
            unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }

    #[test]
    fn kernel_process_identity_binds_pid_uid_path_and_microsecond_start() {
        let executable = std::env::current_exe().expect("current executable");
        let parsed = observe_exact_process(std::process::id(), &executable)
            .expect("observe")
            .expect("identity");
        assert_eq!(parsed.pid, std::process::id());
        assert_eq!(parsed.uid, unsafe { libc::geteuid() });
        assert_eq!(parsed.executable, executable);
        assert!(parsed.start_identity.is_valid());
        assert!(identity_exists(&parsed).expect("identity still exists"));
    }

    #[test]
    fn missing_pid_is_a_proven_absence_not_an_observation_failure() {
        let missing = fixture_identity(
            i32::MAX as u32,
            Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"),
        );
        assert!(!identity_exists(&missing).expect("missing process is observable"));
    }

    struct FakeChild {
        pid: u32,
        exited: bool,
        reaped: bool,
    }

    impl ChildProcess for FakeChild {
        fn process_id(&self) -> u32 {
            self.pid
        }

        fn has_exited(&mut self) -> Result<bool, String> {
            Ok(self.exited)
        }

        fn reap(&mut self) -> Result<(), String> {
            self.reaped = true;
            self.exited = true;
            Ok(())
        }
    }

    struct FakeProcessOperations {
        observations: RefCell<VecDeque<Option<ProcessIdentity>>>,
        bounded_exit: bool,
        signals: RefCell<Vec<libc::c_int>>,
    }

    impl ProcessOperations for FakeProcessOperations {
        fn observe(
            &self,
            _pid: u32,
            _executable: &Path,
        ) -> Result<Option<ProcessIdentity>, String> {
            self.observations
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "test process observation sequence was exhausted".to_owned())
        }

        fn signal(&self, _pid: u32, signal: libc::c_int) -> Result<(), String> {
            self.signals.borrow_mut().push(signal);
            Ok(())
        }

        fn wait_bounded(
            &self,
            _child: &mut dyn ChildProcess,
            _timeout: Duration,
        ) -> Result<bool, String> {
            Ok(self.bounded_exit)
        }
    }

    #[test]
    fn resource_cleanup_attempts_documents_after_termination_failure() {
        let executable = Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac");
        let operations = FakeProcessOperations {
            observations: RefCell::new(VecDeque::from([None])),
            bounded_exit: false,
            signals: RefCell::new(Vec::new()),
        };
        let mut child = FakeChild {
            pid: 42,
            exited: false,
            reaped: false,
        };
        let documents = std::cell::Cell::new(false);
        let error = cleanup_handoff_resources(Some(&mut child), executable, &operations, || {
            documents.set(true);
            Ok(())
        })
        .expect_err("identity failure must remain visible");
        assert!(documents.get(), "document cleanup must always be attempted");
        assert!(error.contains("termination=Err"));
        assert!(operations.signals.borrow().is_empty());
    }

    #[test]
    fn graceful_resource_cleanup_explicitly_reaps_the_child() {
        let executable = Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac");
        let identity = fixture_identity(42, executable);
        let operations = FakeProcessOperations {
            observations: RefCell::new(VecDeque::from([Some(identity.clone()), Some(identity)])),
            bounded_exit: true,
            signals: RefCell::new(Vec::new()),
        };
        let mut child = FakeChild {
            pid: 42,
            exited: false,
            reaped: false,
        };
        cleanup_handoff_resources(Some(&mut child), executable, &operations, || Ok(()))
            .expect("graceful cleanup");
        assert_eq!(*operations.signals.borrow(), [libc::SIGTERM]);
        assert!(child.reaped);
    }

    #[test]
    fn child_termination_uses_exact_identity_and_test_process_operations() {
        let executable = Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac");
        let identity = fixture_identity(42, executable);
        let operations = FakeProcessOperations {
            observations: RefCell::new(VecDeque::from([
                Some(identity.clone()),
                Some(identity.clone()),
                Some(identity.clone()),
            ])),
            bounded_exit: false,
            signals: RefCell::new(Vec::new()),
        };
        let mut child = FakeChild {
            pid: 42,
            exited: false,
            reaped: false,
        };
        terminate_exact_process_with(&mut child, executable, &operations)
            .expect("exact termination");
        assert_eq!(*operations.signals.borrow(), [libc::SIGTERM, libc::SIGKILL]);
        assert!(child.reaped);

        let mismatched = FakeProcessOperations {
            observations: RefCell::new(VecDeque::from([None])),
            bounded_exit: false,
            signals: RefCell::new(Vec::new()),
        };
        let mut changed = FakeChild {
            pid: 43,
            exited: false,
            reaped: false,
        };
        assert!(terminate_exact_process_with(&mut changed, executable, &mismatched).is_err());
        assert!(mismatched.signals.borrow().is_empty());
        assert!(!changed.reaped);

        let changed_before_kill = FakeProcessOperations {
            observations: RefCell::new(VecDeque::from([
                Some(identity.clone()),
                Some(identity),
                None,
            ])),
            bounded_exit: false,
            signals: RefCell::new(Vec::new()),
        };
        let mut changed = FakeChild {
            pid: 42,
            exited: false,
            reaped: false,
        };
        assert!(
            terminate_exact_process_with(&mut changed, executable, &changed_before_kill).is_err()
        );
        assert_eq!(*changed_before_kill.signals.borrow(), [libc::SIGTERM]);
        assert!(!changed.reaped);
    }

    #[test]
    fn private_documents_are_canonical_single_use_and_replay_fails() {
        let fixture = tempfile::tempdir().expect("fixture");
        std::fs::set_permissions(
            fixture.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("protect fixture");
        let directory = PrivateDirectory::open_or_create(fixture.path()).expect("directory");
        directory
            .write_new("ticket-test.json", br#"{"a":1}"#)
            .expect("write");
        let (file, bytes) = directory
            .read_locked_optional("ticket-test.json")
            .expect("read")
            .expect("exists");
        assert_eq!(bytes, br#"{"a":1}"#);
        directory
            .unlink_locked("ticket-test.json", file)
            .expect("consume");
        assert!(
            directory
                .read_locked_optional("ticket-test.json")
                .expect("replay read")
                .is_none()
        );
    }

    #[test]
    fn stale_sweep_is_expiry_aware_and_bounded() {
        let fixture = tempfile::tempdir().expect("fixture");
        std::fs::set_permissions(
            fixture.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("protect fixture");
        let directory = PrivateDirectory::open_or_create(fixture.path()).expect("directory");
        let now = 1_800_000_000_000;
        let stale_issued = now
            - duration_millis(TICKET_LIFETIME).expect("ttl")
            - duration_millis(STALE_DOCUMENT_GRACE).expect("grace")
            - 1;
        let stale = fixture_ticket("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", stale_issued);
        let fresh = fixture_ticket("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now);
        directory
            .write_new(
                &ticket_filename(&stale.token),
                &canonical_bytes(&stale).expect("stale"),
            )
            .expect("write stale");
        directory
            .write_new(
                &ticket_filename(&fresh.token),
                &canonical_bytes(&fresh).expect("fresh"),
            )
            .expect("write fresh");

        directory.sweep_stale(now).expect("sweep");
        assert!(
            directory
                .read_locked_optional(&ticket_filename(&stale.token))
                .expect("stale read")
                .is_none()
        );
        assert!(
            directory
                .read_locked_optional(&ticket_filename(&fresh.token))
                .expect("fresh read")
                .is_some()
        );

        for index in 0..MAX_HANDOFF_DOCUMENTS {
            directory
                .write_new(&format!("unexpected-{index}.json"), b"{}")
                .expect("bounded fixture");
        }
        assert!(directory.sweep_stale(now).is_err());
    }
}
