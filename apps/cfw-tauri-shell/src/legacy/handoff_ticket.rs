#[cfg(test)]
use crate::process_identity::ProcessStartIdentity;
use crate::process_identity::{
    ProcessIdentity, observe_exact_process, process_identity_exists as identity_exists,
};
use std::ffi::OsString;
#[cfg(all(test, unix))]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(unix)]
#[path = "handoff_ticket/storage_unix.rs"]
mod native_storage;
#[cfg(windows)]
#[path = "handoff_ticket/storage_windows.rs"]
mod native_storage;
use native_storage::PrivateDirectory;
#[path = "handoff_ticket/storage_contract.rs"]
mod storage_contract;
#[cfg(all(test, unix))]
use native_storage::write_failure_after_cleanup;
use storage_contract::{
    HANDOFF_DIRECTORY, LockedDocument, MAX_DOCUMENT_BYTES, MAX_HANDOFF_DOCUMENTS, WriteNewFailure,
};

mod cleanup;
mod documents;
use cleanup::{HandoffCleanup, PendingHandoffChild};
use documents::{
    canonical_bytes, child_argv, current_unix_ms, decode_canonical, duration_millis,
    new_renderer_challenges, ready_filename, require_canonical_renderer_challenge,
    require_canonical_token, ticket_filename,
};

const HANDOFF_FLAG: &str = "--migration-handoff";
const TICKET_FLAG: &str = "--migration-ticket";
const TICKET_SCHEMA_VERSION: u16 = 2;
const READY_SCHEMA_VERSION: u16 = 2;
const TICKET_DOCUMENT: &str = "migration-handoff-startup-ticket-v2";
const READY_DOCUMENT: &str = "migration-handoff-renderer-ready-v2";
const READY_WINDOW_LABEL: &str = "main";
const RENDERER_CHALLENGE_COUNT: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const TICKET_LIFETIME: Duration = Duration::from_secs(60);
const TICKET_CLOCK_SKEW: Duration = Duration::from_secs(5);
const STALE_DOCUMENT_GRACE: Duration = Duration::from_secs(60);

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

pub(crate) struct ConsumedHandoffTicket {
    root: PathBuf,
    ticket: StartupTicket,
    child: ProcessIdentity,
    _locked_ticket: LockedDocument,
    ready_failure_quarantine: Mutex<Option<LockedDocument>>,
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
        if !self.parent_absent()? {
            Err(
                "the ticket-bound dashboard parent is still running; cutover remains blocked"
                    .into(),
            )
        } else {
            Ok(())
        }
    }

    pub(crate) fn parent_absent(&self) -> Result<bool, String> {
        identity_exists(&self.ticket.parent).map(|exists| !exists)
    }
}

#[cfg(test)]
mod tests;
