use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cfw_engine_api::{CutoverPreflightRequest, EngineCommandContext, EngineMode};
use cfw_platform::LegacyProxyServiceIdentity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::gui_handoff::LegacyGuiIdentity;
#[cfg(test)]
use super::handoff_ticket::ProcessStartIdentity;
use super::process_cleanup::ProcessRecord;

const JOURNAL_FILE: &str = "legacy-cutover-journal-v1.json";
const TEMPORARY_FILE: &str = ".legacy-cutover-journal-v1.tmp";
const SCHEMA_VERSION: u16 = 1;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CutoverPhase {
    Prepared,
    GuiStopped,
    NetworkRetiring,
    LegacyRetired,
    ReplacementActive,
    CleanupComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CutoverJournal {
    schema_version: u16,
    operation_id: String,
    pub(super) phase: CutoverPhase,
    pub(super) target: EngineMode,
    pub(super) profile_id: String,
    pub(super) profile_digest: String,
    pub(super) context: EngineCommandContext,
    pub(super) system_proxy_digest: String,
    pub(super) tunnel_digest: String,
    pub(super) legacy_interface: Option<String>,
    pub(super) legacy_process: Option<ProcessRecord>,
    pub(super) legacy_session: Option<LegacySessionJournalIdentity>,
    pub(super) legacy_proxy_services: Vec<LegacyProxyServiceIdentity>,
    pub(super) legacy_proxy_port: Option<u16>,
    pub(super) legacy_gui: Option<LegacyGuiIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacySessionJournalIdentity {
    pub(super) mixed_port: u16,
    pub(super) controller_port: u16,
    pub(super) generation: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct LegacyNetworkJournalInput {
    pub(super) interface: Option<String>,
    pub(super) process: Option<ProcessRecord>,
    pub(super) session: Option<LegacySessionJournalIdentity>,
    pub(super) proxy_services: Vec<LegacyProxyServiceIdentity>,
    pub(super) proxy_port: Option<u16>,
}

impl CutoverJournal {
    pub(super) fn prepared(
        profile_id: impl Into<String>,
        profile_digest: impl Into<String>,
        request: &CutoverPreflightRequest,
        legacy: LegacyNetworkJournalInput,
        legacy_gui: Option<LegacyGuiIdentity>,
    ) -> Result<Self, String> {
        let journal = Self {
            schema_version: SCHEMA_VERSION,
            operation_id: Uuid::new_v4().hyphenated().to_string(),
            phase: CutoverPhase::Prepared,
            target: request.target(),
            profile_id: profile_id.into(),
            profile_digest: profile_digest.into(),
            context: request.system_proxy_request().context.clone(),
            system_proxy_digest: request.system_proxy_request().config_digest.clone(),
            tunnel_digest: request.tunnel_request().config_digest.clone(),
            legacy_interface: legacy.interface,
            legacy_process: legacy.process,
            legacy_session: legacy.session,
            legacy_proxy_services: legacy.proxy_services,
            legacy_proxy_port: legacy.proxy_port,
            legacy_gui,
        };
        journal.validate()?;
        Ok(journal)
    }

    fn matches_recovery_projection(
        &self,
        profile_id: &str,
        profile_digest: &str,
        request: &CutoverPreflightRequest,
    ) -> bool {
        self.target == request.target()
            && self.profile_id == profile_id
            && self.profile_digest == profile_digest
            && self.context.installation_id
                == request.system_proxy_request().context.installation_id
            && self.context.config_epoch == request.system_proxy_request().context.config_epoch
            && request.system_proxy_request().context.generation >= self.context.generation
            && self.system_proxy_digest == request.system_proxy_request().config_digest
            && self.tunnel_digest == request.tunnel_request().config_digest
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION
            || !canonical_uuid(&self.operation_id)
            || !canonical_uuid(&self.profile_id)
            || self.target == EngineMode::Off
            || !canonical_uuid(&self.context.installation_id)
            || self.context.config_epoch == 0
            || self.context.generation == 0
            || !sha256_digest(&self.profile_digest)
            || !sha256_digest(&self.system_proxy_digest)
            || !sha256_digest(&self.tunnel_digest)
            || self.legacy_interface.as_ref().is_some_and(|interface| {
                !interface.strip_prefix("utun").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
            })
            || self.legacy_process.is_some() != self.legacy_session.is_some()
            || self.legacy_interface.is_some() && self.legacy_process.is_none()
            || self.legacy_process.as_ref().is_some_and(|process| {
                process.uid != 0
                    || process.pid == 0
                    || process.start_identity.is_empty()
                    || process.start_identity.len() > 128
                    || process.start_identity.chars().any(char::is_control)
                    || process.command.is_empty()
                    || process.command.len() > 4096
                    || process.command.chars().any(char::is_control)
                    || !matches!(
                        process
                            .executable
                            .file_name()
                            .and_then(|name| name.to_str()),
                        Some("clash-darwin" | "clash-rs" | "mihomo")
                    )
            })
            || self.legacy_session.as_ref().is_some_and(|session| {
                session.mixed_port == 0 || session.controller_port == 0 || session.generation == 0
            })
            || self.legacy_proxy_services.is_empty() != self.legacy_proxy_port.is_none()
            || self.legacy_proxy_services.len() > 64
            || self.legacy_proxy_services.iter().any(|service| {
                service.service_id().is_empty()
                    || service.service_id().len() > 1024
                    || service.service_id().chars().any(char::is_control)
                    || service.display_name().is_empty()
                    || service.display_name().len() > 1024
                    || service.display_name().chars().any(char::is_control)
            })
            || self.legacy_proxy_port == Some(0)
            || self.legacy_gui.as_ref().is_some_and(|legacy_gui| {
                legacy_gui.uid != unsafe { libc::geteuid() }
                    || legacy_gui.pid == 0
                    || !legacy_gui.start_identity.is_valid()
                    || legacy_gui.executable
                        != Path::new("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac")
            })
            || self.legacy_gui.is_none()
                && (self.legacy_interface.is_some()
                    || self.legacy_process.is_some()
                    || self.legacy_session.is_some()
                    || !self.legacy_proxy_services.is_empty()
                    || self.legacy_proxy_port.is_some())
        {
            return Err("legacy cutover journal identity is invalid".into());
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("failed to encode legacy cutover journal: {error}"))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("legacy cutover journal exceeds 16 KiB".into());
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone)]
pub(super) struct CutoverJournalStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum JournalAdvanceError {
    Failed(String),
    CommitUncertain(Box<CommitUncertainJournal>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CommitUncertainJournal {
    intended: CutoverJournal,
    persisted: Result<Option<CutoverJournal>, String>,
    detail: String,
}

impl JournalAdvanceError {
    pub(super) fn commit_is_uncertain(&self) -> bool {
        matches!(self, Self::CommitUncertain(_))
    }
}

impl std::fmt::Display for JournalAdvanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(message) => formatter.write_str(message),
            Self::CommitUncertain(state) => write!(
                formatter,
                "cutover journal {:?} commit durability is uncertain after rename ({detail}); lock-bound reread phase: {}",
                state.intended.phase,
                match &state.persisted {
                    Ok(Some(journal)) => format!("{:?}", journal.phase),
                    Ok(None) => "missing".into(),
                    Err(error) => format!("unreadable ({error})"),
                },
                detail = state.detail,
            ),
        }
    }
}

impl From<String> for JournalAdvanceError {
    fn from(value: String) -> Self {
        Self::Failed(value)
    }
}

impl From<JournalAdvanceError> for String {
    fn from(value: JournalAdvanceError) -> Self {
        value.to_string()
    }
}

#[derive(Debug)]
enum AtomicWriteError {
    Failed(String),
    CommitUncertain(String),
}

impl CutoverJournalStore {
    pub(super) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(super) fn load(&self) -> Result<Option<CutoverJournal>, String> {
        let directory = Directory::open_or_create(&self.root)?;
        directory.lock()?;
        directory.read_journal()
    }

    pub(super) fn write_prepared(&self, journal: &CutoverJournal) -> Result<(), String> {
        if journal.phase != CutoverPhase::Prepared {
            return Err("only a Prepared journal can begin a cutover".into());
        }
        let directory = Directory::open_or_create(&self.root)?;
        directory.lock()?;
        if let Some(existing) = directory.read_journal()? {
            return Err(format!(
                "an existing legacy cutover journal in phase {:?} must be recovered and cannot be overwritten",
                existing.phase
            ));
        }
        directory.write_atomic(&journal.canonical_bytes()?)
    }

    pub(super) fn advance(
        &self,
        expected: CutoverPhase,
        next: CutoverPhase,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        self.advance_with_directory_sync(expected, next, File::sync_all)
    }

    fn advance_with_directory_sync(
        &self,
        expected: CutoverPhase,
        next: CutoverPhase,
        sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        if !valid_transition(expected, next) {
            return Err(JournalAdvanceError::Failed(
                "invalid legacy cutover journal phase transition".into(),
            ));
        }
        let directory = Directory::open_or_create(&self.root).map_err(JournalAdvanceError::from)?;
        directory.lock().map_err(JournalAdvanceError::from)?;
        let mut journal = directory
            .read_journal()
            .map_err(JournalAdvanceError::from)?
            .ok_or_else(|| {
                JournalAdvanceError::Failed("legacy cutover journal is missing".to_owned())
            })?;
        if journal.phase != expected {
            return Err(JournalAdvanceError::Failed(format!(
                "legacy cutover journal is {:?}, expected {expected:?}",
                journal.phase
            )));
        }
        journal.phase = next;
        let bytes = journal
            .canonical_bytes()
            .map_err(JournalAdvanceError::from)?;
        match directory.write_atomic_with_directory_sync(&bytes, sync_directory) {
            Ok(()) => Ok(journal),
            Err(AtomicWriteError::Failed(error)) => Err(JournalAdvanceError::Failed(error)),
            Err(AtomicWriteError::CommitUncertain(detail)) => {
                // The directory remains exclusively locked while binding the
                // visible journal back to the exact intended operation/phase.
                // Even an exact reread remains durability-uncertain and must
                // never be converted to ordinary success.
                let persisted = directory.read_journal();
                Err(JournalAdvanceError::CommitUncertain(Box::new(
                    CommitUncertainJournal {
                        intended: journal,
                        persisted,
                        detail,
                    },
                )))
            }
        }
    }

    pub(super) fn abandon_pre_network(&self, expected: CutoverPhase) -> Result<(), String> {
        if !matches!(expected, CutoverPhase::Prepared | CutoverPhase::GuiStopped) {
            return Err("only a pre-network cutover journal can be abandoned".into());
        }
        let directory = Directory::open_or_create(&self.root)?;
        directory.lock()?;
        let journal = directory
            .read_journal()?
            .ok_or_else(|| "legacy cutover journal is missing".to_owned())?;
        if journal.phase != expected {
            return Err(format!(
                "legacy cutover journal is {:?}, expected {expected:?}",
                journal.phase
            ));
        }
        let name = CString::new(JOURNAL_FILE).expect("fixed name");
        if unsafe { libc::unlinkat(directory.file.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to abandon pre-network cutover journal: {}",
                std::io::Error::last_os_error()
            ));
        }
        directory
            .file
            .sync_all()
            .map_err(|error| format!("failed to fsync journal abandonment: {error}"))
    }

    pub(super) fn rebind_recovery_request(
        &self,
        expected: CutoverPhase,
        profile_id: &str,
        profile_digest: &str,
        request: &CutoverPreflightRequest,
    ) -> Result<CutoverJournal, String> {
        if !matches!(
            expected,
            CutoverPhase::NetworkRetiring
                | CutoverPhase::LegacyRetired
                | CutoverPhase::ReplacementActive
        ) {
            return Err("cutover phase cannot be rebound for replacement recovery".into());
        }
        let directory = Directory::open_or_create(&self.root)?;
        directory.lock()?;
        let mut journal = directory
            .read_journal()?
            .ok_or_else(|| "legacy cutover journal is missing".to_owned())?;
        if journal.phase != expected
            || !journal.matches_recovery_projection(profile_id, profile_digest, request)
        {
            return Err("recovery profile, projection, lineage, or phase does not match the persisted cutover".into());
        }
        journal.context = request.system_proxy_request().context.clone();
        directory.write_atomic(&journal.canonical_bytes()?)?;
        Ok(journal)
    }
}

fn valid_transition(expected: CutoverPhase, next: CutoverPhase) -> bool {
    matches!(
        (expected, next),
        (CutoverPhase::Prepared, CutoverPhase::GuiStopped)
            | (CutoverPhase::GuiStopped, CutoverPhase::NetworkRetiring)
            | (CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            | (CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
            | (
                CutoverPhase::ReplacementActive,
                CutoverPhase::CleanupComplete
            )
    )
}

/// Process-lifetime exclusion for `--migration-handoff`. A second handoff
/// instance cannot prepare, overwrite, or recover the same one-way operation.
#[derive(Debug)]
pub(crate) struct MigrationHandoffLease {
    _file: File,
}

impl MigrationHandoffLease {
    pub(crate) fn acquire(root: &Path) -> Result<Self, String> {
        const LOCK_FILE: &str = "legacy-cutover-handoff-v1.lock";
        let directory = Directory::open_or_create(root)?;
        let name = CString::new(LOCK_FILE).expect("fixed lock name");
        let descriptor = unsafe {
            libc::openat(
                directory.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to open migration handoff lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err("migration handoff lock has unsafe metadata".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            let error = std::io::Error::last_os_error();
            return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                "another migration handoff instance is already running".into()
            } else {
                format!("failed to lock migration handoff: {error}")
            });
        }
        Ok(Self { _file: file })
    }
}

struct Directory {
    file: File,
}

impl Directory {
    fn open_or_create(path: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err("legacy cutover journal root is not a directory".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path).map_err(|error| {
                    format!("failed to create legacy cutover journal root: {error}")
                })?;
            }
            Err(error) => return Err(format!("failed to inspect journal root: {error}")),
        }
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "legacy cutover journal path contains NUL".to_owned())?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(format!(
                "failed to open legacy cutover journal root: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("legacy cutover journal root has unsafe ownership".into());
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } == -1 {
            return Err(format!(
                "failed to secure legacy cutover journal root: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }

    fn lock(&self) -> Result<(), String> {
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX) } == -1 {
            Err(format!(
                "failed to lock legacy cutover journal: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn read_journal(&self) -> Result<Option<CutoverJournal>, String> {
        let name = CString::new(JOURNAL_FILE).expect("fixed name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(format!("failed to open legacy cutover journal: {error}"))
            };
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_JOURNAL_BYTES
        {
            return Err("legacy cutover journal has unsafe metadata".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::by_ref(&mut file)
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read legacy cutover journal: {error}"))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("legacy cutover journal exceeds 16 KiB".into());
        }
        let journal: CutoverJournal = serde_json::from_slice(&bytes)
            .map_err(|error| format!("legacy cutover journal JSON is invalid: {error}"))?;
        if journal.canonical_bytes()? != bytes {
            return Err("legacy cutover journal is not canonical JSON".into());
        }
        Ok(Some(journal))
    }

    fn write_atomic(&self, bytes: &[u8]) -> Result<(), String> {
        self.write_atomic_with_directory_sync(bytes, File::sync_all)
            .map_err(|error| match error {
                AtomicWriteError::Failed(message) => message,
                AtomicWriteError::CommitUncertain(message) => format!(
                    "cutover journal commit durability is uncertain after rename: {message}"
                ),
            })
    }

    fn write_atomic_with_directory_sync(
        &self,
        bytes: &[u8],
        sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), AtomicWriteError> {
        self.remove_stale_temporary()
            .map_err(AtomicWriteError::Failed)?;
        let temporary = CString::new(TEMPORARY_FILE).expect("fixed name");
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(AtomicWriteError::Failed(format!(
                "failed to create legacy cutover journal temporary: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let before_rename = (|| -> Result<(), String> {
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
                return Err(format!(
                    "failed to secure journal temporary: {}",
                    std::io::Error::last_os_error()
                ));
            }
            file.write_all(bytes)
                .map_err(|error| format!("failed to write cutover journal: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("failed to fsync cutover journal: {error}"))?;
            drop(file);
            let destination = CString::new(JOURNAL_FILE).expect("fixed name");
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    temporary.as_ptr(),
                    self.file.as_raw_fd(),
                    destination.as_ptr(),
                )
            } == -1
            {
                return Err(format!(
                    "failed to commit cutover journal: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        if let Err(error) = before_rename {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), temporary.as_ptr(), 0);
            }
            return Err(AtomicWriteError::Failed(error));
        }
        sync_directory(&self.file).map_err(|error| {
            AtomicWriteError::CommitUncertain(format!("directory fsync failed: {error}"))
        })
    }

    fn remove_stale_temporary(&self) -> Result<(), String> {
        let temporary = CString::new(TEMPORARY_FILE).expect("fixed name");
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(format!("failed to inspect journal temporary: {error}"))
            };
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_nlink != 1
            || stat.st_mode & 0o077 != 0
            || stat.st_size < 0
            || stat.st_size as u64 > MAX_JOURNAL_BYTES
        {
            return Err("stale cutover journal temporary has unsafe metadata".into());
        }
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), temporary.as_ptr(), 0) } == -1 {
            return Err(format!(
                "failed to remove stale journal temporary: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::{EngineStartRequest, TunnelNetworkOptions};

    fn request() -> CutoverPreflightRequest {
        let context = EngineCommandContext {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
            generation: 9,
        };
        let credential_audience = cfw_engine_api::CredentialAudience::new(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
        )
        .expect("audience");
        let proxy = EngineStartRequest {
            context: context.clone(),
            credential_audience: credential_audience.clone(),
            config_json: "{}".into(),
            config_content_digest: "10".repeat(32),
            config_digest: "11".repeat(32),
            credential_slots: Vec::new(),
            tunnel_options: None,
        };
        let tunnel = EngineStartRequest {
            context,
            credential_audience,
            config_json: "{}".into(),
            config_content_digest: "20".repeat(32),
            config_digest: "22".repeat(32),
            credential_slots: Vec::new(),
            tunnel_options: Some(TunnelNetworkOptions {
                ipv6_enabled: true,
                bypass_private_networks: true,
                mtu: 1500,
            }),
        };
        CutoverPreflightRequest::new(EngineMode::Tunnel, proxy, tunnel).expect("request")
    }

    #[test]
    fn phase_journal_is_canonical_durable_and_monotonic() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            LegacyNetworkJournalInput::default(),
            Some(LegacyGuiIdentity {
                uid: unsafe { libc::geteuid() },
                pid: 42,
                start_identity: ProcessStartIdentity {
                    seconds: 1_721_599_857,
                    microseconds: 123_456,
                },
                executable: PathBuf::from(
                    "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
                ),
            }),
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        assert_eq!(store.load().expect("load").expect("journal"), journal);
        assert!(
            store.write_prepared(&journal).is_err(),
            "even an existing Prepared journal cannot be overwritten"
        );
        assert_eq!(
            store
                .advance(CutoverPhase::Prepared, CutoverPhase::GuiStopped)
                .expect("advance")
                .phase,
            CutoverPhase::GuiStopped
        );
        assert!(
            store
                .advance(CutoverPhase::Prepared, CutoverPhase::GuiStopped)
                .is_err()
        );
        store
            .advance(CutoverPhase::GuiStopped, CutoverPhase::NetworkRetiring)
            .expect("network retiring");
        store
            .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            .expect("legacy retired");
    }

    #[test]
    fn post_rename_directory_fsync_failure_is_bound_and_commit_uncertain() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            LegacyNetworkJournalInput::default(),
            Some(LegacyGuiIdentity {
                uid: unsafe { libc::geteuid() },
                pid: 42,
                start_identity: ProcessStartIdentity {
                    seconds: 1_721_599_857,
                    microseconds: 123_456,
                },
                executable: PathBuf::from(
                    "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
                ),
            }),
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");

        let failure = store
            .advance_with_directory_sync(CutoverPhase::Prepared, CutoverPhase::GuiStopped, |_| {
                Err(std::io::Error::other("injected directory fsync failure"))
            })
            .expect_err("directory fsync must remain commit-uncertain");
        assert!(failure.commit_is_uncertain());
        match failure {
            JournalAdvanceError::CommitUncertain(state) => {
                assert_eq!(state.intended.phase, CutoverPhase::GuiStopped);
                assert_eq!(state.persisted, Ok(Some(state.intended.clone())));
                assert!(state.detail.contains("injected directory fsync failure"));
            }
            other => panic!("unexpected fault classification: {other:?}"),
        }
        assert_eq!(
            store.load().expect("load").expect("journal").phase,
            CutoverPhase::GuiStopped,
            "the lock-bound reread must expose the renamed phase; callers keep the GUI stopped"
        );
    }

    #[test]
    fn malformed_or_writable_journal_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temp");
        let path = root.path().join(JOURNAL_FILE);
        fs::write(&path, b"{}").expect("write malformed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(CutoverJournalStore::new(root.path()).load().is_err());
    }

    #[test]
    fn fresh_install_journal_has_no_invented_legacy_gui_identity() {
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("fresh journal");
        assert!(journal.legacy_gui.is_none());

        let mut inconsistent = journal;
        inconsistent.legacy_interface = Some("utun7".into());
        assert!(inconsistent.validate().is_err());
    }
}
