//! The journal's store: reading the journal under its directory lock,
//! committing each phase transition, and the error that tells a failed commit
//! from one whose durability is uncertain.

use super::*;

#[derive(Debug, Clone)]
pub(in crate::legacy) struct CutoverJournalStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::legacy) enum JournalAdvanceError {
    Failed(String),
    CommitUncertain(Box<CommitUncertainJournal>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::legacy) struct CommitUncertainJournal {
    pub(super) intended: CutoverJournal,
    pub(super) persisted: Result<Option<CutoverJournal>, String>,
    pub(super) detail: String,
}

impl JournalAdvanceError {
    pub(in crate::legacy) fn commit_is_uncertain(&self) -> bool {
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

fn read_journal(directory: &PrivateDirectory) -> Result<Option<CutoverJournal>, String> {
    let Some(bytes) = directory.read().map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    let journal: CutoverJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("legacy cutover journal JSON is invalid: {error}"))?;
    if journal.canonical_bytes()? != bytes {
        return Err("legacy cutover journal is not canonical JSON".into());
    }
    Ok(Some(journal))
}

impl CutoverJournalStore {
    pub(in crate::legacy) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(in crate::legacy) fn load(&self) -> Result<Option<CutoverJournal>, String> {
        let directory = open_journal_directory(&self.root)?;
        directory.lock()?;
        read_journal(&directory)
    }

    pub(in crate::legacy) fn write_prepared(&self, journal: &CutoverJournal) -> Result<(), String> {
        if journal.phase != CutoverPhase::Prepared {
            return Err("only a Prepared journal can begin a cutover".into());
        }
        let directory = open_journal_directory(&self.root)?;
        directory.lock()?;
        if let Some(existing) = read_journal(&directory)? {
            return Err(format!(
                "an existing legacy cutover journal in phase {:?} must be recovered and cannot be overwritten",
                existing.phase
            ));
        }
        directory
            .write_atomic_with_directory_sync(&journal.canonical_bytes()?, File::sync_all)
            .map_err(|error| match error {
                AtomicWriteError::Failed(message) => message,
                AtomicWriteError::CommitUncertain(message) => format!(
                    "cutover journal commit durability is uncertain after rename: {message}"
                ),
            })
    }

    pub(in crate::legacy) fn advance(
        &self,
        expected: CutoverPhase,
        next: CutoverPhase,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        self.advance_with_directory_sync(expected, next, File::sync_all)
    }

    pub(super) fn advance_with_directory_sync(
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
        let directory = open_journal_directory(&self.root).map_err(JournalAdvanceError::from)?;
        directory.lock().map_err(JournalAdvanceError::from)?;
        let mut journal = read_journal(&directory)
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
        commit_journal_with_directory_sync(&directory, journal, bytes, sync_directory)
    }

    pub(in crate::legacy) fn rebind_recovery_request(
        &self,
        expected: CutoverPhase,
        profile_id: &str,
        profile_digest: &str,
        request: &CutoverPreflightRequest,
        replacement_settings: &EngineSettings,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        if !matches!(
            expected,
            CutoverPhase::NetworkRetiring | CutoverPhase::LegacyRetired
        ) {
            return Err(JournalAdvanceError::Failed(
                "cutover phase cannot be rebound for replacement recovery".into(),
            ));
        }
        let directory = open_journal_directory(&self.root).map_err(JournalAdvanceError::from)?;
        directory.lock().map_err(JournalAdvanceError::from)?;
        let mut journal = read_journal(&directory)
            .map_err(JournalAdvanceError::from)?
            .ok_or_else(|| {
                JournalAdvanceError::Failed("legacy cutover journal is missing".to_owned())
            })?;
        if journal.phase != expected
            || !journal.matches_recovery_projection(
                profile_id,
                profile_digest,
                request,
                replacement_settings,
            )
        {
            return Err(JournalAdvanceError::Failed(
                "recovery profile, projection, lineage, or phase does not match the persisted cutover".into(),
            ));
        }
        journal.context = request.system_proxy_request().context.clone();
        journal.system_proxy_digest = request.system_proxy_request().config_digest.clone();
        journal.tunnel_digest = request.tunnel_request().config_digest.clone();
        let bytes = journal
            .canonical_bytes()
            .map_err(JournalAdvanceError::from)?;
        commit_journal_with_directory_sync(&directory, journal, bytes, File::sync_all)
    }

    pub(in crate::legacy) fn rebind_endpoint_request(
        &self,
        expected: &CutoverJournal,
        request: &CutoverPreflightRequest,
        replacement_settings: &EngineSettings,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        self.rebind_endpoint_request_with_directory_sync(
            expected,
            request,
            replacement_settings,
            File::sync_all,
        )
    }

    pub(super) fn rebind_endpoint_request_with_directory_sync(
        &self,
        expected: &CutoverJournal,
        request: &CutoverPreflightRequest,
        replacement_settings: &EngineSettings,
        sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<CutoverJournal, JournalAdvanceError> {
        if !matches!(
            expected.phase,
            CutoverPhase::NetworkRetiring | CutoverPhase::LegacyRetired
        ) {
            return Err(JournalAdvanceError::Failed(
                "cutover endpoint binding cannot change in the current phase".into(),
            ));
        }
        if request.target() != expected.target
            || request
                .system_proxy_request()
                .credential_audience
                .profile_id()
                != expected.profile_id
            || request
                .system_proxy_request()
                .credential_audience
                .profile_digest()
                != expected.profile_digest
            || request.tunnel_request().credential_audience
                != request.system_proxy_request().credential_audience
            || request.system_proxy_request().context.installation_id
                != expected.context.installation_id
            || request.system_proxy_request().context.config_epoch != expected.context.config_epoch
            || request.system_proxy_request().context.generation <= expected.context.generation
            || !settings_advance_only_endpoints(
                &expected.replacement_settings,
                replacement_settings,
            )
        {
            return Err(JournalAdvanceError::Failed(
                "cutover endpoint rebind changed immutable projection identity".into(),
            ));
        }

        let directory = open_journal_directory(&self.root).map_err(JournalAdvanceError::from)?;
        directory.lock().map_err(JournalAdvanceError::from)?;
        let current = read_journal(&directory)
            .map_err(JournalAdvanceError::from)?
            .ok_or_else(|| {
                JournalAdvanceError::Failed("legacy cutover journal is missing".to_owned())
            })?;
        if current != *expected {
            return Err(JournalAdvanceError::Failed(
                "legacy cutover journal changed before endpoint rebind commit".into(),
            ));
        }

        let mut rebound = current;
        rebound.context = request.system_proxy_request().context.clone();
        rebound.system_proxy_digest = request.system_proxy_request().config_digest.clone();
        rebound.tunnel_digest = request.tunnel_request().config_digest.clone();
        rebound.replacement_settings = replacement_settings.clone();
        let bytes = rebound
            .canonical_bytes()
            .map_err(JournalAdvanceError::from)?;
        commit_journal_with_directory_sync(&directory, rebound, bytes, sync_directory)
    }
}

fn commit_journal_with_directory_sync(
    directory: &PrivateDirectory,
    intended: CutoverJournal,
    bytes: Vec<u8>,
    sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<CutoverJournal, JournalAdvanceError> {
    match directory.write_atomic_with_directory_sync(&bytes, sync_directory) {
        Ok(()) => Ok(intended),
        Err(AtomicWriteError::Failed(error)) => Err(JournalAdvanceError::Failed(error)),
        Err(AtomicWriteError::CommitUncertain(detail)) => {
            // The directory remains exclusively locked while binding the
            // visible journal back to the exact intended operation.
            let persisted = read_journal(directory);
            Err(JournalAdvanceError::CommitUncertain(Box::new(
                CommitUncertainJournal {
                    intended,
                    persisted,
                    detail,
                },
            )))
        }
    }
}

fn valid_transition(expected: CutoverPhase, next: CutoverPhase) -> bool {
    matches!(
        (expected, next),
        (CutoverPhase::Prepared, CutoverPhase::GuiStopped)
            | (CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            | (CutoverPhase::GuiStopped, CutoverPhase::NetworkRetiring)
            | (CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            | (CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
            | (
                CutoverPhase::ReplacementActive,
                CutoverPhase::CleanupComplete
            )
    )
}

fn settings_advance_only_endpoints(current: &EngineSettings, replacement: &EngineSettings) -> bool {
    let mut expected = current.clone();
    expected.mixed_port = replacement.mixed_port;
    expected.controller_port = replacement.controller_port;
    expected == *replacement
        && replacement.mixed_port >= current.mixed_port
        && replacement.controller_port >= current.controller_port
        && (replacement.mixed_port > current.mixed_port
            || replacement.controller_port > current.controller_port)
}
