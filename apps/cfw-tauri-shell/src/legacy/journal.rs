use std::fs::File;
use std::path::{Path, PathBuf};

use cfw_engine_api::{CutoverPreflightRequest, EngineCommandContext, EngineMode};
use cfw_platform::LegacyProxyServiceIdentity;
use cfw_singbox_config::EngineSettings;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::gui_handoff::LegacyGuiIdentity;
use super::network_fingerprint::LegacyNetworkJournalIdentity;
use super::process_cleanup::ProcessRecord;
use super::runtime_plan::LegacyRuntimePlanKind;
use crate::private_store::{AtomicWriteError, LockFileError, PrivateDirectory, PrivateDocument};

const JOURNAL_FILE: &str = "legacy-cutover-journal-v1.json";
const TEMPORARY_FILE: &str = ".legacy-cutover-journal-v1.tmp";
const SCHEMA_VERSION: u16 = 3;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const JOURNAL_DOCUMENT: PrivateDocument = PrivateDocument {
    subject: "legacy cutover journal",
    file: JOURNAL_FILE,
    temporary: TEMPORARY_FILE,
    maximum_bytes: MAX_JOURNAL_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CutoverPhase {
    Prepared,
    /// Schema-stable historical name: the journal-bound legacy GUI has exited,
    /// but the legacy network is still intact and no network mutation is sealed.
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
    /// Exact non-secret engine inputs used to produce both replacement
    /// projections. The per-process controller secret is intentionally not
    /// persisted and is regenerated when a recovery process starts.
    pub(super) replacement_settings: EngineSettings,
    pub(super) runtime_kind: LegacyRuntimePlanKind,
    pub(super) legacy_tunnel: Option<LegacyNetworkJournalIdentity>,
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
    pub(super) tunnel: Option<LegacyNetworkJournalIdentity>,
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
        replacement_settings: EngineSettings,
        runtime_kind: LegacyRuntimePlanKind,
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
            replacement_settings,
            runtime_kind,
            legacy_tunnel: legacy.tunnel,
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
        replacement_settings: &EngineSettings,
    ) -> bool {
        self.target == request.target()
            && self.profile_id == profile_id
            && self.profile_digest == profile_digest
            && self.context.installation_id
                == request.system_proxy_request().context.installation_id
            && self.context.config_epoch == request.system_proxy_request().context.config_epoch
            && request.system_proxy_request().context.generation >= self.context.generation
            && request
                .system_proxy_request()
                .credential_audience
                .profile_id()
                == self.profile_id
            && request
                .system_proxy_request()
                .credential_audience
                .profile_digest()
                == self.profile_digest
            && request.tunnel_request().credential_audience
                == request.system_proxy_request().credential_audience
            && &self.replacement_settings == replacement_settings
    }

    fn validate(&self) -> Result<(), String> {
        let runtime_identity_valid = match self.runtime_kind {
            LegacyRuntimePlanKind::LiveOwned { service_job } => {
                matches!(
                    service_job,
                    cfw_platform::LegacyServiceJobObservation::LoadedActive {
                        program: cfw_platform::LegacyServiceJobProgram::LegacyHelper
                    }
                ) && self.legacy_process.is_some()
                    && self.legacy_session.is_some()
                    && self.legacy_gui.is_some()
            }
            LegacyRuntimePlanKind::DormantRegistered { service_job } => {
                matches!(
                    service_job,
                    cfw_platform::LegacyServiceJobObservation::LoadedInactive {
                        program: cfw_platform::LegacyServiceJobProgram::LegacyHelper
                            | cfw_platform::LegacyServiceJobProgram::RetirementTombstone
                    }
                ) && self.has_no_legacy_runtime_identity()
            }
            LegacyRuntimePlanKind::OfflineUpgrade | LegacyRuntimePlanKind::FreshInstall => {
                self.has_no_legacy_runtime_identity()
            }
        };
        if self.schema_version != SCHEMA_VERSION
            || !canonical_uuid(&self.operation_id)
            || !canonical_uuid(&self.profile_id)
            || !matches!(self.target, EngineMode::SystemProxy | EngineMode::Tunnel)
            || !canonical_uuid(&self.context.installation_id)
            || self.context.config_epoch == 0
            || self.context.generation == 0
            || !sha256_digest(&self.profile_digest)
            || !sha256_digest(&self.system_proxy_digest)
            || !sha256_digest(&self.tunnel_digest)
            || validate_replacement_settings(&self.replacement_settings).is_err()
            || self
                .legacy_tunnel
                .as_ref()
                .is_some_and(|tunnel| tunnel.validate().is_err())
            || self.legacy_process.is_some() != self.legacy_session.is_some()
            || self.legacy_tunnel.is_some() && self.legacy_process.is_none()
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
            || !runtime_identity_valid
        {
            return Err("legacy cutover journal identity is invalid".into());
        }
        Ok(())
    }

    fn has_no_legacy_runtime_identity(&self) -> bool {
        self.legacy_tunnel.is_none()
            && self.legacy_process.is_none()
            && self.legacy_session.is_none()
            && self.legacy_proxy_services.is_empty()
            && self.legacy_proxy_port.is_none()
            && self.legacy_gui.is_none()
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

fn open_journal_directory(root: &Path) -> Result<PrivateDirectory, String> {
    PrivateDirectory::open_or_create(root, JOURNAL_DOCUMENT)
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
    pub(super) fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(super) fn load(&self) -> Result<Option<CutoverJournal>, String> {
        let directory = open_journal_directory(&self.root)?;
        directory.lock()?;
        read_journal(&directory)
    }

    pub(super) fn write_prepared(&self, journal: &CutoverJournal) -> Result<(), String> {
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

    pub(super) fn rebind_recovery_request(
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

    pub(super) fn rebind_endpoint_request(
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

    fn rebind_endpoint_request_with_directory_sync(
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

/// Process-lifetime exclusion for `--migration-handoff`. A second handoff
/// instance cannot prepare, overwrite, or recover the same one-way operation.
#[derive(Debug)]
pub(crate) struct MigrationHandoffLease {
    _file: File,
}

impl MigrationHandoffLease {
    pub(crate) fn acquire(root: &Path) -> Result<Self, String> {
        const LOCK_FILE: &str = "legacy-cutover-handoff-v1.lock";
        open_journal_directory(root)?
            .acquire_lock_file(LOCK_FILE)
            .map(|file| Self { _file: file })
            .map_err(|error| match error {
                LockFileError::Open(error) => {
                    format!("failed to open migration handoff lock: {error}")
                }
                LockFileError::Inspect(error) => error.to_string(),
                LockFileError::UnsafeMetadata => {
                    "migration handoff lock has unsafe metadata".into()
                }
                LockFileError::Busy => {
                    "another migration handoff instance is already running".into()
                }
                LockFileError::Lock(error) => format!("failed to lock migration handoff: {error}"),
            })
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn validate_replacement_settings(settings: &EngineSettings) -> Result<(), String> {
    if settings.mixed_port == 0 {
        return Err("replacement mixed proxy port must be nonzero".into());
    }
    settings
        .clash_api_endpoint()
        .map_err(|error| format!("replacement controller endpoint is invalid: {error}"))?;
    if !(1_280..=9_000).contains(&settings.tunnel_mtu) {
        return Err(format!(
            "replacement tunnel MTU {} is outside the supported range",
            settings.tunnel_mtu
        ));
    }
    Ok(())
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

fn sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use cfw_engine_api::{DirectIpv4HostRoutes, EngineStartRequest, TunnelNetworkOptions};

    fn request() -> CutoverPreflightRequest {
        request_with(9, "11".repeat(32), "22".repeat(32))
    }

    fn request_with(
        generation: u64,
        system_proxy_digest: String,
        tunnel_digest: String,
    ) -> CutoverPreflightRequest {
        let context = EngineCommandContext {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
            generation,
        };
        let credential_audience = cfw_engine_api::CredentialAudience::new(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
        )
        .expect("audience");
        let proxy = EngineStartRequest {
            mode: cfw_singbox_config::ProjectionMode::SystemProxy,
            context: context.clone(),
            credential_audience: credential_audience.clone(),
            config_json: "{}".into(),
            config_content_digest: "10".repeat(32),
            config_digest: system_proxy_digest,
            credential_slots: Vec::new(),
            tunnel_options: None,
        };
        let tunnel = EngineStartRequest {
            mode: cfw_singbox_config::ProjectionMode::Tunnel,
            context,
            credential_audience,
            config_json: "{}".into(),
            config_content_digest: "20".repeat(32),
            config_digest: tunnel_digest,
            credential_slots: Vec::new(),
            tunnel_options: Some(TunnelNetworkOptions {
                ipv6_enabled: true,
                bypass_private_networks: true,
                direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
                mtu: 1500,
                system_proxy_port: None,
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
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
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
                .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
                .expect("advance")
                .phase,
            CutoverPhase::NetworkRetiring
        );
        assert!(
            store
                .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
                .is_err()
        );
        store
            .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            .expect("legacy retired");
    }

    #[test]
    fn replacement_settings_are_source_bound_and_survive_journal_round_trip() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let settings = EngineSettings {
            mixed_port: 7891,
            controller_port: 9091,
            ..EngineSettings::default()
        };
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            settings.clone(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        let loaded = store.load().expect("load").expect("journal");
        assert_eq!(loaded.replacement_settings, settings);
        assert!(loaded.matches_recovery_projection(
            &loaded.profile_id,
            &loaded.profile_digest,
            &request(),
            &settings,
        ));
        let different = EngineSettings {
            mixed_port: 7892,
            ..settings
        };
        assert!(!loaded.matches_recovery_projection(
            &loaded.profile_id,
            &loaded.profile_digest,
            &request(),
            &different,
        ));
    }

    #[test]
    fn replacement_settings_validation_rejects_unusable_persisted_endpoints() {
        let mut journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        journal.replacement_settings.controller_port = journal.replacement_settings.mixed_port;
        assert!(journal.validate().is_err());
    }

    #[test]
    fn endpoint_rebind_atomically_updates_every_projection_binding() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let original_request = request();
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &original_request,
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        let expected = store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .expect("network retiring");

        let replacement_settings = EngineSettings {
            mixed_port: expected.replacement_settings.mixed_port + 1,
            ..expected.replacement_settings.clone()
        };
        let replacement_request = request_with(10, "44".repeat(32), "55".repeat(32));
        let rebound = store
            .rebind_endpoint_request(&expected, &replacement_request, &replacement_settings)
            .expect("atomic endpoint rebind");
        assert_eq!(
            rebound.context,
            replacement_request.system_proxy_request().context
        );
        assert_eq!(
            rebound.system_proxy_digest,
            replacement_request.system_proxy_request().config_digest
        );
        assert_eq!(
            rebound.tunnel_digest,
            replacement_request.tunnel_request().config_digest
        );
        assert_eq!(rebound.replacement_settings, replacement_settings);
        assert_eq!(store.load().expect("load").expect("journal"), rebound);
        assert!(
            store
                .rebind_endpoint_request(
                    &expected,
                    &request_with(11, "66".repeat(32), "77".repeat(32)),
                    &EngineSettings {
                        mixed_port: replacement_settings.mixed_port + 1,
                        ..replacement_settings
                    },
                )
                .is_err(),
            "a stale journal CAS cannot overwrite the committed binding"
        );
    }

    #[test]
    fn endpoint_rebind_directory_fsync_failure_preserves_exact_recovery_binding() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        let expected = store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .expect("network retiring");
        let replacement_settings = EngineSettings {
            mixed_port: expected.replacement_settings.mixed_port + 1,
            controller_port: expected.replacement_settings.controller_port + 1,
            ..expected.replacement_settings.clone()
        };
        let replacement_request = request_with(10, "44".repeat(32), "55".repeat(32));

        let failure = store
            .rebind_endpoint_request_with_directory_sync(
                &expected,
                &replacement_request,
                &replacement_settings,
                |_| {
                    Err(std::io::Error::other(
                        "injected endpoint directory fsync failure",
                    ))
                },
            )
            .expect_err("directory fsync must remain commit-uncertain");
        assert!(failure.commit_is_uncertain());
        let intended = match failure {
            JournalAdvanceError::CommitUncertain(state) => {
                assert_eq!(
                    state.intended.context,
                    replacement_request.system_proxy_request().context
                );
                assert_eq!(
                    state.intended.system_proxy_digest,
                    replacement_request.system_proxy_request().config_digest
                );
                assert_eq!(
                    state.intended.tunnel_digest,
                    replacement_request.tunnel_request().config_digest
                );
                assert_eq!(state.intended.replacement_settings, replacement_settings);
                assert_eq!(state.persisted, Ok(Some(state.intended.clone())));
                assert!(
                    state
                        .detail
                        .contains("injected endpoint directory fsync failure")
                );
                state.intended
            }
            other => panic!("unexpected fault classification: {other:?}"),
        };

        let reopened = CutoverJournalStore::new(root.path());
        assert_eq!(
            reopened.load().expect("reopen journal"),
            Some(intended),
            "restart recovery must observe the exact rebound projection"
        );
    }

    #[test]
    fn endpoint_rebind_rejects_non_endpoint_drift_and_replacement_active() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        let network_retiring = store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .expect("network retiring");
        let drifted = EngineSettings {
            mixed_port: network_retiring.replacement_settings.mixed_port + 1,
            enable_ipv6: !network_retiring.replacement_settings.enable_ipv6,
            ..network_retiring.replacement_settings.clone()
        };
        assert!(
            store
                .rebind_endpoint_request(
                    &network_retiring,
                    &request_with(10, "44".repeat(32), "55".repeat(32)),
                    &drifted,
                )
                .is_err(),
            "endpoint recovery cannot change non-endpoint settings"
        );

        let legacy_retired = store
            .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            .expect("legacy retired");
        let replacement_active = store
            .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
            .expect("replacement active");
        assert!(
            store
                .rebind_endpoint_request(
                    &replacement_active,
                    &request_with(10, "44".repeat(32), "55".repeat(32)),
                    &EngineSettings {
                        controller_port: legacy_retired.replacement_settings.controller_port + 1,
                        ..legacy_retired.replacement_settings
                    },
                )
                .is_err(),
            "ReplacementActive is immutable"
        );
    }

    #[test]
    fn recovery_rebind_rotates_context_digests_but_not_replacement_active() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .expect("network retiring");

        let rotated = request_with(9, "44".repeat(32), "55".repeat(32));
        let rebound = store
            .rebind_recovery_request(
                CutoverPhase::NetworkRetiring,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &"33".repeat(32),
                &rotated,
                &EngineSettings::default(),
            )
            .expect("same-generation unused recovery projection can rotate process-bound digests");
        assert_eq!(rebound.context, rotated.system_proxy_request().context);
        assert_eq!(
            rebound.system_proxy_digest,
            rotated.system_proxy_request().config_digest
        );
        assert_eq!(
            rebound.tunnel_digest,
            rotated.tunnel_request().config_digest
        );

        store
            .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
            .expect("legacy retired");
        store
            .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
            .expect("replacement active");
        assert!(
            store
                .rebind_recovery_request(
                    CutoverPhase::ReplacementActive,
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    &"33".repeat(32),
                    &request_with(10, "66".repeat(32), "77".repeat(32)),
                    &EngineSettings::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn post_rename_directory_fsync_failure_is_bound_and_commit_uncertain() {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");

        let failure = store
            .advance_with_directory_sync(
                CutoverPhase::Prepared,
                CutoverPhase::NetworkRetiring,
                |_| Err(std::io::Error::other("injected directory fsync failure")),
            )
            .expect_err("directory fsync must remain commit-uncertain");
        assert!(failure.commit_is_uncertain());
        match failure {
            JournalAdvanceError::CommitUncertain(state) => {
                assert_eq!(state.intended.phase, CutoverPhase::NetworkRetiring);
                assert_eq!(state.persisted, Ok(Some(state.intended.clone())));
                assert!(state.detail.contains("injected directory fsync failure"));
            }
            other => panic!("unexpected fault classification: {other:?}"),
        }
        assert_eq!(
            store.load().expect("load").expect("journal").phase,
            CutoverPhase::NetworkRetiring,
            "the lock-bound reread exposes the sealed phase for idempotent recovery"
        );
    }

    #[test]
    fn pre_network_crash_states_converge_to_one_way_recovery_without_gui_relaunch() {
        for phase in [CutoverPhase::Prepared, CutoverPhase::GuiStopped] {
            let root = tempfile::tempdir().expect("temp");
            let store = CutoverJournalStore::new(root.path());
            let journal = CutoverJournal::prepared(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "33".repeat(32),
                &request(),
                EngineSettings::default(),
                LegacyRuntimePlanKind::FreshInstall,
                LegacyNetworkJournalInput::default(),
                None,
            )
            .expect("journal");
            store.write_prepared(&journal).expect("write prepared");
            if phase == CutoverPhase::GuiStopped {
                store
                    .advance(CutoverPhase::Prepared, CutoverPhase::GuiStopped)
                    .expect("materialize old-schema GUI phase");
            }
            assert_eq!(
                store
                    .advance(phase, CutoverPhase::NetworkRetiring)
                    .expect("seal retry")
                    .phase,
                CutoverPhase::NetworkRetiring
            );
        }
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
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("fresh journal");
        assert!(journal.legacy_gui.is_none());

        let mut inconsistent = journal;
        inconsistent.legacy_tunnel = Some(LegacyNetworkJournalIdentity {
            interface: "utun7".into(),
            route_digest: "11".repeat(32),
            route_count: 1,
            scoped_dns_resolvers: 0,
        });
        assert!(inconsistent.validate().is_err());
    }
}
