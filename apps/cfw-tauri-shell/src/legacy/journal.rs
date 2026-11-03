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

mod store;
pub(super) use store::CutoverJournalStore;

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

fn open_journal_directory(root: &Path) -> Result<PrivateDirectory, String> {
    PrivateDirectory::open_or_create(root, JOURNAL_DOCUMENT)
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
                #[cfg(unix)]
                LockFileError::Open(error) => {
                    format!("failed to open migration handoff lock: {error}")
                }
                #[cfg(unix)]
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

fn sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Test support: writes the journal a finished cutover leaves while its
/// legacy cleanup is pending, `ReplacementActive` with `settings`, under
/// `app_home`.
#[cfg(test)]
pub(crate) fn write_journal_governing_startup(app_home: &Path, settings: EngineSettings) {
    let store = CutoverJournalStore::new(app_home);
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &tests::request(),
        settings,
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    for (expected, next) in [
        (CutoverPhase::Prepared, CutoverPhase::NetworkRetiring),
        (CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired),
        (CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive),
    ] {
        store.advance(expected, next).expect("advance");
    }
}

#[cfg(test)]
mod tests;
