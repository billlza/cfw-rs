//! Durable ownership of this user's WinINet LAN proxy settings. This is below
//! service/engine authority: a settings receipt is never a global-Off proof.
mod native;
mod restoration;
pub use restoration::ProxyRestorationObservation;

use crate::{EngineProcess, NativePeerIdentity, NativePeerProcess, PreparedConfig};
use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineCommandContext, SystemProxyAuthorization,
};
use cfw_windows_storage::{PrivateDirectory, PrivateUserMutex, ReadPolicy, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::{fmt, io, path::Path, sync::Arc, time::Duration};
use windows_sys::Win32::Networking::WinInet::{
    PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
};

const MAX_STRING_UNITS: usize = 8192;
const MAX_JOURNAL_BYTES: usize = 512 * 1024;
const JOURNAL: &str = "system-proxy-v1.json";

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Windows proxy storage: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[error("Windows proxy identity: {0}")]
    Identity(#[from] crate::PeerIdentityError),
    #[error("Windows proxy engine observation: {0}")]
    Engine(#[from] crate::Error),
    #[error("Windows proxy {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows proxy requires an unrestricted interactive process user")]
    UnsafeUser,
    #[error("Windows policy prohibits changing this user's proxy settings")]
    PolicyDenied,
    #[error("Windows proxy observation is malformed or exceeds its bound")]
    InvalidObservation,
    #[error("Windows proxy ownership journal is invalid")]
    InvalidJournal,
    #[error("Windows proxy settings changed outside this ownership transaction")]
    SettingsChanged,
    #[error("an explicit proxy or PAC configuration already exists")]
    ExistingProxy,
    #[error("Windows proxy ownership requires reconciliation before another activation")]
    OwnershipConflict,
    #[error("Windows proxy ownership journal is missing; restoration is unproven")]
    OwnershipMissing,
    #[error("Windows proxy has no durable restoration record; restoration is unproven")]
    RestorationMissing,
    #[error("Windows proxy restoration record is invalid")]
    InvalidRestorationRecord,
    #[error("Windows proxy request does not match the running engine")]
    RuntimeMismatch,
    #[error("Windows proxy publication may have changed settings; recovery is required: {0}")]
    OutcomeUnknown(Box<ProxyError>),
    #[error("Windows proxy operation failed ({operation}); cleanup also failed ({cleanup})")]
    CleanupFailed {
        operation: Box<ProxyError>,
        cleanup: Box<ProxyError>,
    },
}

fn with_cleanup<T>(
    result: Result<T, ProxyError>,
    cleanup: Result<(), ProxyError>,
) -> Result<T, ProxyError> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(ProxyError::CleanupFailed {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// Exact native option values. Empty and absent strings have the same WinINet
/// meaning. Raw UTF-16 preserves the original values without lossy conversion.
/// The private recovery journal may contain a PAC URL, so Debug redacts strings.
/// This native snapshot is not a frontend payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySettings {
    flags: u32,
    server: Vec<u16>,
    bypass: Vec<u16>,
    pac_url: Vec<u16>,
}
impl fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySettings")
            .field("flags", &self.flags)
            .field("strings", &"[REDACTED]")
            .finish()
    }
}
impl ProxySettings {
    fn validate(&self) -> Result<(), ProxyError> {
        let known = PROXY_TYPE_DIRECT
            | PROXY_TYPE_PROXY
            | PROXY_TYPE_AUTO_PROXY_URL
            | PROXY_TYPE_AUTO_DETECT;
        if self.flags & !known != 0
            || self.flags == 0
            || [&self.server, &self.bypass, &self.pac_url]
                .iter()
                .any(|value| value.len() > MAX_STRING_UNITS || value.contains(&0))
            || (self.flags & PROXY_TYPE_PROXY != 0 && self.server.is_empty())
            || (self.flags & PROXY_TYPE_AUTO_PROXY_URL != 0 && self.pac_url.is_empty())
        {
            return Err(ProxyError::InvalidObservation);
        }
        Ok(())
    }
    pub fn explicit_proxy_enabled(&self) -> bool {
        self.flags & (PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL) != 0
    }
    fn for_endpoint(&self, endpoint: std::net::SocketAddr) -> Self {
        Self {
            flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
            server: format!("http={endpoint};https={endpoint}")
                .encode_utf16()
                .collect(),
            bypass: "<local>;localhost;127.*;[::1]".encode_utf16().collect(),
            // Keep the disabled PAC URL verbatim; recovery restores its flags.
            pac_url: self.pac_url.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    user_sid: String,
    context: EngineCommandContext,
    config_digest: String,
    process_id: u32,
    process_created_at: u64,
    endpoint: std::net::SocketAddr,
    before: ProxySettings,
    applied: ProxySettings,
}

fn valid_context(context: &EngineCommandContext) -> bool {
    uuid::Uuid::parse_str(&context.installation_id)
        .is_ok_and(|id| !id.is_nil() && id.to_string() == context.installation_id)
        && context.config_epoch > 0
        && context.generation > 0
}

impl Record {
    fn encode(&self, sid: &str) -> Result<Vec<u8>, ProxyError> {
        if self.version != 1
            || self.user_sid != sid
            || !valid_context(&self.context)
            || self.config_digest.len() != 64
            || !self
                .config_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.process_id == 0
            || self.process_created_at == 0
            || self.endpoint.port() == 0
            || !self.endpoint.ip().is_loopback()
            || self.before.explicit_proxy_enabled()
            || self.applied != self.before.for_endpoint(self.endpoint)
        {
            return Err(ProxyError::InvalidJournal);
        }
        self.before.validate()?;
        self.applied.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ProxyError::InvalidJournal)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(ProxyError::InvalidJournal);
        }
        Ok(bytes)
    }
    fn read(transaction: &WriteTransaction, sid: &str) -> Result<Option<Self>, ProxyError> {
        let Some(snapshot) = transaction.read(JOURNAL, MAX_JOURNAL_BYTES, ReadPolicy::Private)?
        else {
            return Ok(None);
        };
        let record: Self =
            serde_json::from_slice(&snapshot.bytes).map_err(|_| ProxyError::InvalidJournal)?;
        if record.encode(sid)? != snapshot.bytes {
            return Err(ProxyError::InvalidJournal);
        }
        Ok(Some(record))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyOwnershipObservation {
    /// Only this journal is absent. Existing OS proxies and other runtimes may
    /// still exist; this cannot certify global Off.
    NoJournal,
    Original {
        context: EngineCommandContext,
    },
    Applied {
        context: EngineCommandContext,
    },
    Conflict {
        context: EngineCommandContext,
    },
}

#[derive(Debug)]
pub struct ProxySettingsReceipt {
    pub context: EngineCommandContext,
    pub configuration_digest: String,
}
#[derive(Debug)]
pub struct ProxySettingsRestored {
    pub context: EngineCommandContext,
    pub configuration_digest: String,
}

/// Synchronous user-agent adapter. Hold the engine lifecycle reservation across
/// activation/restoration, and restore settings before stopping its engine.
/// There is no Drop-based restoration and no claim of a WinINet atomic CAS
/// against non-cooperating applications. Conflicts retain the recovery record.
#[derive(Clone)]
pub struct WindowsSystemProxy {
    directory: Arc<PrivateDirectory>,
    identity: NativePeerIdentity,
}

/// Installed in the process owner before the first possible proxy write.
/// Private construction prevents an unrelated completion from clearing it.
pub(crate) struct ProxyCleanup {
    authority: WindowsSystemProxy,
    context: EngineCommandContext,
    pub(crate) config_digest: String,
    before: ProxySettings,
}
impl ProxyCleanup {
    pub(crate) fn verify_restored(&self) -> Result<(), ProxyError> {
        self.authority.locked(|transaction| {
            if Record::read(transaction, self.authority.identity.user_sid())?.is_some()
                || native::observe()? != self.before
            {
                return Err(ProxyError::OwnershipConflict);
            }
            Ok(())
        })
    }
    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        self.context == other.context
            && self.config_digest == other.config_digest
            && self.before == other.before
            && self.authority.identity == other.authority.identity
    }
    pub(crate) fn restore(&self) -> Result<(), ProxyError> {
        match self.authority.restore(&self.context) {
            Ok(receipt) if receipt.configuration_digest == self.config_digest => Ok(()),
            Ok(_) => Err(ProxyError::OwnershipConflict),
            Err(ProxyError::OwnershipMissing) => self.authority.locked(|transaction| {
                // An explicit restoration may already have removed the journal.
                // Absence alone is insufficient: reobserve our exact original
                // settings under the same user and global ownership lock.
                if Record::read(transaction, self.authority.identity.user_sid())?.is_some()
                    || native::observe()? != self.before
                {
                    return Err(ProxyError::OwnershipConflict);
                }
                Ok(())
            }),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn user_identity() -> Result<NativePeerIdentity, ProxyError> {
    let process = NativePeerProcess::open(std::process::id())?;
    let identity = process.identity();
    if identity.session_id() == 0
        || identity.integrity_rid() < 0x2000
        || identity.is_app_container()
        || identity.is_restricted()
        || matches!(identity.user_sid(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
    {
        return Err(ProxyError::UnsafeUser);
    }
    Ok(identity.clone())
}

impl WindowsSystemProxy {
    pub fn new(directory: &Path) -> Result<Self, ProxyError> {
        let identity = user_identity()?;
        Ok(Self {
            directory: Arc::new(PrivateDirectory::open_or_create(directory)?),
            identity,
        })
    }

    fn locked<T>(
        &self,
        operation: impl FnOnce(&mut WriteTransaction) -> Result<T, ProxyError>,
    ) -> Result<T, ProxyError> {
        if user_identity()? != self.identity {
            return Err(ProxyError::UnsafeUser);
        }
        let guard = PrivateUserMutex::acquire("system-proxy-v1", Duration::from_secs(3))?;
        // Reload the durable journal and OS settings even after abandoned mutex
        // ownership. Never infer a successful restoration from lock admission.
        let result = self
            .directory
            .write()
            .map_err(ProxyError::from)
            .and_then(|mut tx| operation(&mut tx));
        with_cleanup(result, guard.release().map_err(ProxyError::from))
    }

    pub fn snapshot(&self) -> Result<ProxySettings, ProxyError> {
        self.locked(|_| native::observe())
    }

    pub fn inspect(&self) -> Result<ProxyOwnershipObservation, ProxyError> {
        self.locked(|transaction| {
            let record = Record::read(transaction, self.identity.user_sid())?;
            let observed = native::observe()?;
            Ok(match record {
                None => ProxyOwnershipObservation::NoJournal,
                Some(record) if observed == record.before => ProxyOwnershipObservation::Original {
                    context: record.context,
                },
                Some(record) if observed == record.applied => ProxyOwnershipObservation::Applied {
                    context: record.context,
                },
                Some(record) => ProxyOwnershipObservation::Conflict {
                    context: record.context,
                },
            })
        })
    }

    pub(crate) fn verify_owned(
        &self,
        context: &EngineCommandContext,
        engine: &mut EngineProcess,
    ) -> Result<(), ProxyError> {
        self.locked(|transaction| {
            let record = Record::read(transaction, self.identity.user_sid())?
                .ok_or(ProxyError::OwnershipMissing)?;
            let running = engine.observe_under_proxy_lock(Duration::from_secs(15))?;
            let process = NativePeerProcess::open(running.process_id)?;
            if record.context != *context
                || record.config_digest != running.configuration_digest
                || record.process_id != running.process_id
                || record.process_created_at != process.identity().process_creation_time()
                || process.identity().user_session() != self.identity.user_session()
                || native::observe()? != record.applied
            {
                return Err(ProxyError::RuntimeMismatch);
            }
            Ok(())
        })
    }

    /// The exact SystemProxy projection must already be running in this owned
    /// child. This function reobserves the child and its listeners before any
    /// settings write; a local projection cannot be reinterpreted as this mode.
    pub fn activate(
        &self,
        context: &EngineCommandContext,
        engine: &mut EngineProcess,
        config: &PreparedConfig,
    ) -> Result<ProxySettingsReceipt, ProxyError> {
        if !valid_context(context) {
            return Err(ProxyError::RuntimeMismatch);
        }
        let endpoint = config
            .system_proxy_endpoint()
            .ok_or(ProxyError::RuntimeMismatch)?;
        self.locked(|transaction| {
            let running = engine.observe_under_proxy_lock(Duration::from_secs(15))?;
            if running.configuration_digest != config.digest() {
                return Err(ProxyError::RuntimeMismatch);
            }
            let process = NativePeerProcess::open(running.process_id)?;
            if process.identity().user_sid() != self.identity.user_sid() {
                return Err(ProxyError::RuntimeMismatch);
            }
            let observed = native::observe()?;
            if let Some(record) = Record::read(transaction, self.identity.user_sid())? {
                if record.context != *context
                    || record.config_digest != config.digest()
                    || record.process_id != running.process_id
                    || record.process_created_at != process.identity().process_creation_time()
                    || observed != record.applied
                {
                    return Err(ProxyError::OwnershipConflict);
                }
                engine.bind_proxy_cleanup(ProxyCleanup {
                    authority: self.clone(),
                    context: context.clone(),
                    config_digest: config.digest().to_owned(),
                    before: record.before.clone(),
                })?;
                native::notify().map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
                if native::observe()? != record.applied {
                    return Err(ProxyError::SettingsChanged);
                }
            } else {
                if observed.explicit_proxy_enabled() {
                    return Err(ProxyError::ExistingProxy);
                }
                let record = Record {
                    version: 1,
                    user_sid: self.identity.user_sid().to_owned(),
                    context: context.clone(),
                    config_digest: config.digest().to_owned(),
                    process_id: running.process_id,
                    process_created_at: process.identity().process_creation_time(),
                    endpoint,
                    applied: observed.for_endpoint(endpoint),
                    before: observed,
                };
                engine.bind_proxy_cleanup(ProxyCleanup {
                    authority: self.clone(),
                    context: context.clone(),
                    config_digest: config.digest().to_owned(),
                    before: record.before.clone(),
                })?;
                // Durable recovery material precedes the first possible effect.
                transaction.replace(
                    JOURNAL,
                    &record.encode(self.identity.user_sid())?,
                    MAX_JOURNAL_BYTES,
                )?;
                if native::observe()? != record.before {
                    return Err(ProxyError::SettingsChanged);
                }
                native::apply(&record.applied)
                    .map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
                if native::observe()? != record.applied {
                    return Err(ProxyError::OutcomeUnknown(Box::new(
                        ProxyError::SettingsChanged,
                    )));
                }
            }
            let confirmed = engine
                .observe_under_proxy_lock(Duration::from_secs(15))
                .map_err(|error| ProxyError::OutcomeUnknown(Box::new(ProxyError::Engine(error))))?;
            if confirmed.configuration_digest != config.digest() {
                return Err(ProxyError::OutcomeUnknown(Box::new(
                    ProxyError::RuntimeMismatch,
                )));
            }
            Ok(ProxySettingsReceipt {
                context: context.clone(),
                configuration_digest: config.digest().to_owned(),
            })
        })
    }

    /// May also recover a crashed predecessor's recorded context. Success
    /// confirms settings restoration only; it does not stop or attest engines.
    pub fn restore(
        &self,
        context: &EngineCommandContext,
    ) -> Result<ProxySettingsRestored, ProxyError> {
        self.restore_at_cut(context, restoration::RestoreCut::None)
    }
    fn restore_at_cut(
        &self,
        context: &EngineCommandContext,
        cut: restoration::RestoreCut,
    ) -> Result<ProxySettingsRestored, ProxyError> {
        self.locked(|transaction| {
            let record = Record::read(transaction, self.identity.user_sid())?
                .ok_or(ProxyError::OwnershipMissing)?;
            if record.context != *context {
                return Err(ProxyError::OwnershipConflict);
            }
            let observed = native::observe()?;
            if observed == record.applied {
                native::apply(&record.before)
                    .map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
            } else if observed == record.before {
                native::notify().map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
            } else {
                return Err(ProxyError::SettingsChanged);
            }
            if native::observe()? != record.before {
                return Err(ProxyError::OutcomeUnknown(Box::new(
                    ProxyError::SettingsChanged,
                )));
            }
            // A later process must be able to distinguish an observed restore
            // from mere journal absence. Publish bounded, nonsecret identity
            // before retiring the active ownership record.
            restoration::publish(transaction, &record)
                .map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
            let current = native::observe().map_err(|e| ProxyError::OutcomeUnknown(Box::new(e)))?;
            if current != record.before {
                return Err(ProxyError::OutcomeUnknown(Box::new(
                    ProxyError::SettingsChanged,
                )));
            }
            cut.check()?;
            transaction
                .remove(JOURNAL, MAX_JOURNAL_BYTES, ReadPolicy::Private)
                .map_err(|e| ProxyError::OutcomeUnknown(Box::new(e.into())))?;
            Ok(ProxySettingsRestored {
                context: record.context,
                configuration_digest: record.config_digest,
            })
        })
    }

    fn authorize(&self, restoration_only: bool) -> Result<(), ProxyError> {
        self.locked(|transaction| {
            let record = Record::read(transaction, self.identity.user_sid())?;
            if restoration_only && record.is_none() {
                return Ok(());
            }
            let observed = native::observe()?;
            match record {
                Some(record) if observed != record.before && observed != record.applied => {
                    Err(ProxyError::SettingsChanged)
                }
                None if observed.explicit_proxy_enabled() => Err(ProxyError::ExistingProxy),
                _ => Ok(()),
            }
        })
    }
}

impl SystemProxyAuthorization for WindowsSystemProxy {
    fn authorize_system_proxy(&self, restoration_only: bool) -> BackendFuture<'_, ()> {
        let authority = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || authority.authorize(restoration_only))
                .await
                .map_err(|_| {
                    BackendError::new(
                        BackendErrorKind::Internal,
                        "Windows proxy authorization worker did not complete",
                    )
                })?
                .map_err(|error| {
                    let kind = match &error {
                        ProxyError::PolicyDenied
                        | ProxyError::UnsafeUser
                        | ProxyError::Identity(_) => BackendErrorKind::PermissionDenied,
                        ProxyError::ExistingProxy => BackendErrorKind::ExistingSystemProxy,
                        ProxyError::SettingsChanged | ProxyError::OwnershipConflict => {
                            BackendErrorKind::SystemProxyAuthorityFailed
                        }
                        _ => BackendErrorKind::SystemProxyPreferencesFailed,
                    };
                    BackendError::new(kind, error.to_string())
                })
        })
    }
}

#[cfg(test)]
mod tests;
