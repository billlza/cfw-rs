use super::*;
use sha2::{Digest, Sha256};

const NAME: &str = "system-proxy-restored-v1.json";
const MAX_BYTES: usize = 4096;

/// A fresh WinINet comparison with a private, durable restoration record. The
/// process fields identify the former owner; they do not prove its retirement.
/// No serde/default/raw constructor may turn a caller's claim into this proof.
pub struct ProxyRestorationObservation {
    context: EngineCommandContext,
    configuration_digest: String,
    process_id: u32,
    process_created_at: u64,
}
impl ProxyRestorationObservation {
    pub fn context(&self) -> &EngineCommandContext {
        &self.context
    }
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
    pub fn recorded_process_id(&self) -> u32 {
        self.process_id
    }
    pub fn recorded_process_creation_time(&self) -> u64 {
        self.process_created_at
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorationRecord {
    version: u16,
    user_sid: String,
    context: EngineCommandContext,
    configuration_digest: String,
    process_id: u32,
    process_created_at: u64,
    original_settings_sha256: [u8; 32],
}
fn settings_digest(settings: &ProxySettings) -> Result<[u8; 32], ProxyError> {
    settings.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"cfw.windows.proxy-restoration.v1\0");
    hash.update(settings.flags.to_le_bytes());
    // Versioned, length-delimited raw UTF-16; independent of JSON formatting
    // and preserves even native values that are not valid Unicode strings.
    for field in [&settings.server, &settings.bypass, &settings.pac_url] {
        let length = u32::try_from(field.len()).map_err(|_| ProxyError::InvalidObservation)?;
        hash.update(length.to_le_bytes());
        for unit in field {
            hash.update(unit.to_le_bytes());
        }
    }
    Ok(hash.finalize().into())
}
impl RestorationRecord {
    fn from_active(record: &Record) -> Result<Self, ProxyError> {
        // Keep only identity and a digest; retired PAC/server/bypass strings do
        // not need to remain in the persistent restoration record.
        Ok(Self {
            version: 1,
            user_sid: record.user_sid.clone(),
            context: record.context.clone(),
            configuration_digest: record.config_digest.clone(),
            process_id: record.process_id,
            process_created_at: record.process_created_at,
            original_settings_sha256: settings_digest(&record.before)?,
        })
    }
    fn encode(&self, sid: &str) -> Result<Vec<u8>, ProxyError> {
        if self.version != 1
            || self.user_sid != sid
            || !valid_context(&self.context)
            || self.configuration_digest.len() != 64
            || !self
                .configuration_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.process_id == 0
            || self.process_created_at == 0
        {
            return Err(ProxyError::InvalidRestorationRecord);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ProxyError::InvalidRestorationRecord)?;
        if bytes.len() > MAX_BYTES {
            return Err(ProxyError::InvalidRestorationRecord);
        }
        Ok(bytes)
    }
    fn read(transaction: &WriteTransaction, sid: &str) -> Result<Self, ProxyError> {
        let value = transaction
            .read(NAME, MAX_BYTES, ReadPolicy::Private)?
            .ok_or(ProxyError::RestorationMissing)?;
        let record: Self = serde_json::from_slice(&value.bytes)
            .map_err(|_| ProxyError::InvalidRestorationRecord)?;
        if record.encode(sid)? != value.bytes {
            return Err(ProxyError::InvalidRestorationRecord);
        }
        Ok(record)
    }
}

pub(super) fn publish(
    transaction: &mut WriteTransaction,
    active: &Record,
) -> Result<(), ProxyError> {
    let record = RestorationRecord::from_active(active)?;
    transaction.replace(NAME, &record.encode(&active.user_sid)?, MAX_BYTES)?;
    Ok(())
}
impl WindowsSystemProxy {
    /// Reopen after the restoring process exits, using the installation-owned
    /// persistent directory and exact expected runtime identity. Missing records,
    /// active ownership, mismatched generations and changed OS values are errors.
    pub fn observe_restoration(
        &self,
        context: &EngineCommandContext,
        configuration_digest: &str,
    ) -> Result<ProxyRestorationObservation, ProxyError> {
        if !valid_context(context) {
            return Err(ProxyError::RuntimeMismatch);
        }
        self.locked(|transaction| {
            if Record::read(transaction, self.identity.user_sid())?.is_some() {
                return Err(ProxyError::OwnershipConflict);
            }
            let record = RestorationRecord::read(transaction, self.identity.user_sid())?;
            if record.context != *context || record.configuration_digest != configuration_digest {
                return Err(ProxyError::OwnershipConflict);
            }
            if settings_digest(&native::observe()?)? != record.original_settings_sha256 {
                return Err(ProxyError::SettingsChanged);
            }
            Ok(ProxyRestorationObservation {
                context: record.context,
                configuration_digest: record.configuration_digest,
                process_id: record.process_id,
                process_created_at: record.process_created_at,
            })
        })
    }
}

pub(super) enum RestoreCut {
    None,
    #[cfg(feature = "native-engine-validation")]
    AfterRecord,
}
impl RestoreCut {
    pub(super) fn check(self) -> Result<(), ProxyError> {
        match self {
            Self::None => Ok(()),
            #[cfg(feature = "native-engine-validation")]
            Self::AfterRecord => Err(ProxyError::OutcomeUnknown(Box::new(ProxyError::Native {
                operation: "validation cut after restoration record publication",
                source: io::Error::new(
                    io::ErrorKind::Interrupted,
                    "active ownership intentionally retained",
                ),
            }))),
        }
    }
}
#[cfg(feature = "native-engine-validation")]
impl WindowsSystemProxy {
    /// Disposable native fault injection. Always fails after the durable record
    /// and before active-journal removal; normal restore must finish the work.
    pub fn restore_interrupted_for_validation(
        &self,
        context: &EngineCommandContext,
    ) -> Result<ProxySettingsRestored, ProxyError> {
        if std::env::var("CFW_NATIVE_PROXY_MUTATION_TESTS").as_deref() != Ok("1") {
            return Err(ProxyError::UnsafeUser);
        }
        self.restore_at_cut(context, RestoreCut::AfterRecord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoration_record_keeps_exact_identity_without_retired_proxy_strings() {
        let active = super::super::tests::record();
        let record = RestorationRecord::from_active(&active).unwrap();
        let digest: String = record
            .original_settings_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "9bc6b3fb9e7d29236f21980ec40ee4b5a73c8cc571a2d4e5ddfbf113a5578770"
        );
        let bytes = record.encode(&active.user_sid).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("private.invalid")
                && !text.contains("pac_url")
                && !text.contains("bypass")
        );
        assert_eq!(record.context, active.context);
        assert_eq!(record.configuration_digest, active.config_digest);
        assert_eq!(record.process_id, active.process_id);
        assert_eq!(record.process_created_at, active.process_created_at);
        assert!(record.encode("S-1-5-18").is_err());
        let mut changed = active.before.clone();
        changed.bypass.push(1);
        assert_ne!(
            settings_digest(&changed).unwrap(),
            record.original_settings_sha256
        );
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RestorationRecord>(value).is_err());
    }
    #[test]
    fn missing_or_corrupt_restoration_never_becomes_successful_observation() {
        let root = tempfile::tempdir().unwrap();
        let proxy = WindowsSystemProxy::new(&root.path().join("proxy")).unwrap();
        let before = proxy.snapshot().unwrap();
        let context = super::super::tests::context();
        assert!(matches!(
            proxy.observe_restoration(&context, &"a".repeat(64)),
            Err(ProxyError::RestorationMissing)
        ));
        proxy
            .directory
            .write()
            .unwrap()
            .replace(NAME, b"{}", MAX_BYTES)
            .unwrap();
        assert!(matches!(
            proxy.observe_restoration(&context, &"a".repeat(64)),
            Err(ProxyError::InvalidRestorationRecord)
        ));
        assert_eq!(proxy.snapshot().unwrap(), before);
    }
}
