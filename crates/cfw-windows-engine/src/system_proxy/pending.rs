//! A run that will own this user's proxy settings first records that it has
//! not taken them. The UserAgent writes the record before it is bound, and
//! activation retires it as soon as its own ownership record is durable, so
//! afterwards one of the two always says how far the run got. A run that
//! failed or was lost before activation can then be told apart from one whose
//! ownership record is missing: only the former has nothing to restore.
use super::*;

const NAME: &str = "system-proxy-pending-v1.json";
const MAX_BYTES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    version: u16,
    user_sid: String,
    context: EngineCommandContext,
    configuration_digest: String,
    process_id: u32,
    process_created_at: u64,
}
impl PendingRecord {
    fn encode(&self, sid: &str) -> Result<Vec<u8>, ProxyError> {
        if self.version != 1
            || self.user_sid != sid
            || !valid_context(&self.context)
            || !valid_digest(&self.configuration_digest)
            || self.process_id == 0
            || self.process_created_at == 0
        {
            return Err(ProxyError::InvalidPendingRecord);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ProxyError::InvalidPendingRecord)?;
        if bytes.len() > MAX_BYTES {
            return Err(ProxyError::InvalidPendingRecord);
        }
        Ok(bytes)
    }
    fn read(transaction: &WriteTransaction, sid: &str) -> Result<Option<Self>, ProxyError> {
        let Some(value) = transaction.read(NAME, MAX_BYTES, ReadPolicy::Private)? else {
            return Ok(None);
        };
        let record: Self =
            serde_json::from_slice(&value.bytes).map_err(|_| ProxyError::InvalidPendingRecord)?;
        if record.encode(sid)? != value.bytes {
            return Err(ProxyError::InvalidPendingRecord);
        }
        Ok(Some(record))
    }
}

impl WindowsSystemProxy {
    /// Call in the process that will activate the proxy, before it is bound to
    /// its lease. An unresolved ownership record or an explicit proxy refuses
    /// the run here, while it has changed nothing and holds no lease.
    pub(crate) fn record_pending(
        &self,
        context: &EngineCommandContext,
        configuration_digest: &str,
    ) -> Result<(), ProxyError> {
        if !valid_context(context) || !valid_digest(configuration_digest) {
            return Err(ProxyError::RuntimeMismatch);
        }
        let process = NativePeerProcess::open(std::process::id())?;
        self.locked(|transaction| {
            let sid = self.identity.user_sid();
            if Record::read(transaction, sid)?.is_some() {
                return Err(ProxyError::OwnershipConflict);
            }
            if native::observe()?.explicit_proxy_enabled() {
                return Err(ProxyError::ExistingProxy);
            }
            let record = PendingRecord {
                version: 1,
                user_sid: sid.to_owned(),
                context: context.clone(),
                configuration_digest: configuration_digest.to_owned(),
                process_id: process.process_id(),
                process_created_at: process.identity().process_creation_time(),
            };
            transaction.replace(NAME, &record.encode(sid)?, MAX_BYTES)?;
            Ok(())
        })
    }
}

/// The ownership record is durable: the run is not pending any more.
pub(super) fn retire(transaction: &mut WriteTransaction) -> Result<(), ProxyError> {
    if transaction
        .read(NAME, MAX_BYTES, ReadPolicy::Private)?
        .is_some()
    {
        transaction.remove(NAME, MAX_BYTES, ReadPolicy::Private)?;
    }
    Ok(())
}

/// This exact run's record of not having taken the proxy. The caller holds the
/// ownership lock and has found neither an ownership record nor a restoration
/// record of this run.
pub(super) fn observe(
    transaction: &WriteTransaction,
    sid: &str,
    context: &EngineCommandContext,
    configuration_digest: &str,
) -> Result<Option<ProxyRestorationObservation>, ProxyError> {
    Ok(PendingRecord::read(transaction, sid)?
        .filter(|record| {
            record.context == *context && record.configuration_digest == configuration_digest
        })
        .map(|record| {
            ProxyRestorationObservation::never_applied(
                record.context,
                record.configuration_digest,
                record.process_id,
                record.process_created_at,
            )
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> (tempfile::TempDir, WindowsSystemProxy) {
        let root = tempfile::tempdir().unwrap();
        let proxy = WindowsSystemProxy::new(&root.path().join("proxy")).unwrap();
        (root, proxy)
    }
    fn digest() -> String {
        "a".repeat(64)
    }
    /// An ownership record of `context` for this user, as activation writes it.
    fn owned(proxy: &WindowsSystemProxy, context: &EngineCommandContext) -> Record {
        let before = proxy.snapshot().unwrap();
        let endpoint = "127.0.0.1:12345".parse().unwrap();
        Record {
            version: 1,
            user_sid: proxy.identity.user_sid().to_owned(),
            context: context.clone(),
            config_digest: digest(),
            process_id: 123,
            process_created_at: 456,
            endpoint,
            applied: before.for_endpoint(endpoint),
            before,
        }
    }
    fn write(proxy: &WindowsSystemProxy, name: &str, bytes: &[u8]) {
        proxy
            .directory
            .write()
            .unwrap()
            .replace(name, bytes, MAX_JOURNAL_BYTES)
            .unwrap();
    }

    #[test]
    fn a_run_that_never_took_the_proxy_proves_it_by_its_own_pending_record() {
        let (_root, proxy) = proxy();
        let before = proxy.snapshot().unwrap();
        // Activation refuses an explicit proxy, and so does its pending record.
        if before.explicit_proxy_enabled() {
            assert!(matches!(
                proxy.record_pending(&super::super::tests::context(), &digest()),
                Err(ProxyError::ExistingProxy)
            ));
            return;
        }
        let context = super::super::tests::context();
        proxy.record_pending(&context, &digest()).unwrap();
        let observed = proxy.observe_restoration(&context, &digest()).unwrap();
        assert_eq!(observed.context(), &context);
        assert_eq!(observed.configuration_digest(), digest());
        assert_eq!(observed.recorded_process_id(), std::process::id());
        assert_ne!(observed.recorded_process_creation_time(), 0);
        // Another run, or another configuration of this one, proves nothing.
        let other = super::super::tests::context();
        assert!(matches!(
            proxy.observe_restoration(&other, &digest()),
            Err(ProxyError::RestorationMissing)
        ));
        assert!(matches!(
            proxy.observe_restoration(&context, &"b".repeat(64)),
            Err(ProxyError::RestorationMissing)
        ));
        // A later run replaces the record; the earlier one is no longer proven.
        proxy.record_pending(&other, &digest()).unwrap();
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::RestorationMissing)
        ));
        proxy.observe_restoration(&other, &digest()).unwrap();
        assert_eq!(proxy.snapshot().unwrap(), before);
    }

    #[test]
    fn an_ownership_record_outranks_the_pending_record() {
        let (_root, proxy) = proxy();
        let before = proxy.snapshot().unwrap();
        if before.explicit_proxy_enabled() {
            return;
        }
        let context = super::super::tests::context();
        let sid = proxy.identity.user_sid().to_owned();
        proxy.record_pending(&context, &digest()).unwrap();
        // The run took the proxy and was lost before it retired the record.
        write(
            &proxy,
            JOURNAL,
            &owned(&proxy, &context).encode(&sid).unwrap(),
        );
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::OwnershipConflict)
        ));
        // No run starts over unresolved ownership.
        assert!(matches!(
            proxy.record_pending(&super::super::tests::context(), &digest()),
            Err(ProxyError::OwnershipConflict)
        ));
        assert_eq!(proxy.snapshot().unwrap(), before);
    }

    #[test]
    fn a_restoration_record_of_the_run_decides_alone() {
        let (_root, proxy) = proxy();
        let before = proxy.snapshot().unwrap();
        if before.explicit_proxy_enabled() {
            return;
        }
        let context = super::super::tests::context();
        proxy.record_pending(&context, &digest()).unwrap();
        // The run took the proxy, restored other settings than these, and its
        // pending record outlived both. That is not a run that changed nothing.
        let mut changed = owned(&proxy, &context);
        changed.before.flags ^= PROXY_TYPE_AUTO_DETECT;
        restoration::publish(&mut proxy.directory.write().unwrap(), &changed).unwrap();
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::SettingsChanged)
        ));
        // With the settings it restored still in place, the restoration is
        // proven by its own record, which names the engine that was owned.
        // Read the settings before the directory is locked for the write.
        let restored = owned(&proxy, &context);
        restoration::publish(&mut proxy.directory.write().unwrap(), &restored).unwrap();
        let observed = proxy.observe_restoration(&context, &digest()).unwrap();
        assert_eq!(observed.recorded_process_id(), 123);
        assert_eq!(proxy.snapshot().unwrap(), before);
    }

    #[test]
    fn activation_retires_the_pending_record() {
        let (_root, proxy) = proxy();
        if proxy.snapshot().unwrap().explicit_proxy_enabled() {
            return;
        }
        let context = super::super::tests::context();
        proxy.record_pending(&context, &digest()).unwrap();
        retire(&mut proxy.directory.write().unwrap()).unwrap();
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::RestorationMissing)
        ));
        // Retiring an absent record is not an error.
        retire(&mut proxy.directory.write().unwrap()).unwrap();
    }

    #[test]
    fn a_malformed_pending_record_is_never_a_proof() {
        let (_root, proxy) = proxy();
        let before = proxy.snapshot().unwrap();
        let context = super::super::tests::context();
        write(&proxy, NAME, b"{}");
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::InvalidPendingRecord)
        ));
        let sid = proxy.identity.user_sid().to_owned();
        let valid = PendingRecord {
            version: 1,
            user_sid: sid.clone(),
            context: context.clone(),
            configuration_digest: digest(),
            process_id: 7,
            process_created_at: 9,
        };
        valid.encode(&sid).unwrap();
        assert!(valid.encode("S-1-5-18").is_err());
        for modify in [
            |value: &mut PendingRecord| value.version = 2,
            |value: &mut PendingRecord| value.context.generation = 0,
            |value: &mut PendingRecord| value.configuration_digest = "A".repeat(64),
            |value: &mut PendingRecord| value.process_id = 0,
            |value: &mut PendingRecord| value.process_created_at = 0,
        ] {
            let mut altered = PendingRecord {
                version: 1,
                user_sid: sid.clone(),
                context: context.clone(),
                configuration_digest: digest(),
                process_id: 7,
                process_created_at: 9,
            };
            modify(&mut altered);
            assert!(altered.encode(&sid).is_err());
        }
        // Another user's record, even well formed, is not this user's proof.
        let mut foreign = serde_json::to_value(&valid).unwrap();
        foreign["user_sid"] = serde_json::json!("S-1-5-21-1-2-3-1000");
        write(&proxy, NAME, &serde_json::to_vec(&foreign).unwrap());
        assert!(matches!(
            proxy.observe_restoration(&context, &digest()),
            Err(ProxyError::InvalidPendingRecord)
        ));
        assert_eq!(proxy.snapshot().unwrap(), before);
    }
}
