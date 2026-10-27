//! MSI-owned service availability. The desktop retains query-only SCM access.
//! A running authority starts Off; these operations never select a network mode.
use super::*;

impl InstalledRuntime {
    /// Run after target completion, with a rollback retirement action already
    /// queued. Keep the original record until the MSI transaction has ended.
    pub fn activate_update_maintenance(
        &self,
        transaction: Uuid,
        target_manifest: &str,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        self.require_manifest_sha256(target_manifest)?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let admitted = (|| {
            let bytes = guard
                .read()?
                .ok_or(HostError::State("update activation has no intent"))?;
            let record = Record::decode(&bytes)?;
            record.bind_target(transaction, target_manifest)?;
            if !matches!(record.phase, Phase::Committed { .. }) {
                return Err(HostError::State(
                    "update activation requires completed maintenance",
                ));
            }
            Ok((bytes, record.original_start))
        })();
        // The service's own startup gate needs this same record lock.
        let (expected, start) = finish(admitted, guard.release())?;
        let control = ServiceControl::open(self.runtime()?)?;
        let running = control.start(start, Instant::now() + DRAIN)?;
        let off = fresh_off()?;
        control.verify_running(&running)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            if guard.read()?.as_deref() != Some(expected.as_slice()) {
                return Err(HostError::State(
                    "maintenance changed during target activation",
                ));
            }
            Ok(
                serde_json::json!({"transaction":transaction,"target_manifest_sha256":target_manifest,
                "target_service":running.receipt(),"authority":off,"rollback_record_retained":true}),
            )
        })();
        finish(result, guard.release())
    }

    /// This rollback action runs before original files are restored. Publishing
    /// retirement first blocks another target start even if this action fails.
    pub fn retire_update_target(
        &self,
        transaction: Uuid,
        target_manifest: &str,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        self.require_manifest_sha256(target_manifest)?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            let bytes = guard
                .read()?
                .ok_or(HostError::State("target retirement has no intent"))?;
            let mut record = Record::decode(&bytes)?;
            record.bind_target(transaction, target_manifest)?;
            let off = match &record.phase {
                Phase::Prepared { off }
                | Phase::Committing { off }
                | Phase::Committed { off }
                | Phase::RetiringTarget { off } => off.clone(),
                _ => {
                    return Err(HostError::State(
                        "target retirement has no prepared authority",
                    ));
                }
            };
            record.phase = Phase::RetiringTarget { off };
            let retiring = record.encode()?;
            guard.compare_exchange(Some(&bytes), &retiring)?;
            Ok((retiring, record.original_start))
        })();
        // A partially started target may still be reading its startup gate.
        let (expected, original_start) = finish(result, guard.release())?;
        let control = ServiceControl::open(self.runtime()?)?;
        let exited = match control.start_type()? {
            SERVICE_DISABLED => {
                control.require_stopped(SERVICE_DISABLED)?;
                None
            }
            mode if mode == original_start => {
                let exited = control.drain(mode, Instant::now() + DRAIN)?;
                control.change_start(mode, SERVICE_DISABLED)?;
                exited
            }
            _ => {
                return Err(HostError::State(
                    "target retirement refuses changed startup configuration",
                ));
            }
        };
        let off = fresh_off()?;
        control.require_stopped(SERVICE_DISABLED)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            if guard.read()?.as_deref() != Some(expected.as_slice()) {
                return Err(HostError::State(
                    "maintenance changed during target retirement",
                ));
            }
            Ok(
                serde_json::json!({"transaction":transaction,"target_manifest_sha256":target_manifest,
                "target_retired":true,"retained_process_exit_observed":exited.is_some(),"retired_service":exited,"authority":off}),
            )
        })();
        finish(result, guard.release())
    }

    /// Original files must already be restored. Persist restart admission
    /// before releasing the record lock, so interrupted rollback can resume.
    pub fn rollback_update_maintenance(&self, transaction: Uuid) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        if transaction.is_nil() {
            return Err(HostError::State("maintenance transaction is nil"));
        }
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let admitted = (|| {
            let Some(bytes) = guard.read()? else {
                return Ok(None);
            };
            let mut record = Record::decode(&bytes)?;
            record.bind_original(transaction, &self.manifest_sha256)?;
            if record.target_manifest_sha256.is_none() {
                return Err(HostError::State("update rollback has no target"));
            }
            let control = ServiceControl::open(self.runtime()?)?;
            match control.start_type()? {
                mode if mode == record.original_start => {}
                SERVICE_DISABLED => {
                    control.change_start(SERVICE_DISABLED, record.original_start)?
                }
                _ => {
                    return Err(HostError::State(
                        "rollback refuses a foreign startup configuration",
                    ));
                }
            }
            record.phase = Phase::RestoringOriginal;
            let restoring = record.encode()?;
            guard.compare_exchange(Some(&bytes), &restoring)?;
            Ok(Some((restoring, record)))
        })();
        let Some((expected, record)) = finish(admitted, guard.release())? else {
            return Ok(
                serde_json::json!({"transaction":transaction,"pending":false,
                "startup_restored":false,"original_service":null}),
            );
        };
        let control = ServiceControl::open(self.runtime()?)?;
        let running = if record.original_running {
            Some(control.start(record.original_start, Instant::now() + DRAIN)?)
        } else {
            control.require_stopped(record.original_start)?;
            None
        };
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            if let Some(running) = &running {
                control.verify_running(running)?;
            }
            guard.remove(&expected)?;
            Ok(serde_json::json!({"transaction":transaction,"pending":true,
                "startup_restored":true,"original_running":record.original_running,
                "original_service":running.as_ref().map(|p| p.receipt())}))
        })();
        finish(result, guard.release())
    }

    pub fn activate_fresh_installation(&self, target_manifest: &str) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        self.require_manifest_sha256(target_manifest)?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let admitted = (|| {
            if guard.read()?.is_some() {
                return Err(HostError::State(
                    "fresh activation refuses maintenance history",
                ));
            }
            Ok(())
        })();
        finish(admitted, guard.release())?;
        let control = ServiceControl::open(self.runtime()?)?;
        let running = control.start(control.start_type()?, Instant::now() + DRAIN)?;
        let off = fresh_off()?;
        control.verify_running(&running)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            if guard.read()?.is_some() {
                return Err(HostError::State(
                    "maintenance appeared during fresh activation",
                ));
            }
            Ok(serde_json::json!({"target_manifest_sha256":target_manifest,
                "fresh_service":running.receipt(),"authority":off}))
        })();
        finish(result, guard.release())
    }

    /// Queued only after the fresh target files and service were validated.
    /// If no activation occurred there need not be an authority journal yet.
    pub fn retire_fresh_installation(&self, target_manifest: &str) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        self.require_manifest_sha256(target_manifest)?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let admitted = (|| {
            if guard.read()?.is_some() {
                return Err(HostError::State(
                    "fresh retirement refuses maintenance history",
                ));
            }
            Ok(())
        })();
        finish(admitted, guard.release())?;
        let control = ServiceControl::open(self.runtime()?)?;
        let start = control.start_type()?;
        let exited = control.drain(start, Instant::now() + DRAIN)?;
        control.change_start(start, SERVICE_DISABLED)?;
        let off = if exited.is_some() {
            Some(fresh_off()?)
        } else {
            None
        };
        Ok(
            serde_json::json!({"target_manifest_sha256":target_manifest,"fresh_service_retired":true,
            "retained_process_exit_observed":exited.is_some(),"retired_service":exited,"authority":off}),
        )
    }
}
