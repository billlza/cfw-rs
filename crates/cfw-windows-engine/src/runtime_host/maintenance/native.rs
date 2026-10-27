use super::*;
use crate::{
    authority::WindowsAuthority,
    runtime_host::{InstalledRuntime, SERVICE_NAME},
    service_peer::maintenance::ServiceControl,
};
use cfw_windows_storage::{MachineRecordGuard, PrivateMachineRecord};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Services::SERVICE_DISABLED;

const SCOPE: &str = "CFWAuthorityMaintenance";
const LOCK_WAIT: Duration = Duration::from_secs(3);
const DRAIN: Duration = Duration::from_secs(40);

mod activation;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceMaintenanceFault {
    IntentPublished,
    RestartDisabled,
}

fn finish<T>(
    operation: Result<T>,
    release: std::result::Result<(), cfw_windows_storage::MachineRecordError>,
) -> Result<T> {
    match (operation, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(operation), Err(cleanup)) => Err(HostError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup.into()),
        }),
    }
}
pub(crate) fn require_service_start_allowed(installation: &InstalledRuntime) -> Result<()> {
    crate::service_peer::require_system_service_identity()?;
    let record = PrivateMachineRecord::new(SCOPE)?;
    let guard = record.lock(LOCK_WAIT)?;
    let result = (|| {
        if let Some(bytes) = guard.read()? {
            let pending = Record::decode(&bytes)?;
            if !pending.permits_start(&installation.manifest_sha256) {
                return Err(HostError::State(
                    "installation maintenance is pending; service startup is blocked",
                ));
            }
        }
        Ok(())
    })();
    finish(result, guard.release())
}
fn fresh_off() -> Result<AuthoritySnapshot> {
    let root = InstalledRuntime::machine_root()?;
    let observation =
        WindowsAuthority::observe_off_for_maintenance(&root.join("journal"), SERVICE_NAME)?;
    let record = observation.record();
    // This describes the freshly checked protected record. The temporary
    // controller remains Recovering and cannot grant a new runtime operation.
    Ok(AuthoritySnapshot {
        state: record.state(),
        revision: Some(record.revision()),
        root: Some(record.root().clone()),
    })
}
fn prepare(
    installation: &InstalledRuntime,
    transaction: Uuid,
    target_manifest: Option<&str>,
    guard: &MachineRecordGuard<'_>,
    hook: &mut impl FnMut(ServiceMaintenanceFault) -> Result<()>,
) -> Result<serde_json::Value> {
    let caller = crate::service_peer::require_system_maintenance_identity()?;
    let control = ServiceControl::open(installation.runtime()?)?;
    let existing = guard.read()?;
    let (mut record, original_bytes) = if let Some(bytes) = existing {
        let record = Record::decode(&bytes)?;
        if matches!(record.phase, Phase::Committed { .. }) {
            if record.transaction == transaction
                || !record.permits_start(&installation.manifest_sha256)
            {
                return Err(HostError::State(
                    "completed maintenance does not admit this new transaction",
                ));
            }
            let next = Record::preparing(
                transaction,
                installation.manifest_sha256.clone(),
                target_manifest.map(str::to_owned),
                control.start_type()?,
                control.is_running()?,
            )?;
            let next_bytes = next.encode()?;
            guard.compare_exchange(Some(&bytes), &next_bytes)?;
            (next, next_bytes)
        } else {
            if !matches!(record.phase, Phase::Preparing | Phase::Prepared { .. }) {
                return Err(HostError::State(
                    "update completion must finish or roll back before preparation",
                ));
            }
            record.bind_original(transaction, &installation.manifest_sha256)?;
            if record.target_manifest_sha256.as_deref() != target_manifest {
                return Err(HostError::State(
                    "maintenance target changed after preparation began",
                ));
            }
            (record, bytes)
        }
    } else {
        let record = Record::preparing(
            transaction,
            installation.manifest_sha256.clone(),
            target_manifest.map(str::to_owned),
            control.start_type()?,
            control.is_running()?,
        )?;
        let bytes = record.encode()?;
        guard.compare_exchange(None, &bytes)?;
        (record, bytes)
    };
    hook(ServiceMaintenanceFault::IntentPublished)?;
    // A failed/abandoned attempt is only resumed for the same transaction and
    // unchanged protected installation. The marker remains on every failure.
    let process_exit_observed = match control.start_type()? {
        mode if mode == record.original_start => control.drain(mode, Instant::now() + DRAIN)?,
        SERVICE_DISABLED => {
            control.require_stopped(SERVICE_DISABLED)?;
            None
        }
        _ => {
            return Err(HostError::State(
                "service startup changed outside maintenance",
            ));
        }
    };
    let off = fresh_off()?;
    if let Phase::Prepared { off: expected } = &record.phase
        && expected != &off
    {
        return Err(HostError::State(
            "authority state changed after maintenance preparation",
        ));
    }
    if control.start_type()? == record.original_start {
        control.change_start(record.original_start, SERVICE_DISABLED)?;
    }
    control.require_stopped(SERVICE_DISABLED)?;
    hook(ServiceMaintenanceFault::RestartDisabled)?;
    if fresh_off()? != off {
        return Err(HostError::State(
            "authority changed while disabling restart",
        ));
    }
    record.phase = Phase::Prepared { off: off.clone() };
    guard.compare_exchange(Some(&original_bytes), &record.encode()?)?;
    Ok(
        serde_json::json!({"transaction":transaction,"target_manifest_sha256":record.target_manifest_sha256,"caller_session_id":caller.identity().session_id(),"authority":off,"service_stopped":true,
        "service_start_disabled":true,"original_start_type":record.original_start,"original_running":record.original_running,
        "retained_process_exit_observed":process_exit_observed.is_some(),"retired_service":process_exit_observed,
        "replacement_authorized":false}),
    )
}
impl InstalledRuntime {
    /// A fresh MSI may retire completed history left by an uninstall. Pending
    /// or damaged intent is never discarded, and a live/registered service or
    /// non-Off authority prevents this operation. The retained authority data
    /// itself is neither removed nor re-enrolled.
    pub fn retire_completed_maintenance_for_fresh_install(
        &self,
        target_manifest: &str,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        self.require_manifest_sha256(target_manifest)?;
        let _runtime = self.runtime()?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        ServiceControl::require_absent()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            let Some(bytes) = guard.read()? else {
                return Ok(
                    serde_json::json!({"completed_history_retired":false,"runtime_started":false}),
                );
            };
            let record = Record::decode(&bytes)?;
            if !matches!(record.phase, Phase::Committed { .. }) {
                return Err(HostError::State(
                    "fresh installation refuses pending maintenance",
                ));
            }
            let off = fresh_off()?;
            ServiceControl::require_absent()?;
            guard.remove(&bytes)?;
            Ok(
                serde_json::json!({"completed_history_retired":true,"prior_transaction":record.transaction,
                "authority":off,"runtime_started":false}),
            )
        })();
        finish(result, guard.release())
    }

    /// SYSTEM installer boundary. Leaves a durable marker if preparation fails;
    /// the matching rollback action must be scheduled before invoking this.
    /// The caller still holds installation pins. No MSI or file is installed.
    pub fn prepare_service_maintenance(&self, transaction: Uuid) -> Result<serde_json::Value> {
        self.prepare_maintenance_with_hook(transaction, None, &mut |_| Ok(()))
    }

    /// Bind the SYSTEM installer's exact target before changing service state.
    /// The digest must come from its authenticated MSI, not a renderer claim.
    pub fn prepare_update_maintenance(
        &self,
        transaction: Uuid,
        target_manifest: &str,
    ) -> Result<serde_json::Value> {
        self.prepare_maintenance_with_hook(transaction, Some(target_manifest), &mut |_| Ok(()))
    }
    #[cfg(feature = "native-service-validation")]
    pub fn prepare_service_maintenance_for_validation(
        &self,
        transaction: Uuid,
        fault: ServiceMaintenanceFault,
    ) -> Result<serde_json::Value> {
        self.prepare_maintenance_with_hook(transaction, None, &mut |point| {
            if point == fault {
                Err(HostError::State("injected native maintenance interruption"))
            } else {
                Ok(())
            }
        })
    }
    fn prepare_maintenance_with_hook(
        &self,
        transaction: Uuid,
        target_manifest: Option<&str>,
        hook: &mut impl FnMut(ServiceMaintenanceFault) -> Result<()>,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        if transaction.is_nil() {
            return Err(HostError::State("maintenance transaction is nil"));
        }
        let record = PrivateMachineRecord::new(SCOPE)?;
        let guard = record.lock(LOCK_WAIT)?;
        let result = prepare(self, transaction, target_manifest, &guard, hook);
        finish(result, guard.release())
    }

    /// Admit the exact installed target without starting networking. The record
    /// is retained: a later failing MSI commit action must still be able to
    /// restore the original startup configuration after old files roll back.
    pub fn commit_update_maintenance(
        &self,
        transaction: Uuid,
        target_manifest: &str,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        if transaction.is_nil() {
            return Err(HostError::State("maintenance transaction is nil"));
        }
        self.require_manifest_sha256(target_manifest)?;
        let _desktop = self.desktop()?;
        let _engine = self.engine()?;
        let store = PrivateMachineRecord::new(SCOPE)?;
        let guard = store.lock(LOCK_WAIT)?;
        let result = (|| {
            let bytes = guard
                .read()?
                .ok_or(HostError::State("update maintenance intent is absent"))?;
            let mut record = Record::decode(&bytes)?;
            record.bind_target(transaction, target_manifest)?;
            let (off, already_committed, completing) = match &record.phase {
                Phase::Prepared { off } => (off.clone(), false, false),
                Phase::Committing { off } => (off.clone(), false, true),
                Phase::Committed { off } => (off.clone(), true, false),
                Phase::Preparing | Phase::RetiringTarget { .. } | Phase::RestoringOriginal => {
                    return Err(HostError::State("update maintenance was not prepared"));
                }
            };
            let control = ServiceControl::open(self.runtime()?)?;
            let start = control.start_type()?;
            if already_committed {
                // An exact repeated completion observes the retained record;
                // it must not require the service to remain permanently Off.
                if start != record.original_start {
                    return Err(HostError::State(
                        "completed service startup configuration changed",
                    ));
                }
            } else {
                if start != SERVICE_DISABLED && start != record.original_start {
                    return Err(HostError::State(
                        "commit refuses a foreign service startup configuration",
                    ));
                }
                control.require_stopped(start)?;
                if fresh_off()? != off {
                    return Err(HostError::State("authority changed before update commit"));
                }
                if !completing {
                    record.phase = Phase::Committing { off: off.clone() };
                    guard.compare_exchange(Some(&bytes), &record.encode()?)?;
                }
                let completing_bytes = record.encode()?;
                if start == SERVICE_DISABLED {
                    control.change_start(SERVICE_DISABLED, record.original_start)?;
                }
                control.require_stopped(record.original_start)?;
                if fresh_off()? != off {
                    return Err(HostError::State(
                        "authority changed while committing update",
                    ));
                }
                record.phase = Phase::Committed { off: off.clone() };
                guard.compare_exchange(Some(&completing_bytes), &record.encode()?)?;
            }
            Ok(
                serde_json::json!({"transaction":transaction,"target_manifest_sha256":target_manifest,
                "prepared_off":off,"already_committed":already_committed,"startup_restored":true,
                "original_start_type":record.original_start,"runtime_started":false,"rollback_record_retained":true}),
            )
        })();
        finish(result, guard.release())
    }
    /// Restore only the original startup configuration for the exact unchanged
    /// installation. This does not start a service or restore a network mode.
    /// MSI rollback must restore old files before invoking this entrypoint.
    pub fn rollback_service_maintenance(&self, transaction: Uuid) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        if transaction.is_nil() {
            return Err(HostError::State("maintenance transaction is nil"));
        }
        let record = PrivateMachineRecord::new(SCOPE)?;
        let guard = record.lock(LOCK_WAIT)?;
        let result = (|| {
            let Some(bytes) = guard.read()? else {
                // A rollback action is scheduled before preparation; it may
                // run when preparation never published any maintenance intent.
                return Ok(
                    serde_json::json!({"transaction":transaction,"pending":false,
                    "startup_restored":false,"runtime_started":false}),
                );
            };
            let pending = Record::decode(&bytes)?;
            pending.bind_original(transaction, &self.manifest_sha256)?;
            if pending.target_manifest_sha256.is_some() {
                return Err(HostError::State(
                    "update rollback requires the update recovery entrypoint",
                ));
            }
            let control = ServiceControl::open(self.runtime()?)?;
            match control.start_type()? {
                mode if mode == pending.original_start => {}
                SERVICE_DISABLED => {
                    control.change_start(SERVICE_DISABLED, pending.original_start)?
                }
                _ => {
                    return Err(HostError::State(
                        "rollback refuses a foreign service startup configuration",
                    ));
                }
            }
            guard.remove(&bytes)?;
            Ok(serde_json::json!({"transaction":transaction,"pending":true,
                "startup_restored":true,"runtime_started":false}))
        })();
        finish(result, guard.release())
    }
}
