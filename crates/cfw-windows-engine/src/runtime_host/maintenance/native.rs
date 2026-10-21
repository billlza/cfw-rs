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
pub(crate) fn require_service_start_allowed() -> Result<()> {
    crate::service_peer::require_system_service_identity()?;
    let record = PrivateMachineRecord::new(SCOPE)?;
    let guard = record.lock(LOCK_WAIT)?;
    let result = (|| {
        if let Some(bytes) = guard.read()? {
            Record::decode(&bytes)?;
            return Err(HostError::State(
                "installation maintenance is pending; service startup is blocked",
            ));
        }
        Ok(())
    })();
    finish(result, guard.release())
}
fn bind(record: &Record, transaction: Uuid, installation: &InstalledRuntime) -> Result<()> {
    if record.transaction != transaction || record.manifest_sha256 != installation.manifest_sha256 {
        return Err(HostError::State(
            "maintenance belongs to a different transaction or installed manifest",
        ));
    }
    Ok(())
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
    guard: &MachineRecordGuard<'_>,
    hook: &mut impl FnMut(ServiceMaintenanceFault) -> Result<()>,
) -> Result<serde_json::Value> {
    let caller = crate::service_peer::require_system_maintenance_identity()?;
    let control = ServiceControl::open(installation.runtime()?)?;
    let existing = guard.read()?;
    let (mut record, original_bytes) = if let Some(bytes) = existing {
        let record = Record::decode(&bytes)?;
        bind(&record, transaction, installation)?;
        (record, bytes)
    } else {
        let record = Record::preparing(
            transaction,
            installation.manifest_sha256.clone(),
            control.start_type()?,
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
            false
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
        serde_json::json!({"transaction":transaction,"caller_session_id":caller.identity().session_id(),"authority":off,"service_stopped":true,
        "service_start_disabled":true,"original_start_type":record.original_start,"retained_process_exit_observed":process_exit_observed,
        "replacement_authorized":false}),
    )
}
impl InstalledRuntime {
    /// SYSTEM installer boundary. Leaves a durable marker if preparation fails;
    /// the matching rollback action must be scheduled before invoking this.
    /// The caller still holds installation pins. No MSI or file is installed.
    pub fn prepare_service_maintenance(&self, transaction: Uuid) -> Result<serde_json::Value> {
        self.prepare_maintenance_with_hook(transaction, &mut |_| Ok(()))
    }
    #[cfg(feature = "native-service-validation")]
    pub fn prepare_service_maintenance_for_validation(
        &self,
        transaction: Uuid,
        fault: ServiceMaintenanceFault,
    ) -> Result<serde_json::Value> {
        self.prepare_maintenance_with_hook(transaction, &mut |point| {
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
        hook: &mut impl FnMut(ServiceMaintenanceFault) -> Result<()>,
    ) -> Result<serde_json::Value> {
        crate::service_peer::require_system_maintenance_identity()?;
        if transaction.is_nil() {
            return Err(HostError::State("maintenance transaction is nil"));
        }
        let record = PrivateMachineRecord::new(SCOPE)?;
        let guard = record.lock(LOCK_WAIT)?;
        let result = prepare(self, transaction, &guard, hook);
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
            bind(&pending, transaction, self)?;
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
