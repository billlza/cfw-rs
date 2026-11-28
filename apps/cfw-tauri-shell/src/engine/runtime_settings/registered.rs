//! A change of the runtime preferences counted among the mode changes from
//! its press. It is admitted on what is read before its turn, and what it
//! requests is had only with that turn, so it is applied under the lease of
//! its press and of no other.
use cfw_core::SettingsStore;
use cfw_engine_api::EngineMode;
use cfw_profiles::ProfileRepository;

use super::{AdmissibleChange, RequestedChange, SavedRuntimePreferences};
use crate::engine::maintenance::PendingReapply;
use crate::engine::{EngineMaintenanceError, EngineModeChangeLease, ManagedEngine};

/// A change of the runtime preferences admitted on what was read before its
/// turn among the mode changes, which it is counted among from before that
/// read. What it requests is given with its turn ([`Self::begin`]) and in no
/// other way.
pub(crate) struct RegisteredChange {
    pending: PendingReapply,
    change: AdmissibleChange,
}

/// Admits the change that `request` makes of the saved preferences on what
/// `store` and the selection of `repository` give before its turn, counted
/// among the mode changes from before that read: a full queue refuses it
/// before anything is read, maintenance waits for it meanwhile, and a mode
/// request made, or a revision observed, while it is read is not superseded
/// when the change takes its turn after it. The reads leave the async runtime
/// and keep the change's place until they have ended, also when the command
/// that asked for them is given up meanwhile, which does not stop them.
pub(crate) async fn admit_runtime_preferences_change(
    engine: &ManagedEngine,
    store: SettingsStore,
    repository: ProfileRepository,
    request: impl FnOnce(&SavedRuntimePreferences) -> Result<RequestedChange, String> + Send + 'static,
) -> Result<RegisteredChange, String> {
    let pending = engine
        .maintenance
        .register_reapply()
        .map_err(|error| error.to_string())?;
    let reader = engine.saved_runtime_preferences();
    tauri::async_runtime::spawn_blocking(move || {
        let change = reader.admit(&store, &repository, request)?;
        Ok(RegisteredChange { pending, change })
    })
    .await
    .map_err(|error| error.to_string())?
}

impl RegisteredChange {
    /// The turn of the change among the mode changes, the desired mode it
    /// reapplies, read once the turn has come, and what it requests.
    pub(in crate::engine) async fn begin(
        self,
        engine: &ManagedEngine,
    ) -> Result<(EngineMode, EngineModeChangeLease, RequestedChange), EngineMaintenanceError> {
        let lease = self.pending.begin().await?;
        Ok((
            engine.coordinator.snapshot().desired_mode,
            lease,
            self.change.into_requested(),
        ))
    }
}
