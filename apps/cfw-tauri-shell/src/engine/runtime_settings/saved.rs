//! The saved runtime preferences beside the engine settings of this process,
//! and how the two are read together.
use std::sync::RwLock;

use cfw_core::{RuntimeSettingsSnapshot, SettingsStoreError};
use cfw_singbox_config::{EngineSettings, RuntimePreferences};

use crate::engine::EngineEndpointBinding;

impl EngineEndpointBinding {
    /// Whether these preferences are the ones this process runs the engine
    /// with, or would start it with: a change to them would change nothing,
    /// neither the engine settings nor the port preference its endpoints
    /// were selected with. Preferences that cannot be applied to those
    /// settings are not.
    ///
    /// A port the file names is therefore run only once the cursor holds it
    /// as its preference. The engine may listen on that very port without
    /// it, and would then move to the next one where the file says to keep
    /// this one and to refuse.
    pub(in crate::engine) fn runs(&self, preferences: &RuntimePreferences) -> bool {
        let current = self.controller.settings();
        preferences.apply_to(current.clone()).is_ok_and(|applied| {
            applied == *current
                && self
                    .cursor
                    .has_port_preference(preferences.preferred_mixed_port)
        })
    }

    /// `saved` beside the engine settings of this binding.
    pub(in crate::engine) fn beside(
        &self,
        saved: RuntimeSettingsSnapshot<RuntimePreferences>,
    ) -> SavedRuntimePreferences {
        SavedRuntimePreferences {
            in_force: self.runs(&saved.settings),
            engine: self.controller.settings().clone(),
            saved,
        }
    }
}

/// The saved runtime preferences beside the engine settings of this process.
pub(crate) struct SavedRuntimePreferences {
    pub(crate) saved: RuntimeSettingsSnapshot<RuntimePreferences>,
    /// What this process runs the engine with, or would start it with.
    pub(crate) engine: EngineSettings,
    /// Whether the saved preferences are those settings. They are after every
    /// change made here, which commits the file and the settings together,
    /// and no longer once anything else has changed the file.
    pub(crate) in_force: bool,
}

/// How many times the file is read before the read gives up, when a write
/// is made during each of them. A change is a transaction of its own that
/// replaces the engine, so one after another inside single reads of a small
/// file is not expected; the bound keeps the read from going on regardless.
const SAVED_PREFERENCES_READS: usize = 3;

/// `read_file` runs while nothing of the engine is held, so a read that
/// stalls keeps no transition of the engine waiting. The commit of a change,
/// `commit_runtime_settings`, replaces the file and the settings together
/// and counts every write it sets out on, and the count is taken before and
/// after the file. A read that a write was made during is done again. The
/// file of one change is therefore never returned beside the settings of
/// another, where a change just made here would be reported as not in force,
/// and neither is a document that a failed write has taken back since.
pub(in crate::engine) fn read_saved_runtime_preferences(
    endpoints: &RwLock<EngineEndpointBinding>,
    read_file: impl FnMut() -> Result<RuntimeSettingsSnapshot<RuntimePreferences>, SettingsStoreError>,
) -> Result<SavedRuntimePreferences, String> {
    read_file_beside_binding(endpoints, read_file, |binding, saved| binding.beside(saved))
}

/// What `take` makes of the file and of the binding it was read beside, with
/// no write made between the two.
pub(super) fn read_file_beside_binding<T>(
    endpoints: &RwLock<EngineEndpointBinding>,
    mut read_file: impl FnMut()
        -> Result<RuntimeSettingsSnapshot<RuntimePreferences>, SettingsStoreError>,
    take: impl FnOnce(&EngineEndpointBinding, RuntimeSettingsSnapshot<RuntimePreferences>) -> T,
) -> Result<T, String> {
    for _ in 0..SAVED_PREFERENCES_READS {
        let writes = read_binding(endpoints)?.preference_writes;
        let saved = read_file().map_err(|error| error.to_string())?;
        let binding = read_binding(endpoints)?;
        if binding.preference_writes == writes {
            return Ok(take(&binding, saved));
        }
    }
    Err("the network settings were changed each time they were read".into())
}

fn read_binding(
    endpoints: &RwLock<EngineEndpointBinding>,
) -> Result<std::sync::RwLockReadGuard<'_, EngineEndpointBinding>, String> {
    endpoints
        .read()
        .map_err(|_| "engine endpoint lock is poisoned".into())
}
