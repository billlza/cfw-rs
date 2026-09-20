//! Runtime preference changes reuse the profile transaction actor: validate,
//! replace, commit, and restore the previous runtime on failure.
use cfw_application::{EngineControllerAccess, EngineCoordinatorError, ProfileChange};
use cfw_core::{RuntimeSettingsSnapshot, SettingsStore, SettingsStoreError};
use cfw_engine_api::EngineMode;
use cfw_profiles::{LockedCredentialProfileMutation, StoredProfile};
use cfw_singbox_config::{EngineSettings, RuntimePreferences, ValidatedSingBoxProfile};

use super::{
    EngineEndpointBinding, ManagedEngine, authorize_proxy_transition, record_endpoint_runtime,
};
use crate::{commands::ManagedProfiles, legacy::LegacyRetirementGate, settings_store};

struct PreparedRuntimeSettings {
    previous: RuntimeSettingsSnapshot<RuntimePreferences>,
    expected: EngineEndpointBinding,
    replacement: EngineEndpointBinding,
    settings: EngineSettings,
    guard: LockedCredentialProfileMutation,
    selected: Option<StoredProfile>,
    store: SettingsStore,
    preferences: RuntimePreferences,
}

pub(crate) async fn change_runtime_preferences(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    preferences: RuntimePreferences,
    expected_revision: Option<String>,
) -> Result<(), String> {
    preferences.validate().map_err(|error| error.to_string())?;
    let (mode, lease) = engine
        .begin_current_mode_change()
        .await
        .map_err(|error| error.to_string())?;
    if mode != EngineMode::Off {
        crate::legacy::require_network_start_allowed(retirement)?;
        engine.require_capability(mode)?;
    }
    let coordinator = engine.coordinator.clone();
    let endpoints = engine.endpoints.clone();
    let authorization = engine.authorization_bridge.clone();
    let repository = profiles.repository().clone();
    let store = settings_store()?;
    let (result, lease) = lease
        .run_to_completion(async move {
            let preparation_endpoints = endpoints.clone();
            let prepared = tauri::async_runtime::spawn_blocking(move || {
                let previous: RuntimeSettingsSnapshot<RuntimePreferences> = store
                    .runtime_settings()
                    .map_err(|error| error.to_string())?;
                if previous.revision != expected_revision {
                    return Err(SettingsStoreError::RuntimeSettingsChanged.to_string());
                }
                let expected = preparation_endpoints
                    .read()
                    .map_err(|_| "engine endpoint lock is poisoned")?
                    .clone();
                let settings = preferences
                    .apply_to(expected.controller.settings().clone())
                    .map_err(|error| error.to_string())?;
                let (settings, cursor) = expected
                    .cursor
                    .with_runtime_preferences(settings, preferences.preferred_mixed_port)
                    .map_err(|error| error.to_string())?;
                let controller = EngineControllerAccess::resolve(settings.clone())
                    .map_err(|error| error.to_string())?;
                let guard = repository
                    .begin_credential_profile_mutation()
                    .map_err(|error| error.to_string())?;
                let selected = guard
                    .selected_profile()
                    .map_err(|error| error.to_string())?;
                if mode != EngineMode::Off && selected.is_none() {
                    return Err("a running engine has no selected profile".into());
                }
                Ok(PreparedRuntimeSettings {
                    previous,
                    expected,
                    replacement: EngineEndpointBinding {
                        controller,
                        cursor,
                        active: None,
                    },
                    settings,
                    guard,
                    selected,
                    store,
                    preferences,
                })
            })
            .await
            .map_err(|error| format!("runtime settings preparation failed: {error}"))??;
            let PreparedRuntimeSettings {
                previous,
                expected,
                replacement,
                settings,
                guard,
                selected,
                store,
                preferences,
            } = prepared;
            let before = coordinator.snapshot();
            let commit_endpoints = endpoints.clone();
            let (profile_id, profile) = selected.map_or_else(
                || {
                    (
                        "00000000-0000-4000-8000-000000000000".into(),
                        ValidatedSingBoxProfile::direct(),
                    )
                },
                |stored| (stored.record.id, stored.profile),
            );
            let previous_profile =
                (mode != EngineMode::Off).then(|| (profile_id.clone(), profile.clone()));
            let result = coordinator
                .change_profile(settings, async move {
                    if mode != EngineMode::Off {
                        authorize_proxy_transition(
                            authorization.as_ref(),
                            mode != EngineMode::SystemProxy,
                        )
                        .await
                        .map_err(EngineCoordinatorError::ProfilePreparation)?;
                    }
                    Ok(ProfileChange {
                        profile_id,
                        profile,
                        activate: true,
                        previous_profile,
                        commit: Box::new(move || {
                            commit_runtime_settings(
                                &commit_endpoints,
                                &expected,
                                replacement,
                                &store,
                                &previous,
                                &preferences,
                            )?;
                            drop(guard);
                            Ok(())
                        }),
                    })
                })
                .await;
            let after = coordinator.snapshot();
            let binding = if before == after {
                Ok(())
            } else {
                record_endpoint_runtime(&endpoints, &after)
            };
            match (result, binding) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error.to_string()),
                (Ok(()), Err(error)) => Err(format!(
                    "settings committed but controller identity refresh failed: {error}"
                )),
                (Err(error), Err(binding)) => Err(format!(
                    "{error}; controller identity refresh failed: {binding}"
                )),
            }
        })
        .await
        .map_err(|_| "runtime settings task ended without a response".to_owned())?;
    drop(lease);
    result
}

pub(super) fn commit_runtime_settings(
    endpoints: &std::sync::RwLock<EngineEndpointBinding>,
    expected: &EngineEndpointBinding,
    replacement: EngineEndpointBinding,
    store: &SettingsStore,
    previous: &RuntimeSettingsSnapshot<RuntimePreferences>,
    preferences: &RuntimePreferences,
) -> Result<(), String> {
    let mut current = endpoints
        .write()
        .map_err(|_| "engine endpoint lock is poisoned")?;
    if current.controller != expected.controller || current.cursor != expected.cursor {
        return Err("runtime settings changed before the transaction committed".into());
    }
    commit_preferences(store, previous, preferences)?;
    let active = current.active.clone();
    *current = EngineEndpointBinding {
        active,
        ..replacement
    };
    Ok(())
}

fn commit_preferences(
    store: &SettingsStore,
    previous: &RuntimeSettingsSnapshot<RuntimePreferences>,
    next: &RuntimePreferences,
) -> Result<(), String> {
    match store.compare_and_swap_runtime_settings(previous.revision.as_deref(), next) {
        Ok(()) => Ok(()),
        Err(SettingsStoreError::RuntimeSettingsChanged) => {
            Err(SettingsStoreError::RuntimeSettingsChanged.to_string())
        }
        Err(error) => {
            // A directory fsync can fail after rename. If our new document is
            // visible, compensate once before the actor restores the old core.
            let observed = store
                .runtime_settings::<RuntimePreferences>()
                .map_err(|read| format!("{error}; settings persistence is uncertain: {read}"))?;
            if observed.settings == *next && observed.revision != previous.revision {
                store
                    .compare_and_swap_runtime_settings(
                        observed.revision.as_deref(),
                        &previous.settings,
                    )
                    .map_err(|restore| {
                        format!("{error}; settings restoration also failed: {restore}")
                    })?;
            }
            Err(error.to_string())
        }
    }
}
