//! Settings UI and legacy scalar commands share one transactional backend.
use crate::{
    commands::ManagedProfiles,
    engine::{ManagedEngine, change_runtime_preferences},
    legacy::LegacyRetirementGate,
    settings_store,
};
use cfw_core::RuntimeSettingsSnapshot;
use cfw_singbox_config::{
    EngineLogLevel, EngineSettings, LanProxySettings, RuntimePreferences, ValidatedSingBoxProfile,
};
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub(crate) struct RuntimeSettingsView {
    pub settings: RuntimePreferences,
    pub revision: Option<String>,
    pub effective: RuntimeSettingsEffective,
}

#[derive(Serialize)]
pub(crate) struct RuntimeSettingsEffective {
    mixed_port: u16,
    log_level: EngineLogLevel,
    tunnel_mtu: u16,
    ipv6_dns_enabled: bool,
    lan_proxy: Option<LanProxySettings>,
}

impl RuntimeSettingsEffective {
    fn for_profile(value: EngineSettings, profile: &ValidatedSingBoxProfile) -> Self {
        let ipv6_dns_enabled = profile.effective_ipv6_dns_enabled(&value);
        Self {
            mixed_port: value.mixed_port,
            log_level: value.log_level,
            tunnel_mtu: value.tunnel_mtu,
            ipv6_dns_enabled,
            lan_proxy: value.lan_proxy,
        }
    }
}

pub(super) async fn snapshot(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
) -> Result<RuntimeSettingsView, String> {
    let store = settings_store()?;
    let repository = profiles.repository().clone();
    let settings = engine.engine_settings()?;
    let (saved, effective) = tauri::async_runtime::spawn_blocking(move || {
        let saved: RuntimeSettingsSnapshot<RuntimePreferences> = store
            .runtime_settings()
            .map_err(|error| error.to_string())?;
        let profile = repository
            .load_selected()
            .map_err(|error| error.to_string())?
            .map_or_else(ValidatedSingBoxProfile::direct, |stored| stored.profile);
        Ok::<_, String>((
            saved,
            RuntimeSettingsEffective::for_profile(settings, &profile),
        ))
    })
    .await
    .map_err(|error| error.to_string())??;
    saved
        .settings
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(RuntimeSettingsView {
        settings: saved.settings,
        revision: saved.revision,
        effective,
    })
}

#[tauri::command]
pub(crate) async fn read_runtime_settings_snapshot(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<RuntimeSettingsView, String> {
    snapshot(&engine, &profiles).await
}

#[tauri::command]
pub(crate) async fn write_runtime_settings_snapshot(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    settings: RuntimePreferences,
    revision: Option<String>,
) -> Result<RuntimeSettingsView, String> {
    change_runtime_preferences(&engine, &retirement, &profiles, settings, revision).await?;
    snapshot(&engine, &profiles).await
}

pub(super) async fn update(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    change: impl FnOnce(&mut RuntimePreferences) -> Result<(), String>,
) -> Result<RuntimeSettingsView, String> {
    let mut saved = snapshot(engine, profiles).await?;
    change(&mut saved.settings)?;
    change_runtime_preferences(engine, retirement, profiles, saved.settings, saved.revision)
        .await?;
    snapshot(engine, profiles).await
}

pub(super) fn log_level(value: &str) -> Result<EngineLogLevel, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(EngineLogLevel::Trace),
        "debug" => Ok(EngineLogLevel::Debug),
        "info" => Ok(EngineLogLevel::Info),
        "warn" | "warning" => Ok(EngineLogLevel::Warn),
        "error" => Ok(EngineLogLevel::Error),
        "fatal" => Ok(EngineLogLevel::Fatal),
        "silent" => Ok(EngineLogLevel::Silent),
        _ => Err("log level must be trace, debug, info, warn, error, fatal or silent".into()),
    }
}
