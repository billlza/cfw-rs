//! Settings UI and legacy scalar commands share one transactional backend.
use crate::{
    commands::ManagedProfiles,
    engine::{
        ManagedEngine, PreferencesBasis, RegisteredChange, RequestedChange,
        SAVED_PREFERENCES_NOT_IN_FORCE, SavedRuntimePreferences, admit_runtime_preferences_change,
        change_runtime_preferences, ipv6_dns_enabled_of,
    },
    platform_maintenance::PlatformMaintenanceGate,
    settings_store,
};
use cfw_core::SettingsStore;
use cfw_profiles::ProfileRepository;
use cfw_singbox_config::{
    EngineLogLevel, EngineSettings, LanProxySettings, RuntimePreferences, ValidatedSingBoxProfile,
};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Serialize)]
pub(crate) struct RuntimeSettingsView {
    pub settings: RuntimePreferences,
    pub revision: Option<String>,
    pub effective: RuntimeSettingsEffective,
    /// Whether `settings`, the saved ones, are what the engine runs with or
    /// would start with. They are not once anything but a change made here
    /// has changed the file: `effective` then differs from them, and a write
    /// of one more change would apply the rest of the file with it.
    pub in_force: bool,
    /// IPv6 DNS as `settings`, the saved ones, give it: their own choice, or
    /// the selected profile's where they leave it open. `effective` has what
    /// the engine runs with, which is another value while they are not in
    /// force.
    pub saved_ipv6_dns_enabled: bool,
    pub tunnel_mtu_limits: cfw_engine_api::TunnelMtuLimits,
    /// Why no change of these settings can be made now, or none. A write is
    /// refused with it before anything else is asked of it, so the pages say
    /// it in place of what they advise for saved settings that are not in
    /// force: that advice could not be followed.
    pub change_refused: Option<String>,
}

impl RuntimeSettingsView {
    fn of(
        read: SavedRuntimePreferences,
        profile: &ValidatedSingBoxProfile,
        tunnel_mtu_limits: cfw_engine_api::TunnelMtuLimits,
        change_refused: Option<String>,
    ) -> Result<Self, String> {
        read.saved
            .settings
            .validate()
            .map_err(|error| error.to_string())?;
        let saved_ipv6_dns_enabled =
            ipv6_dns_enabled_of(&read.saved.settings, &read.engine, profile);
        Ok(Self {
            settings: read.saved.settings,
            revision: read.saved.revision,
            effective: RuntimeSettingsEffective::for_profile(read.engine, profile),
            in_force: read.in_force,
            saved_ipv6_dns_enabled,
            tunnel_mtu_limits,
            change_refused,
        })
    }
}

/// What a write says of the settings snapshot it was built on, under the
/// names the snapshot has for it.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrittenOn {
    in_force: bool,
    saved_ipv6_dns_enabled: bool,
}

impl WrittenOn {
    /// The change a write asks for: `settings` in place of the saved ones of
    /// `revision`, built on what this says of their snapshot.
    fn change(self, settings: RuntimePreferences, revision: Option<String>) -> RequestedChange {
        RequestedChange {
            preferences: settings,
            expected_revision: revision,
            basis: PreferencesBasis::of_snapshot(self.in_force, self.saved_ipv6_dns_enabled),
        }
    }
}

/// Why no change of the saved settings in `store` can be made now, or none.
fn change_refused(store: &SettingsStore) -> Option<String> {
    crate::platform_maintenance::require_runtime_preferences_changeable(&store.paths().app_home)
        .err()
}

/// The selected profile, or the direct one where none is selected.
fn selected_profile(repository: &ProfileRepository) -> Result<ValidatedSingBoxProfile, String> {
    Ok(repository
        .load_selected()
        .map_err(|error| error.to_string())?
        .map_or_else(ValidatedSingBoxProfile::direct, |stored| stored.profile))
}

/// The change of one setting among the saved preferences `found`. It writes
/// all of them back, so they have to be the ones in force, which is said of
/// them before the change is made: what the change itself would be refused
/// for is of no use while they are not.
fn one_setting(
    found: &SavedRuntimePreferences,
    change: impl FnOnce(&mut RuntimePreferences) -> Result<(), String>,
) -> Result<RequestedChange, String> {
    found
        .saved
        .settings
        .validate()
        .map_err(|error| error.to_string())?;
    if !found.in_force {
        return Err(SAVED_PREFERENCES_NOT_IN_FORCE.into());
    }
    let mut preferences = found.saved.settings.clone();
    change(&mut preferences)?;
    Ok(RequestedChange {
        preferences,
        expected_revision: found.saved.revision.clone(),
        basis: PreferencesBasis::InForce,
    })
}

/// Admits a change on what is known of it before its turn among the mode
/// changes, which it is counted among from its press
/// ([`admit_runtime_preferences_change`]).
async fn admit(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
    request: impl FnOnce(&SavedRuntimePreferences) -> Result<RequestedChange, String> + Send + 'static,
) -> Result<RegisteredChange, String> {
    let store = settings_store()?;
    admit_runtime_preferences_change(engine, store, profiles.repository().clone(), request).await
}

#[derive(Serialize)]
pub(crate) struct RuntimeSettingsEffective {
    mixed_port: u16,
    log_level: EngineLogLevel,
    tunnel_mtu: u16,
    ipv6_dns_enabled: bool,
    lan_proxy: Option<LanProxySettings>,
    /// The user's choice, always present. Whether it applies to the selected
    /// profile (its selected route must be remote) is the projection's.
    mainland_china_direct: bool,
    /// The user's choice, always present. It applies in Tunnel mode only,
    /// which is the projection's to decide.
    dns_leak_protection: bool,
    /// The user's choice, always present. It applies in Tunnel mode only and
    /// outside Direct mode, which is the projection's to decide.
    webrtc_leak_protection: bool,
    /// The user's choice, always present, although the stored preferences
    /// omit it while it is on.
    tcp_concurrency: bool,
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
            mainland_china_direct: value.mainland_china_direct,
            dns_leak_protection: value.dns_leak_protection,
            webrtc_leak_protection: value.webrtc_leak_protection,
            tcp_concurrency: value.tcp_concurrency,
        }
    }
}

pub(super) async fn snapshot(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
) -> Result<RuntimeSettingsView, String> {
    let store = settings_store()?;
    let repository = profiles.repository().clone();
    let reader = engine.saved_runtime_preferences();
    let tunnel_mtu_limits = engine.coordinator.runtime_platform().tunnel_mtu_limits();
    tauri::async_runtime::spawn_blocking(move || {
        let read = reader.read(&store)?;
        let profile = selected_profile(&repository)?;
        RuntimeSettingsView::of(read, &profile, tunnel_mtu_limits, change_refused(&store))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn read_runtime_settings_snapshot(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
) -> Result<RuntimeSettingsView, String> {
    snapshot(&engine, &profiles).await
}

/// `revision` and `basis` are of the settings snapshot the write was built
/// on, and the file must still have that revision. Settings built on ones in
/// force change what was asked for and nothing else only while those are in
/// force still, so the write is refused once they are not. `in_force` is
/// false for saved settings that are applied in the knowledge that the
/// engine does not run with them, as the form that shows them has them: as
/// they are or corrected. The switches are no fields of that form and stay
/// as the engine runs them, whatever the write says of them, and IPv6 DNS
/// that the write leaves to the profile has to be what the form showed
/// still.
#[tauri::command]
pub(crate) async fn write_runtime_settings_snapshot(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    settings: RuntimePreferences,
    revision: Option<String>,
    basis: WrittenOn,
) -> Result<RuntimeSettingsView, String> {
    let change = admit(&engine, &profiles, move |_| {
        Ok(basis.change(settings, revision))
    })
    .await?;
    change_runtime_preferences(&engine, &retirement, &profiles, change).await?;
    snapshot(&engine, &profiles).await
}

pub(super) async fn update(
    engine: &ManagedEngine,
    retirement: &PlatformMaintenanceGate,
    profiles: &ManagedProfiles,
    change: impl FnOnce(&mut RuntimePreferences) -> Result<(), String> + Send + 'static,
) -> Result<RuntimeSettingsView, String> {
    // One setting is changed among the saved ones, and the write applies all
    // of them. It is refused unless they are the ones in force: it would
    // bring every other difference of the file into force too.
    let change = admit(engine, profiles, move |found| one_setting(found, change)).await?;
    change_runtime_preferences(engine, retirement, profiles, change).await?;
    snapshot(engine, profiles).await
}

/// The change of the log level to `level`, as a command is given it. The
/// level is read in the change, so a change of one setting is refused first
/// for what refuses every change of one: a pending cleanup, and saved
/// settings that are not in force.
pub(super) fn log_level_change(
    level: String,
) -> impl FnOnce(&mut RuntimePreferences) -> Result<(), String> + Send + 'static {
    move |settings| {
        settings.log_level = log_level(&level)?;
        Ok(())
    }
}

/// The change of the address of the LAN listener to `address`, as a command
/// is given it, read in the change as the log level is.
pub(super) fn bind_address_change(
    address: String,
) -> impl FnOnce(&mut RuntimePreferences) -> Result<(), String> + Send + 'static {
    move |settings| {
        let address = address
            .trim()
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "LAN listener address must be a numeric IPv4 address")?;
        let lan = settings
            .lan_proxy
            .as_mut()
            .ok_or("configure LAN sharing and trusted source ranges first")?;
        lan.listen = address;
        settings.validate().map_err(|error| error.to_string())
    }
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

#[cfg(test)]
mod tests;
