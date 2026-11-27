//! What admits a change of the runtime preferences: what it may be built on,
//! and what is settled of it before it is made.
use std::collections::BTreeSet;
use std::sync::RwLock;

use cfw_application::EngineControllerAccess;
use cfw_core::{SettingsStore, SettingsStoreError};
use cfw_engine_api::TunnelMtuLimits;
use cfw_profiles::{ProfileError, StoredProfile};
use cfw_singbox_config::{EngineSettings, RuntimePreferences, ValidatedSingBoxProfile};

use super::saved::{SavedRuntimePreferences, read_file_beside_binding};
use crate::engine::endpoints::{EndpointSelectionError, observe_reserved_ports};
use crate::engine::{EndpointCandidateCursor, EngineEndpointBinding};

/// What a change of one setting is refused with once the saved preferences
/// it was built on are not the ones in force.
pub(crate) const SAVED_PREFERENCES_NOT_IN_FORCE: &str = "the saved network settings are not the ones in use; Reload From Disk in Settings shows them to be applied, and a single setting can be changed after that";

/// What the Apply of the form on saved preferences is refused with once the
/// selected profile chooses IPv6 DNS otherwise than that form showed.
pub(in crate::engine) const PROFILE_IPV6_DNS_CHANGED: &str = "the selected profile no longer gives the IPv6 DNS setting this form shows; cancel it, and Reload From Disk in Settings shows the saved settings as they are now";

/// IPv6 DNS as `preferences` give it beside the engine settings `engine`:
/// their own choice, or the choice of `profile` where they leave it open.
pub(crate) fn ipv6_dns_enabled_of(
    preferences: &RuntimePreferences,
    engine: &EngineSettings,
    profile: &ValidatedSingBoxProfile,
) -> bool {
    profile.effective_ipv6_dns_enabled(&EngineSettings {
        ipv6_dns_enabled: preferences.ipv6_dns_enabled,
        ..engine.clone()
    })
}

/// What a change of the runtime preferences was built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreferencesBasis {
    /// The saved preferences, as the ones in force. The change differs from
    /// what the engine runs with in what was asked for and in nothing else,
    /// so it is refused once they are no longer in force.
    InForce,
    /// The saved preferences, known not to be in force, as the form that
    /// shows them has them: as they are or corrected. The change puts them
    /// in force and leaves the switches, which that form does not show, as
    /// the engine runs them.
    Saved {
        /// IPv6 DNS as that form showed it: the choice of the saved
        /// preferences, or of the selected profile where they leave it
        /// open.
        ipv6_dns_enabled: bool,
    },
}

impl PreferencesBasis {
    /// By the `in_force` and the `saved_ipv6_dns_enabled` of the settings
    /// snapshot the change was built on.
    pub(crate) fn of_snapshot(in_force: bool, saved_ipv6_dns_enabled: bool) -> Self {
        if in_force {
            Self::InForce
        } else {
            Self::Saved {
                ipv6_dns_enabled: saved_ipv6_dns_enabled,
            }
        }
    }

    /// Why `preferences`, a change built on this and on saved preferences of
    /// `expected_revision`, may not be made of the saved preferences as they
    /// are `found`, as far as that is known without the selected profile, or
    /// else what the change asks of the profile.
    ///
    /// The saved preferences have to be the ones the change was built on,
    /// which their revision says, and a change built on preferences in force
    /// needs them to be in force still. The revision does not say that. It
    /// is the same again once a file is removed that did not exist before,
    /// or is put back as it was, while the engine runs with what was changed
    /// in between: the change would undo that, though it was made for one
    /// setting.
    ///
    /// A change built on saved preferences that are not in force may leave
    /// IPv6 DNS to the profile, as they did. Its form showed the profile's
    /// choice for it, and no revision changes with the profile: once the
    /// profile chooses otherwise, the change would put in force what the
    /// form did not show.
    fn require(
        self,
        expected_revision: Option<&str>,
        preferences: &RuntimePreferences,
        found: &SavedRuntimePreferences,
    ) -> Result<ProfileCondition, String> {
        if found.saved.revision.as_deref() != expected_revision {
            return Err(SettingsStoreError::RuntimeSettingsChanged.to_string());
        }
        match self {
            Self::InForce if found.in_force => Ok(ProfileCondition::Nothing),
            Self::InForce => Err(SAVED_PREFERENCES_NOT_IN_FORCE.into()),
            Self::Saved { ipv6_dns_enabled } if preferences.ipv6_dns_enabled.is_none() => {
                Ok(ProfileCondition::Ipv6DnsAsShown(ipv6_dns_enabled))
            }
            Self::Saved { .. } => Ok(ProfileCondition::Nothing),
        }
    }
}

/// What a change asks of the selected profile besides that it can be read,
/// once everything else of it is settled.
///
/// Every change asks that much of it: the view of the settings after the
/// change derives effective DNS from the selected document. The profile is
/// read under the lock of the profile repository, which an update of a
/// subscription may hold for longer than the read waits, and a change that is
/// refused for something else is to be refused for that, so the profile is
/// asked last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileCondition {
    /// Nothing more: the change does not depend on what the profile gives.
    Nothing,
    /// IPv6 DNS as the form of the change showed it, which the change leaves
    /// to the profile: the profile has to give it still.
    Ipv6DnsAsShown(bool),
}

impl ProfileCondition {
    /// Why the change to `preferences` may not be made beside the selected
    /// profile, `profile`.
    fn require(
        self,
        preferences: &RuntimePreferences,
        found: &SavedRuntimePreferences,
        profile: &ValidatedSingBoxProfile,
    ) -> Result<(), String> {
        match self {
            Self::Nothing => Ok(()),
            Self::Ipv6DnsAsShown(shown) => {
                let given = ipv6_dns_enabled_of(preferences, &found.engine, profile);
                if given == shown {
                    Ok(())
                } else {
                    Err(PROFILE_IPV6_DNS_CHANGED.into())
                }
            }
        }
    }
}

/// The preferences a change commits of the saved ones as they are `found`,
/// and what it asks of the selected profile, or why it may not be made of
/// them.
///
/// A change built on saved preferences that are not in force is the Apply of
/// the form that shows them. It commits the switches as the engine runs them
/// here, whatever it was given for them: that form may have been open across
/// another change, and across one that the same revision hides as well.
fn admitted(
    found: &SavedRuntimePreferences,
    expected_revision: Option<&str>,
    basis: PreferencesBasis,
    preferences: RuntimePreferences,
) -> Result<(RuntimePreferences, ProfileCondition), String> {
    let condition = basis.require(expected_revision, &preferences, found)?;
    let preferences = match basis {
        PreferencesBasis::InForce => preferences,
        PreferencesBasis::Saved { .. } => RuntimePreferences {
            mainland_china_direct: found.engine.mainland_china_direct,
            dns_leak_protection: found.engine.dns_leak_protection,
            webrtc_leak_protection: found.engine.webrtc_leak_protection,
            tcp_concurrency: found.engine.tcp_concurrency,
            ..preferences
        },
    };
    Ok((preferences, condition))
}

/// [`admitted`] and what the change then asks of the selected profile,
/// `profile`, as one: the preferences a change commits, or why it may not be
/// made.
#[cfg(test)]
pub(in crate::engine) fn admit_change(
    found: &SavedRuntimePreferences,
    profile: &ValidatedSingBoxProfile,
    expected_revision: Option<&str>,
    basis: PreferencesBasis,
    preferences: RuntimePreferences,
) -> Result<RuntimePreferences, String> {
    let (preferences, condition) = admitted(found, expected_revision, basis, preferences)?;
    condition.require(&preferences, found, profile)?;
    Ok(preferences)
}

/// A change of the runtime preferences as it is asked for: the preferences
/// to commit, the revision of the saved ones it was built on, and what it
/// was built on besides.
#[derive(Debug, Clone)]
pub(crate) struct RequestedChange {
    pub(crate) preferences: RuntimePreferences,
    pub(crate) expected_revision: Option<String>,
    pub(crate) basis: PreferencesBasis,
}

/// A requested change that nothing known beforehand refuses. Only such a
/// change takes a place in the queue of mode changes: there it supersedes
/// what is under way, and a change that is refused only there has ended the
/// retry of a start for nothing. [`admit_requested_change`] makes one, and
/// the transaction settles it again where it has its turn.
#[derive(Debug)]
pub(crate) struct AdmissibleChange(RequestedChange);

impl AdmissibleChange {
    /// The change, for the transaction that makes it.
    pub(super) fn into_requested(self) -> RequestedChange {
        self.0
    }

    #[cfg(test)]
    pub(in crate::engine) fn requested(&self) -> &RequestedChange {
        &self.0
    }
}

/// What a change commits, settled of the engine it finds: the preferences,
/// the engine settings they make of the settings it runs with, and the
/// endpoints those are selected with.
pub(super) struct SettledChange {
    pub(super) preferences: RuntimePreferences,
    pub(super) settings: EngineSettings,
    pub(super) cursor: EndpointCandidateCursor,
    pub(super) controller: EngineControllerAccess,
}

/// A change settled of everything that is known of it without the selected
/// profile, which it may still depend on. Only [`Self::with_profile`] gives
/// what it commits, so what it asks of the profile is never left out.
pub(super) struct UnprofiledChange {
    settled: SettledChange,
    condition: ProfileCondition,
}

impl UnprofiledChange {
    /// The settled change, once the selected profile, `profile`, gives what
    /// the change depends on it for. Every change is asked of the profile,
    /// which is read before it is asked.
    pub(super) fn with_profile(
        self,
        found: &SavedRuntimePreferences,
        profile: &ValidatedSingBoxProfile,
    ) -> Result<SettledChange, String> {
        self.condition
            .require(&self.settled.preferences, found, profile)?;
        Ok(self.settled)
    }
}

/// Settles `change` of the saved preferences as they are `found` beside
/// `binding`, on a platform that takes the TUN MTU within `tunnel_mtu`, or
/// says why it cannot be made of them: what it was built on no longer holds,
/// the platform does not take its TUN MTU, or the settings and endpoints of
/// the engine do not take it, as sharing at a port the engine keeps for it.
/// Nothing is written, and nothing of the selected profile is read: what the
/// change asks of it comes with what is settled, to be asked last.
///
/// This is all that is known of a change without making it. It is asked
/// before the change takes its place in the queue of mode changes, and again
/// inside it of what is read there, by this one function: what the queue
/// would refuse of the same engine is refused before it.
pub(super) fn settle_change(
    binding: &EngineEndpointBinding,
    found: &SavedRuntimePreferences,
    tunnel_mtu: TunnelMtuLimits,
    change: RequestedChange,
) -> Result<UnprofiledChange, String> {
    let RequestedChange {
        preferences,
        expected_revision,
        basis,
    } = change;
    let (preferences, condition) =
        admitted(found, expected_revision.as_deref(), basis, preferences)?;
    // The engine settings allow for a wider TUN MTU than a platform takes, so
    // that saved preferences beyond it can still be corrected.
    tunnel_mtu
        .validate(preferences.tunnel_mtu)
        .map_err(|error| error.to_string())?;
    let (settings, cursor) = binding.endpoints_for(&preferences, observe_reserved_ports)?;
    let controller =
        EngineControllerAccess::resolve(settings.clone()).map_err(|error| error.to_string())?;
    Ok(UnprofiledChange {
        settled: SettledChange {
            preferences,
            settings,
            cursor,
            controller,
        },
        condition,
    })
}

impl EngineEndpointBinding {
    /// The engine settings that `preferences` make of the settings of this
    /// binding, and the endpoints they are run with. The endpoints are kept
    /// where the preferences keep the port preference they were selected
    /// with, or name the port the engine listens on, and are selected again
    /// otherwise, clear of the LAN listener and of the ports that `reserved`
    /// observes as taken, as a start selects them. The listener is checked
    /// against the endpoints the change will use, and not against a port it
    /// gives up or a port of the controller that the selection moves.
    pub(in crate::engine) fn endpoints_for(
        &self,
        preferences: &RuntimePreferences,
        reserved: impl FnOnce() -> Result<BTreeSet<u16>, EndpointSelectionError>,
    ) -> Result<(EngineSettings, EndpointCandidateCursor), String> {
        let settings = preferences
            .apply_before_endpoint_selection(self.controller.settings().clone())
            .map_err(|error| error.to_string())?;
        let (settings, cursor) = self
            .cursor
            .with_runtime_preferences(settings, preferences.preferred_mixed_port, reserved)
            .map_err(|error| error.to_string())?;
        settings
            .validate_listener_settings()
            .map_err(|error| error.to_string())?;
        Ok((settings, cursor))
    }
}

/// Admits the change that `request` makes of the saved preferences as they
/// are read now, on a platform that takes the TUN MTU within `tunnel_mtu`.
/// `selected` reads the selected profile once nothing else refuses the
/// change, which is then asked of it as the queue asks it: a selection that
/// cannot be read refuses it, one that fails validation among them. A
/// repository that is held for longer than the read waits refuses nothing
/// here: an update of a subscription holds it at its place in the queue,
/// which the change takes after it, and there the change is asked of the
/// selected profile. While a cutover journal governs startup no change can be
/// made, whatever it is built on, so that is said before anything of the
/// settings is read.
pub(in crate::engine) fn admit_requested_change(
    endpoints: &RwLock<EngineEndpointBinding>,
    store: &SettingsStore,
    tunnel_mtu: TunnelMtuLimits,
    selected: impl FnOnce() -> Result<Option<StoredProfile>, ProfileError>,
    request: impl FnOnce(&SavedRuntimePreferences) -> Result<RequestedChange, String>,
) -> Result<AdmissibleChange, String> {
    crate::platform_maintenance::require_runtime_preferences_changeable(&store.paths().app_home)?;
    let (binding, found) = read_file_beside_binding(
        endpoints,
        || store.runtime_settings(),
        |binding, saved| (binding.clone(), binding.beside(saved)),
    )?;
    let change = request(&found)?;
    let unprofiled = settle_change(&binding, &found, tunnel_mtu, change.clone())?;
    match selected() {
        Ok(selection) => {
            let profile =
                selection.map_or_else(ValidatedSingBoxProfile::direct, |stored| stored.profile);
            unprofiled.with_profile(&found, &profile)?;
        }
        Err(ProfileError::RepositoryBusy) => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(AdmissibleChange(change))
}
