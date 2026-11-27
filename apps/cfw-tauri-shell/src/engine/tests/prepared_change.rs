//! What the transaction of the runtime preferences prepares where it has its
//! turn among the mode changes, and what its commit leaves, on a store and a
//! profile repository of the test's own.
use super::admitted_change::profile_without_ipv6_dns;
use super::saved_preferences::{MAC_TUNNEL_MTU, binding_running, temporary_store};
use super::*;
use crate::engine::runtime_settings::{
    PROFILE_IPV6_DNS_CHANGED, PreferencesBasis, RequestedChange, SAVED_PREFERENCES_NOT_IN_FORCE,
    commit_runtime_settings, prepare_runtime_settings, read_saved_runtime_preferences,
};
use cfw_core::SettingsStoreError;
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

/// The change of the form on saved preferences that showed IPv6 DNS so.
fn showed(ipv6_dns_enabled: bool) -> PreferencesBasis {
    PreferencesBasis::Saved { ipv6_dns_enabled }
}

/// A change that leaves all as it rests but the log level.
fn louder(basis: PreferencesBasis, expected_revision: Option<&str>) -> RequestedChange {
    RequestedChange {
        preferences: RuntimePreferences {
            log_level: EngineLogLevel::Debug,
            ..RuntimePreferences::default()
        },
        expected_revision: expected_revision.map(str::to_owned),
        basis,
    }
}

/// The engine of these tests: DNS leak protection is on, and IPv6 DNS is
/// turned off by a choice of the settings. There is no settings file, as
/// after something removed it, so the saved preferences are not in force.
fn running() -> std::sync::RwLock<EngineEndpointBinding> {
    std::sync::RwLock::new(binding_running(&RuntimePreferences {
        ipv6_dns_enabled: Some(false),
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    }))
}

/// The selected profile turns IPv6 DNS off, and it is the one the change is
/// asked of once more: a form that showed it on is refused, though the
/// profile where none is selected would have left it on.
#[test]
fn the_transaction_asks_once_more_where_it_has_its_turn() {
    let (_home, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let imported = repository
        .import(Some("Selected"), &profile_without_ipv6_dns())
        .expect("import");
    repository.select(&imported.id).expect("select");
    let endpoints = running();
    let prepare = |mode, change| {
        prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            mode,
            change,
        )
    };

    for mode in [EngineMode::Off, EngineMode::SystemProxy] {
        assert_eq!(
            prepare(mode, louder(showed(false), Some("then"))).err(),
            Some(SettingsStoreError::RuntimeSettingsChanged.to_string())
        );
        assert_eq!(
            prepare(mode, louder(PreferencesBasis::InForce, None))
                .err()
                .as_deref(),
            Some(SAVED_PREFERENCES_NOT_IN_FORCE)
        );
        assert_eq!(
            prepare(mode, louder(showed(true), None)).err().as_deref(),
            Some(PROFILE_IPV6_DNS_CHANGED)
        );
    }

    let prepared = prepare(EngineMode::SystemProxy, louder(showed(false), None))
        .expect("the change of the form");
    // What was given, with the switch the form does not show as the engine
    // runs it, and the settings of the engine with that applied.
    let committed = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    assert_eq!(prepared.preferences, committed);
    let before = endpoints.read().expect("endpoints").clone();
    assert_eq!(
        prepared.settings,
        committed
            .apply_to(before.controller.settings().clone())
            .expect("engine settings")
    );
    assert_eq!(prepared.settings.ipv6_dns_enabled, None);
    assert_eq!(
        prepared.replacement.controller.settings(),
        &prepared.settings
    );
    assert!(prepared.replacement.active.is_none());
    assert!(prepared.expected.controller == before.controller);
    assert!(prepared.expected.cursor == before.cursor);
    assert_eq!(prepared.previous.revision, None);
    assert_eq!(prepared.previous.settings, RuntimePreferences::default());
    assert_eq!(
        prepared
            .selected
            .as_ref()
            .map(|stored| stored.record.id.as_str()),
        Some(imported.id.as_str())
    );
    // Nothing is written by the preparation.
    let read = || {
        read_saved_runtime_preferences(&endpoints, || store.runtime_settings())
            .expect("saved preferences")
    };
    assert_eq!(read().saved.revision, None);
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 0);

    // Its commit leaves the saved preferences in force.
    commit_runtime_settings(
        &endpoints,
        &prepared.expected,
        prepared.replacement,
        &prepared.store,
        &prepared.previous,
        &prepared.preferences,
    )
    .expect("commit");
    drop(prepared.guard);
    let after = read();
    assert!(after.in_force);
    assert_eq!(after.saved.settings, committed);
    assert!(after.saved.revision.is_some());
    assert_eq!(after.engine, prepared.settings);
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 1);
    // The next change is one of a single setting, built on them.
    let quieter = RequestedChange {
        preferences: RuntimePreferences {
            dns_leak_protection: true,
            ..RuntimePreferences::default()
        },
        expected_revision: after.saved.revision.clone(),
        basis: PreferencesBasis::InForce,
    };
    let next = prepare(EngineMode::SystemProxy, quieter).expect("a change of one setting");
    assert_eq!(next.settings.log_level, EngineLogLevel::Info);
    assert_eq!(next.replacement.preference_writes, 1);
}

/// Without a selected profile an engine that is off is asked of the direct
/// profile, which leaves IPv6 DNS on, and one that runs has nothing to run.
/// That is said after what is refused without the profiles.
#[test]
fn a_change_without_a_selected_profile_is_asked_of_the_direct_one() {
    let (_home, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let endpoints = running();
    let prepare = |mode, change| {
        prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            mode,
            change,
        )
    };
    assert_eq!(
        prepare(EngineMode::Off, louder(showed(false), None))
            .err()
            .as_deref(),
        Some(PROFILE_IPV6_DNS_CHANGED)
    );
    let prepared =
        prepare(EngineMode::Off, louder(showed(true), None)).expect("the change of the form");
    assert!(prepared.selected.is_none());
    assert!(prepared.preferences.dns_leak_protection);
    drop(prepared);
    for basis in [showed(true), showed(false)] {
        assert_eq!(
            prepare(EngineMode::SystemProxy, louder(basis, None))
                .err()
                .as_deref(),
            Some("a running engine has no selected profile")
        );
    }
    assert_eq!(
        prepare(
            EngineMode::SystemProxy,
            louder(PreferencesBasis::InForce, None)
        )
        .err()
        .as_deref(),
        Some(SAVED_PREFERENCES_NOT_IN_FORCE)
    );
}
