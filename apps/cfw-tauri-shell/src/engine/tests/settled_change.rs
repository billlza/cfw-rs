//! What is settled of a change before it takes a place among the mode
//! changes and again inside it: what the settings and endpoints of the
//! engine refuse of it, and what of it depends on the selected profile.
use super::restoration::{RestorationRightsBridge, engine_with_rights_bridge};
use super::saved_preferences::{MAC_TUNNEL_MTU, lan, temporary_store};
use super::*;
use crate::engine::ManagedEngine;
use crate::engine::runtime_settings::{
    PreferencesBasis, RequestedChange, SAVED_PREFERENCES_NOT_IN_FORCE, admit_requested_change,
    commit_runtime_settings, prepare_runtime_settings, read_saved_runtime_preferences,
};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

/// The form of saved preferences that showed IPv6 DNS on, as the profile
/// where none is selected gives it.
const SAVED: PreferencesBasis = PreferencesBasis::Saved {
    ipv6_dns_enabled: true,
};

/// Sharing at `port`, which the engine may use itself.
fn sharing(port: u16) -> RuntimePreferences {
    RuntimePreferences {
        allow_lan: true,
        lan_proxy: Some(lan(port)),
        ..RuntimePreferences::default()
    }
}

fn louder() -> RuntimePreferences {
    RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..RuntimePreferences::default()
    }
}

/// A file that was put back turns sharing on at the port the controller of
/// the engine listens on. The settings of the engine refuse that, which is
/// known before the change is made: it is not admitted to the queue of mode
/// changes, where it would end the retry of a start, and the queue refuses
/// it of the same engine as well.
#[test]
fn a_change_the_engine_settings_refuse_is_not_admitted() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(endpoint_binding(engine.clone()));
    for basis in [PreferencesBasis::InForce, SAVED] {
        for port in [engine.controller_port, engine.mixed_port] {
            let request = || RequestedChange {
                preferences: sharing(port),
                expected_revision: None,
                basis,
            };
            let refused = admit_requested_change(
                &endpoints,
                &store,
                MAC_TUNNEL_MTU,
                || Ok(None),
                |_| Ok(request()),
            );
            let error = refused.expect_err("sharing at a port of the engine");
            assert!(error.contains("must be distinct"), "{basis:?}: {error}");
            let queued = prepare_runtime_settings(
                store.clone(),
                &endpoints,
                &repository,
                MAC_TUNNEL_MTU,
                EngineMode::Off,
                request(),
            );
            let error = queued.err().expect("sharing at a port of the engine");
            assert!(error.contains("must be distinct"), "{basis:?}: {error}");
        }
        // Sharing at a port of its own is admitted, as it was requested.
        let request = RequestedChange {
            preferences: sharing(17890),
            expected_revision: None,
            basis,
        };
        let admitted = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || Ok(None),
            |_| Ok(request),
        )
        .expect("sharing at a port of its own");
        assert_eq!(admitted.requested().preferences, sharing(17890));
    }
    // Preferences that are not valid in themselves are refused there too.
    let request = RequestedChange {
        preferences: RuntimePreferences {
            allow_lan: true,
            ..RuntimePreferences::default()
        },
        expected_revision: None,
        basis: PreferencesBasis::InForce,
    };
    let refused = admit_requested_change(
        &endpoints,
        &store,
        MAC_TUNNEL_MTU,
        || Ok(None),
        |_| Ok(request),
    );
    let error = refused.expect_err("sharing without a listener");
    assert!(error.contains("LAN listener"), "{error}");
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 0);
}

/// The selected profile is read under the lock of the profile repository,
/// which an update of a subscription may hold, and every change is asked of
/// it: the view of the settings after a change derives effective DNS from the
/// selected document. It is read last, so a change that is refused for
/// something else is refused for that without it.
#[test]
fn the_selected_profile_is_read_last_of_every_change_that_nothing_else_refuses() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let reads = std::cell::Cell::new(0);
    let admit = |preferences: &RuntimePreferences, expected_revision: Option<&str>, basis| {
        let request = RequestedChange {
            preferences: preferences.clone(),
            expected_revision: expected_revision.map(str::to_owned),
            basis,
        };
        let before = reads.get();
        let admitted = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || {
                reads.set(reads.get() + 1);
                Ok(None)
            },
            |_| Ok(request),
        );
        (admitted.map(|_| ()), reads.get() - before)
    };
    let in_force = PreferencesBasis::InForce;
    let changed = cfw_core::SettingsStoreError::RuntimeSettingsChanged.to_string();
    assert_eq!(admit(&louder(), None, in_force), (Ok(()), 1));
    assert_eq!(
        admit(&louder(), Some("then"), in_force),
        (Err(changed.clone()), 0)
    );
    let external = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    store
        .compare_and_swap_runtime_settings(None, &external)
        .expect("external write");
    let revision = store
        .runtime_settings::<RuntimePreferences>()
        .expect("saved preferences")
        .revision;
    assert_eq!(
        admit(&louder(), revision.as_deref(), in_force),
        (Err(SAVED_PREFERENCES_NOT_IN_FORCE.to_owned()), 0)
    );
    // The form of the saved preferences, with IPv6 DNS set in it, and left
    // to the profile.
    let chosen = RuntimePreferences {
        ipv6_dns_enabled: Some(false),
        ..louder()
    };
    assert_eq!(admit(&chosen, revision.as_deref(), SAVED), (Ok(()), 1));
    assert_eq!(admit(&louder(), revision.as_deref(), SAVED), (Ok(()), 1));
    assert_eq!(admit(&louder(), Some("then"), SAVED), (Err(changed), 0));
}

/// The engine listens on its port by its own choice, and a change names
/// that port. The endpoints are settled with it as their preference, so the
/// commit leaves the saved preferences in force.
#[test]
fn a_change_that_names_the_port_of_the_engine_is_settled_with_that_preference() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(endpoint_binding(engine.clone()));
    let named = RuntimePreferences {
        preferred_mixed_port: Some(engine.mixed_port),
        ..RuntimePreferences::default()
    };
    let request = || RequestedChange {
        preferences: named.clone(),
        expected_revision: None,
        basis: PreferencesBasis::InForce,
    };
    admit_requested_change(
        &endpoints,
        &store,
        MAC_TUNNEL_MTU,
        || Ok(None),
        |_| Ok(request()),
    )
    .expect("the port the engine has");
    let prepared = prepare_runtime_settings(
        store.clone(),
        &endpoints,
        &repository,
        MAC_TUNNEL_MTU,
        EngineMode::Off,
        request(),
    )
    .expect("the port the engine has");
    assert!(
        !prepared
            .expected
            .cursor
            .has_port_preference(named.preferred_mixed_port)
    );
    assert!(
        prepared
            .replacement
            .cursor
            .has_port_preference(named.preferred_mixed_port)
    );
    assert_eq!(prepared.settings, engine);
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
    let after = read_saved_runtime_preferences(&endpoints, || store.runtime_settings())
        .expect("saved preferences");
    assert!(after.in_force);
    assert_eq!(after.saved.settings, named);
}

/// An update of a subscription holds the profile repository, and a change is
/// refused for something that is known without the profiles: another
/// revision of the file, or sharing at the port of the controller. It is
/// refused for that at once, before the queue and in it, and not after the
/// wait for the repository with the words of the repository: where it has its
/// turn it would keep the queue of mode changes waiting meanwhile. The words
/// of each refusal say which came first, as the repository gives its own once
/// it has waited.
#[test]
fn a_change_is_refused_for_what_is_known_without_the_profiles_before_they_are_read() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let engine = EngineSettings::default();
    let endpoints = std::sync::RwLock::new(endpoint_binding(engine.clone()));
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    let stale = RequestedChange {
        preferences: louder(),
        expected_revision: Some("then".into()),
        basis: PreferencesBasis::InForce,
    };
    let queued = prepare_runtime_settings(
        store.clone(),
        &endpoints,
        &repository,
        MAC_TUNNEL_MTU,
        EngineMode::Off,
        stale,
    );
    assert_eq!(
        queued.err(),
        Some(cfw_core::SettingsStoreError::RuntimeSettingsChanged.to_string())
    );
    for basis in [PreferencesBasis::InForce, SAVED] {
        let colliding = || RequestedChange {
            preferences: sharing(engine.controller_port),
            expected_revision: None,
            basis,
        };
        let queued = prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            EngineMode::Off,
            colliding(),
        );
        let error = queued.err().unwrap_or_default();
        assert!(error.contains("must be distinct"), "{basis:?}: {error}");
        // Before the queue the profile is not read for it either, also
        // where the change leaves IPv6 DNS to the profile.
        let reads = std::cell::Cell::new(0);
        let refused = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || {
                reads.set(reads.get() + 1);
                Ok(None)
            },
            |_| Ok(colliding()),
        );
        let error = refused.expect_err("sharing at the port of the controller");
        assert!(error.contains("must be distinct"), "{basis:?}: {error}");
        assert_eq!(reads.get(), 0, "{basis:?}");
    }
    drop(held);
}

/// The platform takes a narrower range of the TUN MTU than the saved
/// preferences may hold, and the page sends no change beyond it. One that
/// comes is refused for that, which is known without the profiles: before
/// the queue and in it, while an update holds the profiles, and the profile
/// is not read for it, also where the change leaves IPv6 DNS to the profile.
/// The range is that of the platform the engine runs on.
#[test]
fn a_tunnel_mtu_beyond_what_the_platform_takes_is_refused_before_the_profiles_are_read() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let wide = |basis| RequestedChange {
        preferences: RuntimePreferences {
            tunnel_mtu: 1_600,
            ..RuntimePreferences::default()
        },
        expected_revision: None,
        basis,
    };
    let refusal = MAC_TUNNEL_MTU
        .validate(1_600)
        .expect_err("beyond what the Mac takes")
        .to_string();
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    for basis in [PreferencesBasis::InForce, SAVED] {
        let reads = std::cell::Cell::new(0);
        let refused = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || {
                reads.set(reads.get() + 1);
                Ok(None)
            },
            |_| Ok(wide(basis)),
        );
        assert_eq!(refused.map(|_| ()), Err(refusal.clone()), "{basis:?}");
        assert_eq!(reads.get(), 0, "{basis:?}");
        let queued = prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            EngineMode::Off,
            wide(basis),
        );
        assert_eq!(queued.err(), Some(refusal.clone()), "{basis:?}");
    }
    drop(held);
    let windows = EngineRuntimePlatform::Windows.tunnel_mtu_limits();
    for basis in [PreferencesBasis::InForce, SAVED] {
        let admitted = admit_requested_change(
            &endpoints,
            &store,
            windows,
            || Ok(None),
            |_| Ok(wide(basis)),
        );
        assert_eq!(
            admitted.map(|change| change.requested().preferences.tunnel_mtu),
            Ok(1_600),
            "{basis:?}"
        );
        let prepared = prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            windows,
            EngineMode::Off,
            wide(basis),
        );
        assert_eq!(
            prepared.map(|prepared| prepared.preferences.tunnel_mtu),
            Ok(1_600),
            "{basis:?}"
        );
    }
}

/// The engine listens on the port the saved preferences named, and a change
/// leaves the port to it and shares at that port, as a file that was put back
/// may. The endpoints are selected again for the change, clear of the LAN
/// listener and of the ports others take, as a start selects them, so the
/// change is settled with the endpoints it will use and not refused for the
/// port it gives up. Endpoints the change keeps are still not given to the
/// listener, and beside a port the change names the listener is checked
/// before anything is observed.
#[test]
fn the_lan_listener_is_checked_against_the_endpoints_a_change_will_use() {
    const NAMED: u16 = 8888;
    let first = EngineSettings::default().mixed_port;
    let named = endpoint_binding(EngineSettings {
        mixed_port: NAMED,
        ..EngineSettings::default()
    });
    for (taken, selected) in [(vec![], first), (vec![first], first + 1)] {
        let (settings, cursor) = named
            .endpoints_for(&sharing(NAMED), || Ok(taken.iter().copied().collect()))
            .expect("the endpoints of the change");
        assert_eq!(settings.mixed_port, selected, "{taken:?}");
        assert_eq!(settings.lan_proxy.as_ref().map(|lan| lan.port), Some(NAMED));
        assert!(cursor.has_port_preference(None));
    }
    let kept = endpoint_binding(EngineSettings::default())
        .endpoints_for(&sharing(first), || {
            panic!("endpoints that are kept observe nothing")
        })
        .expect_err("sharing at the port the engine keeps");
    assert!(kept.contains("must be distinct"), "{kept}");
    let beside = RuntimePreferences {
        preferred_mixed_port: Some(17890),
        ..sharing(17890)
    };
    let error = named
        .endpoints_for(&beside, || {
            panic!("beside a port the change names nothing is observed")
        })
        .expect_err("sharing at the port it names");
    assert!(error.contains("must be distinct"), "{error}");
}

/// Saved preferences that leave the port to the engine and share at the port
/// it would take first: a start selects the next one, clear of the LAN
/// listener and of the ports others take, as a change to them selects it.
#[test]
fn a_start_selects_an_automatic_port_beside_the_lan_listener() {
    let (_root, store) = temporary_store();
    let first = EngineSettings::default().mixed_port;
    store
        .compare_and_swap_runtime_settings(None, &sharing(first))
        .expect("saved preferences");
    for (taken, selected) in [(vec![], first + 1), (vec![first + 1], first + 2)] {
        let (settings, cursor) =
            crate::engine::preparation::configured_engine_settings(&store, || {
                Ok(taken.iter().copied().collect())
            })
            .expect("a start");
        assert_eq!(settings.mixed_port, selected, "{taken:?}");
        assert_eq!(settings.lan_proxy.as_ref().map(|lan| lan.port), Some(first));
        assert!(cursor.has_port_preference(None));
    }
}

/// A change that names a proxy port and shares at the port the controller
/// listens on selects the controller again, clear of the LAN listener and of
/// the ports others take, as a start selects it: before the selection the
/// listener is checked only against the port the change names.
#[test]
fn a_change_that_names_a_port_selects_the_controller_beside_the_lan_listener() {
    const NAMED: u16 = 8888;
    let controller = EngineSettings::default().controller_port;
    let binding = endpoint_binding(EngineSettings::default());
    let named = RuntimePreferences {
        preferred_mixed_port: Some(NAMED),
        ..sharing(controller)
    };
    for (taken, selected) in [
        (vec![], controller + 1),
        (vec![controller + 1], controller + 2),
    ] {
        let (settings, cursor) = binding
            .endpoints_for(&named, || Ok(taken.iter().copied().collect()))
            .expect("the endpoints of the change");
        assert_eq!(
            (settings.mixed_port, settings.controller_port),
            (NAMED, selected),
            "{taken:?}"
        );
        assert_eq!(
            settings.lan_proxy.as_ref().map(|lan| lan.port),
            Some(controller)
        );
        assert!(cursor.has_port_preference(Some(NAMED)));
    }
}

/// Saved preferences that share at the port the controller would take
/// first: a start selects the next one for the controller, and so does the
/// next start once the proxy port the engine took is named, as a change of
/// the port preference saves it. Settings the app saves keep its next start
/// from nothing.
#[test]
fn a_start_selects_the_controller_beside_the_lan_listener() {
    let (_root, store) = temporary_store();
    let controller = EngineSettings::default().controller_port;
    let start = |store: &cfw_core::SettingsStore| {
        crate::engine::preparation::configured_engine_settings(store, || Ok(Default::default()))
    };
    store
        .compare_and_swap_runtime_settings(None, &sharing(controller))
        .expect("saved preferences");
    let (automatic, _) = start(&store).expect("a start that leaves the port to the engine");
    assert_eq!(automatic.controller_port, controller + 1);
    let revision = store
        .runtime_settings::<RuntimePreferences>()
        .expect("saved preferences")
        .revision;
    let named = RuntimePreferences {
        preferred_mixed_port: Some(automatic.mixed_port),
        ..sharing(controller)
    };
    store
        .compare_and_swap_runtime_settings(revision.as_deref(), &named)
        .expect("the port the engine took, named");
    let (settings, cursor) = start(&store).expect("a start that names the port the engine took");
    assert_eq!(
        (settings.mixed_port, settings.controller_port),
        (automatic.mixed_port, controller + 1)
    );
    assert!(cursor.has_port_preference(Some(automatic.mixed_port)));
}

/// The commands admit a change with the reader of the engine, which takes
/// the TUN MTU within the range of the platform the engine runs on: what the
/// Mac refuses, Windows takes.
#[tokio::test]
async fn the_engine_admits_a_change_with_the_tunnel_mtu_of_its_platform() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    for (platform, takes) in [
        (EngineRuntimePlatform::MacOs, false),
        (EngineRuntimePlatform::Windows, true),
    ] {
        let mut backend = EndpointRetryBackend::new(0);
        backend.platform = platform;
        let engine = ManagedEngine {
            coordinator: endpoint_retry_coordinator(Arc::new(backend)),
            ..engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()))
        };
        let request = RequestedChange {
            preferences: RuntimePreferences {
                tunnel_mtu: 1_600,
                ..RuntimePreferences::default()
            },
            expected_revision: None,
            basis: PreferencesBasis::InForce,
        };
        let admitted = engine
            .saved_runtime_preferences()
            .admit(&store, &repository, |_| Ok(request));
        assert_eq!(admitted.is_ok(), takes, "{platform:?}: {admitted:?}");
    }
}
