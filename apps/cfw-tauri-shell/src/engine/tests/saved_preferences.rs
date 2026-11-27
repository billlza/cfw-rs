//! Whether the saved runtime preferences are the ones this process runs the
//! engine with, and how the two are read beside each other.
use super::*;
use crate::engine::runtime_settings::{commit_runtime_settings, read_saved_runtime_preferences};
use cfw_core::{AppPaths, RuntimeSettingsSnapshot, SettingsStore, SettingsStoreError};
use cfw_singbox_config::{EngineLogLevel, LanProxySettings, RuntimePreferences};

/// The TUN MTU that the changes these tests admit are taken with: what the
/// Mac takes, the narrower of the two platforms.
pub(super) const MAC_TUNNEL_MTU: cfw_engine_api::TunnelMtuLimits =
    EngineRuntimePlatform::MacOs.tunnel_mtu_limits();

pub(super) fn lan(port: u16) -> LanProxySettings {
    LanProxySettings {
        listen: std::net::Ipv4Addr::UNSPECIFIED,
        port,
        allowed_source_cidrs: vec!["192.168.1.0/24".into()],
    }
}

/// One preference changed at a time, each with its name.
pub(super) fn single_changes() -> Vec<(&'static str, RuntimePreferences)> {
    let saved = RuntimePreferences::default;
    vec![
        (
            "the proxy port",
            RuntimePreferences {
                preferred_mixed_port: Some(8890),
                ..saved()
            },
        ),
        (
            "the log level",
            RuntimePreferences {
                log_level: EngineLogLevel::Debug,
                ..saved()
            },
        ),
        (
            "the TUN MTU",
            RuntimePreferences {
                tunnel_mtu: 1400,
                ..saved()
            },
        ),
        (
            "IPv6 DNS off",
            RuntimePreferences {
                ipv6_dns_enabled: Some(false),
                ..saved()
            },
        ),
        (
            "IPv6 DNS on by choice",
            RuntimePreferences {
                ipv6_dns_enabled: Some(true),
                ..saved()
            },
        ),
        (
            "LAN sharing",
            RuntimePreferences {
                allow_lan: true,
                lan_proxy: Some(lan(7898)),
                ..saved()
            },
        ),
        (
            "Mainland China direct",
            RuntimePreferences {
                mainland_china_direct: true,
                ..saved()
            },
        ),
        (
            "DNS leak protection",
            RuntimePreferences {
                dns_leak_protection: true,
                ..saved()
            },
        ),
        (
            "WebRTC leak protection",
            RuntimePreferences {
                webrtc_leak_protection: true,
                ..saved()
            },
        ),
        (
            "TCP concurrency",
            RuntimePreferences {
                tcp_concurrency: false,
                ..saved()
            },
        ),
    ]
}

/// The binding of a process that runs these preferences.
pub(super) fn binding_running(preferences: &RuntimePreferences) -> EngineEndpointBinding {
    endpoint_binding(
        preferences
            .apply_to(EngineSettings::default())
            .expect("engine settings"),
    )
}

#[test]
fn preferences_are_run_until_one_of_them_differs_from_the_engine_settings() {
    let untouched = endpoint_binding(EngineSettings::default());
    assert!(untouched.runs(&RuntimePreferences::default()));
    for (name, changed) in single_changes() {
        assert!(
            !untouched.runs(&changed),
            "{name} is saved but the engine does not run it"
        );
        let applied = binding_running(&changed);
        assert!(applied.runs(&changed), "{name} is saved and run");
        assert!(
            !applied.runs(&RuntimePreferences::default()),
            "{name} is run but no longer saved"
        );
    }
}

#[test]
fn a_listener_kept_for_later_is_run() {
    // LAN sharing is off, so its saved listener reaches no engine setting.
    assert!(
        endpoint_binding(EngineSettings::default()).runs(&RuntimePreferences {
            lan_proxy: Some(lan(7898)),
            ..RuntimePreferences::default()
        })
    );
}

/// The engine listens on a port it selected, and may move to the next one
/// when it cannot bind it. A file that names this very port says to keep it
/// and to refuse instead. The engine settings are the same with either, so
/// only the port preference tells them apart.
#[test]
fn a_port_named_by_number_is_run_once_it_is_the_port_preference() {
    let selected = endpoint_binding(EngineSettings::default());
    let settings = selected.controller.settings().clone();
    let named = RuntimePreferences {
        preferred_mixed_port: Some(settings.mixed_port),
        ..RuntimePreferences::default()
    };
    assert_eq!(
        named.apply_to(settings.clone()).expect("engine settings"),
        settings
    );
    assert!(
        !selected.runs(&named),
        "the engine would still move from the port the file says to keep"
    );

    // The change that takes the preference selects nothing again.
    let (kept, cursor) = selected
        .cursor
        .with_runtime_preferences(settings.clone(), named.preferred_mixed_port, || {
            panic!("the endpoints are kept, and nothing is observed for them")
        })
        .expect("the cursor of the change");
    assert_eq!(kept, settings);
    let holding = EngineEndpointBinding {
        controller: EngineControllerAccess::resolve(kept).expect("controller"),
        cursor,
        active: None,
        preference_writes: 0,
    };
    assert!(holding.runs(&named));
    assert!(
        !holding.runs(&RuntimePreferences::default()),
        "an automatic port is saved while the engine keeps this one"
    );
}

#[test]
fn an_automatic_port_is_not_run_while_the_engine_holds_a_chosen_one() {
    let chosen = RuntimePreferences {
        preferred_mixed_port: Some(8890),
        ..RuntimePreferences::default()
    };
    // Applying "automatic" leaves the port in the settings as it is, but the
    // endpoints would be selected again and may move.
    assert!(!binding_running(&chosen).runs(&RuntimePreferences::default()));
}

#[test]
fn preferences_that_cannot_be_applied_are_not_run() {
    let untouched = endpoint_binding(EngineSettings::default());
    let controller_port = untouched.controller.settings().controller_port;
    assert!(
        !untouched.runs(&RuntimePreferences {
            allow_lan: true,
            lan_proxy: Some(lan(controller_port)),
            ..RuntimePreferences::default()
        }),
        "a LAN listener on the controller's port"
    );
    assert!(
        !untouched.runs(&RuntimePreferences {
            allow_lan: true,
            ..RuntimePreferences::default()
        }),
        "LAN sharing without a listener"
    );
}

/// The store makes its directory itself: on Windows it accepts an app home
/// only with the access rules it sets there.
pub(super) fn temporary_store() -> (tempfile::TempDir, SettingsStore) {
    let root = tempfile::tempdir().expect("temporary directory");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path().join("app")));
    (root, store)
}

/// Commits `preferences` over `previous`, as the transaction does.
fn commit(
    endpoints: &std::sync::RwLock<EngineEndpointBinding>,
    store: &SettingsStore,
    previous: &RuntimeSettingsSnapshot<RuntimePreferences>,
    preferences: &RuntimePreferences,
) {
    let expected = endpoints.read().expect("endpoints").clone();
    let settings = preferences
        .apply_to(expected.controller.settings().clone())
        .expect("engine settings");
    commit_runtime_settings(
        endpoints,
        &expected,
        endpoint_binding(settings),
        store,
        previous,
        preferences,
    )
    .expect("commit");
}

#[test]
fn the_saved_preferences_are_read_beside_the_engine_settings() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let read = || {
        read_saved_runtime_preferences(&endpoints, || store.runtime_settings())
            .expect("saved preferences")
    };

    let fresh = read();
    assert!(fresh.in_force, "no file is the default preferences");
    assert_eq!(fresh.saved.revision, None);
    assert_eq!(fresh.engine, EngineSettings::default());

    // Something other than this process writes the file.
    let external = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    store
        .compare_and_swap_runtime_settings(None, &external)
        .expect("external write");
    let changed = read();
    assert!(!changed.in_force, "the engine was not given the new file");
    assert_eq!(changed.saved.settings, external);
    assert!(changed.saved.revision.is_some());
    assert_eq!(
        changed.engine,
        EngineSettings::default(),
        "the engine settings are the ones this process holds"
    );

    // A change made here commits the file and the settings together.
    let preferences = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..external.clone()
    };
    commit(&endpoints, &store, &changed.saved, &preferences);
    let committed = read();
    assert!(committed.in_force);
    assert_eq!(committed.saved.settings, preferences);
    assert_eq!(
        committed.engine,
        preferences
            .apply_to(EngineSettings::default())
            .expect("engine settings")
    );
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 1);
}

/// A read of the file that stalls would otherwise keep every transition of
/// the engine waiting for the settings it holds.
#[test]
fn nothing_of_the_engine_is_held_while_the_file_is_read() {
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let mut free = None;
    let read = read_saved_runtime_preferences(&endpoints, || {
        free = Some(endpoints.try_write().is_ok());
        Ok(RuntimeSettingsSnapshot {
            settings: RuntimePreferences::default(),
            revision: None,
        })
    })
    .expect("saved preferences");
    assert_eq!(free, Some(true));
    assert!(read.in_force);
}

/// A change replaces the file and the settings together. A read that was
/// under way then holds the file of before beside the settings of after, and
/// would report the change that was just made here as not in force.
#[test]
fn a_file_read_while_a_change_was_committed_is_read_again() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let changed = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let mut reads = 0;
    let read = read_saved_runtime_preferences(&endpoints, || {
        reads += 1;
        let before = store.runtime_settings()?;
        if reads == 1 {
            commit(&endpoints, &store, &before, &changed);
        }
        Ok(before)
    })
    .expect("saved preferences");
    assert_eq!(reads, 2);
    assert_eq!(read.saved.settings, changed);
    assert!(read.engine.dns_leak_protection);
    assert!(read.in_force, "the file of the change beside its settings");
}

/// Two changes, the second of which puts the settings back as they were. The
/// settings held before and after the read are then the same, and only the
/// count of the changes says that the file read in between belongs to
/// neither.
#[test]
fn a_change_made_and_undone_while_a_file_was_read_is_noticed_too() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let before = endpoints.read().expect("endpoints").clone();
    let changed = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let mut reads = 0;
    let read = read_saved_runtime_preferences(&endpoints, || {
        reads += 1;
        if reads > 1 {
            return store.runtime_settings();
        }
        let first = store.runtime_settings()?;
        commit(&endpoints, &store, &first, &changed);
        let between = store.runtime_settings()?;
        commit(&endpoints, &store, &between, &RuntimePreferences::default());
        Ok(between)
    })
    .expect("saved preferences");
    let after = endpoints.read().expect("endpoints").clone();
    assert_eq!(
        (&after.controller, &after.cursor),
        (&before.controller, &before.cursor),
        "the settings are as they were"
    );
    assert_eq!(after.preference_writes, 2);
    assert_eq!(reads, 2);
    assert_eq!(read.saved.settings, RuntimePreferences::default());
    assert!(read.saved.revision.is_some());
    assert!(read.in_force);
}

/// A write that fails is counted as well. Its document may have been the file
/// for a moment, taken back because the directory could not be synced, and
/// the settings held here are the same before and after it.
#[test]
fn a_write_that_failed_while_a_file_was_read_is_noticed_too() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let before = endpoints.read().expect("endpoints").clone();
    let refused = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let mut reads = 0;
    let read = read_saved_runtime_preferences(&endpoints, || {
        reads += 1;
        let file = store.runtime_settings()?;
        if reads == 1 {
            // Something else makes the file, so the write that was built on
            // there being none fails.
            store
                .compare_and_swap_runtime_settings(None, &RuntimePreferences::default())
                .expect("external write");
            let error = commit_runtime_settings(
                &endpoints,
                &before,
                endpoint_binding(
                    refused
                        .apply_to(EngineSettings::default())
                        .expect("engine settings"),
                ),
                &store,
                &file,
                &refused,
            )
            .expect_err("a write built on another revision");
            assert_eq!(
                error,
                SettingsStoreError::RuntimeSettingsChanged.to_string()
            );
        }
        Ok(file)
    })
    .expect("saved preferences");
    let after = endpoints.read().expect("endpoints").clone();
    assert_eq!(
        (&after.controller, &after.cursor),
        (&before.controller, &before.cursor),
        "the settings are as they were"
    );
    assert_eq!(after.preference_writes, 1);
    assert_eq!(reads, 2);
    assert!(read.saved.revision.is_some(), "the file as it is now");
    assert!(read.in_force);
}

#[test]
fn a_read_gives_up_when_a_change_is_committed_during_each_of_its_attempts() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let mut reads = 0;
    let error = read_saved_runtime_preferences(&endpoints, || {
        reads += 1;
        let before = store.runtime_settings()?;
        let next = RuntimePreferences {
            dns_leak_protection: reads % 2 == 1,
            ..RuntimePreferences::default()
        };
        commit(&endpoints, &store, &before, &next);
        Ok(before)
    })
    .err()
    .expect("a read that never met settings at rest");
    assert_eq!(reads, 3);
    assert!(error.contains("each time they were read"), "{error}");
}

#[test]
fn a_file_that_cannot_be_read_fails_the_read() {
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let error =
        read_saved_runtime_preferences(&endpoints, || Err(SettingsStoreError::NonCanonicalJson))
            .err()
            .expect("a failed read");
    assert_eq!(error, SettingsStoreError::NonCanonicalJson.to_string());
}
