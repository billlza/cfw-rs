//! What a change of the runtime preferences may be built on, what admits it
//! before it takes a place among the mode changes, and what it commits of
//! what it was given.
use super::saved_preferences::{
    MAC_TUNNEL_MTU, binding_running, lan, single_changes, temporary_store,
};
use super::*;
use crate::engine::runtime_settings::{
    PROFILE_IPV6_DNS_CHANGED, PreferencesBasis, RequestedChange, SAVED_PREFERENCES_NOT_IN_FORCE,
    admit_change, admit_requested_change, ipv6_dns_enabled_of,
};
use cfw_core::{RuntimeSettingsSnapshot, SettingsStoreError};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

/// The form of saved preferences that showed IPv6 DNS on, as the profile
/// these tests use gives it unless they say otherwise.
const SAVED: PreferencesBasis = PreferencesBasis::Saved {
    ipv6_dns_enabled: true,
};

/// The saved preferences where there is no settings file.
fn no_file() -> RuntimeSettingsSnapshot<RuntimePreferences> {
    RuntimeSettingsSnapshot {
        settings: RuntimePreferences::default(),
        revision: None,
    }
}

/// The profile where none is selected. It leaves IPv6 DNS on.
fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

/// A profile whose DNS policy turns IPv6 DNS off.
pub(super) fn profile_without_ipv6_dns() -> ValidatedSingBoxProfile {
    let document = serde_json::json!({
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "dns": {
            "servers": [{"type": "udp", "server": "1.1.1.1", "server_port": 53}],
            "ipv6": false,
        },
    });
    ValidatedSingBoxProfile::parse(&document.to_string()).expect("a profile")
}

/// A form is opened while there is no settings file, so its change carries
/// no revision. Another change then turns DNS leak protection on, and the
/// file it wrote is removed. The revision is the same again, and the change
/// of the form would turn the protection off though it changed the log
/// level.
#[test]
fn a_change_built_on_preferences_in_force_needs_them_in_force_still() {
    let protecting = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let binding = binding_running(&protecting);
    let found = binding.beside(no_file());
    let louder = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..RuntimePreferences::default()
    };
    let refused = admit_change(
        &found,
        &direct(),
        None,
        PreferencesBasis::InForce,
        louder.clone(),
    );
    assert_eq!(refused, Err(SAVED_PREFERENCES_NOT_IN_FORCE.to_owned()));
    assert!(SAVED_PREFERENCES_NOT_IN_FORCE.contains("Reload From Disk"));
    // The form of the saved preferences applies them in the knowledge that
    // the engine does not run with them. It was given the switches as the
    // engine ran them when it was opened, before the protection was turned
    // on, and it leaves the protection on.
    let applied = admit_change(&found, &direct(), None, SAVED, louder);
    let expected = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..protecting.clone()
    };
    assert_eq!(applied, Ok(expected));
    // And one setting is changed among those the engine runs with.
    let kept = binding.beside(RuntimeSettingsSnapshot {
        settings: protecting,
        revision: Some("kept".into()),
    });
    let unprotected = RuntimePreferences::default();
    let changed = admit_change(
        &kept,
        &direct(),
        Some("kept"),
        PreferencesBasis::InForce,
        unprotected.clone(),
    );
    assert_eq!(changed, Ok(unprotected));
}

/// The form of the saved preferences has no fields for the switches, so its
/// change leaves each of them as the engine runs it, on or off, and takes
/// nothing else from the engine.
#[test]
fn a_change_built_on_saved_preferences_leaves_each_switch_as_the_engine_runs_it() {
    let given = RuntimePreferences {
        tunnel_mtu: 1400,
        ..RuntimePreferences::default()
    };
    for (name, running) in single_changes() {
        let found = binding_running(&running).beside(no_file());
        // IPv6 DNS as the form showed it, which this is not about.
        let basis = PreferencesBasis::Saved {
            ipv6_dns_enabled: ipv6_dns_enabled_of(&given, &found.engine, &direct()),
        };
        let committed = admit_change(&found, &direct(), None, basis, given.clone());
        let expected = RuntimePreferences {
            mainland_china_direct: running.mainland_china_direct,
            dns_leak_protection: running.dns_leak_protection,
            webrtc_leak_protection: running.webrtc_leak_protection,
            tcp_concurrency: running.tcp_concurrency,
            ..given.clone()
        };
        assert_eq!(committed, Ok(expected), "{name}");
    }
    // Switches the change was given away from where the engine has them, as
    // a file that was put back has them, are not taken either.
    let restored = RuntimePreferences {
        mainland_china_direct: true,
        dns_leak_protection: true,
        webrtc_leak_protection: true,
        tcp_concurrency: false,
        ..given.clone()
    };
    let found = binding_running(&RuntimePreferences::default()).beside(no_file());
    let committed = admit_change(&found, &direct(), None, SAVED, restored.clone());
    assert_eq!(committed, Ok(given));
    // A change built on preferences in force is committed as it was given.
    let committed = admit_change(
        &found,
        &direct(),
        None,
        PreferencesBasis::InForce,
        restored.clone(),
    );
    assert_eq!(committed, Ok(restored));
}

/// Every preference is a field of the network settings form or a switch
/// that a change built on the saved preferences leaves to the engine. One
/// that is added has to become one of the two: it is named here, and it is
/// written unless the change leaves it where the engine has it.
#[test]
fn every_preference_is_a_field_of_the_form_or_a_switch_left_to_the_engine() {
    const FORM: [&str; 6] = [
        "allow_lan",
        "ipv6_dns_enabled",
        "lan_proxy",
        "log_level",
        "preferred_mixed_port",
        "tunnel_mtu",
    ];
    // Each of them away from where it rests, so that each is written.
    let given = RuntimePreferences {
        preferred_mixed_port: Some(8890),
        log_level: EngineLogLevel::Debug,
        tunnel_mtu: 1400,
        ipv6_dns_enabled: Some(false),
        allow_lan: true,
        lan_proxy: Some(lan(7898)),
        mainland_china_direct: true,
        dns_leak_protection: true,
        webrtc_leak_protection: true,
        tcp_concurrency: false,
    };
    let written = |preferences: &RuntimePreferences| {
        let document = serde_json::to_value(preferences).expect("a document");
        let mut names: Vec<String> = document
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    };
    assert_eq!(written(&given).len(), FORM.len() + 4);
    // The engine runs every switch where it rests, and none is written there.
    let found = binding_running(&RuntimePreferences::default()).beside(no_file());
    let committed =
        admit_change(&found, &direct(), None, SAVED, given).expect("a change of the form");
    assert_eq!(written(&committed), FORM);
}

#[test]
fn a_change_built_on_another_revision_is_refused_whatever_it_was_built_on() {
    let found = endpoint_binding(EngineSettings::default()).beside(RuntimeSettingsSnapshot {
        settings: RuntimePreferences::default(),
        revision: Some("now".into()),
    });
    let changed = Err(SettingsStoreError::RuntimeSettingsChanged.to_string());
    let given = RuntimePreferences::default;
    // The form that showed IPv6 DNS off is refused for that once the
    // revision is the one it was built on, and for the revision before.
    let mistaken = PreferencesBasis::Saved {
        ipv6_dns_enabled: false,
    };
    for basis in [PreferencesBasis::InForce, SAVED, mistaken] {
        for revision in [Some("then"), None] {
            assert_eq!(
                admit_change(&found, &direct(), revision, basis, given()),
                changed
            );
        }
        let admitted = if basis == mistaken {
            Err(PROFILE_IPV6_DNS_CHANGED.to_owned())
        } else {
            Ok(given())
        };
        assert_eq!(
            admit_change(&found, &direct(), Some("now"), basis, given()),
            admitted
        );
    }
}

#[test]
fn what_a_change_was_built_on_follows_the_snapshot_it_read() {
    for shown in [true, false] {
        assert_eq!(
            PreferencesBasis::of_snapshot(true, shown),
            PreferencesBasis::InForce
        );
        assert_eq!(
            PreferencesBasis::of_snapshot(false, shown),
            PreferencesBasis::Saved {
                ipv6_dns_enabled: shown
            }
        );
    }
}

/// The engine runs with IPv6 DNS turned off by a choice of its own. A file
/// is put back that leaves it to the profile, and the profile turns it off
/// as well, so the form of the saved preferences shows it off. While that
/// form is open the profile is replaced by one that leaves it on, which no
/// revision of the settings says. The Apply of the untouched form would then
/// turn IPv6 DNS on though its box is not ticked.
#[test]
fn a_change_that_leaves_ipv6_dns_to_the_profile_needs_it_as_the_form_showed_it() {
    let choosing = RuntimePreferences {
        ipv6_dns_enabled: Some(false),
        ..RuntimePreferences::default()
    };
    let found = binding_running(&choosing).beside(no_file());
    assert!(!found.in_force);
    let (off, on) = (profile_without_ipv6_dns(), direct());
    let untouched = RuntimePreferences::default;
    assert!(!ipv6_dns_enabled_of(&untouched(), &found.engine, &off));
    assert!(ipv6_dns_enabled_of(&untouched(), &found.engine, &on));
    let showed = |ipv6_dns_enabled| PreferencesBasis::Saved { ipv6_dns_enabled };
    let refused = Err(PROFILE_IPV6_DNS_CHANGED.to_owned());
    for (shown, profile, admitted) in [
        (false, &off, Ok(untouched())),
        (false, &on, refused.clone()),
        (true, &on, Ok(untouched())),
        (true, &off, refused),
    ] {
        assert_eq!(
            admit_change(&found, profile, None, showed(shown), untouched()),
            admitted,
            "the form showed {shown}"
        );
    }
    assert!(PROFILE_IPV6_DNS_CHANGED.contains("Reload From Disk"));
    // A box that was changed is the choice of the form, whatever the profile
    // gives, and whatever the form showed before.
    for chosen in [false, true] {
        let touched = RuntimePreferences {
            ipv6_dns_enabled: Some(chosen),
            ..RuntimePreferences::default()
        };
        for profile in [&off, &on] {
            for shown in [false, true] {
                assert_eq!(
                    admit_change(&found, profile, None, showed(shown), touched.clone()),
                    Ok(touched.clone())
                );
            }
        }
    }
    // The profile's choice counts as the engine takes it: not at all while
    // the engine has IPv6 off, where the form showed it off with any profile.
    let without_ipv6 = endpoint_binding(EngineSettings {
        enable_ipv6: false,
        dns_leak_protection: true,
        ..EngineSettings::default()
    })
    .beside(no_file());
    assert!(!without_ipv6.in_force);
    let kept = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    for profile in [&off, &on] {
        assert_eq!(
            admit_change(&without_ipv6, profile, None, showed(false), untouched()),
            Ok(kept.clone())
        );
    }
    // A change built on preferences in force leaves IPv6 DNS to the profile
    // as it was left before: what the profile chooses is no change of its.
    let following = endpoint_binding(EngineSettings::default()).beside(no_file());
    assert!(following.in_force);
    for profile in [&off, &on] {
        assert_eq!(
            admit_change(
                &following,
                profile,
                None,
                PreferencesBasis::InForce,
                untouched()
            ),
            Ok(untouched())
        );
    }
}

/// A change takes a place among the mode changes only when nothing that is
/// known of it refuses it: there it supersedes what is under way, the retry
/// of a start among it. It is admitted on what is read then, and nothing is
/// written or counted for that.
#[test]
fn a_requested_change_is_admitted_on_what_is_read_before_it_is_queued() {
    let (_root, store) = temporary_store();
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let louder = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..RuntimePreferences::default()
    };
    let admit = |expected_revision: Option<String>, basis: PreferencesBasis| {
        let request = RequestedChange {
            preferences: louder.clone(),
            expected_revision,
            basis,
        };
        admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || Ok(None),
            |_| Ok(request),
        )
        .map(|admitted| {
            let requested = admitted.requested();
            (
                requested.preferences.clone(),
                requested.expected_revision.clone(),
                requested.basis,
            )
        })
    };
    let in_force = PreferencesBasis::InForce;
    // No file is the default preferences, which the engine runs.
    assert_eq!(admit(None, in_force), Ok((louder.clone(), None, in_force)));
    assert_eq!(
        admit(Some("then".into()), in_force),
        Err(SettingsStoreError::RuntimeSettingsChanged.to_string())
    );

    // Something other than this process writes the file.
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
    assert!(revision.is_some());
    assert_eq!(
        admit(None, in_force),
        Err(SettingsStoreError::RuntimeSettingsChanged.to_string())
    );
    assert_eq!(
        admit(revision.clone(), in_force),
        Err(SAVED_PREFERENCES_NOT_IN_FORCE.to_owned())
    );
    // As it was requested: the switches are settled where it has its turn.
    assert_eq!(
        admit(revision.clone(), SAVED),
        Ok((louder.clone(), revision.clone(), SAVED))
    );
    let mistaken = PreferencesBasis::Saved {
        ipv6_dns_enabled: false,
    };
    assert_eq!(
        admit(revision.clone(), mistaken),
        Err(PROFILE_IPV6_DNS_CHANGED.to_owned())
    );

    // The request is made of what was read, and its refusal is the answer.
    let refusing = admit_requested_change(
        &endpoints,
        &store,
        MAC_TUNNEL_MTU,
        || Ok(None),
        |found| {
            assert!(!found.in_force);
            assert_eq!(found.saved.settings, external);
            assert_eq!(found.saved.revision, revision);
            assert_eq!(found.engine, EngineSettings::default());
            Err("the request refuses".into())
        },
    );
    assert_eq!(refusing.err().as_deref(), Some("the request refuses"));
    // So is a selected profile that cannot be read.
    let request = RequestedChange {
        preferences: louder,
        expected_revision: revision.clone(),
        basis: SAVED,
    };
    let unread = admit_requested_change(
        &endpoints,
        &store,
        MAC_TUNNEL_MTU,
        || {
            Err(ProfileError::Io(std::io::Error::other(
                "the profile is not read",
            )))
        },
        |_| Ok(request),
    );
    assert_eq!(
        unread.err().as_deref(),
        Some("profile repository I/O failed: the profile is not read")
    );

    let saved = store
        .runtime_settings::<RuntimePreferences>()
        .expect("saved preferences");
    assert_eq!(saved.revision, revision);
    assert_eq!(saved.settings, external);
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 0);
}

/// While a cutover journal governs startup no change can be made. That is
/// said in place of anything the settings would be refused for: the advice
/// to apply the saved settings first could not be followed. Only the Mac
/// has such a journal.
#[cfg(target_os = "macos")]
#[test]
fn no_change_is_admitted_while_a_cutover_journal_governs_startup() {
    use cfw_core::{AppPaths, SettingsStore};

    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    crate::legacy::write_journal_governing_startup(
        &store.paths().app_home,
        EngineSettings::default(),
    );
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let asked = std::cell::Cell::new(0);
    let refused = admit_requested_change(
        &endpoints,
        &store,
        MAC_TUNNEL_MTU,
        || {
            asked.set(asked.get() + 1);
            Ok(None)
        },
        |_| {
            asked.set(asked.get() + 1);
            Err(SAVED_PREFERENCES_NOT_IN_FORCE.into())
        },
    );
    let error = refused.expect_err("a change while the journal governs startup");
    assert!(error.contains("legacy cleanup"), "{error}");
    assert_eq!(asked.get(), 0, "nothing of the settings was asked for");
}
