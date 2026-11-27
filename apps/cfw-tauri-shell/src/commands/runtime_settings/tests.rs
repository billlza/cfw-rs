//! The settings view, the argument of a write and the change of one setting,
//! each made of what was read.
use super::*;
use cfw_core::RuntimeSettingsSnapshot;

fn read(saved: RuntimePreferences, in_force: bool) -> SavedRuntimePreferences {
    SavedRuntimePreferences {
        saved: RuntimeSettingsSnapshot {
            settings: saved,
            revision: Some("revision".into()),
        },
        engine: EngineSettings::default(),
        in_force,
    }
}

fn view(saved: RuntimePreferences, in_force: bool) -> Result<RuntimeSettingsView, String> {
    RuntimeSettingsView::of(
        read(saved, in_force),
        &ValidatedSingBoxProfile::direct(),
        cfw_engine_api::TunnelMtuLimits::AUTHORITY_V1,
        None,
    )
}

/// The view says why no change can be made, beside whether the saved
/// settings are in force: the pages say the first in place of what they
/// advise for the second.
#[test]
fn the_view_says_why_no_change_can_be_made() {
    let serialized = |change_refused: Option<&str>| {
        let view = RuntimeSettingsView::of(
            read(RuntimePreferences::default(), false),
            &ValidatedSingBoxProfile::direct(),
            cfw_engine_api::TunnelMtuLimits::AUTHORITY_V1,
            change_refused.map(str::to_owned),
        );
        serde_json::to_value(view.expect("view")).expect("serialized view")
    };
    let free = serialized(None);
    assert_eq!(free["change_refused"], serde_json::Value::Null);
    assert_eq!(free["in_force"], serde_json::json!(false));
    let held = serialized(Some("a cleanup is pending"));
    assert_eq!(
        held["change_refused"],
        serde_json::json!("a cleanup is pending")
    );
    assert_eq!(held["in_force"], serde_json::json!(false));
}

/// A store whose startup a cutover journal governs takes no change, and
/// one without a journal does. Only the Mac has such a journal.
#[cfg(target_os = "macos")]
#[test]
fn a_store_says_why_no_change_can_be_made_of_it() {
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(cfw_core::AppPaths::from_app_home(root.path()));
    assert_eq!(change_refused(&store), None);
    crate::legacy::write_journal_governing_startup(
        &store.paths().app_home,
        EngineSettings::default(),
    );
    let reason = change_refused(&store).expect("a journal governs startup");
    assert!(reason.contains("legacy cleanup"), "{reason}");
}

/// The file says one thing and the engine runs another: the view carries
/// both, and says that they differ.
#[test]
fn the_view_says_whether_the_saved_settings_are_in_force() {
    let saved = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    for in_force in [true, false] {
        let view = serde_json::to_value(view(saved.clone(), in_force).expect("view"))
            .expect("serialized view");
        assert_eq!(view["in_force"], serde_json::json!(in_force));
        assert_eq!(
            view["settings"]["dns_leak_protection"],
            serde_json::json!(true)
        );
        assert_eq!(
            view["effective"]["dns_leak_protection"],
            serde_json::json!(false),
            "the engine settings, not the file"
        );
        assert_eq!(view["revision"], serde_json::json!("revision"));
    }
}

/// The form is opened on the saved settings, also when they are not in
/// force, and shows IPv6 DNS as they give it. The engine may run with a
/// choice of its own that they do not make.
#[test]
fn the_view_says_what_ipv6_dns_the_saved_settings_give() {
    let profile = ValidatedSingBoxProfile::direct();
    let view = |saved: Option<bool>, engine: Option<bool>| {
        let read = SavedRuntimePreferences {
            engine: EngineSettings {
                ipv6_dns_enabled: engine,
                ..EngineSettings::default()
            },
            ..read(
                RuntimePreferences {
                    ipv6_dns_enabled: saved,
                    ..RuntimePreferences::default()
                },
                saved == engine,
            )
        };
        let view = RuntimeSettingsView::of(
            read,
            &profile,
            cfw_engine_api::TunnelMtuLimits::AUTHORITY_V1,
            None,
        )
        .expect("view");
        let view = serde_json::to_value(view).expect("serialized view");
        (
            view["saved_ipv6_dns_enabled"].clone(),
            view["effective"]["ipv6_dns_enabled"].clone(),
        )
    };
    let (on, off) = (serde_json::json!(true), serde_json::json!(false));
    // The saved settings follow the profile, which has IPv6 DNS on, while
    // the engine runs with a choice that turned it off.
    assert_eq!(view(None, Some(false)), (on.clone(), off.clone()));
    // The saved settings turn it off while the engine follows the profile.
    assert_eq!(view(Some(false), None), (off.clone(), on.clone()));
    // In force, both are the same value.
    assert_eq!(view(None, None), (on.clone(), on.clone()));
    assert_eq!(view(Some(false), Some(false)), (off.clone(), off));
    assert_eq!(view(Some(true), Some(true)), (on.clone(), on));
}

#[test]
fn a_change_of_one_setting_is_refused_on_saved_settings_that_are_not_in_force() {
    let saved = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let louder = |settings: &mut RuntimePreferences| {
        settings.log_level = EngineLogLevel::Debug;
        Ok(())
    };
    let change = one_setting(&read(saved.clone(), true), louder).expect("settings in force");
    assert_eq!(
        change.preferences,
        RuntimePreferences {
            log_level: EngineLogLevel::Debug,
            ..saved.clone()
        }
    );
    assert_eq!(change.expected_revision.as_deref(), Some("revision"));
    assert_eq!(change.basis, PreferencesBasis::InForce);
    // Not in force: that is said, and the change is not even made, so
    // what it would be refused for itself is not said in its place.
    let unmade = |_: &mut RuntimePreferences| Err("the change was made".to_owned());
    assert_eq!(
        one_setting(&read(saved.clone(), false), unmade)
            .err()
            .as_deref(),
        Some(SAVED_PREFERENCES_NOT_IN_FORCE)
    );
    // A change that is refused for itself is refused with its own words.
    assert_eq!(
        one_setting(&read(saved, true), unmade).err().as_deref(),
        Some("the change was made")
    );
    // Saved settings that are not valid are no ground for a change.
    let invalid = RuntimePreferences {
        allow_lan: true,
        ..RuntimePreferences::default()
    };
    let error = one_setting(&read(invalid, true), louder).expect_err("an invalid file");
    assert!(error.contains("LAN listener"), "{error}");
}

/// The write gives back two fields of the snapshot under the names the
/// snapshot has for them, and nothing it does not know.
#[test]
fn a_write_names_what_it_was_built_on_as_the_snapshot_names_it() {
    let written: WrittenOn = serde_json::from_value(
        serde_json::json!({"in_force": false, "saved_ipv6_dns_enabled": true}),
    )
    .expect("a basis");
    assert!(!written.in_force && written.saved_ipv6_dns_enabled);
    // Each of the two says what it says in the snapshot.
    let louder = RuntimePreferences {
        log_level: EngineLogLevel::Debug,
        ..RuntimePreferences::default()
    };
    for (in_force, shown) in [(false, true), (false, false), (true, false), (true, true)] {
        let written: WrittenOn = serde_json::from_value(
            serde_json::json!({"in_force": in_force, "saved_ipv6_dns_enabled": shown}),
        )
        .expect("a basis");
        let change = written.change(louder.clone(), Some("built on".into()));
        assert_eq!(change.preferences, louder);
        assert_eq!(change.expected_revision.as_deref(), Some("built on"));
        let basis = if in_force {
            PreferencesBasis::InForce
        } else {
            PreferencesBasis::Saved {
                ipv6_dns_enabled: shown,
            }
        };
        assert_eq!(change.basis, basis);
    }
    assert_eq!(written.change(louder, None).expected_revision, None);
    let view = serde_json::to_value(view(RuntimePreferences::default(), true).expect("view"))
        .expect("serialized view");
    for name in ["in_force", "saved_ipv6_dns_enabled"] {
        assert!(view[name].is_boolean(), "{name} is a field of the snapshot");
    }
    for incomplete in [
        serde_json::json!({"in_force": true}),
        serde_json::json!({"saved_ipv6_dns_enabled": true}),
        serde_json::json!({"in_force": true, "saved_ipv6_dns_enabled": true, "more": 1}),
        serde_json::json!({"in_force": 1, "saved_ipv6_dns_enabled": true}),
    ] {
        assert!(
            serde_json::from_value::<WrittenOn>(incomplete.clone()).is_err(),
            "{incomplete}"
        );
    }
}

#[test]
fn saved_settings_that_are_not_valid_fail_the_view() {
    let invalid = RuntimePreferences {
        allow_lan: true,
        ..RuntimePreferences::default()
    };
    let error = view(invalid, true).err().expect("an invalid file");
    assert!(error.contains("LAN listener"), "{error}");
}

#[test]
fn the_effective_view_always_reports_mainland_china_direct() {
    let profile = ValidatedSingBoxProfile::direct();
    let view = |settings: EngineSettings| {
        serde_json::to_value(RuntimeSettingsEffective::for_profile(settings, &profile))
            .expect("effective view")
    };
    assert_eq!(
        view(EngineSettings::default())["mainland_china_direct"],
        serde_json::json!(false)
    );
    assert_eq!(
        view(EngineSettings {
            mainland_china_direct: true,
            ..EngineSettings::default()
        })["mainland_china_direct"],
        serde_json::json!(true)
    );
    // The stored preferences omit the key while it is off, so the
    // renderer must accept its absence there.
    let stored = serde_json::to_value(RuntimePreferences::default()).expect("preferences");
    assert!(stored.get("mainland_china_direct").is_none());
}

#[test]
fn the_effective_view_always_reports_dns_leak_protection() {
    let profile = ValidatedSingBoxProfile::direct();
    let view = |settings: EngineSettings| {
        serde_json::to_value(RuntimeSettingsEffective::for_profile(settings, &profile))
            .expect("effective view")
    };
    assert_eq!(
        view(EngineSettings::default())["dns_leak_protection"],
        serde_json::json!(false)
    );
    assert_eq!(
        view(EngineSettings {
            dns_leak_protection: true,
            ..EngineSettings::default()
        })["dns_leak_protection"],
        serde_json::json!(true)
    );
    // Off is absent from the stored preferences, as for the mainland switch.
    let stored = serde_json::to_value(RuntimePreferences::default()).expect("preferences");
    assert!(stored.get("dns_leak_protection").is_none());
}

#[test]
fn the_effective_view_always_reports_webrtc_leak_protection() {
    let profile = ValidatedSingBoxProfile::direct();
    let view = |settings: EngineSettings| {
        serde_json::to_value(RuntimeSettingsEffective::for_profile(settings, &profile))
            .expect("effective view")
    };
    assert_eq!(
        view(EngineSettings::default())["webrtc_leak_protection"],
        serde_json::json!(false)
    );
    assert_eq!(
        view(EngineSettings {
            webrtc_leak_protection: true,
            ..EngineSettings::default()
        })["webrtc_leak_protection"],
        serde_json::json!(true)
    );
    // Off is absent from the stored preferences, as for the other switches.
    let stored = serde_json::to_value(RuntimePreferences::default()).expect("preferences");
    assert!(stored.get("webrtc_leak_protection").is_none());
}

#[test]
fn the_effective_view_always_reports_tcp_concurrency() {
    let profile = ValidatedSingBoxProfile::direct();
    let view = |settings: EngineSettings| {
        serde_json::to_value(RuntimeSettingsEffective::for_profile(settings, &profile))
            .expect("effective view")
    };
    assert_eq!(
        view(EngineSettings::default())["tcp_concurrency"],
        serde_json::json!(true)
    );
    assert_eq!(
        view(EngineSettings {
            tcp_concurrency: false,
            ..EngineSettings::default()
        })["tcp_concurrency"],
        serde_json::json!(false)
    );
    // On is absent from the stored preferences, so the renderer must read
    // an absent key there as on.
    let stored = serde_json::to_value(RuntimePreferences::default()).expect("preferences");
    assert!(stored.get("tcp_concurrency").is_none());
}

/// The commands that are given one setting as text read it in the change, so
/// what refuses every change of one setting is said first: saved settings
/// that are not in force here, and a pending cleanup before the request is
/// made at all. The fault of the text comes after that.
#[test]
fn a_setting_given_as_text_is_read_after_what_refuses_every_change_of_one() {
    let held = read(RuntimePreferences::default(), false);
    assert_eq!(
        one_setting(&held, log_level_change("loudest".into()))
            .err()
            .as_deref(),
        Some(SAVED_PREFERENCES_NOT_IN_FORCE)
    );
    assert_eq!(
        one_setting(&held, bind_address_change("anywhere".into()))
            .err()
            .as_deref(),
        Some(SAVED_PREFERENCES_NOT_IN_FORCE)
    );
    let free = read(RuntimePreferences::default(), true);
    assert_eq!(
        one_setting(&free, log_level_change("loudest".into()))
            .err()
            .as_deref(),
        Some("log level must be trace, debug, info, warn, error, fatal or silent")
    );
    assert_eq!(
        one_setting(&free, bind_address_change("anywhere".into()))
            .err()
            .as_deref(),
        Some("LAN listener address must be a numeric IPv4 address")
    );
    let change = one_setting(&free, log_level_change(" Warning ".into())).expect("a level");
    assert_eq!(change.preferences.log_level, EngineLogLevel::Warn);
    let sharing = RuntimePreferences {
        allow_lan: true,
        lan_proxy: Some(LanProxySettings {
            listen: std::net::Ipv4Addr::UNSPECIFIED,
            port: 17890,
            allowed_source_cidrs: vec!["192.168.1.0/24".into()],
        }),
        ..RuntimePreferences::default()
    };
    let change = one_setting(
        &read(sharing, true),
        bind_address_change(" 192.168.1.2 ".into()),
    )
    .expect("an address");
    assert_eq!(
        change.preferences.lan_proxy.map(|lan| lan.listen),
        Some(std::net::Ipv4Addr::new(192, 168, 1, 2))
    );
}
