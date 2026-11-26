//! TCP concurrency: the engine option every projection carries unless the
//! switch is off.

use serde_json::{Value, json};

use super::goldens::{cases, golden_directory, snapshot};
use super::tunnel_switches::{PROFILE_ID, profiles, release_evidence_projections, runtime};
use crate::{
    EngineSettings, ProjectionMode, ReleasePacketEvidenceCase, RuntimePreferences, TunnelStack,
    ValidatedSingBoxProfile,
};

const MODES: [ProjectionMode; 4] = [
    ProjectionMode::LocalProxy,
    ProjectionMode::SystemProxy,
    ProjectionMode::Tunnel,
    ProjectionMode::TunnelSystemProxy,
];

fn off() -> EngineSettings {
    EngineSettings {
        tcp_concurrency: false,
        ..EngineSettings::default()
    }
}

#[test]
fn it_is_on_by_default_and_adds_one_route_option_in_every_mode() {
    assert!(EngineSettings::default().tcp_concurrency);
    assert!(RuntimePreferences::default().tcp_concurrency);
    for (label, profile) in profiles() {
        for mode in MODES {
            let on = runtime(&profile, mode, &EngineSettings::default());
            assert_eq!(
                on["route"]["tcp_concurrent"],
                json!(true),
                "{label} {mode:?}"
            );
            let mut without = on;
            without["route"]
                .as_object_mut()
                .expect("route object")
                .remove("tcp_concurrent");
            assert_eq!(without, runtime(&profile, mode, &off()), "{label} {mode:?}");
        }
    }
}

#[test]
fn the_packet_endpoint_stack_carries_it_as_well() {
    for (label, profile) in profiles() {
        for (settings, expected) in [(EngineSettings::default(), Some(true)), (off(), None)] {
            let projected = profile
                .project_with_tunnel_stack(
                    PROFILE_ID,
                    ProjectionMode::Tunnel,
                    &settings,
                    TunnelStack::Gvisor,
                )
                .expect("projection");
            let value: Value = serde_json::from_str(projected.as_json()).expect("runtime JSON");
            assert_eq!(
                value["route"]
                    .get("tcp_concurrent")
                    .and_then(Value::as_bool),
                expected,
                "{label}"
            );
        }
    }
}

/// The goldens bind the projections with the switch off. With it on, each of
/// them gains the route option, in the configuration and in the latency
/// probe, and nothing else.
#[test]
fn it_adds_only_the_route_option_to_each_golden_projection() {
    for mut case in cases() {
        assert!(!case.settings.tcp_concurrency, "{}", case.name);
        let path = golden_directory().join(format!("{}.json", case.name));
        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("golden"))
                .expect("golden JSON");
        expected["config"]["route"]["tcp_concurrent"] = json!(true);
        expected["probe"]["route"]["tcp_concurrent"] = json!(true);
        case.settings.tcp_concurrency = true;
        let actual: Value = serde_json::from_str(&snapshot(&case)).expect("snapshot JSON");
        assert_eq!(actual, expected, "{}", case.name);
    }
}

/// A latency test of a stopped core measures what a connection gets: the
/// probe takes the dialing option of the projection it comes from, and the
/// engine admits nothing else in a probe's route but the resolver.
#[test]
fn the_latency_probe_dials_as_the_core_does() {
    for (label, profile) in profiles() {
        for mode in MODES {
            let probe = |settings: &EngineSettings| -> Value {
                let projected = profile
                    .project(PROFILE_ID, mode, settings)
                    .expect("projection");
                serde_json::from_str(&projected.proxy_probe_template().expect("probe").json)
                    .expect("probe JSON")
            };
            let racing = probe(&EngineSettings::default());
            let route = racing["route"].as_object().expect("probe route");
            assert_eq!(route["tcp_concurrent"], json!(true), "{label} {mode:?}");
            assert!(
                route
                    .keys()
                    .all(|key| key == "default_domain_resolver" || key == "tcp_concurrent"),
                "{label} {mode:?}: {route:?}"
            );
            // The switch decides that one key and nothing else of the probe.
            let mut without = racing;
            let route = without["route"].as_object_mut().expect("probe route");
            route.remove("tcp_concurrent");
            if route.is_empty() {
                without.as_object_mut().expect("probe").remove("route");
            }
            assert_eq!(without, probe(&off()), "{label} {mode:?}");
        }
    }
}

/// Release evidence is taken with the dialing the release ships: the switch
/// reaches an evidence projection as it reaches any other, and a packet case
/// without a projection of its own still runs the ordinary DIRECT
/// configuration.
#[test]
fn a_release_evidence_projection_follows_it_like_any_other() {
    for (label, profile, mode) in release_evidence_projections() {
        let on = runtime(&profile, mode, &EngineSettings::default());
        assert_eq!(on["route"]["tcp_concurrent"], json!(true), "{label}");
        let mut without = on;
        without["route"]
            .as_object_mut()
            .expect("route object")
            .remove("tcp_concurrent");
        assert_eq!(without, runtime(&profile, mode, &off()), "{label}");
    }
    for settings in [EngineSettings::default(), off()] {
        let ordinary = runtime(
            &ValidatedSingBoxProfile::direct(),
            ProjectionMode::Tunnel,
            &settings,
        );
        for case in ReleasePacketEvidenceCase::ALL {
            if case.dns_evidence_case().is_none() {
                let evidence = ValidatedSingBoxProfile::release_packet_evidence(case);
                assert_eq!(
                    runtime(&evidence, ProjectionMode::Tunnel, &settings),
                    ordinary,
                    "{case:?}"
                );
            }
        }
    }
}

#[test]
fn it_is_stored_only_while_it_is_off() {
    // On is absent, so settings saved before the switch existed keep their
    // bytes and read back as on.
    let stored = serde_json::to_value(RuntimePreferences::default()).expect("preferences");
    assert!(stored.get("tcp_concurrency").is_none());
    let restored: RuntimePreferences = serde_json::from_value(stored).expect("preferences");
    assert!(restored.tcp_concurrency);
    let engine = serde_json::to_value(EngineSettings::default()).expect("settings");
    assert!(engine.get("tcp_concurrency").is_none());
    let restored: EngineSettings = serde_json::from_value(engine).expect("settings");
    assert!(restored.tcp_concurrency);

    let preferences = RuntimePreferences {
        tcp_concurrency: false,
        ..RuntimePreferences::default()
    };
    let stored = serde_json::to_value(&preferences).expect("preferences");
    assert_eq!(stored["tcp_concurrency"], json!(false));
    let restored: RuntimePreferences = serde_json::from_value(stored).expect("preferences");
    assert_eq!(restored, preferences);
    let engine = serde_json::to_value(off()).expect("settings");
    assert_eq!(engine["tcp_concurrency"], json!(false));
    let restored: EngineSettings = serde_json::from_value(engine).expect("settings");
    assert_eq!(restored, off());
}

#[test]
fn the_stored_choice_reaches_the_engine_settings() {
    for choice in [true, false] {
        let preferences = RuntimePreferences {
            tcp_concurrency: choice,
            ..RuntimePreferences::default()
        };
        // The settings being replaced hold the other choice.
        let prior = EngineSettings {
            tcp_concurrency: !choice,
            ..EngineSettings::default()
        };
        let settings = preferences.apply_to(prior).expect("settings");
        assert_eq!(settings.tcp_concurrency, choice);
    }
}
