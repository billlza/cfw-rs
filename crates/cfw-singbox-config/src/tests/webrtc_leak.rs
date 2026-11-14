//! WebRTC leak protection: the rules that refuse STUN, which the Tunnel
//! projections carry while the switch is on, and nothing else.

use serde_json::{Value, json};

use super::tunnel_switches::{
    PROFILE_ID, carries, hijack, profiles, runtime, shadowsocks, switch_free_projections,
    without_route_rules,
};
use crate::{
    EngineSettings, LanProxySettings, ProjectionMode, RuntimePreferences, TunnelStack,
    ValidatedSingBoxProfile, lan_access_rule,
};

fn on() -> EngineSettings {
    EngineSettings {
        webrtc_leak_protection: true,
        ..EngineSettings::default()
    }
}

/// UDP only, and the STUN sniffer alone: no TCP connection waits for the
/// rule, and no other protocol is inspected.
fn recognition() -> Value {
    json!({"network":"udp","action":"sniff","sniffer":["stun"]})
}

fn refusal() -> Value {
    json!({"protocol":"stun","action":"reject"})
}

/// The engine never sniffs these destination ports, so a STUN server on one
/// of them would go unrecognised: UDP to them is refused outright.
fn unsniffed() -> Value {
    json!({"network":"udp","port":[25,110,143,465,587,993,995],"action":"reject"})
}

/// The index of the rule that routes a whole Clash mode.
fn mode_rule(rules: &[Value], mode: &str) -> usize {
    rules
        .iter()
        .position(|rule| rule["clash_mode"] == mode && rule["action"] == "route")
        .unwrap_or_else(|| panic!("{mode} mode rule in {rules:?}"))
}

/// A profile whose DNS policy makes the projection add a resolve step before
/// its route rules, the Clash mode rules among them.
fn dns_policy() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        &json!({"outbounds":[
            {"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},
            {"type":"direct","tag":"direct"}],
        "route":{"final":"proxy","rules":[{"type":"domain","value":"direct.example.com","outbound":"direct"}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53},{"type":"tcp","server":"8.8.8.8","server_port":53}],
            "bootstrap_servers":["223.5.5.5"],
            "nameserver_policy":[{"domain":"+.example.org","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}]}})
        .to_string(),
    )
    .expect("DNS policy profile")
}

#[test]
fn tunnel_projections_refuse_stun_between_the_direct_and_global_mode_rules() {
    let mut subjects = profiles();
    subjects.push(("DNS policy", dns_policy()));
    for (label, profile) in subjects {
        for mode in [ProjectionMode::Tunnel, ProjectionMode::TunnelSystemProxy] {
            let on = runtime(&profile, mode, &on());
            let off = runtime(&profile, mode, &EngineSettings::default());
            let rules_on = on["route"]["rules"].as_array().expect("rules");
            let rules_off = off["route"]["rules"].as_array().expect("rules");
            // Direct mode is routed before the rules, so it is left alone.
            let direct = mode_rule(rules_off, "Direct");
            assert_eq!(mode_rule(rules_on, "Direct"), direct, "{label} {mode:?}");
            assert_eq!(rules_on[direct + 1], recognition(), "{label} {mode:?}");
            assert_eq!(rules_on[direct + 2], refusal(), "{label} {mode:?}");
            assert_eq!(rules_on[direct + 3], unsniffed(), "{label} {mode:?}");
            // Global mode and the profile's rules come after them.
            assert_eq!(
                mode_rule(rules_on, "Global"),
                mode_rule(rules_off, "Global") + 3,
                "{label} {mode:?}"
            );
            assert!(
                mode_rule(rules_on, "Global") > direct + 3,
                "{label} {mode:?}"
            );
            // Nothing else changes: without the rules the routes are equal.
            let mut without = rules_on.clone();
            without.drain(direct + 1..=direct + 3);
            assert_eq!(&without, rules_off, "{label} {mode:?}");
            assert_eq!(
                rules_on
                    .iter()
                    .filter(|rule| rule["action"] == "sniff")
                    .count(),
                1,
                "{label} {mode:?}"
            );
            assert_eq!(
                rules_on
                    .iter()
                    .filter(|rule| rule.get("protocol").is_some())
                    .count(),
                1,
                "{label} {mode:?}"
            );
            assert_eq!(
                without_route_rules(on.clone()),
                without_route_rules(off.clone()),
                "{label} {mode:?}: only the route rules change"
            );
            let projected_on = profile.project(PROFILE_ID, mode, &self::on()).unwrap();
            let projected_off = profile
                .project(PROFILE_ID, mode, &EngineSettings::default())
                .unwrap();
            assert_eq!(
                projected_on.credential_slots(),
                projected_off.credential_slots(),
                "{label} {mode:?}"
            );
            assert_ne!(
                projected_on.configuration_digest(),
                projected_off.configuration_digest(),
                "{label} {mode:?}"
            );
            assert_ne!(
                projected_on.digest(),
                projected_off.digest(),
                "{label} {mode:?}"
            );
        }
    }
}

/// A DNS policy adds a resolve step in front of each route rule. The STUN
/// rules route nothing, so they stay bare, right behind the Direct mode rule.
#[test]
fn a_dns_policy_adds_no_resolve_step_to_the_stun_rules() {
    let value = runtime(&dns_policy(), ProjectionMode::Tunnel, &on());
    let rules = value["route"]["rules"].as_array().expect("rules");
    let direct = mode_rule(rules, "Direct");
    assert_eq!(rules[direct - 1]["action"], "resolve", "{rules:?}");
    assert_eq!(rules[direct + 1], recognition());
    assert_eq!(rules[direct + 2], refusal());
    assert_eq!(rules[direct + 3], unsniffed());
    assert_eq!(rules[direct + 4]["action"], "resolve", "{rules:?}");
    assert_eq!(mode_rule(rules, "Global"), direct + 5);
}

/// The Windows boundary admits the LAN listener only with its access rule
/// first, and both packet stacks carry both switches' rules in the same
/// places.
#[test]
fn the_rules_keep_their_place_beside_lan_sharing_and_dns_leak_protection() {
    let lan = LanProxySettings {
        listen: "0.0.0.0".parse().expect("LAN address"),
        port: 8891,
        allowed_source_cidrs: vec!["192.168.0.0/16".into()],
    };
    let settings = EngineSettings {
        lan_proxy: Some(lan.clone()),
        dns_leak_protection: true,
        ..on()
    };
    for stack in [TunnelStack::System, TunnelStack::Gvisor] {
        for mode in [ProjectionMode::Tunnel, ProjectionMode::TunnelSystemProxy] {
            let projected = shadowsocks()
                .project_with_tunnel_stack(PROFILE_ID, mode, &settings, stack)
                .expect("projection");
            let value: Value = serde_json::from_str(projected.as_json()).expect("runtime JSON");
            let rules = value["route"]["rules"].as_array().expect("rules");
            assert_eq!(rules[0], lan_access_rule(&lan), "{stack:?} {mode:?}");
            assert_eq!(rules[1], hijack(), "{stack:?} {mode:?}");
            assert_eq!(
                rules[2],
                json!({"port":853,"action":"reject"}),
                "{stack:?} {mode:?}"
            );
            assert_eq!(mode_rule(rules, "Direct"), 3, "{stack:?} {mode:?}");
            assert_eq!(rules[4], recognition(), "{stack:?} {mode:?}");
            assert_eq!(rules[5], refusal(), "{stack:?} {mode:?}");
            assert_eq!(rules[6], unsniffed(), "{stack:?} {mode:?}");
            assert_eq!(mode_rule(rules, "Global"), 7, "{stack:?} {mode:?}");
        }
    }
}

#[test]
fn proxy_modes_and_release_evidence_projections_ignore_the_switch() {
    for (label, profile, mode) in switch_free_projections() {
        let switched = profile.project(PROFILE_ID, mode, &on()).unwrap();
        let default = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .unwrap();
        assert_eq!(
            switched
                .as_json()
                .replace(switched.clash_api().expose_secret(), ""),
            default
                .as_json()
                .replace(default.clash_api().expose_secret(), ""),
            "{label} {mode:?}"
        );
        assert_eq!(
            switched.credential_slots(),
            default.credential_slots(),
            "{label} {mode:?}"
        );
        let value: Value = serde_json::from_str(switched.as_json()).expect("runtime JSON");
        for leaf in [json!("stun"), json!("sniff"), json!(995)] {
            assert!(!carries(&value, &leaf), "{label} {mode:?} {leaf}");
        }
    }
}

#[test]
fn the_latency_probe_never_carries_the_rules() {
    for (label, profile) in profiles() {
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let probe = |settings: &EngineSettings| {
                profile
                    .project_proxy_probe(PROFILE_ID, mode, settings)
                    .expect("probe")
            };
            let switched = probe(&on());
            assert_eq!(
                switched,
                probe(&EngineSettings::default()),
                "{label} {mode:?}"
            );
            let value: Value = serde_json::from_str(switched.as_json()).expect("probe JSON");
            for leaf in [json!("stun"), json!("sniff"), json!("reject"), json!(995)] {
                assert!(!carries(&value, &leaf), "{label} {mode:?} {leaf}: {value}");
            }
        }
    }
}

#[test]
fn the_switch_is_absent_when_off_and_round_trips_when_on() {
    let default = serde_json::to_value(EngineSettings::default()).unwrap();
    assert!(default.get("webrtc_leak_protection").is_none());
    let value = serde_json::to_value(on()).unwrap();
    assert_eq!(value["webrtc_leak_protection"], json!(true));
    assert_eq!(
        serde_json::from_value::<EngineSettings>(value).unwrap(),
        on()
    );

    // Stored preferences written before the switch existed keep their bytes.
    let legacy = serde_json::to_string(&RuntimePreferences::default()).unwrap();
    assert!(!legacy.contains("webrtc_leak"), "{legacy}");
    let parsed: RuntimePreferences = serde_json::from_str(&legacy).unwrap();
    assert!(!parsed.webrtc_leak_protection);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
    let on = RuntimePreferences {
        webrtc_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let text = serde_json::to_string(&on).unwrap();
    assert_eq!(
        text,
        format!(
            "{},\"webrtc_leak_protection\":true}}",
            legacy.strip_suffix('}').unwrap()
        )
    );
    assert_eq!(
        serde_json::from_str::<RuntimePreferences>(&text).unwrap(),
        on
    );
    for malformed in ["\"true\"", "1", "null"] {
        let document = text.replace(":true}", &format!(":{malformed}}}"));
        assert!(
            serde_json::from_str::<RuntimePreferences>(&document).is_err(),
            "{document}"
        );
    }
    // Every switch on keeps the keys in declaration order.
    let all = RuntimePreferences {
        mainland_china_direct: true,
        dns_leak_protection: true,
        webrtc_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let text = serde_json::to_string(&all).unwrap();
    assert!(
        text.ends_with(
            ",\"mainland_china_direct\":true,\"dns_leak_protection\":true,\"webrtc_leak_protection\":true}"
        ),
        "{text}"
    );
    assert_eq!(
        serde_json::from_str::<RuntimePreferences>(&text).unwrap(),
        all
    );
}

#[test]
fn apply_to_always_assigns_webrtc_leak_protection() {
    let on = RuntimePreferences {
        webrtc_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let applied = on.apply_to(EngineSettings::default()).unwrap();
    assert!(applied.webrtc_leak_protection);
    assert!(
        !applied.dns_leak_protection && !applied.mainland_china_direct,
        "the switches are independent"
    );
    let applied = RuntimePreferences::default().apply_to(self::on()).unwrap();
    assert!(!applied.webrtc_leak_protection);
}
