//! DNS leak protection: the port 853 refusal the Tunnel projections carry
//! while the switch is on, and nothing else.

use serde_json::{Value, json};

use crate::validation::DnsProjection;
use crate::{
    EngineSettings, LanProxySettings, ProjectionMode, ReleaseDnsEvidenceCase,
    ReleasePacketEvidenceCase, RuntimePreferences, TunnelStack, ValidatedSingBoxProfile,
    lan_access_rule,
};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECRET_PLACEHOLDER: &str = "<CLASH-API-SECRET>";

fn on() -> EngineSettings {
    EngineSettings {
        dns_leak_protection: true,
        ..EngineSettings::default()
    }
}

fn hijack() -> Value {
    json!({"port":53,"action":"hijack-dns"})
}

fn refusal() -> Value {
    json!({"port":853,"action":"reject"})
}

fn parse(value: &Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&value.to_string()).expect("DNS leak test profile")
}

fn shadowsocks() -> ValidatedSingBoxProfile {
    parse(
        &json!({"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"ss.example.com","server_port":443,
        "method":"aes-256-gcm","credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"shadowsocks_password"}}],
        "route":{"final":"proxy"}}),
    )
}

/// A profile with rules of its own whose final group is set to DIRECT: the
/// switch does not depend on the route, unlike mainland China direct.
fn policy_selected_direct() -> ValidatedSingBoxProfile {
    parse(&json!({"outbounds":[
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":["Node","DIRECT"]}],
        "route":{"final":"PROXY","rules":[
            {"type":"domain_suffix","value":"example.com","outbound":"PROXY"},
            {"type":"geo_ip","value":"LAN","outbound":"DIRECT"}]}}))
    .with_selected_outbound("PROXY", "DIRECT")
    .expect("DIRECT selection")
}

fn profiles() -> Vec<(&'static str, ValidatedSingBoxProfile)> {
    vec![
        ("built-in direct", ValidatedSingBoxProfile::direct()),
        ("shadowsocks", shadowsocks()),
        ("selector set to DIRECT", policy_selected_direct()),
    ]
}

/// The projected runtime with its per-process controller secret replaced,
/// so two projections of one profile compare equal everywhere else.
fn runtime(
    profile: &ValidatedSingBoxProfile,
    mode: ProjectionMode,
    settings: &EngineSettings,
) -> Value {
    let projected = profile
        .project(PROFILE_ID, mode, settings)
        .expect("projection");
    serde_json::from_str(
        &projected
            .as_json()
            .replace(projected.clash_api().expose_secret(), SECRET_PLACEHOLDER),
    )
    .expect("runtime JSON")
}

fn without_route_rules(mut value: Value) -> Value {
    value["route"]
        .as_object_mut()
        .expect("route object")
        .remove("rules");
    value
}

#[test]
fn tunnel_projections_refuse_encrypted_dns_right_after_the_plain_dns_hijack() {
    for (label, profile) in profiles() {
        for mode in [ProjectionMode::Tunnel, ProjectionMode::TunnelSystemProxy] {
            let on = runtime(&profile, mode, &on());
            let off = runtime(&profile, mode, &EngineSettings::default());
            let rules_on = on["route"]["rules"].as_array().expect("rules");
            let rules_off = off["route"]["rules"].as_array().expect("rules");
            assert_eq!(rules_on[0], hijack(), "{label} {mode:?}");
            assert_eq!(rules_on[1], refusal(), "{label} {mode:?}");
            assert_eq!(rules_on[2..], rules_off[1..], "{label} {mode:?}");
            assert_eq!(
                rules_on.iter().filter(|rule| rule["port"] == 853).count(),
                1,
                "{label} {mode:?}"
            );
            // The refusal precedes the mode rules, so it holds in every mode.
            let mode_rule = rules_on
                .iter()
                .position(|rule| rule.get("clash_mode").is_some())
                .expect("mode rules");
            assert!(mode_rule > 1, "{label} {mode:?}");
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

/// The Windows boundary admits the LAN listener only with its access rule
/// first, and both packet stacks carry the refusal in the same place.
#[test]
fn the_lan_access_rule_stays_first_on_both_packet_stacks() {
    let lan = LanProxySettings {
        listen: "0.0.0.0".parse().expect("LAN address"),
        port: 8891,
        allowed_source_cidrs: vec!["192.168.0.0/16".into()],
    };
    let settings = EngineSettings {
        lan_proxy: Some(lan.clone()),
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
            assert_eq!(rules[2], refusal(), "{stack:?} {mode:?}");
        }
    }
}

#[test]
fn proxy_modes_and_release_evidence_projections_ignore_the_switch() {
    let mut cases = Vec::new();
    for (label, profile) in profiles() {
        for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
            cases.push((label, profile.clone(), mode));
        }
    }
    for case in [
        ReleaseDnsEvidenceCase::PrimaryIpv4,
        ReleaseDnsEvidenceCase::PrimaryIpv6,
        ReleaseDnsEvidenceCase::SecondaryIpv4,
        ReleaseDnsEvidenceCase::SecondaryIpv6,
    ] {
        cases.push((
            "release DNS evidence",
            ValidatedSingBoxProfile::release_dns_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    for case in ReleasePacketEvidenceCase::ALL {
        cases.push((
            "release packet evidence",
            ValidatedSingBoxProfile::release_packet_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    // Evidence projections of a profile that routes through a proxy, as the
    // mainland switch's test covers them.
    let mut dns_evidence = shadowsocks();
    dns_evidence.dns_projection =
        DnsProjection::ReleaseEvidence(ReleaseDnsEvidenceCase::PrimaryIpv4);
    cases.push(("proxied DNS evidence", dns_evidence, ProjectionMode::Tunnel));
    let mut packet_evidence = shadowsocks();
    packet_evidence.release_packet_evidence_case = Some(ReleasePacketEvidenceCase::TcpIpv4);
    cases.push((
        "proxied packet evidence",
        packet_evidence,
        ProjectionMode::Tunnel,
    ));
    for (label, profile, mode) in cases {
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
        assert!(!switched.as_json().contains("853"), "{label} {mode:?}");
    }
}

#[test]
fn the_latency_probe_never_carries_the_refusal() {
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
            let json = switched.as_json();
            for marker in ["853", "\"reject\"", "hijack-dns"] {
                assert!(!json.contains(marker), "{label} {mode:?} {marker}: {json}");
            }
        }
    }
}

#[test]
fn the_switch_is_absent_when_off_and_round_trips_when_on() {
    let default = serde_json::to_value(EngineSettings::default()).unwrap();
    assert!(default.get("dns_leak_protection").is_none());
    let value = serde_json::to_value(on()).unwrap();
    assert_eq!(value["dns_leak_protection"], json!(true));
    assert_eq!(
        serde_json::from_value::<EngineSettings>(value).unwrap(),
        on()
    );

    // Stored preferences written before the switch existed keep their bytes.
    let legacy = serde_json::to_string(&RuntimePreferences::default()).unwrap();
    assert!(!legacy.contains("dns_leak"), "{legacy}");
    let parsed: RuntimePreferences = serde_json::from_str(&legacy).unwrap();
    assert!(!parsed.dns_leak_protection);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
    let on = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let text = serde_json::to_string(&on).unwrap();
    assert_eq!(
        text,
        format!(
            "{},\"dns_leak_protection\":true}}",
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
    // Both switches on keep their keys in declaration order.
    let both = RuntimePreferences {
        mainland_china_direct: true,
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let text = serde_json::to_string(&both).unwrap();
    assert!(
        text.ends_with(",\"mainland_china_direct\":true,\"dns_leak_protection\":true}"),
        "{text}"
    );
    assert_eq!(
        serde_json::from_str::<RuntimePreferences>(&text).unwrap(),
        both
    );
}

#[test]
fn apply_to_always_assigns_dns_leak_protection() {
    let on = RuntimePreferences {
        dns_leak_protection: true,
        ..RuntimePreferences::default()
    };
    let applied = on.apply_to(EngineSettings::default()).unwrap();
    assert!(applied.dns_leak_protection);
    assert!(
        !applied.mainland_china_direct,
        "the switches are independent"
    );
    let applied = RuntimePreferences::default().apply_to(self::on()).unwrap();
    assert!(!applied.dns_leak_protection);
}
