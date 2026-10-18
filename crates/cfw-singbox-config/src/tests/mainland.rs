use serde_json::{Value, json};

use crate::validation::DnsProjection;
use crate::{
    EngineSettings, ProjectionMode, ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase,
    ValidatedSingBoxProfile,
};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn on() -> EngineSettings {
    EngineSettings {
        mainland_china_direct: true,
        ..EngineSettings::default()
    }
}

fn parse(value: &Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&value.to_string()).expect("mainland test profile")
}

fn runtime(
    profile: &ValidatedSingBoxProfile,
    mode: ProjectionMode,
    settings: &EngineSettings,
) -> Value {
    serde_json::from_str(
        profile
            .project(PROFILE_ID, mode, settings)
            .expect("projection")
            .as_json(),
    )
    .expect("runtime JSON")
}

/// A Mooring-shaped file: outbounds only, so CFM injects its selector.
fn outbound_only_pair() -> ValidatedSingBoxProfile {
    parse(&json!({"outbounds":[
        {"type":"vless","tag":"lon1-reality","server":"45.67.89.10","server_port":443,
         "credential_ref":{"id":"22222222-2222-4222-8222-222222222222","kind":"vless_uuid"},"flow":"xtls-rprx-vision",
         "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
                "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}},
        {"type":"hysteria2","tag":"lon1-hy2","server":"45.67.89.10","server_port":61000,
         "credential_ref":{"id":"33333333-3333-4333-8333-333333333333","kind":"hysteria2_password"},
         "tls":{"enabled":true,"server_name":"n0123456789abcdef.internal",
                "certificate_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}}
    ]}))
}

fn policy() -> Value {
    json!({"outbounds":[
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":["Node","DIRECT"]}],
        "route":{"final":"PROXY","rules":[
            {"type":"domain_suffix","value":"example.com","outbound":"PROXY"},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT"}]}})
}

fn resource(kind: &str, name: &str, detour: &str) -> Value {
    json!({"type":"remote","tag":format!("cfw-{kind}-{name}"),"format":"binary",
        "url":format!("https://raw.githubusercontent.com/SagerNet/sing-{kind}/rule-set/{kind}-{name}.srs"),
        "download_detour":detour,"update_interval":"1d"})
}

fn mainland_rules(direct: &str, proxied: &str) -> Vec<Value> {
    vec![
        json!({"rule_set":"cfw-geosite-cn","action":"route","outbound":direct}),
        json!({"rule_set":"cfw-geosite-geolocation-!cn","action":"route","outbound":proxied}),
        json!({"action":"resolve"}),
        json!({"rule_set":"cfw-geoip-cn","action":"route","outbound":direct}),
    ]
}

fn doh(tag: &str, address: &str, name: &str, detour: Option<&str>) -> Value {
    let mut server = json!({"type":"https","tag":tag,"server":address,"server_port":443,"path":"/dns-query",
        "connect_timeout":"5s","tls":{"enabled":true,"server_name":name,"min_version":"1.2"}});
    if let Some(detour) = detour {
        server["detour"] = json!(detour);
    }
    server
}

fn respond(condition: Value) -> Value {
    json!({"type":"logical","mode":"and","rules":[condition,{"type":"logical","mode":"or","rules":[
        {"match_response":true,"response_rcode":"NOERROR"},
        {"match_response":true,"response_rcode":"NXDOMAIN"}]}],"action":"respond"})
}

#[test]
fn mainland_rules_follow_the_profile_rules_and_precede_the_final_outbound() {
    let profile = outbound_only_pair();
    let off = runtime(
        &profile,
        ProjectionMode::SystemProxy,
        &EngineSettings::default(),
    );
    let system = runtime(&profile, ProjectionMode::SystemProxy, &on());
    let mut expected = vec![
        json!({"clash_mode":"Direct","action":"route","outbound":"cfw-direct"}),
        json!({"clash_mode":"Global","action":"route","outbound":"cfw-proxy-selector"}),
    ];
    expected.extend(mainland_rules("cfw-direct", "cfw-proxy-selector"));
    assert_eq!(system["route"]["rules"], Value::Array(expected.clone()));
    assert_eq!(system["route"]["final"], "cfw-proxy-selector");
    assert_eq!(system["route"]["final"], off["route"]["final"]);
    assert_eq!(
        system["route"]["rule_set"],
        json!([
            resource("geoip", "cn", "cfw-proxy-selector"),
            resource("geosite", "cn", "cfw-proxy-selector"),
            resource("geosite", "geolocation-!cn", "cfw-proxy-selector")
        ])
    );
    assert_eq!(
        system["experimental"]["cache_file"],
        json!({"enabled":true,"path":"routing-cache.db","cache_id":PROFILE_ID})
    );
    let outbounds = system["outbounds"].as_array().unwrap();
    assert_eq!(
        outbounds.last().unwrap(),
        &json!({"type":"direct","tag":"cfw-direct","domain_resolver":{"policy":"default"}})
    );
    // Only the DIRECT dial's resolver changes; the proxies are untouched.
    assert_eq!(
        outbounds[..outbounds.len() - 1],
        off["outbounds"].as_array().unwrap()[..outbounds.len() - 1]
    );

    let tunnel = runtime(&profile, ProjectionMode::Tunnel, &on());
    let mut with_hijack = vec![json!({"port":53,"action":"hijack-dns"})];
    with_hijack.extend(expected);
    assert_eq!(tunnel["route"]["rules"], Value::Array(with_hijack));

    let projected_on = profile
        .project(PROFILE_ID, ProjectionMode::SystemProxy, &on())
        .unwrap();
    let projected_off = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    assert_eq!(
        projected_on.credential_slots(),
        projected_off.credential_slots()
    );
    assert_ne!(projected_on.digest(), projected_off.digest());
}

#[test]
fn app_owned_dns_resolves_only_rule_mode_mainland_names_through_domestic_doh() {
    let profile = outbound_only_pair();
    let dns = runtime(&profile, ProjectionMode::SystemProxy, &on())["dns"].clone();
    let selector = Some("cfw-proxy-selector");
    assert_eq!(
        dns["servers"],
        json!([
            {"type":"udp","tag":"cfw-bootstrap-dns-0","server":"223.6.6.6","server_port":53},
            {"type":"udp","tag":"cfw-bootstrap-dns-1","server":"119.29.29.29","server_port":53},
            doh("cfw-authenticated-dns-0", "1.1.1.1", "cloudflare-dns.com", selector),
            doh("cfw-authenticated-dns-1", "8.8.8.8", "dns.google", selector),
            doh("cfw-mainland-dns-0", "223.5.5.5", "dns.alidns.com", None),
            doh("cfw-mainland-dns-1", "1.12.12.12", "doh.pub", None)
        ])
    );
    let mainland = json!({"clash_mode":"Rule","rule_set":["cfw-geosite-cn"]});
    let mut evaluate = mainland.clone();
    evaluate["action"] = json!("evaluate");
    evaluate["server"] = json!("cfw-mainland-dns-0");
    let mut route = mainland.clone();
    route["action"] = json!("route");
    route["server"] = json!("cfw-mainland-dns-1");
    let mut generic =
        json!({"domain_regex":".*","action":"evaluate","server":"cfw-authenticated-dns-0"});
    assert_eq!(
        dns["rules"],
        json!([
            evaluate,
            respond(mainland.clone()),
            route,
            generic.take(),
            respond(json!({"domain_regex":".*"}))
        ])
    );
    assert_eq!(dns["final"], "cfw-authenticated-dns-1");
    // A domestic resolver is reached only by a Rule-mode mainland query.
    for rule in dns["rules"].as_array().unwrap() {
        if rule["server"]
            .as_str()
            .is_some_and(|server| server.starts_with("cfw-mainland-dns-"))
        {
            assert_eq!(rule["clash_mode"], "Rule", "{rule}");
            assert_eq!(rule["rule_set"], json!(["cfw-geosite-cn"]), "{rule}");
        }
    }
    let route = runtime(&profile, ProjectionMode::SystemProxy, &on())["route"].clone();
    assert_eq!(
        route["default_domain_resolver"],
        json!({"server":"cfw-authenticated-dns-0","fallback_server":"cfw-authenticated-dns-1"})
    );
}

#[test]
fn the_switch_is_inert_unless_the_selected_route_is_remote() {
    let direct_only = parse(&json!({"outbounds":[
        {"type":"direct","tag":"DIRECT"},{"type":"block","tag":"REJECT"}],"route":{"final":"DIRECT"}}));
    let selected_direct = parse(&policy())
        .with_selected_outbound("PROXY", "DIRECT")
        .expect("DIRECT selection");
    let mut profiles = vec![
        (
            "built-in direct",
            ValidatedSingBoxProfile::direct(),
            ProjectionMode::SystemProxy,
        ),
        (
            "built-in direct",
            ValidatedSingBoxProfile::direct(),
            ProjectionMode::Tunnel,
        ),
        (
            "direct and block only",
            direct_only.clone(),
            ProjectionMode::SystemProxy,
        ),
        ("direct and block only", direct_only, ProjectionMode::Tunnel),
        (
            "selector set to DIRECT",
            selected_direct.clone(),
            ProjectionMode::SystemProxy,
        ),
        (
            "selector set to DIRECT",
            selected_direct,
            ProjectionMode::Tunnel,
        ),
    ];
    for case in [
        crate::ReleaseDnsEvidenceCase::PrimaryIpv4,
        crate::ReleaseDnsEvidenceCase::PrimaryIpv6,
        crate::ReleaseDnsEvidenceCase::SecondaryIpv4,
        crate::ReleaseDnsEvidenceCase::SecondaryIpv6,
    ] {
        profiles.push((
            "release DNS evidence",
            ValidatedSingBoxProfile::release_dns_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    for case in crate::ReleasePacketEvidenceCase::ALL {
        profiles.push((
            "release packet evidence",
            ValidatedSingBoxProfile::release_packet_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    for (label, profile, mode) in profiles {
        {
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
                "{label}"
            );
            assert_eq!(
                switched.credential_slots(),
                default.credential_slots(),
                "{label}"
            );
        }
    }
}

#[test]
fn the_profile_rules_and_final_outbound_keep_precedence() {
    let profile = parse(&policy());
    let off = runtime(
        &profile,
        ProjectionMode::SystemProxy,
        &EngineSettings::default(),
    );
    let on = runtime(&profile, ProjectionMode::SystemProxy, &on());
    let mut expected = off["route"]["rules"].as_array().unwrap().clone();
    expected.extend(mainland_rules("DIRECT", "PROXY"));
    assert_eq!(on["route"]["rules"], Value::Array(expected));
    assert_eq!(on["route"]["final"], "PROXY");
    // The profile's own GEOIP CN and the switch share one download.
    assert_eq!(
        on["route"]["rule_set"],
        json!([
            resource("geoip", "cn", "PROXY"),
            resource("geosite", "cn", "PROXY"),
            resource("geosite", "geolocation-!cn", "PROXY")
        ])
    );
    let direct = on["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|outbound| outbound["tag"] == "DIRECT")
        .unwrap();
    assert_eq!(direct["domain_resolver"], json!({"policy":"default"}));
}

#[test]
fn mainland_rules_use_the_projected_direct_tag() {
    // A proxy that takes the name the app would use for its DIRECT outbound.
    let profile = parse(&json!({"outbounds":[
        {"type":"socks5","tag":"cfw-direct","server":"proxy.example.com","server_port":1080},
        {"type":"socks5","tag":"backup","server":"backup.example.com","server_port":1080}]}));
    let runtime = runtime(&profile, ProjectionMode::SystemProxy, &on());
    let rules = runtime["route"]["rules"].as_array().unwrap();
    let direct = rules[0]["outbound"].as_str().unwrap().to_owned();
    assert_eq!(rules[0]["clash_mode"], "Direct");
    assert_ne!(direct, "cfw-direct");
    assert_eq!(rules[2]["outbound"], json!(direct));
    assert_eq!(rules[5]["outbound"], json!(direct));
    assert!(
        runtime["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|outbound| outbound["tag"] == json!(direct) && outbound["type"] == "direct")
    );
}

#[test]
fn a_profile_with_its_own_dns_keeps_it_unchanged() {
    let source = json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},{"type":"direct","tag":"direct"}],
        "route":{"final":"proxy","rules":[{"type":"domain","value":"direct.example.com","outbound":"direct"}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}],
            "nameserver_policy":[{"domain":"+.example.org","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}],
            "direct_servers":[{"type":"tcp","server":"114.114.114.114","server_port":53}]}});
    let profile = parse(&source);
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::Tunnel] {
        let off = runtime(&profile, mode, &EngineSettings::default());
        let on = runtime(&profile, mode, &on());
        assert_eq!(on["dns"], off["dns"], "{mode:?}");
        assert_eq!(on["outbounds"], off["outbounds"], "{mode:?}");
        let rules = on["route"]["rules"].as_array().unwrap();
        let position = |condition: &Value| {
            rules
                .iter()
                .position(|rule| {
                    condition
                        .as_object()
                        .unwrap()
                        .iter()
                        .all(|(key, value)| rule.get(key) == Some(value))
                })
                .expect("rule present")
        };
        assert!(
            position(&json!({"domain":"direct.example.com"}))
                < position(&json!({"rule_set":"cfw-geosite-cn"}))
        );
    }
}

#[test]
fn the_latency_probe_never_carries_mainland_routing() {
    // The Mooring-shaped pair holds a VLESS and a Hysteria2 credential; the
    // policy profile's SOCKS node holds none.
    for (profile, slots) in [(outbound_only_pair(), 2), (parse(&policy()), 0)] {
        let probe = |settings: &EngineSettings| {
            profile
                .project_proxy_probe(PROFILE_ID, ProjectionMode::SystemProxy, settings)
                .expect("probe")
        };
        let switched = probe(&on());
        assert_eq!(switched, probe(&EngineSettings::default()));
        let json = switched.as_json();
        for marker in ["rule_set", "clash_mode", "cfw-geosite", "cfw-mainland-dns"] {
            assert!(!json.contains(marker), "{marker}: {json}");
        }
        // The probe's credentials are those of the runtime projection, with
        // the switch on or off: the switch never touches a proxy outbound.
        for settings in [on(), EngineSettings::default()] {
            let projected = profile
                .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
                .expect("projection");
            assert_eq!(
                switched.credential_audience(),
                projected.credential_audience()
            );
            assert_eq!(switched.credential_slots(), projected.credential_slots());
        }
        assert_eq!(switched.credential_slots().len(), slots);
    }
}

/// Release evidence projections never carry the switch. Today every evidence
/// profile is the built-in DIRECT profile, where the switch is inert anyway;
/// this holds even for one that routed through a proxy.
#[test]
fn release_evidence_projections_ignore_the_switch() {
    let with_ipv6 = |settings: EngineSettings| EngineSettings {
        enable_ipv6: true,
        ..settings
    };
    let mut dns_evidence = outbound_only_pair();
    dns_evidence.dns_projection =
        DnsProjection::ReleaseEvidence(ReleaseDnsEvidenceCase::PrimaryIpv4);
    let mut packet_evidence = outbound_only_pair();
    packet_evidence.release_packet_evidence_case = Some(ReleasePacketEvidenceCase::TcpIpv4);
    for (label, profile) in [("DNS", dns_evidence), ("packet", packet_evidence)] {
        assert!(profile.document.selected_route_is_remote(), "{label}");
        assert_eq!(
            runtime(&profile, ProjectionMode::Tunnel, &with_ipv6(on())),
            runtime(
                &profile,
                ProjectionMode::Tunnel,
                &with_ipv6(EngineSettings::default())
            ),
            "{label}"
        );
    }
}

#[test]
fn the_mainland_resolvers_pass_the_authenticated_endpoint_checks() {
    for ipv6 in [true, false] {
        crate::projection::validate_authenticated_dns_pool(
            &crate::mainland::domestic_resolvers(),
            ipv6,
        )
        .expect("domestic DoH");
        crate::projection::validate_authenticated_dns_pool(
            &crate::mainland::foreign_resolvers(),
            ipv6,
        )
        .expect("foreign DoH");
    }
}
