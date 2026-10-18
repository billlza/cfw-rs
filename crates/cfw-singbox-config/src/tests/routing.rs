use serde_json::{Value, json};

use crate::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn policy() -> Value {
    json!({
        "outbounds": [
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":["Node","DIRECT"]}
        ],
        "route": {"final":"PROXY", "rules":[
            {"type":"process_name","value":"Example Helper","outbound":"PROXY"},
            {"type":"domain_suffix","value":"example.com","outbound":"PROXY"},
            {"type":"ip_cidr","value":"192.0.2.1/32","outbound":"DIRECT","no_resolve":true},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT"}
        ]}
    })
}

#[test]
fn node_selection_changes_runtime_routing_without_invalidating_vault_identity() {
    let profile = ValidatedSingBoxProfile::parse(&policy().to_string()).expect("policy");
    let selected = profile
        .with_selected_outbound("PROXY", "DIRECT")
        .expect("selection");
    assert_eq!(selected.digest(), profile.digest());
    assert_eq!(selected.as_json(), profile.as_json());
    assert_eq!(
        selected.credential_references(),
        profile.credential_references()
    );
    assert!(!selected.routes_through_remote());
    let settings = EngineSettings::default();
    let original = profile
        .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
        .expect("original");
    let changed = selected
        .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
        .expect("selected");
    assert_eq!(
        changed.credential_audience(),
        original.credential_audience()
    );
    assert_ne!(changed.digest(), original.digest());
    let runtime: Value = serde_json::from_str(changed.as_json()).expect("runtime");
    assert_eq!(runtime["outbounds"][2]["default"], "DIRECT");
    assert!(profile.with_selected_outbound("PROXY", "absent").is_err());
    assert!(profile.with_selected_outbound("Node", "DIRECT").is_err());
}

#[test]
fn selector_and_ordered_rules_reach_the_real_runtime_projection() {
    let profile = ValidatedSingBoxProfile::parse(&policy().to_string()).expect("valid policy");
    assert!(profile.routes_through_remote());
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    let config: Value = serde_json::from_str(projected.as_json()).expect("runtime JSON");
    assert_eq!(
        config["outbounds"][2]["outbounds"],
        json!(["Node", "DIRECT"])
    );
    assert_eq!(config["route"]["final"], "PROXY");
    assert_eq!(
        config["route"]["rules"],
        json!([
            {"clash_mode":"Direct","action":"route","outbound":"DIRECT"},
            {"clash_mode":"Global","action":"route","outbound":"PROXY"},
            {"process_name":"Example Helper","action":"route","outbound":"PROXY"},
            {"domain_suffix":"example.com","action":"route","outbound":"PROXY"},
            {"ip_cidr":"192.0.2.1/32","action":"route","outbound":"DIRECT"},
            {"action":"resolve"},
            {"rule_set":"cfw-geoip-cn","action":"route","outbound":"DIRECT"}
        ])
    );
    assert_eq!(
        config["route"]["rule_set"][0]["url"],
        "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
    );
    assert_eq!(config["route"]["rule_set"][0]["download_detour"], "PROXY");
    assert_eq!(config["experimental"]["cache_file"]["enabled"], true);
}

#[test]
fn combined_mode_binds_both_listeners_and_distinct_os_options() {
    let profile = ValidatedSingBoxProfile::parse(&policy().to_string()).expect("valid policy");
    let settings = EngineSettings::default();
    let combined = profile
        .project(PROFILE_ID, ProjectionMode::TunnelSystemProxy, &settings)
        .expect("combined projection");
    let tunnel = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &settings)
        .expect("tunnel projection");
    let config: Value = serde_json::from_str(combined.as_json()).expect("runtime JSON");
    assert_eq!(config["inbounds"].as_array().expect("inbounds").len(), 2);
    assert_eq!(config["inbounds"][0]["type"], "tun");
    assert_eq!(
        config["inbounds"][1],
        json!({"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":settings.mixed_port})
    );
    assert_eq!(
        config["route"]["rules"][0],
        json!({"port":53,"action":"hijack-dns"})
    );
    assert_ne!(combined.digest(), tunnel.digest());
    let mut changed = settings;
    changed.mixed_port += 1;
    assert_ne!(
        combined.digest(),
        profile
            .project(PROFILE_ID, ProjectionMode::TunnelSystemProxy, &changed)
            .expect("different port")
            .digest()
    );
}

#[test]
fn invalid_routing_never_becomes_a_partial_profile() {
    for (label, path, value) in [
        (
            "missing group member",
            "/outbounds/2/outbounds/0",
            json!("absent"),
        ),
        ("cycle", "/outbounds/2/outbounds/0", json!("PROXY")),
        ("invalid default", "/outbounds/2/default", json!("absent")),
        (
            "undeclared target",
            "/route/rules/0/outbound",
            json!("absent"),
        ),
        (
            "invalid cidr",
            "/route/rules/2/value",
            json!("192.0.2.1/33"),
        ),
        (
            "control characters",
            "/route/rules/0/value",
            json!("Example\nHelper"),
        ),
    ] {
        let mut document = policy();
        if path.ends_with("/default") {
            document["outbounds"][2]["default"] = value;
        } else {
            *document.pointer_mut(path).expect("fixture path") = value;
        }
        assert!(
            ValidatedSingBoxProfile::parse(&document.to_string()).is_err(),
            "{label}"
        );
    }
}

fn geosite_profile(rules: Value) -> Value {
    json!({
        "outbounds": [
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"}
        ],
        "route": {"final":"Node", "rules": rules}
    })
}

#[test]
fn geo_site_rule_kind_is_serialized_as_geo_site() {
    assert_eq!(
        serde_json::to_value(crate::RuleKind::GeoSite).unwrap(),
        json!("geo_site")
    );
    assert!(serde_json::from_value::<crate::RuleKind>(json!("geosite")).is_err());
    let profile = ValidatedSingBoxProfile::parse(
        &geosite_profile(json!([{"type":"geo_site","value":"cn","outbound":"DIRECT"}])).to_string(),
    )
    .expect("typed GEOSITE rule");
    let stored: Value = serde_json::from_str(profile.as_json()).unwrap();
    assert_eq!(
        stored["route"]["rules"],
        json!([{"type":"geo_site","value":"cn","outbound":"DIRECT","no_resolve":false}])
    );
}

#[test]
fn geo_site_rules_admit_published_dataset_names_and_refuse_no_resolve() {
    for code in [
        "cn",
        "geolocation-!cn",
        "google@cn",
        "google@!cn",
        "category-ads-all",
    ] {
        let source = geosite_profile(json!([{"type":"geo_site","value":code,"outbound":"DIRECT"}]));
        assert!(
            ValidatedSingBoxProfile::parse(&source.to_string()).is_ok(),
            "{code}"
        );
    }
    for code in [
        "CN", "!cn", "a_b", "a@b@c", "../cn", "cn.x", "cn/x", "cn%2fx", "cn?x", "中国",
    ] {
        let source = geosite_profile(json!([{"type":"geo_site","value":code,"outbound":"DIRECT"}]));
        let error = ValidatedSingBoxProfile::parse(&source.to_string()).unwrap_err();
        assert_eq!(
            error.to_string(),
            crate::ConfigError::UnsupportedPolicyShape {
                path: "$.route.rules[0]".into(),
                reason: "rule value does not match its declared type".into(),
            }
            .to_string(),
            "{code}"
        );
    }
    let source = geosite_profile(
        json!([{"type":"geo_site","value":"cn","outbound":"DIRECT","no_resolve":true}]),
    );
    assert!(
        ValidatedSingBoxProfile::parse(&source.to_string())
            .unwrap_err()
            .to_string()
            .contains("no_resolve is only valid for destination IP rules")
    );
}

#[test]
fn geo_site_rules_project_to_shared_rule_sets_without_resolve() {
    let profile = ValidatedSingBoxProfile::parse(
        &geosite_profile(json!([
            {"type":"geo_site","value":"geolocation-!cn","outbound":"Node"},
            {"type":"geo_site","value":"cn","outbound":"DIRECT"},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT"}
        ]))
        .to_string(),
    )
    .expect("GEOSITE policy");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).unwrap();
    assert_eq!(
        runtime["route"]["rules"],
        json!([
            {"clash_mode":"Direct","action":"route","outbound":"DIRECT"},
            {"clash_mode":"Global","action":"route","outbound":"Node"},
            {"rule_set":"cfw-geosite-geolocation-!cn","action":"route","outbound":"Node"},
            {"rule_set":"cfw-geosite-cn","action":"route","outbound":"DIRECT"},
            {"action":"resolve"},
            {"rule_set":"cfw-geoip-cn","action":"route","outbound":"DIRECT"}
        ])
    );
    let resource = |kind: &str, name: &str| {
        json!({"type":"remote","tag":format!("cfw-{kind}-{name}"),"format":"binary",
            "url":format!("https://raw.githubusercontent.com/SagerNet/sing-{kind}/rule-set/{kind}-{name}.srs"),
            "download_detour":"Node","update_interval":"1d"})
    };
    assert_eq!(
        runtime["route"]["rule_set"],
        json!([
            resource("geoip", "cn"),
            resource("geosite", "cn"),
            resource("geosite", "geolocation-!cn")
        ])
    );
    assert_eq!(
        runtime["experimental"]["cache_file"],
        json!({"enabled":true,"path":"routing-cache.db","cache_id":PROFILE_ID})
    );
}

#[test]
fn expanded_rule_providers_project_geosite_without_resolve() {
    let mut source = geosite_profile(json!([
        {"type":"rule_set","value":"lists","outbound":"DIRECT","no_resolve":true},
        {"type":"rule_set","value":"lists","outbound":"Node"}
    ]));
    source["providers"] = json!({"rules":[{"name":"lists","source":{"interval_seconds":86400},
    "format":"yaml","behavior":"classical","rules":[
        {"type":"geo_site","value":"cn"},
        {"type":"geo_ip","value":"CN"}
    ]}]});
    let profile = ValidatedSingBoxProfile::parse(&source.to_string()).expect("provider policy");
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .unwrap()
            .as_json(),
    )
    .unwrap();
    assert_eq!(
        runtime["route"]["rules"],
        json!([
            {"clash_mode":"Direct","action":"route","outbound":"DIRECT"},
            {"clash_mode":"Global","action":"route","outbound":"Node"},
            {"rule_set":"cfw-geosite-cn","action":"route","outbound":"DIRECT"},
            {"rule_set":"cfw-geoip-cn","action":"route","outbound":"DIRECT"},
            {"rule_set":"cfw-geosite-cn","action":"route","outbound":"Node"},
            {"action":"resolve"},
            {"rule_set":"cfw-geoip-cn","action":"route","outbound":"Node"}
        ])
    );
    assert_eq!(
        runtime["route"]["rule_set"]
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| resource["tag"].clone())
            .collect::<Vec<_>>(),
        [json!("cfw-geoip-cn"), json!("cfw-geosite-cn")]
    );
}

/// Two uppercase letters are a valid GEOIP value, so the budget can be filled
/// with distinct synthetic country codes.
fn country(index: usize) -> String {
    let letters = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String::from_utf8(vec![letters[index / 26], letters[index % 26]]).unwrap()
}

#[test]
fn geo_dataset_budget_counts_distinct_route_provider_and_dns_datasets() {
    let budget = crate::datasets::MAX_GEO_DATASETS;
    let profile = |countries: usize, extra: Value| {
        let mut rules = (0..countries)
            .map(|index| json!({"type":"geo_ip","value":country(index),"outbound":"DIRECT"}))
            .collect::<Vec<_>>();
        rules.extend(extra.as_array().unwrap().iter().cloned());
        let mut source = geosite_profile(Value::Array(rules));
        source["providers"] = json!({"rules":[
            {"name":"listed","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical",
             "rules":[{"type":"geo_site","value":"provider-only"}]},
            {"name":"unreferenced","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical",
             "rules":[{"type":"geo_site","value":"never-downloaded"}]}]});
        source["dns"] = json!({"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}],
            "nameserver_policy":[{"domain":"geosite:cn","servers":[{"type":"tcp","server":"223.5.5.5","server_port":53}]}],
            "fallback_servers":[{"type":"udp","server":"8.8.4.4","server_port":53}],
            "fallback_filter":{"geoip_code":"aa","geosite":["dns-only"]}});
        ValidatedSingBoxProfile::parse(&source.to_string())
    };
    // GEOIP AA..; geosite cn (route and DNS); provider-only; dns-only; the
    // fallback GeoIP "aa" equals route GEOIP AA; LAN and the unreferenced
    // provider count for nothing.
    let shared = json!([
        {"type":"geo_site","value":"cn","outbound":"DIRECT"},
        {"type":"rule_set","value":"listed","outbound":"DIRECT"},
        {"type":"geo_ip","value":"LAN","outbound":"DIRECT"},
        {"type":"geo_ip","value":"AA","outbound":"Node"}
    ]);
    assert!(profile(budget - 3, shared.clone()).is_ok());
    let error = profile(budget - 2, shared).unwrap_err();
    assert_eq!(
        error.to_string(),
        crate::ConfigError::UnsupportedPolicyShape {
            path: "$".into(),
            reason: format!("profile references more than {budget} GeoIP and GeoSite datasets"),
        }
        .to_string()
    );
}
