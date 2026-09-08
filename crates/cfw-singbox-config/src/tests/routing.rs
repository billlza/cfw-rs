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
