use crate::{
    EngineLogLevel, EngineSettings, LanProxySettings, ProjectionMode, RuntimePreferences,
    ValidatedSingBoxProfile,
};
use serde_json::{Value, json};
const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn settings() -> EngineSettings {
    EngineSettings {
        mixed_port: 8890,
        log_level: EngineLogLevel::Debug,
        tunnel_mtu: 1400,
        lan_proxy: Some(LanProxySettings {
            listen: "0.0.0.0".parse().unwrap(),
            port: 8891,
            allowed_source_cidrs: vec!["192.168.0.0/16".into()],
        }),
        ..EngineSettings::default()
    }
}

#[test]
fn real_runtime_settings_project_with_an_independent_guarded_lan_listener() {
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = ValidatedSingBoxProfile::direct()
            .project(ID, mode, &settings())
            .unwrap();
        let value: Value = serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(value["log"]["level"], "debug");
        let inbounds = value["inbounds"].as_array().unwrap();
        let lan = inbounds
            .iter()
            .find(|inbound| inbound["tag"] == "cfw-lan-proxy")
            .unwrap();
        assert_eq!(lan["listen"], "0.0.0.0");
        assert_eq!(lan["listen_port"], 8891);
        assert_eq!(
            value["route"]["rules"][0],
            json!({"type":"logical","mode":"and","rules":[{"inbound":["cfw-lan-proxy"]},{"source_ip_cidr":["192.168.0.0/16"],"invert":true}],"action":"reject"})
        );
        for inbound in inbounds {
            if inbound["tag"] == "cfw-system-proxy" {
                assert_eq!(inbound["listen"], "127.0.0.1");
                assert_eq!(inbound["listen_port"], 8890);
            }
            if inbound["type"] == "tun" {
                assert_eq!(inbound["mtu"], 1400);
            }
        }
        assert_eq!(
            value["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9090"
        );
    }
}

#[test]
fn unguarded_lan_and_conflicting_ports_are_rejected_before_start() {
    for ranges in [
        vec![],
        vec!["0.0.0.0/0"],
        vec!["127.0.0.1/32"],
        vec!["192.168.1.2/24"],
        vec!["192.168.0.0/16", "192.168.0.0/16"],
    ] {
        let mut settings = settings();
        settings.lan_proxy.as_mut().unwrap().allowed_source_cidrs =
            ranges.into_iter().map(String::from).collect();
        assert!(
            ValidatedSingBoxProfile::direct()
                .project(ID, ProjectionMode::LocalProxy, &settings)
                .is_err()
        );
    }
    for port in [80, 8890, 9090] {
        let mut settings = settings();
        settings.lan_proxy.as_mut().unwrap().port = port;
        assert!(
            ValidatedSingBoxProfile::direct()
                .project(ID, ProjectionMode::LocalProxy, &settings)
                .is_err()
        );
    }
    let mut preferences = RuntimePreferences {
        preferred_mixed_port: Some(80),
        ..RuntimePreferences::default()
    };
    assert!(preferences.validate().is_err());
    preferences.preferred_mixed_port = Some(8890);
    preferences.tunnel_mtu = 1279;
    assert!(preferences.validate().is_err());
}

#[test]
fn new_defaults_preserve_existing_persisted_engine_settings_bytes() {
    let value = serde_json::to_value(EngineSettings::default()).unwrap();
    assert!(value.get("log_level").is_none());
    assert!(value.get("lan_proxy").is_none());
    let restored: EngineSettings = serde_json::from_value(value).unwrap();
    assert_eq!(restored, EngineSettings::default());
}
