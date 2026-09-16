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
    assert!(value.get("ipv6_dns_enabled").is_none());
    let restored: EngineSettings = serde_json::from_value(value).unwrap();
    assert_eq!(restored, EngineSettings::default());
}

#[test]
fn ipv4_dns_answers_keep_ipv6_tunnel_capture_and_restore_without_a_profile_rewrite() {
    let preferences = RuntimePreferences {
        ipv6_dns_enabled: Some(false),
        ..RuntimePreferences::default()
    };
    let settings = preferences.apply_to(EngineSettings::default()).unwrap();
    assert!(
        settings.enable_ipv6,
        "DNS preference must not remove IPv6 route coverage"
    );
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = ValidatedSingBoxProfile::direct()
            .project(ID, mode, &settings)
            .unwrap();
        let value: Value = serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(value["dns"]["strategy"], "ipv4_only");
        assert_eq!(
            value["dns"]["rules"][0],
            json!({
                "query_type":["AAAA"], "action":"predefined", "rcode":"NOERROR"
            })
        );
        if let Some(tunnel) = value["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["type"] == "tun")
        {
            assert!(
                tunnel["address"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v.as_str().unwrap().contains(':'))
            );
        }
    }
    let restored = RuntimePreferences::default().apply_to(settings).unwrap();
    let projected = ValidatedSingBoxProfile::direct()
        .project(ID, ProjectionMode::Tunnel, &restored)
        .unwrap();
    let value: Value = serde_json::from_str(projected.as_json()).unwrap();
    assert_eq!(value["dns"]["strategy"], "prefer_ipv4");
    assert_ne!(value["dns"]["rules"][0]["query_type"], json!(["AAAA"]));
}

#[test]
fn legacy_runtime_preferences_retain_canonical_bytes_and_ipv6_dns_is_typed() {
    let legacy = r#"{"preferred_mixed_port":null,"log_level":"info","tunnel_mtu":1500,"allow_lan":false,"lan_proxy":null}"#;
    let mut preferences: RuntimePreferences = serde_json::from_str(legacy).unwrap();
    assert_eq!(preferences.ipv6_dns_enabled, None);
    assert_eq!(serde_json::to_string(&preferences).unwrap(), legacy);
    preferences.ipv6_dns_enabled = Some(false);
    let encoded = serde_json::to_vec(&preferences).unwrap();
    assert_eq!(
        serde_json::from_slice::<RuntimePreferences>(&encoded).unwrap(),
        preferences
    );
    let mut invalid = serde_json::to_value(&preferences).unwrap();
    invalid["ipv6_dns_enabled"] = json!("false");
    assert!(serde_json::from_value::<RuntimePreferences>(invalid).is_err());
}

#[test]
fn manual_ipv6_dns_choices_override_imports_and_survive_serialization() {
    let profile = ValidatedSingBoxProfile::parse(
        &json!({
            "outbounds": [{"type":"direct","tag":"direct"}],
            "dns": {"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],"ipv6":false}
        })
        .to_string(),
    )
    .unwrap();
    let inherited = EngineSettings::default();
    assert!(!profile.effective_ipv6_dns_enabled(&inherited));
    let original_digest = profile.digest();
    for enabled in [true, false, true] {
        let preference = RuntimePreferences {
            ipv6_dns_enabled: Some(enabled),
            ..RuntimePreferences::default()
        };
        let encoded = serde_json::to_value(&preference).unwrap();
        assert_eq!(encoded["ipv6_dns_enabled"], enabled);
        let reloaded: RuntimePreferences = serde_json::from_value(encoded).unwrap();
        let settings = reloaded.apply_to(inherited.clone()).unwrap();
        assert_eq!(profile.effective_ipv6_dns_enabled(&settings), enabled);
        for mode in [
            ProjectionMode::LocalProxy,
            ProjectionMode::SystemProxy,
            ProjectionMode::Tunnel,
            ProjectionMode::TunnelSystemProxy,
        ] {
            let projected = profile.project(ID, mode, &settings).unwrap();
            let config: Value = serde_json::from_str(projected.as_json()).unwrap();
            assert_eq!(
                config["dns"]["strategy"],
                if enabled { "prefer_ipv4" } else { "ipv4_only" }
            );
            let denies_aaaa = config["dns"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["query_type"] == json!(["AAAA"]) && rule["action"] == "predefined"
                });
            assert_eq!(denies_aaaa, !enabled);
        }
        assert!(
            settings.enable_ipv6,
            "DNS choices retain IPv6 route capture"
        );
        assert_eq!(profile.digest(), original_digest);
    }
    let disabled_capture = EngineSettings {
        enable_ipv6: false,
        ipv6_dns_enabled: Some(true),
        ..inherited
    };
    assert!(!profile.effective_ipv6_dns_enabled(&disabled_capture));
}
