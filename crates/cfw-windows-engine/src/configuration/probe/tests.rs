use super::*;
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use serde_json::json;

pub(crate) fn request() -> ProfileDelayTestRequest {
    request_with(&EngineSettings::default())
}

fn request_with(settings: &EngineSettings) -> ProfileDelayTestRequest {
    let profile = ValidatedSingBoxProfile::direct();
    let probe = profile
        .project_proxy_probe(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::LocalProxy,
            settings,
        )
        .unwrap();
    ProfileDelayTestRequest {
        audience: probe.credential_audience().clone(),
        config_json: probe.as_json().into(),
        credential_slots: probe.credential_slots().to_vec(),
        proxies: vec!["direct".into()],
        timeout_ms: 1000,
        target_url: Some("https://example.com/check".into()),
        expected_status: Some("200/204-299".into()),
    }
}

#[test]
fn real_shared_probe_projection_binds_template_audience_and_options() {
    let original = request();
    let checked = CheckedProbeConfiguration::new(original.clone()).unwrap();
    let resolved = checked.resolve([]).unwrap();
    assert_eq!(resolved.options.proxies, original.proxies);
    assert_eq!(resolved.projection.digest(), checked.digest);
    let alterations: [fn(&mut ProfileDelayTestRequest); 5] = [
        |r| r.proxies.push("missing".into()),
        |r| r.timeout_ms = 500,
        |r| r.target_url = Some("https://example.com/changed".into()),
        |r| r.expected_status = Some("204".into()),
        |r| {
            r.audience = CredentialAudience::new(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                r.audience.profile_digest(),
            )
            .unwrap()
        },
    ];
    for alter in alterations {
        let mut value = original.clone();
        alter(&mut value);
        assert_ne!(
            CheckedProbeConfiguration::new(value).unwrap().digest,
            checked.digest
        );
    }
}

#[test]
fn probe_admission_rejects_runtime_effects_before_credential_resolution() {
    for (key, native) in [
        ("inbounds", json!([])),
        ("experimental", json!({"cache_file":{"enabled":true}})),
        ("services", json!([])),
        ("log", json!({"output":"private-file"})),
        ("route", json!({"auto_detect_interface":true})),
        ("route", json!({"tcp_concurrent":true,"final":"direct"})),
        ("route", json!({"tcp_concurrent":false})),
        ("route", json!({"tcp_concurrent":"true"})),
    ] {
        let mut value = request();
        let mut root: serde_json::Value = serde_json::from_str(&value.config_json).unwrap();
        root[key] = native;
        value.config_json = serde_json::to_string(&canonicalize_configuration_value(root)).unwrap();
        assert!(CheckedProbeConfiguration::new(value).is_err());
    }
}

/// A probe reaches a node as the running core does: the shared projection
/// hands it the core's dialing option, the admission takes it, and the digest
/// binds it.
#[test]
fn probe_admission_takes_the_dialing_option_of_the_core() {
    let route = |value: &ProfileDelayTestRequest| {
        serde_json::from_str::<serde_json::Value>(&value.config_json).unwrap()["route"].clone()
    };
    let racing = request();
    let serial = request_with(&EngineSettings {
        tcp_concurrency: false,
        ..EngineSettings::default()
    });
    assert_eq!(route(&racing)["tcp_concurrent"], true);
    assert!(route(&serial).get("tcp_concurrent").is_none());
    assert_ne!(
        CheckedProbeConfiguration::new(racing).unwrap().digest,
        CheckedProbeConfiguration::new(serial).unwrap().digest
    );
}

/// The DNS rules a probe keeps may name the inline rule set of a rule
/// provider, which the probe then declares: the shared projection of such a
/// profile must pass. A set the probe would have to read or fetch must not.
#[test]
fn probe_admission_takes_the_inline_rule_sets_the_projection_declares() {
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},{"type":"direct","tag":"direct"}],
        "route":{"final":"proxy"},
        "providers":{"rules":[{"name":"sites","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical",
        "rules":[{"type":"domain_suffix","value":"example.org"}]}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}],
        "nameserver_policy":[{"domain":"rule-set:sites","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}]}}"#,
    )
    .unwrap();
    let probe = profile
        .project_proxy_probe(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let mut value = request();
    value.audience = probe.credential_audience().clone();
    value.config_json = probe.as_json().into();
    value.credential_slots = probe.credential_slots().to_vec();
    value.proxies = vec!["proxy".into()];
    let root: serde_json::Value = serde_json::from_str(&value.config_json).unwrap();
    let declared = root["route"]["rule_set"].as_array().unwrap();
    assert!(!declared.is_empty());
    assert!(declared.iter().all(|set| set["type"] == "inline"));
    CheckedProbeConfiguration::new(value.clone()).unwrap();
    for (label, sets) in [
        (
            "remote",
            json!([{"type":"remote","tag":"sites","format":"binary","url":"https://example.org/sites.srs"}]),
        ),
        (
            "local",
            json!([{"type":"local","tag":"sites","format":"source","path":"sites.json"}]),
        ),
        (
            "inline beside remote",
            json!([{"type":"inline","tag":"sites","rules":[]},
                {"type":"remote","tag":"more","format":"binary","url":"https://example.org/more.srs"}]),
        ),
        ("untyped", json!([{"tag":"sites","rules":[]}])),
        (
            "not a list",
            json!({"type":"inline","tag":"sites","rules":[]}),
        ),
    ] {
        let mut altered = value.clone();
        let mut root = root.clone();
        root["route"]["rule_set"] = sets;
        altered.config_json =
            serde_json::to_string(&canonicalize_configuration_value(root)).unwrap();
        assert!(CheckedProbeConfiguration::new(altered).is_err(), "{label}");
    }
}

#[test]
fn malformed_probe_targets_and_bounds_never_reach_native_io() {
    let alterations: [fn(&mut ProfileDelayTestRequest); 8] = [
        |r| r.proxies.clear(),
        |r| r.proxies = vec!["duplicate".into(); 2],
        |r| r.proxies = vec!["x".repeat(513)],
        |r| r.proxies = (0..33).map(|i| i.to_string()).collect(),
        |r| r.timeout_ms = 99,
        |r| r.timeout_ms = 10001,
        |r| r.config_json = "{\"outbounds\":[],\"outbounds\":[]}".into(),
        |r| r.config_json = "[]".into(),
    ];
    for alter in alterations {
        let mut value = request();
        alter(&mut value);
        assert!(CheckedProbeConfiguration::new(value).is_err());
    }
    for target in [
        "ftp://example.com/file",
        "http://@example.com/",
        "https://name:secret@example.com/",
        "https://example.com/#fragment",
        "http://example.com:0/",
        "https://example.com/with space",
        "http:example.com",
    ] {
        let mut value = request();
        value.target_url = Some(target.into());
        assert!(CheckedProbeConfiguration::new(value).is_err());
    }
    for expected in [
        "600",
        "20",
        "299-200",
        "200/",
        "/200",
        "200-204-299",
        "2xx",
        "200 /204",
    ] {
        let mut value = request();
        value.expected_status = Some(expected.into());
        assert!(CheckedProbeConfiguration::new(value).is_err());
    }
}

#[test]
fn credential_probe_requires_exact_slots_and_keeps_material_out_of_debug() {
    let profile=ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"trojan","tag":"node","server":"example.com","server_port":443,"credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"example.com"}}]}"#).unwrap();
    let probe = profile
        .project_proxy_probe(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let mut value = request();
    value.audience = probe.credential_audience().clone();
    value.config_json = probe.as_json().into();
    value.credential_slots = probe.credential_slots().to_vec();
    value.proxies = vec!["node".into()];
    let checked = CheckedProbeConfiguration::new(value).unwrap();
    assert!(checked.resolve([]).is_err());
    let references = checked.credential_references();
    let resolved = checked
        .resolve([(&references[0], "probe-secret-never-log")])
        .unwrap();
    assert!(
        std::str::from_utf8(&resolved.projection.bytes)
            .unwrap()
            .contains("probe-secret-never-log")
    );
    assert!(!format!("{resolved:?}").contains("probe-secret-never-log"));
}
