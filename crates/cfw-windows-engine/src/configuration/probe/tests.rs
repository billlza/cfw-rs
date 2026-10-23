use super::*;
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use serde_json::json;

pub(crate) fn request() -> ProfileDelayTestRequest {
    let profile = ValidatedSingBoxProfile::direct();
    let probe = profile
        .project_proxy_probe(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
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
    ] {
        let mut value = request();
        let mut root: serde_json::Value = serde_json::from_str(&value.config_json).unwrap();
        root[key] = native;
        value.config_json = serde_json::to_string(&canonicalize_configuration_value(root)).unwrap();
        assert!(CheckedProbeConfiguration::new(value).is_err());
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
