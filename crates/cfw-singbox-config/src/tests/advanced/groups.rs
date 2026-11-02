//! Fallback, load-balance and other automatic groups, and detours across
//! groups.

use super::*;

#[test]
fn fallback_groups_preserve_priority_and_do_not_become_lowest_latency_groups() {
    let mut source = automatic_profile();
    let group = source["outbounds"][2].as_object_mut().unwrap();
    group.insert("type".into(), json!("fallback"));
    group.remove("tolerance_ms");
    let profile = ValidatedSingBoxProfile::parse(&source.to_string()).unwrap();
    assert!(profile.routes_through_remote());
    assert!(
        profile
            .with_selected_outbound("automatic", "second")
            .is_err()
    );
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .unwrap();
        let runtime: Value = serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(
            runtime["outbounds"][2],
            json!({
                "type":"fallback", "tag":"automatic", "outbounds":["first","second"],
                "url":"https://www.gstatic.com/generate_204", "interval":"300s",
                "idle_timeout":"1800s", "interrupt_exist_connections":false
            })
        );
        let probe: Value =
            serde_json::from_str(&projected.proxy_probe_template().unwrap().json).unwrap();
        assert_eq!(probe["outbounds"][2]["type"], "selector");
        assert!(probe["outbounds"][2].get("url").is_none());
    }
    for (key, invalid) in [
        ("outbounds", json!(["first", "first"])),
        ("outbounds", json!(["missing"])),
        ("outbounds", json!(["PROXY"])),
        ("interval_seconds", json!(0)),
        ("url", json!("file:///tmp/probe")),
        ("tolerance_ms", json!(50)),
    ] {
        let mut invalid_source = source.clone();
        invalid_source["outbounds"][2][key] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&invalid_source.to_string()).is_err(),
            "{key}"
        );
    }
}

#[test]
fn load_balance_strategy_and_continuous_probe_policy_survive_projection() {
    for strategy in ["consistent-hashing", "sticky-sessions", "round-robin"] {
        let mut source = automatic_profile();
        let group = source["outbounds"][2].as_object_mut().unwrap();
        group.insert("type".into(), json!("loadbalance"));
        group.insert("strategy".into(), json!(strategy));
        group.insert("lazy".into(), json!(false));
        group.remove("tolerance_ms");
        let profile = ValidatedSingBoxProfile::parse(&source.to_string()).unwrap();
        let projection = profile
            .project(
                PROFILE_ID,
                ProjectionMode::LocalProxy,
                &EngineSettings::default(),
            )
            .unwrap();
        let runtime: Value = serde_json::from_str(projection.as_json()).unwrap();
        assert_eq!(runtime["outbounds"][2]["type"], "loadbalance");
        assert_eq!(runtime["outbounds"][2]["strategy"], strategy);
        assert_eq!(runtime["outbounds"][2]["lazy"], false);
        assert!(profile.routes_through_remote());
        assert!(
            profile
                .with_selected_outbound("automatic", "first")
                .is_err()
        );
        let probe: Value =
            serde_json::from_str(&projection.proxy_probe_template().unwrap().json).unwrap();
        assert_eq!(probe["outbounds"][2]["type"], "selector");
        source["outbounds"][2]["strategy"] = json!("random");
        assert!(ValidatedSingBoxProfile::parse(&source.to_string()).is_err());
    }
}

#[test]
fn automatic_groups_preserve_timing_and_cannot_be_overridden_by_saved_selection() {
    let profile = ValidatedSingBoxProfile::parse(&automatic_profile().to_string())
        .expect("automatic profile");
    assert!(profile.routes_through_remote());
    assert!(
        profile
            .with_selected_outbound("automatic", "second")
            .is_err()
    );
    for mode in [
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("projection");
        let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
        assert_eq!(
            runtime["outbounds"][2],
            json!({
                "type":"urltest","tag":"automatic","outbounds":["first","second"],
                "url":"https://www.gstatic.com/generate_204","interval":"300s","tolerance":50,
                "idle_timeout":"1800s","interrupt_exist_connections":false
            })
        );
    }
    let mut mixed = automatic_profile();
    mixed["outbounds"][1] = json!({"type":"direct","tag":"second"});
    assert!(
        !ValidatedSingBoxProfile::parse(&mixed.to_string())
            .expect("mixed group")
            .routes_through_remote()
    );
}

#[test]
fn automatic_group_graph_and_probe_inputs_are_validated_before_runtime() {
    for (key, invalid) in [
        ("outbounds", json!([])),
        ("outbounds", json!(["first", "first"])),
        ("outbounds", json!(["missing"])),
        ("outbounds", json!(["PROXY"])),
        ("interval_seconds", json!(29)),
        ("interval_seconds", json!(86_401)),
        ("idle_timeout_seconds", json!(299)),
        ("idle_timeout_seconds", json!(604_801)),
        ("tolerance_ms", json!(10_001)),
        ("url", json!("file:///etc/passwd")),
        ("url", json!("https://name:secret@example.com/probe")),
        ("url", json!("https://example.com/#fragment")),
        ("url", json!("https://example.com:0")),
        ("url", json!("https://example.com/\nprobe")),
    ] {
        let mut value = automatic_profile();
        value["outbounds"][2][key] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&value.to_string()).is_err(),
            "admitted {key}"
        );
    }
}

#[test]
fn detours_preserve_both_hops_and_reject_cycles_across_groups() {
    let mut value = automatic_profile();
    value["detours"] = json!({"first":"second"});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("two hops");
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["outbounds"][0]["detour"], "second");
    assert!(runtime["outbounds"][0].get("domain_resolver").is_none());
    assert!(runtime["outbounds"][1].get("domain_resolver").is_some());
    for invalid in [
        json!({"first":"first"}),
        json!({"first":"second","second":"first"}),
        json!({"first":"PROXY"}),
        json!({"PROXY":"second"}),
        json!({"missing":"second"}),
    ] {
        value["detours"] = invalid;
        assert!(ValidatedSingBoxProfile::parse(&value.to_string()).is_err());
    }
}
