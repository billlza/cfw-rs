//! Remote outbounds, the injected selector, TLS floors and protocol-specific fields.

use super::*;

#[test]
fn profile_probes_preserve_protocol_dns_and_credential_slots_without_network_integration() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"remote","server":"node.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"urltest","tag":"automatic","outbounds":["remote"],"url":"https://www.gstatic.com/generate_204","interval_seconds":300,"tolerance_ms":50,"idle_timeout_seconds":1800}}
        ],"route":{{"final":"automatic"}}}}"#
    )).expect("profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    let runtime: serde_json::Value = serde_json::from_str(projected.as_json()).expect("runtime");
    let probe: serde_json::Value =
        serde_json::from_str(&projected.proxy_probe_template().expect("probe").json).expect("JSON");
    assert_eq!(probe["outbounds"][0], runtime["outbounds"][0]);
    assert_eq!(probe["dns"], runtime["dns"]);
    assert_eq!(probe["outbounds"][1]["type"], "selector");
    assert_eq!(
        probe["outbounds"][1]["outbounds"],
        serde_json::json!(["remote"])
    );
    assert_eq!(probe["route"].as_object().expect("resolver").len(), 1);
    for key in ["inbounds", "experimental", "log", "services", "ntp"] {
        assert!(probe.get(key).is_none(), "probe must not contain {key}");
    }
    assert_eq!(projected.credential_slots().len(), 1);
    let pointer = projected.credential_slots()[0].json_pointer();
    assert_eq!(probe.pointer(pointer), Some(&serde_json::json!("")));
}

#[test]
fn application_injects_a_collision_free_selector_for_implicit_multi_remote_profiles() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"cfw-proxy-selector","server":"first.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"shadowsocks","tag":"second","server":"second.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID_2}","kind":"shadowsocks_password"}}}}
        ]}}"#
    ))
    .expect("implicit multi-remote profile");

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("selector projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected selector JSON");
        let outbounds = config["outbounds"].as_array().expect("runtime outbounds");
        assert_eq!(outbounds.len(), 4);
        assert_eq!(
            outbounds[3],
            serde_json::json!({"type":"direct","tag":"cfw-direct"})
        );
        assert_eq!(outbounds[2]["type"], "selector");
        assert_eq!(outbounds[2]["tag"], "cfw-proxy-selector-2");
        assert_eq!(
            outbounds[2]["outbounds"],
            serde_json::json!(["cfw-proxy-selector", "second"])
        );
        assert_eq!(outbounds[2]["default"], "cfw-proxy-selector");
        assert_eq!(outbounds[2]["interrupt_exist_connections"], false);
        assert_eq!(config["route"]["final"], "cfw-proxy-selector-2");
        for server in config["dns"]["servers"]
            .as_array()
            .expect("DNS servers")
            .iter()
            .filter(|server| server["type"] == "https")
        {
            assert_eq!(server["detour"], "cfw-proxy-selector-2");
        }
        assert_eq!(projected.credential_slots().len(), 2);
        assert_eq!(
            projected.credential_slots()[0].json_pointer(),
            "/outbounds/0/password"
        );
        assert_eq!(
            projected.credential_slots()[1].json_pointer(),
            "/outbounds/1/password"
        );
    }
}

#[test]
fn explicit_profile_route_is_never_replaced_by_the_application_selector() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"first","server":"first.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"shadowsocks","tag":"second","server":"second.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID_2}","kind":"shadowsocks_password"}}}}
        ],"route":{{"final":"second"}}}}"#
    ))
    .expect("explicit multi-remote profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("explicit route projection");
    let config: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("projected explicit route JSON");
    assert_eq!(config["outbounds"].as_array().expect("outbounds").len(), 3);
    assert_eq!(
        config["outbounds"][2],
        serde_json::json!({"type":"direct","tag":"cfw-direct"})
    );
    assert_eq!(config["route"]["final"], "second");
    assert!(projected.as_json().contains(r#""detour":"second""#));
    assert!(!projected.as_json().contains(r#""type":"selector""#));
}

#[test]
fn vmess_legacy_protocol_alter_id_reaches_the_runtime_projection() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"alter_id":1}}]}}"#
    ))
    .expect("VMess legacy protocol profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("VMess projection");
    let config: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("projected VMess JSON");
    assert_eq!(config["outbounds"][0]["alter_id"], 1);
}

#[test]
fn vless_raw_packet_encoding_is_distinct_from_an_omitted_field() {
    for (packet_encoding, expected) in [(Some("raw"), Some("")), (None, None)] {
        let packet_encoding = packet_encoding
            .map(|value| format!(r#","packet_encoding":"{value}""#))
            .unwrap_or_default();
        let profile = ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}}{packet_encoding}}}]}}"#
        ))
        .expect("typed VLESS profile");
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("VLESS projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected VLESS JSON");
        let outbound = config["outbounds"][0].as_object().expect("VLESS outbound");

        match expected {
            Some(value) => assert_eq!(
                outbound.get("packet_encoding"),
                Some(&serde_json::Value::String(value.to_owned()))
            ),
            None => assert!(!outbound.contains_key("packet_encoding")),
        }
    }
}

#[test]
fn every_enabled_remote_tls_projection_has_the_product_tls_floor() {
    let profile = remote_protocol_matrix_profile();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("remote protocol matrix projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let tls_outbounds = config["outbounds"]
            .as_array()
            .expect("outbound matrix")
            .iter()
            .filter(|outbound| outbound["tls"]["enabled"] == true)
            .collect::<Vec<_>>();
        assert_eq!(tls_outbounds.len(), 6);
        for outbound in tls_outbounds {
            assert_eq!(
                outbound["tls"]["min_version"], MINIMUM_REMOTE_TLS_VERSION,
                "{} lost the product TLS floor",
                outbound["tag"]
            );
        }
    }
}

#[test]
fn anytls_and_tuic_project_exact_placeholders_and_slots_in_both_modes() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"front.example.com","alpn":["h2"],"utls":{{"enabled":true,"fingerprint":"chrome"}}}}}},
          {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":10443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}},"congestion_control":"new_reno","udp_relay_mode":"quic"}}
        ],"route":{{"final":"tuic"}}}}"#
    ))
    .expect("typed AnyTLS/TUIC profile");

    let mut mode_outbounds = Vec::new();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("AnyTLS/TUIC runtime projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let outbounds = config["outbounds"].as_array().expect("outbounds");
        assert_eq!(outbounds.len(), 3);
        assert_eq!(
            outbounds[2],
            serde_json::json!({"type":"direct","tag":"cfw-direct"})
        );
        assert_eq!(outbounds[0]["type"], "anytls");
        assert_eq!(outbounds[0]["password"], "");
        assert_eq!(outbounds[0]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(
            outbounds[0]["tls"]["min_version"],
            MINIMUM_REMOTE_TLS_VERSION
        );
        assert!(outbounds[0].get("credential_ref").is_none());
        assert_eq!(outbounds[1]["type"], "tuic");
        assert_eq!(outbounds[1]["uuid"], "");
        assert_eq!(outbounds[1]["password"], "");
        assert_eq!(outbounds[1]["congestion_control"], "new_reno");
        assert_eq!(outbounds[1]["udp_relay_mode"], "quic");
        assert_eq!(outbounds[1]["zero_rtt_handshake"], false);
        assert_eq!(
            outbounds[1]["tls"]["min_version"],
            MINIMUM_REMOTE_TLS_VERSION
        );
        assert!(outbounds[1].get("uuid_credential_ref").is_none());
        assert!(outbounds[1].get("password_credential_ref").is_none());

        assert_eq!(projected.credential_slots().len(), 3);
        let slots = projected.credential_slots();
        assert_eq!(slots[0].reference().id(), ANYTLS_ID);
        assert_eq!(slots[0].json_pointer(), "/outbounds/0/password");
        assert_eq!(slots[1].reference().id(), TUIC_UUID_ID);
        assert_eq!(slots[1].json_pointer(), "/outbounds/1/uuid");
        assert_eq!(slots[2].reference().id(), TUIC_PASSWORD_ID);
        assert_eq!(slots[2].json_pointer(), "/outbounds/1/password");
        assert_eq!(
            serde_json::to_value(&slots[0]).unwrap()["target"],
            "anytls_password"
        );
        assert_eq!(
            serde_json::to_value(&slots[1]).unwrap()["target"],
            "tuic_uuid"
        );
        assert_eq!(
            serde_json::to_value(&slots[2]).unwrap()["target"],
            "tuic_password"
        );
        mode_outbounds.push(outbounds.clone());
    }
    assert_eq!(mode_outbounds[0], mode_outbounds[1]);
}

#[test]
fn hysteria2_port_hopping_projects_to_pinned_sing_box_fields() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"server_ports":["443","5000:5002"],"hop_interval_seconds":30,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
    ))
    .expect("Hysteria2 hopping profile");

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("Hysteria2 hopping projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("runtime JSON");
        let hysteria2 = config["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|outbound| outbound["type"] == "hysteria2")
            .expect("runtime Hysteria2");
        assert_eq!(
            hysteria2["server_ports"],
            serde_json::json!(["443:443", "5000:5002"])
        );
        assert_eq!(hysteria2["hop_interval"], "30s");
        assert_eq!(hysteria2["password"], "");
    }
}

#[test]
fn hysteria2_sing_box_1_14_options_project_only_when_present() {
    let hysteria2 = |fields: &str| {
        ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"server_ports":["5000:5100"],"hop_interval_seconds":10,{fields}"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
        ))
        .expect("Hysteria2 profile")
    };
    let projected = |profile: &ValidatedSingBoxProfile| {
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("Hysteria2 projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("runtime JSON");
        config["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|outbound| outbound["type"] == "hysteria2")
            .expect("runtime Hysteria2")
            .clone()
    };

    let options = projected(&hysteria2(&format!(
        r#""hop_interval_max_seconds":60,"bbr_profile":"aggressive","obfs":{{"type":"gecko","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}},"min_packet_size":400,"max_packet_size":1400}},"#
    )));
    assert_eq!(options["hop_interval"], "10s");
    assert_eq!(options["hop_interval_max"], "60s");
    assert_eq!(options["bbr_profile"], "aggressive");
    assert_eq!(
        options["obfs"],
        serde_json::json!({"type":"gecko","password":"","min_packet_size":400,"max_packet_size":1400})
    );

    let existing = projected(&hysteria2(&format!(
        r#""obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}},"#
    )));
    for absent in ["hop_interval_max", "bbr_profile"] {
        assert!(existing.get(absent).is_none(), "{absent}");
    }
    assert_eq!(
        existing["obfs"],
        serde_json::json!({"type":"salamander","password":""})
    );
}

#[test]
fn reality_x25519mlkem768_key_share_is_stored_and_projected_only_when_requested() {
    let profile = |hybrid: &str| {
        ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"{hybrid}}}}}}}],"route":{{"final":"proxy"}}}}"#
        ))
        .expect("typed Reality profile")
    };
    let reality = |profile: &ValidatedSingBoxProfile| {
        let stored: serde_json::Value =
            serde_json::from_str(profile.as_json()).expect("stored profile");
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("Reality projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        (
            stored["outbounds"][0]["tls"]["reality"].clone(),
            config["outbounds"][0]["tls"]["reality"].clone(),
        )
    };
    let existing = serde_json::json!({
        "enabled": true,
        "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
        "short_id": "0123456789abcdef",
    });
    for disabled in ["", r#","support_x25519mlkem768":false"#] {
        assert_eq!(
            reality(&profile(disabled)),
            (existing.clone(), existing.clone())
        );
    }
    let mut hybrid = existing.clone();
    hybrid["support_x25519mlkem768"] = serde_json::Value::Bool(true);
    assert_eq!(
        reality(&profile(r#","support_x25519mlkem768":true"#)),
        (hybrid.clone(), hybrid)
    );
}
