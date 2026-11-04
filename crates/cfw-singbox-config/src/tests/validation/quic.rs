//! Hysteria2, TUIC and AnyTLS options and the QUIC TLS rules.

use super::*;

#[test]
fn hysteria2_sing_box_1_14_options_follow_the_runtime_bounds() {
    let hysteria2 = |fields: &str| {
        format!(
            r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,{fields}"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
        )
    };
    let obfs = |kind: &str, sizes: &str| {
        format!(
            r#""obfs":{{"type":"{kind}","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}{sizes}}},"#
        )
    };

    let full = format!(
        r#""server_ports":["5000:5100"],"hop_interval_seconds":10,"hop_interval_max_seconds":60,"bbr_profile":"conservative","down_mbps":200,{}"#,
        obfs("gecko", r#","min_packet_size":400,"max_packet_size":1400"#)
    );
    let profile = ValidatedSingBoxProfile::parse(&hysteria2(&full)).expect("1.14 options");
    let value: Value = serde_json::from_str(profile.as_json()).expect("canonical profile JSON");
    let outbound = &value["outbounds"][0];
    assert_eq!(outbound["hop_interval_max_seconds"], 60);
    assert_eq!(outbound["bbr_profile"], "conservative");
    assert_eq!(outbound["obfs"]["type"], "gecko");
    assert_eq!(outbound["obfs"]["min_packet_size"], 400);
    assert_eq!(outbound["obfs"]["max_packet_size"], 1400);
    for accepted in [
        obfs("gecko", ""),
        obfs("gecko", r#","min_packet_size":1200"#),
        obfs("gecko", r#","max_packet_size":512"#),
        obfs("gecko", r#","min_packet_size":1,"max_packet_size":2048"#),
        r#""server_ports":["5000:5100"],"hop_interval_seconds":5,"#.to_owned(),
        r#""server_ports":["5000:5100"],"hop_interval_seconds":3600,"hop_interval_max_seconds":3600,"#.to_owned(),
        r#""bbr_profile":"aggressive","down_mbps":100,"#.to_owned(),
    ] {
        ValidatedSingBoxProfile::parse(&hysteria2(&accepted))
            .unwrap_or_else(|error| panic!("{accepted}: {error}"));
    }

    for (label, fields, expected_path) in [
        (
            "hop below the runtime minimum",
            r#""server_ports":["5000:5100"],"hop_interval_seconds":4,"#.to_owned(),
            "$.outbounds[0].hop_interval_seconds",
        ),
        (
            "range without ports",
            r#""hop_interval_seconds":10,"hop_interval_max_seconds":60,"#.to_owned(),
            "$.outbounds[0].hop_interval_seconds",
        ),
        (
            "range without minimum",
            r#""server_ports":["5000:5100"],"hop_interval_max_seconds":60,"#.to_owned(),
            "$.outbounds[0].hop_interval_max_seconds",
        ),
        (
            "range below minimum",
            r#""server_ports":["5000:5100"],"hop_interval_seconds":60,"hop_interval_max_seconds":30,"#.to_owned(),
            "$.outbounds[0].hop_interval_max_seconds",
        ),
        (
            "range above bound",
            r#""server_ports":["5000:5100"],"hop_interval_seconds":60,"hop_interval_max_seconds":3601,"#.to_owned(),
            "$.outbounds[0].hop_interval_max_seconds",
        ),
        (
            "bbr profile beside Brutal upload",
            r#""bbr_profile":"standard","up_mbps":100,"#.to_owned(),
            "$.outbounds[0].bbr_profile",
        ),
        (
            "salamander packet size",
            obfs("salamander", r#","min_packet_size":512"#),
            "$.outbounds[0].obfs",
        ),
        (
            "gecko minimum above maximum",
            obfs("gecko", r#","min_packet_size":1300,"max_packet_size":1200"#),
            "$.outbounds[0].obfs",
        ),
        (
            "gecko minimum above default maximum",
            obfs("gecko", r#","min_packet_size":1300"#),
            "$.outbounds[0].obfs",
        ),
        (
            "gecko maximum below default minimum",
            obfs("gecko", r#","max_packet_size":511"#),
            "$.outbounds[0].obfs",
        ),
        (
            "gecko maximum above the wire limit",
            obfs("gecko", r#","max_packet_size":2049"#),
            "$.outbounds[0].obfs",
        ),
        (
            "gecko zero minimum",
            obfs("gecko", r#","min_packet_size":0"#),
            "$.outbounds[0].obfs",
        ),
    ] {
        let error = ValidatedSingBoxProfile::parse(&hysteria2(&fields)).expect_err(label);
        assert!(
            matches!(error, ConfigError::UnsupportedPolicyShape { ref path, .. } if path == expected_path),
            "{label}: {error:?}"
        );
    }
    for (label, fields) in [
        ("unknown bbr profile", r#""bbr_profile":"fast","#),
        ("chrome parrot switch", r#""disable_chrome_parrot":true,"#),
    ] {
        let error = ValidatedSingBoxProfile::parse(&hysteria2(fields)).expect_err(label);
        assert!(
            matches!(error, ConfigError::InvalidJson(_)),
            "{label}: {error:?}"
        );
    }
}

#[test]
fn hysteria2_port_hopping_is_canonical_bounded_and_non_overlapping() {
    let valid = format!(
        r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"server_ports":["443","5000:5002"],"hop_interval_seconds":30,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
    );
    let profile = ValidatedSingBoxProfile::parse(&valid).expect("canonical port hopping");
    let value: Value = serde_json::from_str(profile.as_json()).expect("canonical profile JSON");
    assert_eq!(
        value["outbounds"][0]["server_ports"],
        serde_json::json!(["443", "5000:5002"])
    );
    assert_eq!(value["outbounds"][0]["hop_interval_seconds"], 30);

    for (label, fields, expected_path) in [
        (
            "overlap",
            r#""server_ports":["443","440:450"],"#,
            "$.outbounds[0].server_ports[1]",
        ),
        (
            "noncanonical range",
            r#""server_ports":["0500:0600"],"#,
            "$.outbounds[0].server_ports[0]",
        ),
        (
            "hop without ports",
            r#""hop_interval_seconds":30,"#,
            "$.outbounds[0].hop_interval_seconds",
        ),
        (
            "hop outside bound",
            r#""server_ports":["5000:5002"],"hop_interval_seconds":3601,"#,
            "$.outbounds[0].hop_interval_seconds",
        ),
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,{fields}"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
        );
        let error = ValidatedSingBoxProfile::parse(&input).expect_err(label);
        assert!(
            matches!(error, ConfigError::UnsupportedPolicyShape { ref path, .. } if path == expected_path),
            "{label}: {error:?}"
        );
    }
}

#[test]
fn anytls_and_tuic_require_exact_credential_shapes_and_closed_tuic_options() {
    let wrong_uuid_kind = format!(
        r#"{{"outbounds":[{{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_password"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}}}}]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&wrong_uuid_kind),
        Err(ConfigError::CredentialKindMismatch { path, .. })
            if path == "$.outbounds[0].uuid_credential_ref"
    ));

    let wrong_password_kind = format!(
        r#"{{"outbounds":[{{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com"}}}}]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&wrong_password_kind),
        Err(ConfigError::CredentialKindMismatch { path, .. })
            if path == "$.outbounds[0].credential_ref"
    ));

    for invalid in [
        format!(
            r#"{{"outbounds":[{{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}}}}]}}"#
        ),
        format!(
            r#"{{"outbounds":[{{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}}}}]}}"#
        ),
        format!(
            r#"{{"outbounds":[{{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}},"congestion_control":"reno"}}]}}"#
        ),
        format!(
            r#"{{"outbounds":[{{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}},"udp_relay_mode":"stream"}}]}}"#
        ),
    ] {
        assert!(ValidatedSingBoxProfile::parse(&invalid).is_err());
    }
}

#[test]
fn quic_protocols_reject_utls_and_reality_while_anytls_accepts_them() {
    let reality = r#""reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}"#;
    let utls = r#""utls":{"enabled":true,"fingerprint":"chrome"}"#;

    let anytls = format!(
        r#"{{"outbounds":[{{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com",{utls},{reality}}}}}]}}"#
    );
    ValidatedSingBoxProfile::parse(&anytls).expect("AnyTLS supports standard TLS extensions");

    for (protocol, extension, expected_path) in [
        ("hysteria2", utls, "$.outbounds[0].tls.utls"),
        ("hysteria2", reality, "$.outbounds[0].tls.reality"),
        ("tuic", utls, "$.outbounds[0].tls.utls"),
        ("tuic", reality, "$.outbounds[0].tls.reality"),
    ] {
        let outbound = if protocol == "hysteria2" {
            format!(
                r#"{{"type":"hysteria2","tag":"quic","server":"quic.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"quic.example.com",{extension}}}}}"#
            )
        } else {
            format!(
                r#"{{"type":"tuic","tag":"quic","server":"quic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"quic.example.com",{extension}}}}}"#
            )
        };
        let error = ValidatedSingBoxProfile::parse(&format!(r#"{{"outbounds":[{outbound}]}}"#))
            .expect_err("QUIC TLS must reject unsupported TLS adapters");
        assert!(matches!(
            error,
            ConfigError::UnsupportedPolicyShape { path, .. } if path == expected_path
        ));
    }
}
