//! The TLS floor, Reality and its uTLS and key-share requirements.

use super::*;

#[test]
fn profile_tls_cannot_lower_the_product_version_policy() {
    for field in [r#""min_version":"1.1""#, r#""max_version":"1.2""#] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com",{field}}}}}]}}"#
        );
        assert!(
            ValidatedSingBoxProfile::parse(&input).is_err(),
            "profile input overrode TLS policy with {field}"
        );
    }
}

#[test]
fn reality_requires_enabled_canonical_x25519_public_material() {
    let fixture = include_str!("../../../../../contracts/typed-profile-v1.json");
    for invalid in [
        fixture.replacen(
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS*",
            1,
        ),
        fixture.replacen("0123456789abcdef", "0123456789ABCDEF", 1),
        fixture.replacen(
            "\"reality\": {\n          \"enabled\": true",
            "\"reality\": {\n          \"enabled\": false",
            1,
        ),
    ] {
        assert_ne!(
            invalid, fixture,
            "the invalid Reality fixture must differ from the valid input"
        );
        assert!(ValidatedSingBoxProfile::parse(&invalid).is_err());
    }
}

#[test]
fn reality_requires_enabled_utls_on_every_tls_stream_protocol() {
    let reality = r#""reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}"#;
    for (protocol, credential) in [
        ("http", String::new()),
        (
            "vmess",
            format!(r#","credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}}"#),
        ),
        (
            "vless",
            format!(r#","credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}}"#),
        ),
        (
            "trojan",
            format!(r#","credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}}"#),
        ),
        (
            "anytls",
            format!(r#","credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}}"#),
        ),
    ] {
        let profile = |tls_extensions: &str| {
            format!(
                r#"{{"outbounds":[{{"type":"{protocol}","tag":"proxy","server":"proxy.example.com","server_port":443{credential},"tls":{{"enabled":true,"server_name":"www.example.com",{tls_extensions}}}}}]}}"#
            )
        };

        let error = ValidatedSingBoxProfile::parse(&profile(reality))
            .expect_err("sing-box refuses a Reality client without uTLS");
        assert_eq!(
            error,
            ConfigError::UnsupportedPolicyShape {
                path: "$.outbounds[0].tls.utls".into(),
                reason: "Reality requires uTLS".into(),
            },
            "{protocol}"
        );
        assert_eq!(
            error.to_string(),
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS",
            "{protocol}"
        );

        let disabled = ValidatedSingBoxProfile::parse(&profile(&format!(
            r#""utls":{{"enabled":false,"fingerprint":"chrome"}},{reality}"#
        )))
        .expect_err("disabled uTLS cannot satisfy Reality");
        assert!(
            matches!(
                &disabled,
                ConfigError::UnsupportedPolicyShape { path, .. }
                    if path == "$.outbounds[0].tls.utls.enabled"
            ),
            "{protocol}: {disabled}"
        );

        ValidatedSingBoxProfile::parse(&profile(&format!(
            r#""utls":{{"enabled":true,"fingerprint":"chrome"}},{reality}"#
        )))
        .unwrap_or_else(|error| panic!("{protocol} Reality with uTLS: {error}"));
    }
}

#[test]
fn reality_x25519mlkem768_key_share_requires_the_chrome_fingerprint() {
    let profile = |fingerprint: &str, hybrid: &str| {
        format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"{fingerprint}"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"{hybrid}}}}}}}]}}"#
        )
    };
    let hybrid = r#","support_x25519mlkem768":true"#;
    ValidatedSingBoxProfile::parse(&profile("chrome", hybrid))
        .expect("the chrome hello carries the X25519MLKEM768 key share");
    for fingerprint in [
        "firefox",
        "edge",
        "safari",
        "360",
        "qq",
        "ios",
        "android",
        "random",
        "randomized",
    ] {
        let error = ValidatedSingBoxProfile::parse(&profile(fingerprint, hybrid))
            .expect_err("only the chrome hello carries the hybrid key share");
        assert_eq!(
            error,
            ConfigError::UnsupportedPolicyShape {
                path: "$.outbounds[0].tls.utls.fingerprint".into(),
                reason: "Reality X25519MLKEM768 requires the chrome uTLS fingerprint".into(),
            },
            "{fingerprint}"
        );
        for disabled in ["", r#","support_x25519mlkem768":false"#] {
            ValidatedSingBoxProfile::parse(&profile(fingerprint, disabled))
                .unwrap_or_else(|error| panic!("{fingerprint} without the key share: {error}"));
        }
    }
    let error =
        ValidatedSingBoxProfile::parse(&profile("chrome", r#","support_x25519mlkem768":"true""#))
            .expect_err("the key share flag is a JSON boolean");
    assert!(
        matches!(&error, ConfigError::InvalidJson(_))
            && error.to_string().contains("expected a boolean"),
        "{error}"
    );
}

#[test]
fn reality_without_utls_reports_a_more_specific_defect_first() {
    let reality = r#""reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}"#;
    let disabled_reality = reality.replacen(r#""enabled":true"#, r#""enabled":false"#, 1);
    let tls = |extensions: &str| {
        format!(r#""tls":{{"enabled":true,"server_name":"www.example.com",{extensions}}}"#)
    };
    let vless = |tls: String, transport: &str| {
        format!(
            r#"{{"type":"vless","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},{tls}{transport}}}"#
        )
    };
    let quic_transport = r#","transport":{"type":"quic"}"#;
    let quic_unavailable = (
        "$.outbounds[0].tls.reality",
        "Reality is unavailable for QUIC-based protocols",
    );
    let outbound_shape = |reason: &'static str| ("$.outbounds[0]", reason);

    for (label, outbound, (expected_path, expected_reason)) in [
        (
            "disabled Reality",
            vless(tls(&disabled_reality), ""),
            (
                "$.outbounds[0].tls.reality",
                "Reality public_key or short_id is invalid",
            ),
        ),
        (
            "certificate pin",
            vless(
                tls(&format!(
                    r#""certificate_sha256":["q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="],{reality}"#
                )),
                "",
            ),
            outbound_shape("certificate pinning requires TLS, one pin kind, and no Reality"),
        ),
        (
            "explicit curves",
            vless(
                tls(&format!(r#""curve_preferences":["X25519"],{reality}"#)),
                "",
            ),
            outbound_shape(
                "explicit key-exchange curves require standard TLS; this runtime's uTLS and Reality adapters do not apply them",
            ),
        ),
        (
            "ECH",
            vless(
                tls(&format!(
                    r#""min_version":"1.3","ech":{{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----"]}},{reality}"#
                )),
                "",
            ),
            outbound_shape("ECH must be enabled with TLS 1.3 and cannot be combined with Reality"),
        ),
        (
            "VMess V2Ray QUIC",
            format!(
                r#"{{"type":"vmess","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},{}{quic_transport}}}"#,
                tls(reality)
            ),
            quic_unavailable,
        ),
        (
            "VLESS V2Ray QUIC",
            vless(tls(reality), quic_transport),
            quic_unavailable,
        ),
        (
            "Trojan V2Ray QUIC",
            format!(
                r#"{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},{}{quic_transport}}}"#,
                tls(reality)
            ),
            quic_unavailable,
        ),
        (
            "Hysteria2",
            format!(
                r#"{{"type":"hysteria2","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},{}}}"#,
                tls(reality)
            ),
            quic_unavailable,
        ),
        (
            "TUIC",
            format!(
                r#"{{"type":"tuic","tag":"proxy","server":"proxy.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},{}}}"#,
                tls(reality)
            ),
            quic_unavailable,
        ),
    ] {
        assert_eq!(
            ValidatedSingBoxProfile::parse(&format!(r#"{{"outbounds":[{outbound}]}}"#)),
            Err(ConfigError::UnsupportedPolicyShape {
                path: expected_path.into(),
                reason: expected_reason.into(),
            }),
            "{label}"
        );
    }
}

#[test]
fn disabled_tls_refuses_reality_on_every_tls_stream_protocol() {
    let reality = r#""reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}"#;
    let utls_reality = format!(r#""utls":{{"enabled":true,"fingerprint":"chrome"}},{reality}"#);
    for (protocol, credential) in [
        ("http", String::new()),
        (
            "vmess",
            format!(r#","credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}}"#),
        ),
        (
            "vless",
            format!(r#","credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}}"#),
        ),
        (
            "trojan",
            format!(r#","credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}}"#),
        ),
        (
            "anytls",
            format!(r#","credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}}"#),
        ),
    ] {
        // With uTLS present, no later TLS check catches disabled TLS, so the
        // enabled-TLS requirement alone has to refuse the node.
        for extensions in [reality, utls_reality.as_str()] {
            let input = format!(
                r#"{{"outbounds":[{{"type":"{protocol}","tag":"proxy","server":"proxy.example.com","server_port":443{credential},"tls":{{"enabled":false,"server_name":"www.example.com",{extensions}}}}}]}}"#
            );
            assert_eq!(
                ValidatedSingBoxProfile::parse(&input),
                Err(ConfigError::UnsupportedPolicyShape {
                    path: "$.outbounds[0].tls.enabled".into(),
                    reason: "TLS options require enabled TLS".into(),
                }),
                "{protocol} with {extensions}"
            );
        }
    }
}

#[test]
fn vless_vision_and_active_tls_options_require_enabled_tls() {
    for tls in [
        "",
        r#","tls":{"enabled":false,"server_name":"example.com"}"#,
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision"{tls}}}]}}"#
        );
        assert!(matches!(
            ValidatedSingBoxProfile::parse(&input),
            Err(ConfigError::UnsupportedPolicyShape { path, .. })
                if path == "$.outbounds[0].tls.enabled"
        ));
    }

    let disabled_alpn = format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"tls":{{"enabled":false,"server_name":"example.com","alpn":["h2"]}}}}]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&disabled_alpn),
        Err(ConfigError::UnsupportedPolicyShape { path, .. })
            if path == "$.outbounds[0].tls.enabled"
    ));
}
