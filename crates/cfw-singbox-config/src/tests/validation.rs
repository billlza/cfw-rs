use serde_json::Value;

use crate::{
    ConfigError, CredentialKind, CredentialSecret, MAX_PROFILE_BYTES, MAX_PROFILE_NODES,
    ValidatedSingBoxProfile,
};

const SS_ID: &str = "11111111-1111-4111-8111-111111111111";
const VMESS_ID: &str = "22222222-2222-4222-8222-222222222222";
const VLESS_ID: &str = "33333333-3333-4333-8333-333333333333";
const TROJAN_ID: &str = "44444444-4444-4444-8444-444444444444";
const HYSTERIA_ID: &str = "55555555-5555-4555-8555-555555555555";
const HYSTERIA_OBFS_ID: &str = "66666666-6666-4666-8666-666666666666";
const ANYTLS_ID: &str = "88888888-8888-4888-8888-888888888888";
const TUIC_UUID_ID: &str = "99999999-9999-4999-8999-999999999999";
const TUIC_PASSWORD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";

#[test]
fn canonical_digest_does_not_depend_on_object_order() {
    let first = ValidatedSingBoxProfile::parse(
        r#"{"route":{"final":"proxy"},"outbounds":[{"tag":"proxy","type":"direct"}]}"#,
    )
    .expect("first profile");
    let second = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"proxy"}}"#,
    )
    .expect("second profile");
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.as_json(), second.as_json());
}

#[test]
fn application_owned_inbounds_are_rejected() {
    let error = ValidatedSingBoxProfile::parse(r#"{"inbounds":[]}"#)
        .expect_err("profile must not control listeners");
    assert_eq!(
        error,
        ConfigError::UnsupportedTopLevelKey("inbounds".into())
    );
}

#[test]
fn process_matching_is_rejected_at_any_depth() {
    let error =
        ValidatedSingBoxProfile::parse(r#"{"route":{"rules":[{"process_name":["Safari"]}]}}"#)
            .expect_err("process matching is unavailable in the unprivileged design");
    assert!(matches!(
        error,
        ConfigError::ForbiddenKey { key, .. } if key == "process_name"
    ));
}

#[test]
fn executable_and_file_path_options_are_rejected_at_any_depth() {
    for key in [
        "command",
        "script",
        "executable",
        "certificate_path",
        "download_url",
    ] {
        let input = format!(r#"{{"outbounds":[{{"type":"direct","{key}":"/tmp/x"}}]}}"#);
        let error = ValidatedSingBoxProfile::parse(&input)
            .expect_err("executable and file path options must be rejected");
        assert!(matches!(
            error,
            ConfigError::ForbiddenKey { key: rejected, .. } if rejected == key
        ));
    }
}

#[test]
fn engine_managed_remote_resources_are_rejected() {
    let remote_rule_set = ValidatedSingBoxProfile::parse(
        r#"{"route":{"rule_set":[{"type":"remote","tag":"blocked","url":"http://169.254.169.254/latest"}]}}"#,
    )
    .expect_err("the engine must not fetch remote rule sets");
    assert!(matches!(
        remote_rule_set,
        ConfigError::RemoteResource { path } if path == "$.route.rule_set[0]"
    ));

    let health_check = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"urltest","tag":"automatic","url":"https://example.com"}]}"#,
    )
    .expect_err("profiles must not schedule URL-based probes");
    assert!(matches!(
        health_check,
        ConfigError::ForbiddenKey { key, .. } if key == "url"
    ));
}

#[test]
fn credentials_are_rejected_until_keychain_projection_exists() {
    for key in ["password", "private_key", "token", "uuid", "auth_key"] {
        let input = format!(r#"{{"outbounds":[{{"type":"direct","{key}":"sensitive"}}]}}"#);
        let error = ValidatedSingBoxProfile::parse(&input)
            .expect_err("credentials must never be persisted in profile JSON");
        assert!(matches!(
            error,
            ConfigError::CredentialRequiresKeychain { key: rejected, .. } if rejected == key
        ));
    }
}

#[test]
fn typed_remote_outbounds_persist_only_canonical_credential_references() {
    let input = format!(
        r#"{{
          "outbounds": [
            {{"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
            {{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"security":"auto","tls":{{"enabled":true,"server_name":"vmess.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}}}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"vmess.example.com"}}}}}},
            {{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}},
            {{"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"trojan.example.com"}},"transport":{{"type":"grpc","service_name":"tunnel"}}}},
            {{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}},"up_mbps":100,"down_mbps":200,"obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}}}},
            {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com"}}}},
            {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}},"congestion_control":"bbr","udp_relay_mode":"quic"}}
          ],
          "route": {{"final":"ss"}}
        }}"#
    );
    let profile = ValidatedSingBoxProfile::parse(&input).expect("typed remote profile");
    let value: Value = serde_json::from_str(profile.as_json()).expect("canonical profile JSON");
    assert_eq!(value["route"]["final"], "ss");
    assert_eq!(value["outbounds"][0]["credential_ref"]["id"], SS_ID);
    assert!(!contains_key(&value, "password"));
    assert!(!contains_key(&value, "uuid"));
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
fn profile_tls_cannot_override_the_product_version_policy() {
    for field in [r#""min_version":"1.2""#, r#""max_version":"1.3""#] {
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

#[test]
fn vmess_alter_id_is_closed_to_the_pinned_zero_or_one_contract() {
    let profile_with_default = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"alter_id":0}}]}}"#
    ))
    .expect("AEAD VMess profile");
    let profile_without_default = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}}}}]}}"#
    ))
    .expect("default AEAD VMess profile");
    assert_eq!(profile_with_default, profile_without_default);
    assert!(!profile_with_default.as_json().contains("alter_id"));

    let legacy = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"alter_id":1}}]}}"#
    ))
    .expect("legacy-protocol VMess profile");
    let value: Value = serde_json::from_str(legacy.as_json()).expect("canonical VMess JSON");
    assert_eq!(value["outbounds"][0]["alter_id"], 1);
    assert_ne!(legacy.digest(), profile_without_default.digest());

    for invalid in ["-1", "2", "256", "1.5", r#""1""#] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"alter_id":{invalid}}}]}}"#
        );
        assert!(
            ValidatedSingBoxProfile::parse(&input).is_err(),
            "accepted invalid alter_id {invalid}"
        );
    }
}

#[test]
fn cross_layer_typed_profile_fixture_uses_the_native_safe_field_shape() {
    let profile =
        ValidatedSingBoxProfile::parse(include_str!("../../../../contracts/typed-profile-v1.json"))
            .expect("shared typed profile fixture");
    let canonical: serde_json::Value =
        serde_json::from_str(profile.as_json()).expect("canonical fixture");
    assert_eq!(canonical["outbounds"][0]["transport"]["type"], "ws");
    assert_eq!(
        canonical["outbounds"][0]["transport"]["headers"]["Host"],
        "vmess.example.com"
    );
    assert_eq!(canonical["outbounds"][0]["tls"]["utls"]["enabled"], true);
    assert_eq!(canonical["outbounds"][1]["tls"]["reality"]["enabled"], true);
}

#[test]
fn typed_profiles_reject_unknown_fields_and_wrong_credential_kinds() {
    let unknown = format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}},"plugin":"unsafe"}}]}}"#
    );
    assert!(ValidatedSingBoxProfile::parse(&unknown).is_err());

    let wrong_kind = format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"trojan_password"}}}}]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&wrong_kind),
        Err(ConfigError::CredentialKindMismatch { .. })
    ));

    let noncanonical_id = r#"{"outbounds":[{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{"id":"22222222222242228222222222222222","kind":"vmess_uuid"}}]}"#;
    assert!(ValidatedSingBoxProfile::parse(noncanonical_id).is_err());
}

#[test]
fn reality_requires_enabled_canonical_x25519_public_material() {
    let fixture = include_str!("../../../../contracts/typed-profile-v1.json");
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
        assert!(ValidatedSingBoxProfile::parse(&invalid).is_err());
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

#[test]
fn v2ray_quic_requires_standard_enabled_tls() {
    for (protocol, credential_id, credential_kind) in [
        ("vmess", VMESS_ID, "vmess_uuid"),
        ("vless", VLESS_ID, "vless_uuid"),
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"{protocol}","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{credential_id}","kind":"{credential_kind}"}},"transport":{{"type":"quic"}}}}]}}"#
        );
        assert!(matches!(
            ValidatedSingBoxProfile::parse(&input),
            Err(ConfigError::UnsupportedPolicyShape { path, .. })
                if path == "$.outbounds[0].tls.enabled"
        ));
    }

    for (extension, expected_path) in [
        (
            r#","utls":{"enabled":true,"fingerprint":"chrome"}"#,
            "$.outbounds[0].tls.utls",
        ),
        (
            r#","reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}"#,
            "$.outbounds[0].tls.reality",
        ),
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"tls":{{"enabled":true,"server_name":"example.com"{extension}}},"transport":{{"type":"quic"}}}}]}}"#
        );
        assert!(matches!(
            ValidatedSingBoxProfile::parse(&input),
            Err(ConfigError::UnsupportedPolicyShape { path, .. }) if path == expected_path
        ));
    }

    for input in [
        format!(
            r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"tls":{{"enabled":true,"server_name":"example.com"}},"transport":{{"type":"quic"}}}}]}}"#
        ),
        format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"tls":{{"enabled":true,"server_name":"example.com"}},"transport":{{"type":"quic"}}}}]}}"#
        ),
        format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"example.com"}},"transport":{{"type":"quic"}}}}]}}"#
        ),
    ] {
        ValidatedSingBoxProfile::parse(&input).expect("standard TLS V2Ray QUIC profile");
    }
}

#[test]
fn vless_vision_rejects_transport_streams_and_non_xudp_packet_encodings() {
    for transport in [
        r#"{"type":"http","path":"/"}"#,
        r#"{"type":"ws","path":"/"}"#,
        r#"{"type":"grpc","service_name":"vision"}"#,
        r#"{"type":"quic"}"#,
        r#"{"type":"http_upgrade","path":"/"}"#,
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"example.com"}},"transport":{transport}}}]}}"#
        );
        assert!(matches!(
            ValidatedSingBoxProfile::parse(&input),
            Err(ConfigError::UnsupportedPolicyShape { path, .. })
                if path == "$.outbounds[0].transport"
        ));
    }

    for packet_encoding in ["raw", "packet_addr"] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","packet_encoding":"{packet_encoding}","tls":{{"enabled":true,"server_name":"example.com"}}}}]}}"#
        );
        assert!(matches!(
            ValidatedSingBoxProfile::parse(&input),
            Err(ConfigError::UnsupportedPolicyShape { path, .. })
                if path == "$.outbounds[0].packet_encoding"
        ));
    }

    for packet_encoding in [None, Some("xudp")] {
        let packet_encoding = packet_encoding
            .map(|value| format!(r#","packet_encoding":"{value}""#))
            .unwrap_or_default();
        let input = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision"{packet_encoding},"tls":{{"enabled":true,"server_name":"example.com"}}}}]}}"#
        );
        ValidatedSingBoxProfile::parse(&input)
            .expect("Vision accepts omitted or explicit XUDP packet encoding");
    }
}

#[test]
fn websocket_host_accepts_modern_authorities_but_rejects_non_authorities() {
    for host in ["cdn.example.com:8443", "[2606:4700:4700::1111]:8443"] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"{host}"}}}}}}]}}"#
        );
        ValidatedSingBoxProfile::parse(&input).expect("valid WebSocket Host authority");
    }

    for host in [
        "cdn.example.com:0",
        "cdn.example.com:65536",
        "user@cdn.example.com:443",
        "cdn.example.com/path",
        "[2606:4700:4700::1111",
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"{host}"}}}}}}]}}"#
        );
        assert!(ValidatedSingBoxProfile::parse(&input).is_err(), "{host}");
    }
}

#[test]
fn one_credential_id_cannot_cross_protocol_kinds() {
    let input = format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"ss","server":"one.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"trojan","tag":"trojan","server":"two.example.com","server_port":443,"credential_ref":{{"id":"{SS_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"two.example.com"}}}}
        ]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&input),
        Err(ConfigError::ConflictingCredentialReference { id }) if id == SS_ID
    ));
}

#[test]
fn borrowed_secret_debug_is_redacted_and_not_serializable() {
    let secret = CredentialSecret::new("never-log-this-secret").expect("bounded secret");
    assert_eq!(format!("{secret:?}"), "CredentialSecret([REDACTED])");
    assert_eq!(secret.expose_to_vault(), "never-log-this-secret");
}

#[test]
fn uuid_credentials_require_canonical_hyphenated_values() {
    let canonical =
        CredentialSecret::new("11111111-1111-4111-8111-111111111111").expect("bounded UUID secret");
    for kind in [
        CredentialKind::VmessUuid,
        CredentialKind::VlessUuid,
        CredentialKind::TuicUuid,
    ] {
        canonical
            .validate_for_kind(kind)
            .expect("canonical UUID credential");
    }

    for value in [
        "not-a-uuid",
        "11111111111141118111111111111111",
        "11111111-1111-4111-8111-11111111111A",
    ] {
        let invalid = CredentialSecret::new(value).expect("bounded invalid UUID secret");
        for kind in [
            CredentialKind::VmessUuid,
            CredentialKind::VlessUuid,
            CredentialKind::TuicUuid,
        ] {
            assert!(
                invalid.validate_for_kind(kind).is_err(),
                "{kind:?}: {value}"
            );
        }
    }
}

#[test]
fn untyped_network_and_credential_bearing_features_fail_closed() {
    for input in [
        r#"{"dns":{"servers":[{"address":"https://169.254.169.254"}]},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        r#"{"outbounds":[{"type":"hysteria","tag":"proxy","auth_str":"secret"}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct","tls":{"client_key":"secret"}}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct","headers":{"Authorization":"secret"}}]}"#,
    ] {
        assert!(ValidatedSingBoxProfile::parse(input).is_err());
    }
}

#[test]
fn typed_remote_endpoints_reject_non_routable_and_tunnel_reserved_literals() {
    for server in [
        "0.0.0.0",
        "127.0.0.1",
        "169.254.169.254",
        "198.18.0.2",
        "198.18.64.2",
        "203.0.113.10",
        "::1",
        "fe80::1",
        "2001:db8::2",
        "2001:2:0:64::2",
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"{server}","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
        );
        assert!(ValidatedSingBoxProfile::parse(&input).is_err(), "{server}");
    }
}

#[test]
fn excessively_wide_profiles_are_rejected_before_projection() {
    // One byte per node keeps the input well under the 384 KiB byte ceiling so
    // the rejection can only come from the node budget.
    let outbounds = std::iter::repeat_n("0", MAX_PROFILE_NODES)
        .collect::<Vec<_>>()
        .join(",");
    let input = format!(r#"{{"outbounds":[{outbounds}]}}"#);
    assert!(input.len() < MAX_PROFILE_BYTES);
    let error = ValidatedSingBoxProfile::parse(&input)
        .expect_err("node count must remain bounded independently of byte size");
    assert_eq!(
        error,
        ConfigError::TooComplex {
            maximum: MAX_PROFILE_NODES
        }
    );
}

#[test]
fn remote_outbound_admission_distinguishes_real_replacements_from_local_only_profiles() {
    let direct = ValidatedSingBoxProfile::direct();
    assert!(!direct.routes_through_remote());

    let remote = ValidatedSingBoxProfile::parse(
        r#"{
          "outbounds": [
            {
              "type": "shadowsocks",
              "tag": "remote",
              "server": "example.com",
              "server_port": 443,
              "method": "aes-128-gcm",
              "credential_ref": {
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "kind": "shadowsocks_password"
              }
            }
          ]
        }"#,
    )
    .expect("remote profile");
    assert!(remote.routes_through_remote());

    let unused_remote = ValidatedSingBoxProfile::parse(&format!(
        r#"{{
              "outbounds": [
                {{"type":"direct","tag":"direct"}},
                {{
                  "type":"shadowsocks",
                  "tag":"unused-remote",
                  "server":"example.com",
                  "server_port":443,
                  "method":"aes-128-gcm",
                  "credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}
                }}
              ],
              "route":{{"final":"direct"}}
            }}"#
    ))
    .expect("unused remote profile remains valid for local testing");
    assert!(!unused_remote.routes_through_remote());

    let implicit_first_direct = ValidatedSingBoxProfile::parse(&format!(
        r#"{{
              "outbounds": [
                {{"type":"direct","tag":"direct"}},
                {{
                  "type":"shadowsocks",
                  "tag":"unused-remote",
                  "server":"example.com",
                  "server_port":443,
                  "method":"aes-128-gcm",
                  "credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}
                }}
              ]
            }}"#
    ))
    .expect("implicit direct final profile");
    assert!(!implicit_first_direct.routes_through_remote());
}

fn contains_key(value: &Value, expected: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(expected)
                || object.values().any(|value| contains_key(value, expected))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, expected)),
        _ => false,
    }
}
