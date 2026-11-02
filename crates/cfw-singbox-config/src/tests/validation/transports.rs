//! V2Ray transports, VLESS Vision and VMess alter_id.

use super::*;

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
